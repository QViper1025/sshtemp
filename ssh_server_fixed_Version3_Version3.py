import os
import sys
import socket
import threading
import subprocess
import getpass
import paramiko
import logging
from paramiko import RSAKey, ServerInterface

# reduce noisy paramiko output (still shows important errors)
logging.getLogger("paramiko").setLevel(logging.WARNING)

# --- UAC elevation for Windows ---
def is_admin():
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

if os.name == "nt" and not is_admin():
    # Relaunch the script with admin rights
    import ctypes
    params = ' '.join([f'"{arg}"' for arg in sys.argv])
    # ShellExecuteW returns >32 on success, <=32 on failure
    rc = ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, params, None, 1)
    sys.exit(0)

FIREWALL_RULE_NAME = "PythonSSHServerRule"
CONF_FILE = "ssh_server_users.conf"

# Client key file naming (simple, local storage)
CLIENT_KEY_PREFIX = "clientkey"
CLIENT_PRIVATE_SUFFIX = "_private.key"
CLIENT_PUBLIC_SUFFIX = "_public.key"


def firewall_rule_exists(port):
    if os.name != "nt":
        return False
    try:
        res = subprocess.run([
            "netsh", "advfirewall", "firewall", "show", "rule", f"name={FIREWALL_RULE_NAME}"
        ], check=False, capture_output=True, text=True)
        return str(port) in res.stdout
    except Exception:
        return False


def add_firewall_rule(port):
    if os.name == "nt":
        if firewall_rule_exists(port):
            print(f"[+] Firewall rule already exists for port {port}")
            return
        try:
            subprocess.run([
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={FIREWALL_RULE_NAME}",
                "dir=in", "action=allow", "protocol=TCP", f"localport={port}"
            ], check=True, capture_output=True)
            print(f"[+] Firewall rule added for port {port}")
        except subprocess.CalledProcessError as e:
            print(f"[!] Failed to add firewall rule: {e}")


def remove_firewall_rule():
    if os.name == "nt":
        try:
            subprocess.run([
                "netsh", "advfirewall", "firewall", "delete", "rule", f"name={FIREWALL_RULE_NAME}"
            ], check=True, capture_output=True)
            print("[+] Firewall rule removed")
        except subprocess.CalledProcessError:
            pass


def load_users():
    users = []
    if os.path.exists(CONF_FILE):
        with open(CONF_FILE, "r") as f:
            lines = f.read().splitlines()
        for i in range(0, len(lines), 2):
            if i + 1 < len(lines):
                user = lines[i].split(":", 1)[1].strip()
                pwd = lines[i + 1].split(":", 1)[1].strip()
                users.append((user, pwd))
    return users


def save_users(users):
    with open(CONF_FILE, "w") as f:
        for idx, (u, p) in enumerate(users, 1):
            f.write(f"User{idx}:{u}\n")
            f.write(f"Password{idx}:{p}\n")


def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"


class CustomServer(ServerInterface):
    def __init__(self, users=None, key_auth=False):
        self.event = threading.Event()
        self.users = users or []
        self.key_auth = key_auth

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        # If in key-only mode, reject password auth
        if self.key_auth:
            return paramiko.AUTH_FAILED
        for (u, p) in self.users:
            if u == username and p == password:
                return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        # Only allow publickey if key_auth enabled
        if not self.key_auth:
            return paramiko.AUTH_FAILED
        try:
            for fname in os.listdir("."):
                if fname.endswith(CLIENT_PUBLIC_SUFFIX) and fname.startswith(CLIENT_KEY_PREFIX):
                    with open(fname, "r") as f:
                        content = f.read().strip()
                    parts = content.split()
                    # expected: "<keytype> <base64>"
                    if len(parts) >= 2 and key.get_base64() == parts[1]:
                        return paramiko.AUTH_SUCCESSFUL
        except Exception as e:
            print("[!] Key check error:", e)
        return paramiko.AUTH_FAILED

    def check_channel_shell_request(self, channel):
        return True

    def check_channel_pty_request(
        self, channel, term, width, height, pixelwidth, pixelheight, modes
    ):
        return True


# --- Helpers to avoid paramiko trying to handle non-SSH clients and to avoid losing peeked bytes ---
class _BufferedSocketWrapper:
    """Wrap a socket and serve any pre-read buffer first (so we can recv() to detect banner)."""
    def __init__(self, sock, prebuffer=b""):
        self._sock = sock
        self._buf = prebuffer

    def recv(self, n, flags=0):
        if self._buf:
            data = self._buf[:n]
            self._buf = self._buf[n:]
            return data
        return self._sock.recv(n, flags)

    # delegate other attributes/methods
    def __getattr__(self, item):
        return getattr(self._sock, item)


def _peek_socket_for_banner(sock, timeout=3):
    """Peek at the first bytes sent by the client to detect SSH banner.

    Returns (is_ssh_like, wrapper_socket)
    - is_ssh_like: True if peeked data begins with b'SSH-'
    - wrapper_socket: either original sock or buffered wrapper (if we consumed bytes)
    """
    orig_timeout = sock.gettimeout()
    try:
        sock.settimeout(timeout)
        try:
            # Prefer MSG_PEEK so we don't consume data
            data = sock.recv(8, socket.MSG_PEEK)
            if not data:
                return False, sock
            if data.startswith(b"SSH-"):
                return True, sock
            # if not starting with SSH-, it's not an SSH client
            return False, sock
        except (AttributeError, OSError):
            # MSG_PEEK might not be available or failed. Fall back to consuming a small amount,
            # then wrap the socket so Paramiko still sees the consumed bytes.
            try:
                data = sock.recv(8)
                if not data:
                    return False, sock
                is_ssh = data.startswith(b"SSH-")
                wrapped = _BufferedSocketWrapper(sock, prebuffer=data)
                return is_ssh, wrapped
            except Exception:
                return False, sock
    finally:
        try:
            sock.settimeout(orig_timeout)
        except Exception:
            pass


def client_thread(client, addr, host_key, users, key_auth, shared_dir, client_id):
    try:
        # Quick peek: if the peer doesn't send an SSH banner (SSH-...), close early.
        is_ssh, transport_sock = _peek_socket_for_banner(client, timeout=3)
        if not is_ssh:
            # Not an SSH client (or banner not present): drop connection quietly.
            # This prevents Paramiko from spamming tracebacks when random clients connect.
            try:
                client.close()
            except Exception:
                pass
            return

        t = paramiko.Transport(transport_sock)
        t.add_server_key(host_key)
        server = CustomServer(users, key_auth=key_auth)
        try:
            t.start_server(server=server)
        except paramiko.SSHException:
            print("[!] SSH negotiation failed.")
            try:
                t.close()
            except Exception:
                pass
            return

        chan = t.accept(20)
        if chan is None:
            print("[!] No channel.")
            try:
                t.close()
            except Exception:
                pass
            return
        print(f"[+] Client {client_id} connected from {addr}")

        # Use a pty for interactive shell when possible
        if os.name == "nt":
            shell = ["cmd.exe"]
            proc = subprocess.Popen(
                shell,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=shared_dir,
                bufsize=0
            )

            def writeall(stream):
                while True:
                    data = stream.read(1024)
                    if not data:
                        break
                    try:
                        chan.send(data)
                    except Exception:
                        break

            threading.Thread(target=writeall, args=(proc.stdout,), daemon=True).start()
            threading.Thread(target=writeall, args=(proc.stderr,), daemon=True).start()
            try:
                while True:
                    data = chan.recv(1024)
                    if not data:
                        break
                    proc.stdin.write(data)
                    proc.stdin.flush()
            except Exception:
                pass
            proc.terminate()
        else:
            import select
            master_fd, slave_fd = os.openpty()
            proc = subprocess.Popen(
                ["/bin/sh", "-i"],
                preexec_fn=os.setsid,
                stdin=slave_fd,
                stdout=slave_fd,
                stderr=slave_fd,
                cwd=shared_dir,
                bufsize=0
            )
            os.close(slave_fd)

            def shell_to_chan():
                while True:
                    r, _, _ = select.select([master_fd], [], [], 0.1)
                    if master_fd in r:
                        try:
                            data = os.read(master_fd, 1024)
                            if not data:
                                break
                            chan.send(data)
                        except Exception:
                            break

            threading.Thread(target=shell_to_chan, daemon=True).start()
            try:
                while True:
                    data = chan.recv(1024)
                    if not data:
                        break
                    os.write(master_fd, data)
            except Exception:
                pass
            proc.terminate()
            os.close(master_fd)

        try:
            chan.close()
        except Exception:
            pass
        try:
            t.close()
        except Exception:
            pass
    except Exception as e:
        print(f"[!] Client {client_id} error:", e)
        try:
            client.close()
        except Exception:
            pass


def generate_client_keypairs_if_missing(count):
    generated = []
    # check for at least "1_clientkey_public.key" existence
    found = False
    for fname in os.listdir("."):
        if fname.startswith(CLIENT_KEY_PREFIX) and fname.endswith(CLIENT_PUBLIC_SUFFIX):
            found = True
            break
    if found:
        return []

    for i in range(1, count + 1):
        private_file = f"{CLIENT_KEY_PREFIX}{i}{CLIENT_PRIVATE_SUFFIX}"
        public_file = f"{CLIENT_KEY_PREFIX}{i}{CLIENT_PUBLIC_SUFFIX}"
        key = RSAKey.generate(2048)
        key.write_private_key_file(private_file)
        with open(public_file, "w") as f:
            f.write(f"{key.get_name()} {key.get_base64()}")
        generated.append((private_file, public_file))
        print(f"[+] Generated client keypair: {private_file}, {public_file}")
    return generated


def main():
    print("=== Interactive SSH Server ===")

    cwd = os.getcwd()
    print(f"Current directory: {cwd}")
    ans = input("Use this directory? (y/n): ").strip().lower()
    if ans == "n":
        newdir = input("Enter directory path: ").strip()
        if os.path.isdir(newdir):
            os.chdir(newdir)
            cwd = newdir
        else:
            print("[!] Invalid directory, using default.")
    shared_dir = os.getcwd()

    # prompt for port
    try:
        port = int(input("Enter port number: ").strip())
    except Exception:
        print("[!] Invalid port, exiting.")
        return

    # choose auth mode
    print("Choose authentication method:\n1) Username/Password\n2) SSH Key (publickey)")
    choice = input("Enter choice (1/2): ").strip()

    users = []
    host_key = None
    key_auth = False

    if choice == "1":
        if os.path.exists(CONF_FILE):
            users = load_users()
        else:
            print("[!] No ssh_server_users.conf found.")
            try:
                n = int(input("How many users to add? "))
            except Exception:
                print("[!] Invalid number, exiting.")
                return
            for i in range(n):
                u = input(f"Username {i+1}: ").strip()
                p = getpass.getpass(f"Password {i+1}: ")
                users.append((u, p))
            save_users(users)
        if not users:
            print("[!] No users available, exiting.")
            return
    else:
        # key auth selected
        key_auth = True
        try:
            if not any(fname.startswith(CLIENT_KEY_PREFIX) and fname.endswith(CLIENT_PUBLIC_SUFFIX) for fname in os.listdir(".")):
                n = int(input("No client keys found. How many client keypairs to generate? "))
                generate_client_keypairs_if_missing(n)
        except Exception:
            # if input fails, try to generate 1
            generate_client_keypairs_if_missing(1)

    # ensure server host key (separate from client keys)
    if not os.path.exists("server_host.key"):
        print("[*] Generating server host key...")
        key = RSAKey.generate(2048)
        key.write_private_key_file("server_host.key")
    host_key = RSAKey(filename="server_host.key")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("", port))
        sock.listen(100)
    except Exception as e:
        print(f"[!] Failed to bind/listen on port {port}: {e}")
        return

    # add firewall rule if on Windows
    add_firewall_rule(port)

    print("\n=== Server Info ===")
    print(f"Shared directory: {shared_dir}")
    print(f"Port opened: {port}")
    print(f"Local IP: {get_local_ip()}")
    if users:
        print("Authorized Users:")
        for u, p in users:
            print(f" - {u}:{p}")
    if key_auth:
        print("Key authentication: enabled (public keys stored locally)")
        # list public key filenames
        for fname in os.listdir("."):
            if fname.startswith(CLIENT_KEY_PREFIX) and fname.endswith(CLIENT_PUBLIC_SUFFIX):
                print(f" - allowed key: {fname}")
    print("STATUS: RUNNING")

    client_id = 0
    try:
        while True:
            client, addr = sock.accept()
            client_id += 1
            threading.Thread(
                target=client_thread,
                args=(client, addr, host_key, users, key_auth, shared_dir, client_id),
                daemon=True,
            ).start()
    except KeyboardInterrupt:
        print("\n[!] Server shutting down (KeyboardInterrupt).")
    except Exception as e:
        print(f"\n[!] Server error: {e}")
    finally:
        # ensure firewall rule is removed and socket closed on exit
        remove_firewall_rule()
        try:
            sock.close()
        except Exception:
            pass
        print("[+] Clean shutdown complete.")


if __name__ == "__main__":
    main()