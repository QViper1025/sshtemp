#!/usr/bin/env python3
"""
Simple SSH test client for the provided server.

Features:
- Connect using password or local private key (no encryption/password protection).
- Interactive shell (requests a PTY) with basic local terminal handling on Unix.
- Non-interactive command execution via -c.
- Defaults to clientkey1_private.key which matches the server's client key generator naming.

Usage examples:
  python3 ssh_test_client.py -h 127.0.0.1 -p 2222 -u alice -P secret
  python3 ssh_test_client.py -h 127.0.0.1 -p 2222 -u alice -k clientkey1_private.key
  python3 ssh_test_client.py -h 127.0.0.1 -p 2222 -u alice -P secret -c "ls -la"
"""

import argparse
import getpass
import socket
import sys
import threading

import paramiko

# Platform-specific imports for interactive terminal handling
IS_WINDOWS = sys.platform.startswith("win")
if not IS_WINDOWS:
    import termios
    import tty
else:
    import msvcrt

def parse_args():
    p = argparse.ArgumentParser(description="Simple SSH test client")
    p.add_argument("-H", "--host", dest="host", required=True, help="Server host")
    p.add_argument("-p", "--port", dest="port", type=int, default=22, help="Server port")
    p.add_argument("-u", "--user", dest="username", required=True, help="Username")
    p.add_argument("-P", "--password", dest="password", help="Password (if using password auth)")
    p.add_argument("-k", "--key", dest="keyfile", help="Private key file (if using key auth)")
    p.add_argument("-c", "--command", dest="command", help="Run a single command and exit (non-interactive)")
    p.add_argument("--no-tty", dest="tty", action="store_false", help="Do not request a PTY (for non-interactive shells)")
    p.set_defaults(tty=True)
    return p.parse_args()

def open_ssh_client(host, port, username, password=None, keyfile=None, timeout=10):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    connect_kwargs = {
        "hostname": host,
        "port": port,
        "username": username,
        "timeout": timeout,
        "banner_timeout": timeout,
        "auth_timeout": timeout,
    }
    if keyfile:
        try:
            pkey = paramiko.RSAKey.from_private_key_file(keyfile)
            connect_kwargs["pkey"] = pkey
        except Exception as e:
            print(f"[!] Failed to load key {keyfile}: {e}")
            return None
    else:
        connect_kwargs["password"] = password

    try:
        client.connect(**connect_kwargs)
        return client
    except Exception as e:
        print(f"[!] Failed to connect: {e}")
        return None

def interactive_shell(channel):
    """
    Forward data between local stdin/stdout and the SSH channel.
    Attempts to set local terminal to raw mode on Unix for a better interactive experience.
    """
    if not IS_WINDOWS:
        old_tty = termios.tcgetattr(sys.stdin)
        try:
            tty.setraw(sys.stdin.fileno())
            tty.setcbreak(sys.stdin.fileno())
            _interactive_loop_unix(channel)
        finally:
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_tty)
    else:
        _interactive_loop_win(channel)

def _interactive_loop_unix(channel):
    # Reader thread: remote -> local stdout
    def recv_thread():
        try:
            while True:
                data = channel.recv(1024)
                if not data:
                    break
                sys.stdout.buffer.write(data)
                sys.stdout.buffer.flush()
        except Exception:
            pass

    t = threading.Thread(target=recv_thread, daemon=True)
    t.start()

    # Writer loop: local stdin -> remote
    try:
        while True:
            ch = sys.stdin.buffer.read(1)
            if not ch:
                break
            channel.send(ch)
    except (KeyboardInterrupt, EOFError):
        pass

def _interactive_loop_win(channel):
    def recv_thread():
        try:
            while True:
                data = channel.recv(1024)
                if not data:
                    break
                try:
                    sys.stdout.buffer.write(data)
                    sys.stdout.buffer.flush()
                except Exception:
                    print(data.decode(errors="replace"), end="", flush=True)
        except Exception:
            pass

    t = threading.Thread(target=recv_thread, daemon=True)
    t.start()

    try:
        while True:
            if msvcrt.kbhit():
                ch = msvcrt.getwch()
                # paramiko requires bytes
                try:
                    b = ch.encode("utf-8")
                except Exception:
                    b = ch.encode("latin-1", errors="ignore")
                channel.send(b)
    except KeyboardInterrupt:
        pass

def run_command_and_print(channel, command):
    # send the command and read until channel closes or EOF
    try:
        stdin = channel.makefile("wb")
        stdout = channel.makefile("rb")
        stderr = channel.makefile_stderr("rb")
        # send command followed by newline
        channel.exec_command(command)
    except Exception:
        # fallback: use exec_command from client
        pass

def main():
    args = parse_args()

    if not args.keyfile and not args.password:
        # prompt for password if not using keyfile
        args.password = getpass.getpass("Password: ")

    client = open_ssh_client(args.host, args.port, args.username, password=args.password, keyfile=args.keyfile)
    if not client:
        return 1

    try:
        if args.command:
            # Non-interactive command execution
            stdin, stdout, stderr = client.exec_command(args.command)
            out = stdout.read()
            err = stderr.read()
            if out:
                sys.stdout.buffer.write(out)
            if err:
                sys.stderr.buffer.write(err)
        else:
            # Interactive shell
            chan = client.get_transport().open_session()
            if args.tty:
                # request an interactive pty
                try:
                    chan.get_pty(term="xterm", width=80, height=24)
                except Exception:
                    # some servers ignore get_pty() errors
                    pass
            chan.invoke_shell()
            print("[*] Interactive shell established. Ctrl-C or close the remote shell to exit.")
            interactive_shell(chan)
            chan.close()
    except KeyboardInterrupt:
        pass
    finally:
        client.close()
    return 0

if __name__ == "__main__":
    sys.exit(main())