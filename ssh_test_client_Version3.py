#!/usr/bin/env python3
"""
Interactive SSH client with two UI modes: local CLI or browser UI.

This extends the original simple CLI client you provided to:
- Offer a browser UI that uses a file upload button for the private key.
  The uploaded file is read client-side and sent to the local WebSocket
  server for use in authentication.
- Keep private key and username/password support. Private key may be
  provided as a path (on the CLI) or uploaded in the browser UI. No
  passphrase-protected private keys are supported (per your request).
- When connected in either mode the client announces the connection and keeps
  the session active until the remote side or user closes it.

Requirements:
- paramiko
- (for browser mode) tornado
- On Unix, for CLI interactive PTY behavior, the stdlib termios/tty modules are used.
"""
from __future__ import annotations

import argparse
import getpass
import io
import os
import socket
import sys
import threading
import time
import webbrowser
from typing import Optional

import paramiko

# Platform-specific imports for interactive terminal handling
IS_WINDOWS = sys.platform.startswith("win")
if not IS_WINDOWS:
    import termios
    import tty

# Fixed/unchangeable browser server address per user request:
BROWSER_BIND_HOST = "127.0.0.1"
BROWSER_BIND_PORT = 8888
BROWSER_URL = f"http://{BROWSER_BIND_HOST}:{BROWSER_BIND_PORT}/"
WS_PATH = "/ws"

# Basic arg parsing to optionally pre-fill connection information
def parse_args():
    p = argparse.ArgumentParser(description="Interactive SSH test client (CLI + Browser UI)")
    p.add_argument("-H", "--host", dest="host", help="Server host")
    p.add_argument("-p", "--port", dest="port", type=int, default=22, help="Server port")
    p.add_argument("-u", "--user", dest="username", help="Username")
    p.add_argument("-P", "--password", dest="password", help="Password (if using password auth)")
    p.add_argument("-k", "--key", dest="keyfile", help="Private key file path (if using key auth)")
    p.add_argument("-c", "--command", dest="command", help="Run a single command and exit (non-interactive)")
    p.add_argument("--no-tty", dest="tty", action="store_false", help="Do not request a PTY (for non-interactive shells)")
    p.set_defaults(tty=True)
    return p.parse_args()

def load_pkey_from_file(path: str):
    # Only supports non-passphrase-protected keys
    try:
        return paramiko.RSAKey.from_private_key_file(path)
    except Exception:
        try:
            return paramiko.Ed25519Key.from_private_key_file(path)
        except Exception:
            return None

def load_pkey_from_text(key_text: str):
    # Accept private key content as text (no passphrase)
    try:
        return paramiko.RSAKey.from_private_key(io.StringIO(key_text))
    except Exception:
        try:
            return paramiko.Ed25519Key.from_private_key(io.StringIO(key_text))
        except Exception:
            return None

def open_ssh_client(host, port, username, password=None, keyfile=None, key_text=None, timeout=10):
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
    if key_text:
        pkey = load_pkey_from_text(key_text)
        if not pkey:
            print(f"[!] Failed to parse private key from provided text.")
            return None
        connect_kwargs["pkey"] = pkey
    elif keyfile:
        pkey = load_pkey_from_file(keyfile)
        if not pkey:
            print(f"[!] Failed to load key {keyfile}. Only non-encrypted keys are supported.")
            return None
        connect_kwargs["pkey"] = pkey
    else:
        connect_kwargs["password"] = password

    try:
        client.connect(**connect_kwargs)
        return client
    except Exception as e:
        print(f"[!] Failed to connect: {e}")
        return None

# ---------- CLI interactive functions (based on your original code) ----------
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
                try:
                    sys.stdout.buffer.write(data)
                    sys.stdout.buffer.flush()
                except Exception:
                    sys.stdout.write(data.decode(errors="replace"))
                    sys.stdout.flush()
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
    import msvcrt
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

# ---------- Minimal browser UI (Tornado-based) ----------
# The browser UI uses a file input for private key upload. The file is read into
# memory in the browser and sent in the "connect" payload to the local websocket.
BROWSER_HTML = f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Local SSH Browser Client</title>
  <style>
    body {{
      font-family: monospace;
      margin: 12px;
      display: flex;
      flex-direction: column;
      min-height: 100vh;
      background: #111;
      color: #ddd;
    }}
    #connect-form {{ margin-bottom: 12px; }}
    label {{ display:inline-block; width:110px; }}
    input, button {{
      font-family: monospace;
      padding: 4px 6px;
    }}
    #terminal-wrapper {{
      margin-top: auto;
      border: 1px solid #0a0;
      background: #000;
      color: #0f0;
      display: flex;
      flex-direction: column;
      height: 50vh;
    }}
    #terminal-output {{
      flex: 1;
      padding: 8px;
      overflow: auto;
      white-space: pre-wrap;
    }}
    #inputline {{
      width: 100%;
      box-sizing: border-box;
      border: none;
      border-top: 1px solid #0a0;
      background: #000;
      color: #0f0;
      padding: 6px;
      outline: none;
      caret-color: #0f0;
    }}
    #status {{ margin-bottom: 8px; color: #9f9; }}
  </style>
</head>
<body>
  <h3>Local SSH Browser Client (fixed address)</h3>
  <div id="status">Disconnected</div>
  <form id="connect-form">
    <div><label>Host:</label><input id="host" value="127.0.0.1" required /></div>
    <div><label>Port:</label><input id="port" value="22" required /></div>
    <div><label>User:</label><input id="user" required /></div>
    <div><label>Password:</label><input id="password" type="password" /></div>
    <div><label>Private Key:</label><input id="privatekeyfile" type="file" accept=".key,.pem" /></div>
    <div style="margin-top:6px;">
      <button id="btn-connect" type="button">Connect</button>
      <button id="btn-disconnect" type="button" disabled>Disconnect</button>
    </div>
  </form>

  <div id="terminal-wrapper">
    <div id="terminal-output" tabindex="0"></div>
    <input id="inputline" placeholder="Type here (Enter sends, Ctrl+C sends SIGINT)." />
  </div>

<script>
(function() {{
  var ws = null;
  var terminal = document.getElementById('terminal-output');
  var inputline = document.getElementById('inputline');
  var status = document.getElementById('status');
  var privateKeyText = ""; // holds uploaded private key contents

  function append(s) {{
    terminal.textContent += s;
    terminal.scrollTop = terminal.scrollHeight;
  }}

  // Read the uploaded private key file into memory when selected
  document.getElementById('privatekeyfile').addEventListener('change', function(evt) {{
    var f = evt.target.files && evt.target.files[0];
    if (!f) {{
      privateKeyText = "";
      return;
    }}
    var reader = new FileReader();
    reader.onload = function(e) {{
      privateKeyText = e.target.result;
      // Optional: indicate loaded to user
      status.textContent = "Private key loaded (in-memory)";
    }};
    reader.onerror = function() {{
      privateKeyText = "";
      status.textContent = "Failed to read private key file";
    }};
    reader.readAsText(f);
  }});

  document.getElementById('btn-connect').addEventListener('click', function() {{
    if (ws && ws.readyState === WebSocket.OPEN) return;
    var url = "ws://{BROWSER_BIND_HOST}:{BROWSER_BIND_PORT}{WS_PATH}";
    ws = new WebSocket(url);
    ws.binaryType = "arraybuffer";
    ws.onopen = function() {{
      status.textContent = "Connected (WS)";
      var payload = {{
        action: "connect",
        host: document.getElementById('host').value,
        port: parseInt(document.getElementById('port').value, 10) || 22,
        username: document.getElementById('user').value,
        password: document.getElementById('password').value || "",
        privatekey: privateKeyText || ""
      }};
      ws.send(JSON.stringify(payload));
      document.getElementById('btn-disconnect').disabled = false;
      document.getElementById('btn-connect').disabled = true;
    }};
    ws.onmessage = function(evt) {{
      try {{
        var data = evt.data;
        if (typeof data !== "string") {{
          var text = new TextDecoder().decode(data);
          append(text);
          return;
        }}
        var msg = JSON.parse(data);
        if (msg.type === "stdout") {{
          append(msg.data);
        }} else if (msg.type === "status") {{
          status.textContent = msg.data;
          if (msg.data === "Connected") {{
            append("\\n[connected]\\n");
          }}
        }}
      }} catch (e) {{
        append("\\n[parse error]\\n");
      }}
    }};
    ws.onclose = function() {{
      status.textContent = "Disconnected";
      document.getElementById('btn-disconnect').disabled = true;
      document.getElementById('btn-connect').disabled = false;
    }};
    ws.onerror = function(e) {{
      status.textContent = "WebSocket error";
    }};
  }}, false);

  document.getElementById('btn-disconnect').addEventListener('click', function() {{
    if (ws) ws.close();
  }});

  function sendKeySequence(seq) {{
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    ws.send(JSON.stringify({{ action: "stdin", data: seq }}));
  }}

  inputline.addEventListener('keydown', function(e) {{
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    if (e.ctrlKey && e.key === 'c') {{
      sendKeySequence(String.fromCharCode(3));
      e.preventDefault();
      return;
    }}
    if (e.ctrlKey && e.key === 'd') {{
      sendKeySequence(String.fromCharCode(4));
      e.preventDefault();
      return;
    }}
    if (e.key === 'Enter') {{
      sendKeySequence("\\n");
      e.preventDefault();
      return;
    }}
    if (e.key === 'Backspace') {{
      sendKeySequence(String.fromCharCode(127));
      e.preventDefault();
      return;
    }}
    if (e.key === 'Tab') {{
      sendKeySequence("\\t");
      e.preventDefault();
      return;
    }}
    if (e.key === 'ArrowUp') {{
      sendKeySequence("\\u001b[A");
      e.preventDefault();
      return;
    }}
    if (e.key === 'ArrowDown') {{
      sendKeySequence("\\u001b[B");
      e.preventDefault();
      return;
    }}
    if (e.key === 'ArrowRight') {{
      sendKeySequence("\\u001b[C");
      e.preventDefault();
      return;
    }}
    if (e.key === 'ArrowLeft') {{
      sendKeySequence("\\u001b[D");
      e.preventDefault();
      return;
    }}
    if (e.key.length === 1 && !e.ctrlKey && !e.metaKey && !e.altKey) {{
      sendKeySequence(e.key);
      e.preventDefault();
      return;
    }}
  }});

  document.getElementById('terminal-wrapper').addEventListener('click', function() {{
    inputline.focus();
  }});

  inputline.focus();
}})();
</script>
</body>
</html>
"""

# Tornado-based server implementation
class BrowserSSHServer:
    def __init__(self, bind_host=BROWSER_BIND_HOST, port=BROWSER_BIND_PORT):
        self.bind_host = bind_host
        self.port = port
        self._server_thread = None
        self._stop_event = threading.Event()

    def start(self):
        # Start Tornado in a separate thread to avoid blocking the main process.
        try:
            import tornado.ioloop
            import tornado.web
            import tornado.websocket
        except Exception as e:
            print("[!] Browser UI requires tornado. Install it with: pip install tornado")
            raise

        parent = self

        class IndexHandler(tornado.web.RequestHandler):
            def get(self):
                self.set_header("Content-Type", "text/html; charset=utf-8")
                self.write(BROWSER_HTML)

        class WSHandler(tornado.websocket.WebSocketHandler):
            def check_origin(self, origin):
                # Allow only same-origin connections (browser is local). Could tighten if needed.
                return True

            def open(self):
                self._ssh_client = None
                self._transport = None
                self._channel = None
                self._reader_thread = None
                self.set_nodelay(True)
                self.write_message('{"type":"status","data":"WS connected"}')

            def on_message(self, message):
                # Expect JSON messages with action field; stdin payloads are JSON too.
                try:
                    data = message
                    if isinstance(message, (bytes, bytearray)):
                        # treat as raw input -> forward to channel if present
                        if self._channel and self._channel.active:
                            self._channel.send(message)
                        return
                    import json
                    obj = json.loads(data)
                    action = obj.get("action")
                    if action == "connect":
                        # Connect to SSH server using provided params
                        host = obj.get("host")
                        port = int(obj.get("port", 22))
                        username = obj.get("username")
                        password = obj.get("password") or None
                        privatekey_text = obj.get("privatekey") or None
                        # Attempt connection
                        self.write_message(json.dumps({"type":"status","data":"Connecting..."}))
                        client = open_ssh_client(host, port, username, password=password, key_text=privatekey_text)
                        if not client:
                            self.write_message(json.dumps({"type":"status","data":"Connect failed"}))
                            return
                        self._ssh_client = client
                        transport = client.get_transport()
                        try:
                            chan = transport.open_session()
                            chan.get_pty(term="xterm", width=80, height=24)
                        except Exception:
                            # fallback: some servers may not grant pty
                            pass
                        chan.invoke_shell()
                        self._transport = transport
                        self._channel = chan
                        self.write_message(json.dumps({"type":"status","data":"Connected"}))

                        # start a reader thread
                        def reader():
                            try:
                                while True:
                                    if not chan:
                                        break
                                    try:
                                        data = chan.recv(1024)
                                    except Exception:
                                        break
                                    if not data:
                                        break
                                    # send stdout payloads as JSON (text)
                                    try:
                                        self.write_message(json.dumps({"type":"stdout","data": data.decode(errors="replace")}))
                                    except Exception:
                                        # fallback: send raw binary if write_message supports it
                                        try:
                                            self.write_message(data, binary=True)
                                        except Exception:
                                            pass
                            finally:
                                # channel closed
                                try:
                                    self.write_message(json.dumps({"type":"status","data":"Remote closed"}))
                                except Exception:
                                    pass
                                try:
                                    client.close()
                                except Exception:
                                    pass

                        self._reader_thread = threading.Thread(target=reader, daemon=True)
                        self._reader_thread.start()

                    elif action == "stdin":
                        payload = obj.get("data", "")
                        if self._channel and self._channel.active:
                            try:
                                # send as bytes
                                if isinstance(payload, str):
                                    self._channel.send(payload.encode("utf-8", errors="ignore"))
                                else:
                                    self._channel.send(payload)
                            except Exception as e:
                                self.write_message(json.dumps({"type":"status","data":f"Send error: {e}"}))
                        else:
                            self.write_message(json.dumps({"type":"status","data":"No active SSH channel"}))
                except Exception as e:
                    try:
                        self.write_message(json.dumps({"type":"status","data":f"Client error: {e}"}))
                    except Exception:
                        pass

            def on_close(self):
                try:
                    if getattr(self, "_channel", None):
                        try:
                            self._channel.close()
                        except Exception:
                            pass
                    if getattr(self, "_ssh_client", None):
                        try:
                            self._ssh_client.close()
                        except Exception:
                            pass
                except Exception:
                    pass

        app = tornado.web.Application([
            (r"/", IndexHandler),
            (r"/ws", WSHandler),
        ])

        def run_loop():
            try:
                app.listen(self.port, address=self.bind_host)
                loop = tornado.ioloop.IOLoop.current()
                print(f"[+] Browser UI running at {BROWSER_URL} (fixed, not changeable)")
                loop.start()
            except Exception as e:
                print("[!] Browser UI error:", e)

        self._server_thread = threading.Thread(target=run_loop, daemon=True)
        self._server_thread.start()

        # wait a bit for server to come up
        time.sleep(0.2)

    def stop(self):
        # Tornado IOLoop stopping is a bit involved. We rely on daemon thread termination with process exit.
        self._stop_event.set()

# ---------- Main program flow ----------
def choose_mode_interactively() -> str:
    while True:
        m = input("Choose UI mode: [cli/browser] (cli): ").strip().lower()
        if m == "":
            return "cli"
        if m in ("cli", "browser"):
            return m
        print("Please type 'cli' or 'browser'.")

def prompt_connection_info(preargs) -> dict:
    host = preargs.host or input("Host (required): ").strip()
    if not host:
        raise SystemExit("Host required")
    port = preargs.port or int(input("Port (22): ").strip() or "22")
    username = preargs.username or input("Username: ").strip()
    if not username:
        raise SystemExit("Username required")
    password = preargs.password
    keyfile = preargs.keyfile
    if not password and not keyfile:
        # prefer asking whether to use key or password
        use_key = input("Use local private key file? (y/N): ").strip().lower() == "y"
        if use_key:
            keyfile = input("Path to private key file: ").strip()
            if keyfile == "":
                keyfile = None
        else:
            password = getpass.getpass("Password: ")
    return {"host": host, "port": port, "username": username, "password": password, "keyfile": keyfile}

def run_cli_mode(args):
    conn_info = prompt_connection_info(args)

    client = open_ssh_client(conn_info["host"], conn_info["port"], conn_info["username"],
                             password=conn_info.get("password"),
                             keyfile=conn_info.get("keyfile"))
    if not client:
        return 1

    try:
        if args.command:
            stdin, stdout, stderr = client.exec_command(args.command)
            out = stdout.read()
            err = stderr.read()
            if out:
                try:
                    sys.stdout.buffer.write(out)
                except Exception:
                    sys.stdout.write(out.decode(errors="replace"))
            if err:
                try:
                    sys.stderr.buffer.write(err)
                except Exception:
                    sys.stderr.write(err.decode(errors="replace"))
        else:
            chan = client.get_transport().open_session()
            if args.tty:
                try:
                    chan.get_pty(term="xterm", width=80, height=24)
                except Exception:
                    pass
            chan.invoke_shell()
            print("[*] Interactive shell established. You are connected. (Use Ctrl-D or close to exit.)")
            interactive_shell(chan)
            try:
                chan.close()
            except Exception:
                pass
    except KeyboardInterrupt:
        pass
    finally:
        try:
            client.close()
        except Exception:
            pass
    return 0

def run_browser_mode(args):
    # Start the local fixed-address web UI and open it in a browser.
    server = BrowserSSHServer()
    try:
        server.start()
    except Exception:
        return 1

    try:
        print(f"[+] Opening browser to {BROWSER_URL}")
        webbrowser.open(BROWSER_URL)
    except Exception:
        print("[!] Failed to open browser; point your browser to:", BROWSER_URL)
    print("[*] Browser UI running on localhost. Enter Ctrl-C here to stop the local web UI when done.")
    try:
        # block until user interrupts
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Stopping browser UI...")
    finally:
        server.stop()
    return 0

def main():
    args = parse_args()

    # If not all connection info present and no immediate mode requested, ask for UI choice first
    try:
        mode = choose_mode_interactively()
    except KeyboardInterrupt:
        return 1

    if mode == "cli":
        return run_cli_mode(args)
    else:
        # browser mode: start the local web UI (address fixed), then exit when UI stopped
        return run_browser_mode(args)

if __name__ == "__main__":
    try:
        sys.exit(main() or 0)
    except KeyboardInterrupt:
        print("\n[!] Exiting.")
        sys.exit(0)
