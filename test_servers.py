#!/usr/bin/env python3
"""
Emulated login servers for RustSploit bruteforce module testing.
Default creds: admin / password123  (for all services)
Default SNMP community string: public

Ports:
  SSH      → 2222
  SMTP     → 2525
  POP3     → 1110
  MQTT     → 1884
  Telnet   → 2323
  SNMP     → 1161 (UDP)
  RTSP     → 5554
  Fortinet → 4443 (HTTPS)
  L2TP     → 1701 (UDP)
"""

import socket
import ssl
import threading
import struct
import hashlib
import os
import sys
import time
import traceback

BIND = "127.0.0.1"
CREDS = {"admin": "password123", "root": "toor"}
SNMP_COMMUNITY = "public"

# ─── SSH Server (paramiko) ──────────────────────────────────────────

def start_ssh_server(port=2222):
    import paramiko

    host_key = paramiko.RSAKey.generate(2048)

    class SSHServer(paramiko.ServerInterface):
        def __init__(self):
            self.event = threading.Event()
            self.authenticated = False

        def check_channel_request(self, kind, chanid):
            if kind == "session":
                return paramiko.OPEN_SUCCEEDED
            return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

        def check_auth_password(self, username, password):
            if CREDS.get(username) == password:
                self.authenticated = True
                return paramiko.AUTH_SUCCESSFUL
            return paramiko.AUTH_FAILED

        def get_allowed_auths(self, username):
            return "password"

    def handle_client(client_sock):
        try:
            transport = paramiko.Transport(client_sock)
            transport.add_server_key(host_key)
            server = SSHServer()
            transport.start_server(server=server)
            chan = transport.accept(5)
            if chan:
                chan.close()
            transport.close()
        except Exception:
            pass
        finally:
            try: client_sock.close()
            except: pass

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((BIND, port))
    sock.listen(10)
    print(f"[SSH]      listening on {BIND}:{port}  (creds: admin/password123)")

    while True:
        client, addr = sock.accept()
        threading.Thread(target=handle_client, args=(client,), daemon=True).start()


# ─── SMTP Server ────────────────────────────────────────────────────

def start_smtp_server(port=2525):
    """
    SMTP server compatible with the RustSploit smtp_bruteforce module.
    The module uses the Telnet crate to read responses, so we must:
    1. Send banner starting with "220"
    2. EHLO response with "250-AUTH LOGIN PLAIN" and final "250 OK" (space after 250)
    3. AUTH PLAIN / AUTH LOGIN support
    4. Each response must end with \r\n
    """
    import base64

    def handle_client(conn):
        try:
            conn.settimeout(10)
            # Banner
            conn.sendall(b"220 test-smtp ESMTP ready\r\n")
            username = None
            auth_state = None

            while True:
                data = conn.recv(4096)
                if not data:
                    break
                line = data.decode(errors="replace").strip()

                if auth_state == "wait_user":
                    username = base64.b64decode(line).decode(errors="replace")
                    conn.sendall(b"334 UGFzc3dvcmQ6\r\n")
                    auth_state = "wait_pass"
                elif auth_state == "wait_pass":
                    password = base64.b64decode(line).decode(errors="replace")
                    if CREDS.get(username) == password:
                        conn.sendall(b"235 2.7.0 Authentication successful\r\n")
                    else:
                        conn.sendall(b"535 5.7.8 Authentication failed\r\n")
                    auth_state = None
                elif line.upper().startswith("EHLO") or line.upper().startswith("HELO"):
                    # Multi-line response: dash continues, space ends
                    conn.sendall(b"250-test-smtp\r\n")
                    conn.sendall(b"250-AUTH LOGIN PLAIN\r\n")
                    conn.sendall(b"250-SIZE 10240000\r\n")
                    conn.sendall(b"250 OK\r\n")
                elif line.upper().startswith("AUTH PLAIN"):
                    parts = line.split(" ", 2)
                    if len(parts) == 3:
                        try:
                            decoded = base64.b64decode(parts[2]).decode(errors="replace")
                            pieces = decoded.split("\0")
                            if len(pieces) >= 3:
                                u, p = pieces[1], pieces[2]
                                if CREDS.get(u) == p:
                                    conn.sendall(b"235 2.7.0 Authentication successful\r\n")
                                else:
                                    conn.sendall(b"535 5.7.8 Authentication failed\r\n")
                            else:
                                conn.sendall(b"535 Bad format\r\n")
                        except Exception:
                            conn.sendall(b"535 Decode error\r\n")
                    else:
                        conn.sendall(b"334\r\n")
                elif line.upper().startswith("AUTH LOGIN"):
                    conn.sendall(b"334 VXNlcm5hbWU6\r\n")
                    auth_state = "wait_user"
                elif line.upper().startswith("QUIT"):
                    conn.sendall(b"221 Bye\r\n")
                    break
                elif line.upper().startswith("RSET"):
                    conn.sendall(b"250 OK\r\n")
                else:
                    conn.sendall(b"502 Not implemented\r\n")
        except Exception:
            pass
        finally:
            try: conn.close()
            except: pass

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((BIND, port))
    sock.listen(10)
    print(f"[SMTP]     listening on {BIND}:{port}  (creds: admin/password123)")

    while True:
        client, addr = sock.accept()
        threading.Thread(target=handle_client, args=(client,), daemon=True).start()


# ─── POP3 Server ────────────────────────────────────────────────────

def start_pop3_server(port=1110):
    def handle_client(conn):
        try:
            conn.settimeout(10)
            conn.sendall(b"+OK POP3 server ready\r\n")
            username = None
            while True:
                data = conn.recv(1024)
                if not data:
                    break
                line = data.decode(errors="replace").strip()

                if line.upper().startswith("USER "):
                    username = line[5:].strip()
                    conn.sendall(b"+OK\r\n")
                elif line.upper().startswith("PASS "):
                    password = line[5:].strip()
                    if username and CREDS.get(username) == password:
                        conn.sendall(b"+OK Logged in\r\n")
                    else:
                        conn.sendall(b"-ERR Authentication failed\r\n")
                elif line.upper() == "QUIT":
                    conn.sendall(b"+OK Bye\r\n")
                    break
                elif line.upper() == "CAPA":
                    conn.sendall(b"+OK\r\nUSER\r\n.\r\n")
                else:
                    conn.sendall(b"-ERR Unknown command\r\n")
        except Exception:
            pass
        finally:
            try: conn.close()
            except: pass

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((BIND, port))
    sock.listen(10)
    print(f"[POP3]     listening on {BIND}:{port}  (creds: admin/password123)")

    while True:
        client, addr = sock.accept()
        threading.Thread(target=handle_client, args=(client,), daemon=True).start()


# ─── MQTT Server (Broker emulation) ─────────────────────────────────

def start_mqtt_server(port=1884):
    """Minimal MQTT 3.1.1 CONNECT/CONNACK handler with auth."""
    def handle_client(conn):
        try:
            conn.settimeout(10)
            data = conn.recv(4096)
            if not data or (data[0] >> 4) != 1:
                conn.close()
                return

            pos = 1
            multiplier = 1
            remaining = 0
            while pos < len(data):
                byte = data[pos]
                remaining += (byte & 0x7F) * multiplier
                multiplier *= 128
                pos += 1
                if (byte & 0x80) == 0:
                    break

            payload_start = pos
            proto_len = struct.unpack("!H", data[payload_start:payload_start+2])[0]
            idx = payload_start + 2 + proto_len
            idx += 1
            connect_flags = data[idx]
            has_username = bool(connect_flags & 0x80)
            has_password = bool(connect_flags & 0x40)
            idx += 1
            idx += 2
            cid_len = struct.unpack("!H", data[idx:idx+2])[0]
            idx += 2 + cid_len

            username = ""
            password = ""
            if has_username:
                ulen = struct.unpack("!H", data[idx:idx+2])[0]
                idx += 2
                username = data[idx:idx+ulen].decode(errors="replace")
                idx += ulen
            if has_password:
                plen = struct.unpack("!H", data[idx:idx+2])[0]
                idx += 2
                password = data[idx:idx+plen].decode(errors="replace")

            if CREDS.get(username) == password:
                conn.sendall(bytes([0x20, 0x02, 0x00, 0x00]))
            else:
                conn.sendall(bytes([0x20, 0x02, 0x00, 0x05]))
        except Exception:
            pass
        finally:
            try: conn.close()
            except: pass

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((BIND, port))
    sock.listen(10)
    print(f"[MQTT]     listening on {BIND}:{port}  (creds: admin/password123)")

    while True:
        client, addr = sock.accept()
        threading.Thread(target=handle_client, args=(client,), daemon=True).start()


# ─── Telnet Server ──────────────────────────────────────────────────

def start_telnet_server(port=2323):
    """
    Telnet server compatible with the RustSploit telnet_bruteforce module.
    Sends IAC negotiations first, then login/password prompts.
    Success response includes '#' or '$' shell prompt so the module detects it.
    """
    def handle_client(conn):
        try:
            conn.settimeout(10)
            # Send IAC + login prompt together so validation sees 'login' immediately
            conn.sendall(b"\xff\xfb\x01\xff\xfb\x03\r\nlogin: ")
            data = conn.recv(1024)
            if not data:
                conn.close()
                return
            # Strip IAC responses the client may send back
            raw = data
            clean = bytearray()
            i = 0
            while i < len(raw):
                if raw[i] == 0xFF and i + 2 < len(raw):
                    i += 3  # skip IAC command
                else:
                    clean.append(raw[i])
                    i += 1
            username = bytes(clean).decode(errors="replace").strip().replace("\r", "").replace("\n", "")

            conn.sendall(b"Password: ")
            data = conn.recv(1024)
            if not data:
                conn.close()
                return
            password = data.decode(errors="replace").strip().replace("\r", "").replace("\n", "")

            if CREDS.get(username) == password:
                # Send shell prompt with $ so module detects success
                conn.sendall(f"\r\nWelcome {username}\r\n{username}@test:~$ ".encode())
                conn.settimeout(2)
                try: conn.recv(1024)
                except: pass
            else:
                conn.sendall(b"\r\nLogin incorrect\r\n")
                time.sleep(0.3)
        except Exception:
            pass
        finally:
            try: conn.close()
            except: pass

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((BIND, port))
    sock.listen(10)
    print(f"[Telnet]   listening on {BIND}:{port}  (creds: admin/password123)")

    while True:
        client, addr = sock.accept()
        threading.Thread(target=handle_client, args=(client,), daemon=True).start()


# ─── SNMP Server (UDP) ──────────────────────────────────────────────

def start_snmp_server(port=1161):
    """Minimal SNMPv2c GET-RESPONSE handler."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((BIND, port))
    print(f"[SNMP]     listening on {BIND}:{port} (UDP)  (community: public)")

    while True:
        try:
            data, addr = sock.recvfrom(4096)
            if len(data) < 10:
                continue

            idx = 0
            if data[idx] != 0x30:
                continue
            idx += 1
            if data[idx] & 0x80:
                ll = data[idx] & 0x7f
                idx += 1 + ll
            else:
                idx += 1

            if data[idx] != 0x02:
                continue
            idx += 1
            vlen = data[idx]
            idx += 1 + vlen

            if data[idx] != 0x04:
                continue
            idx += 1
            clen = data[idx]
            idx += 1
            community = data[idx:idx+clen].decode(errors="replace")

            if community == SNMP_COMMUNITY:
                sys_descr = b"Linux test-server 5.15.0"
                oid = bytes([0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00])
                val = bytes([0x04, len(sys_descr)]) + sys_descr
                varbind = bytes([0x30, len(oid) + len(val)]) + oid + val
                varbindlist = bytes([0x30, len(varbind)]) + varbind
                req_id = bytes([0x02, 0x01, 0x01])
                error_status = bytes([0x02, 0x01, 0x00])
                error_index = bytes([0x02, 0x01, 0x00])
                pdu_content = req_id + error_status + error_index + varbindlist
                pdu = bytes([0xa2, len(pdu_content)]) + pdu_content
                version = bytes([0x02, 0x01, 0x01])
                comm_bytes = community.encode()
                comm = bytes([0x04, len(comm_bytes)]) + comm_bytes
                msg_content = version + comm + pdu
                msg = bytes([0x30, len(msg_content)]) + msg_content
                sock.sendto(msg, addr)
        except Exception:
            pass


# ─── RTSP Server ────────────────────────────────────────────────────

def start_rtsp_server(port=5554):
    import base64

    def handle_client(conn):
        try:
            conn.settimeout(10)
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                request = data.decode(errors="replace")
                lines = request.split("\r\n")

                auth_header = None
                cseq = "1"
                for line in lines:
                    if line.lower().startswith("authorization:"):
                        auth_header = line.split(":", 1)[1].strip()
                    if line.lower().startswith("cseq:"):
                        cseq = line.split(":", 1)[1].strip()

                if auth_header and auth_header.lower().startswith("basic "):
                    encoded = auth_header[6:]
                    try:
                        decoded = base64.b64decode(encoded).decode()
                        user, passwd = decoded.split(":", 1)
                        if CREDS.get(user) == passwd:
                            resp = f"RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\n\r\n"
                            conn.sendall(resp.encode())
                            continue
                    except Exception:
                        pass

                resp = (
                    f"RTSP/1.0 401 Unauthorized\r\n"
                    f"CSeq: {cseq}\r\n"
                    f"WWW-Authenticate: Basic realm=\"RTSP Server\"\r\n\r\n"
                )
                conn.sendall(resp.encode())
        except Exception:
            pass
        finally:
            try: conn.close()
            except: pass

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((BIND, port))
    sock.listen(10)
    print(f"[RTSP]     listening on {BIND}:{port}  (creds: admin/password123)")

    while True:
        client, addr = sock.accept()
        threading.Thread(target=handle_client, args=(client,), daemon=True).start()


# ─── Fortinet HTTPS Login Server ────────────────────────────────────

def start_fortinet_server(port=4443):
    """
    Emulates FortiGate SSL VPN login page.
    The module sends:
      GET /remote/login → expects HTML with CSRF token
      POST /remote/logincheck → form with username + credential fields
    Success: response body contains "redir" and "portal"
    Failure: response body contains "ret=0"
    """
    from http.server import HTTPServer, BaseHTTPRequestHandler
    import urllib.parse

    class FortiHandler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass

        def do_GET(self):
            if "/remote/login" in self.path:
                # Return login page with CSRF token (magic field)
                html = (
                    '<html><head><title>SSL VPN</title></head><body>'
                    '<form method="post" action="/remote/logincheck">'
                    '<input type="hidden" name="magic" value="test_csrf_token_123">'
                    '<input name="username"><input name="credential" type="password">'
                    '<input name="ajax" value="1">'
                    '</form></body></html>'
                )
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(html)))
                self.end_headers()
                self.wfile.write(html.encode())
            else:
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()

        def do_POST(self):
            if "/remote/logincheck" in self.path:
                content_len = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(content_len).decode(errors="replace")
                params = urllib.parse.parse_qs(body)
                
                username = params.get("username", [""])[0]
                # Module sends "credential" not "password"
                password = params.get("credential", params.get("password", [""]))[0]

                if CREDS.get(username) == password:
                    # Success response with redirect indicators
                    response_body = 'redir=/remote/portal&portal_user=admin'
                    self.send_response(200)
                    self.send_header("Content-Type", "text/plain")
                    self.send_header("Content-Length", str(len(response_body)))
                    self.end_headers()
                    self.wfile.write(response_body.encode())
                else:
                    response_body = 'ret=0&redir='
                    self.send_response(401)
                    self.send_header("Content-Type", "text/plain")
                    self.send_header("Content-Length", str(len(response_body)))
                    self.end_headers()
                    self.wfile.write(response_body.encode())
            else:
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()

    cert_file = "/tmp/test_forti_cert.pem"
    key_file = "/tmp/test_forti_key.pem"
    if not os.path.exists(cert_file):
        os.system(
            f'openssl req -x509 -newkey rsa:2048 -keyout {key_file} -out {cert_file} '
            f'-days 1 -nodes -subj "/CN=localhost" 2>/dev/null'
        )

    httpd = HTTPServer((BIND, port), FortiHandler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_file, key_file)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    print(f"[Fortinet] listening on {BIND}:{port} (HTTPS)  (creds: admin/password123)")
    httpd.serve_forever()


# ─── L2TP Server (UDP) ──────────────────────────────────────────────

def start_l2tp_server(port=1701):
    """
    Minimal L2TP + PPP/CHAP server for bruteforce testing.
    Implements: SCCRQ→SCCRP, SCCCN→ack, ICRQ→ICRP, ICCN→CHAP challenge→response check.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((BIND, port))
    print(f"[L2TP]     listening on {BIND}:{port} (UDP)  (creds: admin/password123)")

    sessions = {}  # addr -> state dict

    while True:
        try:
            data, addr = sock.recvfrom(8192)
            if len(data) < 6:
                continue

            # Parse L2TP header
            flags = struct.unpack("!H", data[0:2])[0]
            is_control = bool(flags & 0x8000)
            has_length = bool(flags & 0x4000)

            if not is_control:
                # Data packet — check for CHAP response
                state = sessions.get(addr, {})
                if state.get("chap_sent"):
                    # Parse PPP CHAP response from data packet
                    # Skip L2TP data header (variable)
                    offset = 4  # minimal L2TP data header
                    if has_length:
                        offset += 2
                    payload = data[offset:]
                    
                    # Look for PPP CHAP in payload
                    ppp_off = 0
                    if len(payload) > 2 and payload[0] == 0xFF and payload[1] == 0x03:
                        ppp_off = 2
                    
                    if len(payload) > ppp_off + 6:
                        proto = struct.unpack("!H", payload[ppp_off:ppp_off+2])[0]
                        if proto == 0xC223:  # PPP CHAP
                            chap_code = payload[ppp_off + 2]
                            if chap_code == 2:  # CHAP Response
                                identifier = payload[ppp_off + 3]
                                chap_len = struct.unpack("!H", payload[ppp_off+4:ppp_off+6])[0]
                                value_size = payload[ppp_off + 6]
                                chap_value = payload[ppp_off + 7: ppp_off + 7 + value_size]
                                
                                # Extract username from remaining bytes
                                name_start = ppp_off + 7 + value_size
                                name_end = ppp_off + 2 + chap_len
                                username = payload[name_start:name_end].decode(errors="replace")
                                
                                # Verify CHAP: MD5(identifier + password + challenge)
                                challenge = state.get("challenge", b"")
                                success = False
                                for uname, pwd in CREDS.items():
                                    if uname == username:
                                        expected = hashlib.md5(
                                            bytes([identifier]) + pwd.encode() + challenge
                                        ).digest()
                                        if expected == chap_value:
                                            success = True
                                            break
                                
                                # Send CHAP Success or Failure via data packet
                                tid = state.get("remote_tunnel_id", 1)
                                sid = state.get("remote_session_id", 1)
                                
                                chap_code_resp = 3 if success else 4
                                msg = b"Access granted" if success else b"Access denied"
                                chap_pkt = struct.pack("!BBH", chap_code_resp, identifier,
                                                       4 + len(msg)) + msg
                                ppp_frame = b"\xff\x03" + struct.pack("!H", 0xC223) + chap_pkt
                                
                                # L2TP data header
                                l2tp_hdr = struct.pack("!HH", 0x0002, tid) + struct.pack("!H", sid)
                                packet = l2tp_hdr + ppp_frame
                                sock.sendto(packet, addr)
                                
                                if success:
                                    sessions.pop(addr, None)
                continue

            # Control packet — needs 12 bytes minimum for header
            if len(data) < 12:
                continue

            offset = 2
            length = struct.unpack("!H", data[offset:offset+2])[0]
            offset += 2
            tunnel_id = struct.unpack("!H", data[offset:offset+2])[0]
            offset += 2
            session_id = struct.unpack("!H", data[offset:offset+2])[0]
            offset += 2
            ns = struct.unpack("!H", data[offset:offset+2])[0]
            offset += 2
            nr = struct.unpack("!H", data[offset:offset+2])[0]
            offset += 2

            # Parse AVPs to find message type
            payload = data[offset:]
            msg_type = None
            if len(payload) >= 6:
                avp_flags = struct.unpack("!H", payload[0:2])[0]
                avp_len = avp_flags & 0x03FF
                if avp_len >= 6:
                    attr_type = struct.unpack("!H", payload[4:6])[0]
                    if attr_type == 0:  # Message Type
                        msg_type = struct.unpack("!H", payload[6:8])[0]

            state = sessions.get(addr, {
                "tunnel_id": 1,
                "session_id": 1,
                "ns": 0,
                "nr": 0,
                "remote_tunnel_id": 0,
                "remote_session_id": 0,
            })

            def build_control(state, avps_data):
                """Build L2TP control message."""
                tid = state.get("remote_tunnel_id", 0)
                sid = 0
                ns_val = state["ns"]
                nr_val = state["nr"]
                hdr_len = 12 + len(avps_data)
                hdr = struct.pack("!HHHHHH", 0xC802, hdr_len, tid, sid, ns_val, nr_val)
                state["ns"] += 1
                return hdr + avps_data

            def build_avp(attr_type, value, mandatory=True):
                """Build AVP."""
                avp_len = 6 + len(value)
                flags = avp_len | (0x8000 if mandatory else 0)
                return struct.pack("!HHH", flags, 0, attr_type) + value

            if msg_type == 1:  # SCCRQ
                state["remote_tunnel_id"] = tunnel_id if tunnel_id else 1
                # Find assigned tunnel ID in AVPs
                avp_off = 0
                while avp_off + 6 <= len(payload):
                    avp_f = struct.unpack("!H", payload[avp_off:avp_off+2])[0]
                    avp_l = avp_f & 0x03FF
                    if avp_l < 6:
                        break
                    avp_t = struct.unpack("!H", payload[avp_off+4:avp_off+6])[0]
                    if avp_t == 9 and avp_l >= 8:  # Assigned Tunnel ID
                        state["remote_tunnel_id"] = struct.unpack("!H", payload[avp_off+6:avp_off+8])[0]
                    avp_off += avp_l

                state["nr"] = ns + 1
                # Send SCCRP
                avps = (
                    build_avp(0, struct.pack("!H", 2)) +  # Message Type = SCCRP
                    build_avp(2, struct.pack("!H", 0x0100)) +  # Protocol Version
                    build_avp(3, struct.pack("!I", 0)) +  # Framing Capabilities
                    build_avp(4, struct.pack("!I", 0)) +  # Bearer Capabilities
                    build_avp(9, struct.pack("!H", state["tunnel_id"])) +  # Assigned Tunnel ID
                    build_avp(7, b"test-l2tp-server") +  # Host Name
                    build_avp(6, struct.pack("!I", 65535))  # Receive Window Size
                )
                pkt = build_control(state, avps)
                sock.sendto(pkt, addr)
                sessions[addr] = state

            elif msg_type == 3:  # SCCCN
                state["nr"] = ns + 1
                # Send ZLB ACK
                zlb = struct.pack("!HHHHHH", 0xC802, 12, state["remote_tunnel_id"], 0, state["ns"], state["nr"])
                state["ns"] += 1
                sock.sendto(zlb, addr)
                sessions[addr] = state

            elif msg_type == 10:  # ICRQ
                state["nr"] = ns + 1
                # Parse assigned session ID
                avp_off = 0
                while avp_off + 6 <= len(payload):
                    avp_f = struct.unpack("!H", payload[avp_off:avp_off+2])[0]
                    avp_l = avp_f & 0x03FF
                    if avp_l < 6:
                        break
                    avp_t = struct.unpack("!H", payload[avp_off+4:avp_off+6])[0]
                    if avp_t == 14 and avp_l >= 8:  # Assigned Session ID
                        state["remote_session_id"] = struct.unpack("!H", payload[avp_off+6:avp_off+8])[0]
                    avp_off += avp_l

                # Send ICRP
                avps = (
                    build_avp(0, struct.pack("!H", 11)) +  # Message Type = ICRP
                    build_avp(14, struct.pack("!H", state["session_id"]))  # Assigned Session ID
                )
                pkt = build_control(state, avps)
                sock.sendto(pkt, addr)
                sessions[addr] = state

            elif msg_type == 12:  # ICCN
                state["nr"] = ns + 1
                # Send ZLB ACK
                zlb = struct.pack("!HHHHHH", 0xC802, 12, state["remote_tunnel_id"], 0, state["ns"], state["nr"])
                state["ns"] += 1
                sock.sendto(zlb, addr)

                # Send CHAP Challenge as data packet
                challenge = os.urandom(16)
                state["challenge"] = challenge
                state["chap_sent"] = True

                identifier = 1
                server_name = b"test-l2tp"
                chap_len = 4 + 1 + len(challenge) + len(server_name)
                chap_pkt = struct.pack("!BBH", 1, identifier, chap_len)
                chap_pkt += bytes([len(challenge)]) + challenge + server_name

                ppp_frame = b"\xff\x03" + struct.pack("!H", 0xC223) + chap_pkt

                # L2TP data header
                l2tp_hdr = struct.pack("!HH", 0x0002, state["remote_tunnel_id"])
                l2tp_hdr += struct.pack("!H", state.get("remote_session_id", 0))
                packet = l2tp_hdr + ppp_frame
                sock.sendto(packet, addr)
                sessions[addr] = state

            else:
                # ZLB ACK for anything else
                state["nr"] = ns + 1
                zlb = struct.pack("!HHHHHH", 0xC802, 12, state.get("remote_tunnel_id", 0), 0, state["ns"], state["nr"])
                state["ns"] += 1
                sock.sendto(zlb, addr)
                sessions[addr] = state

        except Exception as e:
            print(f"[L2TP] Error: {e}", flush=True)


# ─── Main ───────────────────────────────────────────────────────────

def main():
    print("=" * 60)
    print("  RustSploit Test Servers — Emulated Login Services")
    print("  Default creds: admin / password123")
    print("=" * 60)

    services = [
        ("SSH",      start_ssh_server,      2222),
        ("SMTP",     start_smtp_server,     2525),
        ("POP3",     start_pop3_server,     1110),
        ("MQTT",     start_mqtt_server,     1884),
        ("Telnet",   start_telnet_server,   2323),
        ("SNMP",     start_snmp_server,     1161),
        ("RTSP",     start_rtsp_server,     5554),
        ("Fortinet", start_fortinet_server, 4443),
        ("L2TP",     start_l2tp_server,     1701),
    ]

    threads = []
    for name, func, port in services:
        t = threading.Thread(target=func, args=(port,), daemon=True)
        t.start()
        threads.append(t)

    print("\n✅ All servers started! Press Ctrl+C to stop.\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down...")
        sys.exit(0)


if __name__ == "__main__":
    main()
