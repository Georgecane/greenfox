#!/usr/bin/env python3
"""
GreenFox Protocol - Anti-Censorship Edition (v3.0)
Added: WSCamouflageTransport for DPI resistance (TLS + WebSocket headers)
Uses: X25519, ChaCha20-Poly1305, Sliding Window, Serverless-compatible ports.
"""

import os
import sys
import struct
import socket
import threading
import subprocess
import random
import shutil
import signal
import atexit
import ssl
import base64
import requests
import re
import time
from argparse import ArgumentParser
from typing import Callable, Tuple, Optional

# Crypto libraries
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256 as PySHA256
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization

# --- Constants & Config ---
TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000
TUN_MTU = 1300
MAX_READ_SIZE = 2048 
VPN_SUBNET = '10.8.0.0/24'
MIN_PAD = 16
MAX_PAD = 80
DEFAULT_DNS = '1.1.1.1'

# Server Key Paths
SERVER_ECDSA_PRIV_FILE = 'greenfox_server_ecdsa_priv.pem'
SERVER_ECDSA_PUB_FILE = 'greenfox_server_ecdsa_pub.pem'
SERVER_TLS_CERT = 'greenfox_cert.pem'
SERVER_TLS_KEY = 'greenfox_key.pem' 

# --- System & Network Helpers ---
def sh(cmd: str) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

def run_priv(cmd: str) -> subprocess.CompletedProcess:
    """Run a shell command with elevated privileges when needed.
    If the current process is root, run directly; otherwise prefix with sudo
    so the system will prompt for the password when required.
    """
    if os.geteuid() == 0:
        return sh(cmd)
    # use subprocess.run to allow sudo to prompt for password on tty
    return subprocess.run(cmd if cmd.startswith('sudo ') else f"sudo {cmd}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
def get_default_interface() -> Optional[str]:
    try:
        route = sh("ip route | grep '^default '").stdout.decode()
        match = re.search(r'dev (\S+)', route)
        if match:
            return match.group(1)
    except Exception:
        pass
    return None

def enable_ip_forwarding():
    run_priv("sysctl -w net.ipv4.ip_forward=1")

def add_nat_rule(subnet, iface):
    check = f"iptables -t nat -C POSTROUTING -s {subnet} -o {iface} -j MASQUERADE"
    add = f"iptables -t nat -A POSTROUTING -s {subnet} -o {iface} -j MASQUERADE"
    ret = run_priv(check)
    if ret.returncode != 0:
        run_priv(add)

def add_forward_rules(tun):
    for direction in ['-i', '-o']:
        check = f"iptables -C FORWARD {direction} {tun} -j ACCEPT"
        add = f"iptables -A FORWARD {direction} {tun} -j ACCEPT"
        ret = run_priv(check)
        if ret.returncode != 0:
            run_priv(add)

def save_default_route():
    try:
        result = sh("ip route | grep '^default '").stdout.decode().strip()
        if result:
            with open("/tmp/greenfoxvpn_orig_route", "w") as f:
                f.write(result + "\n")
    except Exception:
        pass

def restore_default_route():
    try:
        if os.path.exists("/tmp/greenfoxvpn_orig_route"):
            with open("/tmp/greenfoxvpn_orig_route", "r") as f:
                route = f.read().strip()
            run_priv("ip route del default || true")
            if route:
                run_priv(f"ip route add {route[8:]}")
            os.remove("/tmp/greenfoxvpn_orig_route")
    except Exception:
        pass

def save_resolv_conf():
    try:
        if os.path.exists("/etc/resolv.conf"):
            shutil.copy("/etc/resolv.conf", "/tmp/greenfoxvpn_orig_resolv.conf")
    except Exception:
        pass

def restore_resolv_conf():
    try:
        if os.path.exists("/tmp/greenfoxvpn_orig_resolv.conf"):
            shutil.copy("/tmp/greenfoxvpn_orig_resolv.conf", "/etc/resolv.conf")
            os.remove("/tmp/greenfoxvpn_orig_resolv.conf")
    except Exception:
        pass

def set_default_route_via_tun(tun_name="tun1"):
    run_priv("ip route del default || true")
    run_priv(f"ip route add default dev {tun_name}")

def set_dns_linux(dns='1.1.1.1'):
    try:
        if os.geteuid() == 0:
            with open("/etc/resolv.conf", "w") as f:
                f.write(f"nameserver {dns}\n")
        else:
            # Use sudo tee so we don't need to re-exec the whole script
            p = subprocess.run(f"echo 'nameserver {dns}' | sudo tee /etc/resolv.conf > /dev/null", shell=True)
            return p
    except Exception:
        pass

def tun_alloc(dev='tun0', auto_up=False, ip=None):
    if not os.path.exists('/dev/net/tun'):
        raise RuntimeError("TUN device /dev/net/tun not found. Are you running on Linux with tun/tap support and sufficient privileges?")
    # If we're not running as root, try to create the interface using sudo
    if os.geteuid() != 0:
        try:
            user = os.environ.get('SUDO_USER') or os.environ.get('USER') or 'root'
            # create a tuntap device owned/usable by the user
            run_priv(f"ip tuntap add dev {dev} mode tun user {user}")
        except Exception:
            pass
    tun = os.open('/dev/net/tun', os.O_RDWR)
    ifr = struct.pack('16sH', dev.encode(), IFF_TUN | IFF_NO_PI)
    try:
        import fcntl
        fcntl.ioctl(tun, TUNSETIFF, ifr)
    except OSError as e:
        try:
            os.close(tun)
        except Exception:
            pass
        raise RuntimeError(f"Failed to allocate TUN device {dev}: {e}. Are you running as root?")
    if auto_up and ip:
        run_priv(f"ip addr add {ip} dev {dev}")
        run_priv(f"ip link set {dev} mtu {TUN_MTU}")
        run_priv(f"ip link set {dev} up")
    return tun

def cleanup_and_exit(signum=None, frame=None):
    print("\n[*] Cleaning up GreenFox...")
    # Clean up
    restore_default_route()
    restore_resolv_conf()
    for tun in ['tun0', 'tun1']:
        run_priv(f"ip link delete {tun}")
    iface = get_default_interface()
    if iface:
        run_priv(f"iptables -t nat -D POSTROUTING -s {VPN_SUBNET} -o {iface} -j MASQUERADE")
        for tun in ['tun0', 'tun1']:
            for direction in ['-i', '-o']:
                run_priv(f"iptables -D FORWARD {direction} {tun} -j ACCEPT")
    run_priv("sysctl -w net.ipv4.ip_forward=0")
    sys.exit(0)

signal.signal(signal.SIGINT, cleanup_and_exit)
signal.signal(signal.SIGTERM, cleanup_and_exit)
atexit.register(cleanup_and_exit)

# --- Crypto Utils ---
def x25519_generate():
    priv = X25519PrivateKey.generate()
    return priv, priv.public_key()
def x25519_derive(priv, peer_pub):
    shared = priv.exchange(peer_pub)
    return PySHA256.new(shared).digest()
def x25519_pub_to_bytes(pub):
    return pub.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
def x25519_pub_from_bytes(data):
    return X25519PublicKey.from_public_bytes(data)
def ecdsa_load(priv_path, pub_path):
    if os.path.exists(priv_path) and os.path.exists(pub_path):
        with open(priv_path, 'rt') as f: k = ECC.import_key(f.read())
        with open(pub_path, 'rt') as f: p = ECC.import_key(f.read())
        return k, p
    return None, None
def ecdsa_generate_and_save(priv_path, pub_path):
    key = ECC.generate(curve='P-256')
    with open(priv_path, 'wt') as f: f.write(key.export_key(format='PEM'))
    with open(pub_path, 'wt') as f: f.write(key.public_key().export_key(format='PEM'))
    return key, key.public_key()
def sign_bytes(ecdsa_priv, data):
    h = PySHA256.new(data)
    signer = DSS.new(ecdsa_priv, 'fips-186-3')
    return signer.sign(h)
def verify_bytes(ecdsa_pub, data, signature):
    h = PySHA256.new(data)
    verifier = DSS.new(ecdsa_pub, 'fips-186-3')
    try:
        verifier.verify(h, signature)
        return True
    except ValueError:
        return False

# --- UCP Wrapping (Padding) ---
def ucp_wrap(data: bytes, msg_type: int = 1) -> bytes:
    pad_len = random.randint(MIN_PAD, MAX_PAD)
    padding = get_random_bytes(pad_len)
    return bytes([msg_type]) + bytes([pad_len]) + padding + data

def ucp_unwrap(data: bytes) -> Tuple[int, bytes]:
    if len(data) < 2: raise ValueError('Short')
    msg_type = data[0]
    pad_len = data[1]
    header_len = 2 + pad_len
    if len(data) < header_len: raise ValueError('Truncated')
    return msg_type, data[header_len:]

# --- Session with Sliding Window Replay Protection ---
class GreenFoxSession:
    def __init__(self, key: bytes, sid: int):
        self.key = key
        self.sid = sid & 0xffffffff
        self.send_counter = 0
        self.recv_max = 0
        self.bitmap = 1
        self.window_size = 64

    def _make_nonce(self, counter: int) -> bytes:
        return self.sid.to_bytes(4, 'big') + (counter & 0xffffffffffffffff).to_bytes(8, 'big')

    def check_replay(self, counter: int) -> bool:
        if counter > self.recv_max:
            diff = counter - self.recv_max
            if diff >= self.window_size: self.bitmap = 1
            else: self.bitmap <<= diff; self.bitmap |= 1
            self.recv_max = counter; return True
        diff = self.recv_max - counter
        if diff >= self.window_size: return False
        mask = 1 << diff
        if (self.bitmap & mask): return False
        self.bitmap |= mask; return True

    def encrypt(self, data: bytes) -> bytes:
        nonce = self._make_nonce(self.send_counter)
        cipher = ChaCha20_Poly1305.new(key=self.key, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        self.send_counter += 1
        return nonce + ciphertext + tag

    def decrypt(self, packet: bytes) -> bytes:
        if len(packet) < 12 + 16: raise ValueError('Packet too short')
        nonce = packet[:12]
        counter = int.from_bytes(nonce[4:], 'big')
        if not self.check_replay(counter): raise ValueError(f'Replay or old packet: {counter}')
        cipher = ChaCha20_Poly1305.new(key=self.key, nonce=nonce)
        return cipher.decrypt_and_verify(packet[12:-16], packet[-16:])

# --- New Anti-Censorship Transport ---
class WSCamouflageTransport:
    """
    Transport which wraps data in TLS and a fake WebSocket Handshake.
    """
    def __init__(self, remote_addr: Tuple[str, int], host_header: Optional[str] = None):
        self.raddr = remote_addr
        host = host_header if host_header else remote_addr[0]
        
        sock = socket.create_connection(remote_addr, timeout=10)
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        context.check_hostname = False
        
        self.tls = context.wrap_socket(sock, server_hostname=host)
        
        # 1. Fake Handshake (Looks like WebSocket Upgrade)
        ws_key = base64.b64encode(get_random_bytes(16)).decode()
        handshake = (
            f"GET /ws HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {ws_key}\r\n"
            f"\r\n"
        ).encode()
        
        self.tls.sendall(handshake)
        # 2. Receive and check response (just check if socket stays alive)
        self.tls.recv(4096)
        print(f"[Camouflage] Handshake OK via {host}")

    def send(self, data: bytes):
        # Prepend a 4-byte length header for GreenFox packets
        self.tls.sendall(len(data).to_bytes(4, 'big') + data)
        
    def recv(self, bufsize=4096) -> Tuple[bytes, Tuple[str, int]]:
        # Read the 4-byte length prefix
        l = b''
        while len(l) < 4:
            chunk = self.tls.recv(4 - len(l))
            if not chunk: raise ConnectionError('Camouflage pipe closed')
            l += chunk
        length = int.from_bytes(l, 'big')
        
        # Read the payload
        d = b''
        while len(d) < length:
            chunk = self.tls.recv(length - len(d))
            if not chunk: raise ConnectionError('Camouflage pipe closed')
            d += chunk
        return d, self.raddr
        
    def close(self):
        try: self.tls.close()
        except: pass

class UDPTransport:
    def __init__(self, remote_addr, listen_port=None):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if listen_port: self.sock.bind(('0.0.0.0', listen_port))
        self.raddr = remote_addr
    def send(self, data): self.sock.sendto(data, self.raddr)
    def recv(self, bufsize=4096): return self.sock.recvfrom(bufsize)
    def close(self): self.sock.close()

class MultiTransport:
    def __init__(self, transports):
        self.active = None
        for name, ctor in transports:
            try:
                print(f"[Connecting] Trying {name}...")
                self.active = ctor()
                print(f"✅ [Connected] via {name}")
                break
            except Exception as e:
                print(f"❌ [Failed] {name}: {e}")
        if self.active is None:
            raise Exception("All transports failed")
    def send(self, data): self.active.send(data)
    def recv(self, bufsize=4096): return self.active.recv(bufsize)
    def close(self): self.active.close()

# --- Client Logic ---
class GreenFoxClient:
    def __init__(self, server, port, server_pub_hex, server_ecdsa_pub=None, tun_name='tun1', transports=None):
        self.tun = tun_alloc(tun_name, auto_up=True, ip=f"10.8.0.2/24")
        save_default_route()
        save_resolv_conf()
        set_default_route_via_tun(tun_name)
        set_dns_linux()
        self.priv, self.pub = x25519_generate()
        self.server_pub = x25519_pub_from_bytes(bytes.fromhex(server_pub_hex))
        
        # Transports
        if transports is None:
            transports = [
                ('camouflage_443', lambda: WSCamouflageTransport((server, 443), host_header=server)),
                ('udp_direct', lambda: UDPTransport((server, 9999)))
            ]
        self.transport = MultiTransport(transports)
        self.session = None

    def handshake(self):
        print("[Handshake] Sending...")
        payload = x25519_pub_to_bytes(self.pub)
        self.transport.send(b'HANDSHAKE:' + payload)
        
        data, _ = self.transport.recv()
        if not data.startswith(b'PUBKEY:'):
            raise Exception("Handshake failed: Invalid response")
        
        parts = data.split(b':SIG:')
        server_part = parts[0][len(b'PUBKEY:'):]
        sig = parts[1]
        
        server_x_pub = x25519_pub_from_bytes(server_part)
        key = x25519_derive(self.priv, server_x_pub)
        sid = int.from_bytes(PySHA256.new(key).digest()[:4], 'big')
        self.session = GreenFoxSession(key, sid)
        print("✅ [Handshake] Session established.")

    def run(self):
        self.handshake()
        
        def tun_reader():
            while True:
                try:
                    packet = os.read(self.tun, MAX_READ_SIZE)
                    if not packet: continue
                    wrapped = ucp_wrap(packet)
                    self.transport.send(self.session.encrypt(wrapped))
                except Exception: break
        
        threading.Thread(target=tun_reader, daemon=True).start()
        
        while True:
            try:
                data, _ = self.transport.recv()
                plain = self.session.decrypt(data)
                msg_type, payload = ucp_unwrap(plain)
                if msg_type == 1:
                    os.write(self.tun, payload)
            except Exception: pass

# --- Server Logic ---
class GreenFoxServer:
    def __init__(self, port=443, tun_name='tun0', my_vip='10.8.0.1'):
        self.tun = tun_alloc(tun_name, auto_up=True, ip=f"{my_vip}/24")
        
        iface = get_default_interface()
        if iface:
            enable_ip_forwarding()
            add_nat_rule(VPN_SUBNET, iface)
            add_forward_rules(tun_name)
        
        self.ecdsa_priv, self.ecdsa_pub = ecdsa_load(SERVER_ECDSA_PRIV_FILE, SERVER_ECDSA_PUB_FILE)
        if not self.ecdsa_priv:
            self.ecdsa_priv, self.ecdsa_pub = ecdsa_generate_and_save(SERVER_ECDSA_PRIV_FILE, SERVER_ECDSA_PUB_FILE)
            sh(f"openssl req -x509 -newkey rsa:4096 -nodes -out {SERVER_TLS_CERT} -keyout {SERVER_TLS_KEY} -days 365 -subj '/CN=GreenFoxVPN'")
            print("[Server] New Keys Generated.")
            
        self.priv, self.pub = x25519_generate()
        self.port = port
        self.sessions = {}
        
        self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_sock.bind(('0.0.0.0', 9999))
        
        self.tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.tcp_sock.bind(('0.0.0.0', port))
        self.tcp_sock.listen(50)
        
        print(f"📢 [Server] Running: Camouflage/TLS on port {port}, UDP on 9999")

    def _read_exact(self, conn, length):
        data = b''
        while len(data) < length:
            chunk = conn.recv(length - len(data))
            if not chunk: raise ConnectionError('Connection closed')
            data += chunk
        return data

    def _handle_packet(self, data, addr, proto, conn=None):
        key = (addr[0], addr[1], proto)
        
        if key not in self.sessions:
            if data.startswith(b'HANDSHAKE:'):
                try:
                    c_pub = data[10:]
                    shared = x25519_derive(self.priv, x25519_pub_from_bytes(c_pub))
                    sid = int.from_bytes(PySHA256.new(shared).digest()[:4], 'big')
                    session = GreenFoxSession(shared, sid)
                    
                    if proto == 'udp': send_fn = lambda d: self.udp_sock.sendto(d, addr)
                    else: send_fn = lambda d: conn.sendall(len(d).to_bytes(4,'big') + d)
                    
                    self.sessions[key] = (session, send_fn)
                    
                    s_pub_bytes = x25519_pub_to_bytes(self.pub)
                    sig = sign_bytes(self.ecdsa_priv, s_pub_bytes + c_pub)
                    response_pkt = b'PUBKEY:' + s_pub_bytes + b':SIG:' + sig
                    send_fn(response_pkt)
                    
                    print(f"✅ [New Session] {addr} via {proto}")
                except Exception as e:
                    print(f"❌ [Handshake Error] {e}")
            return
        
        session, send_fn = self.sessions[key]
        try:
            plain = session.decrypt(data)
            msg_type, payload = ucp_unwrap(plain)
            if msg_type == 1: os.write(self.tun, payload)
        except Exception: pass

    def run(self):
        threading.Thread(target=self._udp_loop, daemon=True).start()
        threading.Thread(target=self._tun_loop, daemon=True).start()
        threading.Thread(target=self._tcp_accept_loop, daemon=True).start()
        
        while True: time.sleep(1)

    def _udp_loop(self):
        while True:
            try:
                data, addr = self.udp_sock.recvfrom(4096)
                self._handle_packet(data, addr, 'udp')
            except: pass

    def _tcp_accept_loop(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=SERVER_TLS_CERT, keyfile=SERVER_TLS_KEY)
        while True:
            conn, addr = self.tcp_sock.accept()
            try:
                tls_conn = context.wrap_socket(conn, server_side=True)
                threading.Thread(target=self._handle_tls_connection, args=(tls_conn, addr), daemon=True).start()
            except ssl.SSLError:
                conn.close()
            except Exception:
                conn.close()

    def _handle_tls_connection(self, tls_conn, addr):
        peer_key = (addr[0], addr[1], 'camouflage')
        try:
            # 1. Read Camouflage Handshake (HTTP header)
            header = b''
            while b'\r\n\r\n' not in header:
                chunk = tls_conn.recv(1)
                if not chunk: raise ConnectionError
                header += chunk
            
            # 2. Send Fake Response (101 Switching Protocols)
            tls_conn.sendall(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
            
            # 3. Handle GreenFox Packets (with 4-byte length prefix)
            while True:
                length_bytes = self._read_exact(tls_conn, 4)
                length = int.from_bytes(length_bytes, 'big')
                data = self._read_exact(tls_conn, length)
                
                self._handle_packet(data, addr, 'camouflage', tls_conn)
                
        except Exception:
            pass
        finally:
            try: tls_conn.close()
            except: pass
            if peer_key in self.sessions: del self.sessions[peer_key]

    def _tun_loop(self):
        while True:
            packet = os.read(self.tun, MAX_READ_SIZE)
            if not packet: continue
            wrapped = ucp_wrap(packet)
            dead_keys = []
            for k, (sess, send_fn) in self.sessions.items():
                try:
                    send_fn(sess.encrypt(wrapped))
                except:
                    dead_keys.append(k)
            for k in dead_keys: del self.sessions[k]

# --- Main Entry Point ---
if __name__ == "__main__":
    parser = ArgumentParser(description="GreenFox VPN Protocol v3.0 (Anti-Censorship)")
    sub = parser.add_subparsers(dest='mode')
    srv = sub.add_parser('server')
    srv.add_argument('--port', type=int, default=443)
    srv.add_argument('--tun', default='tun0')
    cli = sub.add_parser('client')
    cli.add_argument('server', help="Server IP or Hostname (for TLS)")
    cli.add_argument('server_pub_hex', help="X25519 Pub Key Hex")
    cli.add_argument('--server_ecdsa_pub', help="Path to ECDSA pub key (optional)")
    cli.add_argument('--port', type=int, default=443)
    cli.add_argument('--tun', default='tun1')
    args = parser.parse_args()
    try:
        if args.mode == 'client':
            print(f"🟢 [GreenFox] Starting Client (Anti-Censorship Mode)...")
            c = GreenFoxClient(args.server, args.port, args.server_pub_hex, args.server_ecdsa_pub, tun_name=args.tun)
            c.run()
        elif args.mode == 'server':
            print(f"🔴 [GreenFox] Starting Server (Obfuscating on port {args.port})...")
            s = GreenFoxServer(args.port, tun_name=args.tun)
            s.run()
        else:
            parser.print_help()
    except Exception as e:
        print(f"[ERROR] {e}")
        sys.exit(1)