#!/usr/bin/env python3
"""
GreenFox Protocol - Fixed / Hardened Single-file Implementation
Includes: Tor-transparent (serverless) automatic docker container creation (host network),
iptables redirection from TUN -> Tor TransPort/DNSPort, secure X25519+ECDSA handshake,
ChaCha20-Poly1305 encryption with nonce-counter, unified transports (UDP/TCP/Tor).
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
from collections import deque
from typing import Callable, Tuple, Optional
from argparse import ArgumentParser

# Crypto libraries
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256 as PySHA256
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization

# Optional: dnspython may be used for DOH if available
try:
    import dns.message
    _HAS_DNSPY = True
except Exception:
    _HAS_DNSPY = False

# Constants
TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000
MAX_PACKET = 2048
VPN_SUBNET = '10.8.0.0/24'
MIN_PAD = 16
MAX_PAD = 128
ORIG_ROUTE_FILE = "/tmp/greenfoxvpn_orig_route"
ORIG_RESOLV_FILE = "/tmp/greenfoxvpn_orig_resolv.conf"
DEFAULT_DNS = '1.1.1.1'
SERVER_ECDSA_PRIV_FILE = 'greenfox_server_ecdsa_priv.pem'
SERVER_ECDSA_PUB_FILE = 'greenfox_server_ecdsa_pub.pem'

# Tor container / tor-trans globals
_TOR_CONTAINER_NAME = 'greenfox_tor'
_TOR_DOCKER_IMAGE = 'dperson/torproxy'
_TOR_TMPDIR = '/tmp/greenfox_tor'
_TOR_TRANS_RULES = []

# --- Utility shell helpers ---
def sh(cmd: str) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

def check_root():
    if os.geteuid() != 0:
        print("[!] Must be run as root.")
        sys.exit(1)

def get_default_interface() -> Optional[str]:
    try:
        route = sh("ip route | grep '^default '").stdout.decode()
        match = re.search(r'dev (\S+)', route)
        if match:
            return match.group(1)
    except Exception:
        pass
    return None

def get_public_ip():
    try:
        ip = requests.get("https://api.ipify.org", timeout=5).text.strip()
        return ip
    except Exception:
        return None

def enable_ip_forwarding():
    sh("sysctl -w net.ipv4.ip_forward=1")

def add_nat_rule(subnet, iface):
    check = f"iptables -t nat -C POSTROUTING -s {subnet} -o {iface} -j MASQUERADE"
    add = f"iptables -t nat -A POSTROUTING -s {subnet} -o {iface} -j MASQUERADE"
    ret = subprocess.run(check, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if ret.returncode != 0:
        subprocess.run(add, shell=True, check=False)

def add_forward_rules(tun):
    for direction in ['-i', '-o']:
        check = f"iptables -C FORWARD {direction} {tun} -j ACCEPT"
        add = f"iptables -A FORWARD {direction} {tun} -j ACCEPT"
        ret = subprocess.run(check, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if ret.returncode != 0:
            subprocess.run(add, shell=True, check=False)

def save_default_route():
    try:
        result = sh("ip route | grep '^default '").stdout.decode().strip()
        if result:
            with open(ORIG_ROUTE_FILE, "w") as f:
                f.write(result + "\n")
    except Exception:
        pass

def restore_default_route():
    try:
        if os.path.exists(ORIG_ROUTE_FILE):
            with open(ORIG_ROUTE_FILE, "r") as f:
                route = f.read().strip()
            sh("ip route del default || true")
            if route:
                sh(f"ip route add {route[8:]}")
            os.remove(ORIG_ROUTE_FILE)
    except Exception:
        pass

def save_resolv_conf():
    try:
        if os.path.exists("/etc/resolv.conf"):
            shutil.copy("/etc/resolv.conf", ORIG_RESOLV_FILE)
    except Exception:
        pass

def restore_resolv_conf():
    try:
        if os.path.exists(ORIG_RESOLV_FILE):
            shutil.copy(ORIG_RESOLV_FILE, "/etc/resolv.conf")
            os.remove(ORIG_RESOLV_FILE)
    except Exception:
        pass

def set_default_route_via_tun(tun_name="tun1"):
    sh("ip route del default || true")
    sh(f"ip route add default dev {tun_name}")

def set_dns_linux(dns=DEFAULT_DNS):
    try:
        with open("/etc/resolv.conf", "w") as f:
            f.write(f"nameserver {dns}\n")
    except Exception:
        pass

def cleanup_and_exit(signum=None, frame=None):
    print("[*] Cleaning up...")
    try:
        disable_tor_transparent()
    except Exception:
        pass
    try:
        stop_tor_container()
    except Exception:
        pass
    restore_default_route()
    restore_resolv_conf()
    for tun in ['tun0', 'tun1']:
        subprocess.run(f"ip link delete {tun}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    iface = get_default_interface()
    if iface:
        for tun in ['tun0', 'tun1']:
            subprocess.run(f"iptables -t nat -D POSTROUTING -s {VPN_SUBNET} -o {iface} -j MASQUERADE", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            for direction in ['-i', '-o']:
                subprocess.run(f"iptables -D FORWARD {direction} {tun} -j ACCEPT", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    sh("sysctl -w net.ipv4.ip_forward=0")
    sys.exit(0)

signal.signal(signal.SIGINT, cleanup_and_exit)
signal.signal(signal.SIGTERM, cleanup_and_exit)
atexit.register(cleanup_and_exit)

# --- Tor transparent (serverless) helpers ---
def ensure_docker_available() -> bool:
    try:
        subprocess.run(['docker', 'version'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        return True
    except Exception:
        return False

def prepare_torrc(path: str, trans_port: int = 9040, dns_port: int = 53) -> str:
    content = f"""SocksPort 9050
TransPort {trans_port}
DNSPort {dns_port}
VirtualAddrNetworkIPv4 10.192.0.0/10
AutomapHostsOnResolve 1
Log notice stdout
"""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as f:
        f.write(content)
    return path

def pull_tor_image():
    print('[TOR-CONTAINER] Pulling tor image...')
    subprocess.run(['docker', 'pull', _TOR_DOCKER_IMAGE], check=False)

def run_tor_container_hostnet(torrc_host_path: str) -> bool:
    if not ensure_docker_available():
        print('[TOR-CONTAINER] docker CLI not found. Please install Docker or run a tor VM manually.')
        return False
    pull_tor_image()
    subprocess.run(['docker', 'rm', '-f', _TOR_CONTAINER_NAME], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    cmd = [
        'docker', 'run', '-d', '--name', _TOR_CONTAINER_NAME,
        '--restart', 'unless-stopped',
        '--cap-add', 'NET_ADMIN',
        '--network', 'host',
        '-v', f'{torrc_host_path}:/etc/tor/torrc:ro',
        _TOR_DOCKER_IMAGE
    ]
    print('[TOR-CONTAINER] Starting tor container (host networked)...')
    try:
        subprocess.run(cmd, check=True)
        print('[TOR-CONTAINER] Started.')
        return True
    except Exception as e:
        print(f'[TOR-CONTAINER] Failed to start: {e}')
        return False

def stop_tor_container():
    try:
        subprocess.run(['docker', 'rm', '-f', _TOR_CONTAINER_NAME], check=False)
        print('[TOR-CONTAINER] Stopped and removed (if existed).')
    except Exception:
        pass

def enable_tor_transparent(container_ip: str = '127.0.0.1', trans_port: int = 9040, dns_port: int = 53, tun: str = 'tun1', hostnet: bool = True):
    global _TOR_TRANS_RULES
    iface = get_default_interface() or 'eth0'
    cmds = []
    if hostnet:
        cmds.append(f"iptables -t nat -A PREROUTING -i {tun} -p tcp -j REDIRECT --to-ports {trans_port}")
        cmds.append(f"iptables -t nat -A PREROUTING -i {tun} -p udp --dport 53 -j REDIRECT --to-ports {dns_port}")
    else:
        cmds.append(f"iptables -t nat -A PREROUTING -i {tun} -p tcp -j DNAT --to-destination {container_ip}:{trans_port}")
        cmds.append(f"iptables -t nat -A PREROUTING -i {tun} -p udp --dport 53 -j DNAT --to-destination {container_ip}:{dns_port}")
        cmds.append(f"iptables -t nat -A POSTROUTING -o {iface} -j MASQUERADE")
    for c in cmds:
        subprocess.run(c, shell=True)
    _TOR_TRANS_RULES = cmds
    set_dns_linux(container_ip if not hostnet else '127.0.0.1')
    print(f"[TOR-TRANS] Enabled: tun->{container_ip}:{trans_port} (hostnet={hostnet}), dns->{'127.0.0.1' if hostnet else container_ip}:{dns_port}")

def disable_tor_transparent():
    global _TOR_TRANS_RULES
    for c in reversed(_TOR_TRANS_RULES):
        c_del = c.replace('-A', '-D', 1)
        subprocess.run(c_del, shell=True)
    _TOR_TRANS_RULES = []
    print('[TOR-TRANS] Disabled')

# --- DOH resolver (best-effort) ---
def resolve_doh(domain, doh_url="https://cloudflare-dns.com/dns-query"):
    if not _HAS_DNSPY:
        return []
    try:
        msg = dns.message.make_query(domain, 'A')
        wire = msg.to_wire()
        headers = {'accept': 'application/dns-message'}
        params = {'dns': base64.urlsafe_b64encode(wire).decode()}
        r = requests.get(doh_url, headers=headers, params=params, timeout=5)
        msg = dns.message.from_wire(r.content)
        return [rr.address for rr in msg.answer[0].items if rr.rdtype == 1]
    except Exception as e:
        print(f"[DOH] Failed {domain} ({e})")
        return []

# --- TUN allocation ---
def tun_alloc(dev='tun0', auto_up=False, ip=None):
    if len(dev) > 15:
        print(f"[!] Device name '{dev}' too long (max 15 chars).")
        sys.exit(1)
    if not os.path.exists('/dev/net/tun'):
        print("[!] /dev/net/tun does not exist. Try: sudo modprobe tun")
        sys.exit(1)
    tun = os.open('/dev/net/tun', os.O_RDWR)
    ifr = struct.pack('16sH', dev.encode(), IFF_TUN | IFF_NO_PI)
    try:
        import fcntl
        fcntl.ioctl(tun, TUNSETIFF, ifr)
    except OSError as e:
        print(f"[!] TUN allocation for '{dev}' failed: {e}")
        sys.exit(1)
    if auto_up and ip:
        subprocess.run(['ip', 'addr', 'add', ip, 'dev', dev], check=False)
        subprocess.run(['ip', 'link', 'set', dev, 'up'], check=False)
    return tun

# --- X25519 helpers ---
def x25519_generate():
    priv = X25519PrivateKey.generate()
    pub = priv.public_key()
    return priv, pub

def x25519_derive(priv: X25519PrivateKey, peer_pub: X25519PublicKey) -> bytes:
    shared = priv.exchange(peer_pub)
    return PySHA256.new(shared).digest()

def x25519_pub_to_bytes(pub: X25519PublicKey) -> bytes:
    return pub.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)

def x25519_pub_from_bytes(data: bytes) -> X25519PublicKey:
    return X25519PublicKey.from_public_bytes(data)

# --- ECDSA helpers (server long-term) ---
def ecdsa_generate_and_save(priv_path=SERVER_ECDSA_PRIV_FILE, pub_path=SERVER_ECDSA_PUB_FILE):
    key = ECC.generate(curve='P-256')
    with open(priv_path, 'wt') as f:
        f.write(key.export_key(format='PEM'))
    with open(pub_path, 'wt') as f:
        f.write(key.public_key().export_key(format='PEM'))
    return key, key.public_key()

def ecdsa_load(priv_path=SERVER_ECDSA_PRIV_FILE, pub_path=SERVER_ECDSA_PUB_FILE):
    if os.path.exists(priv_path) and os.path.exists(pub_path):
        with open(priv_path, 'rt') as f:
            key = ECC.import_key(f.read())
        with open(pub_path, 'rt') as f:
            pub = ECC.import_key(f.read())
        return key, pub
    return None, None

def sign_bytes(ecdsa_priv: ECC.EccKey, data: bytes) -> bytes:
    h = PySHA256.new(data)
    signer = DSS.new(ecdsa_priv, 'fips-186-3')
    return signer.sign(h)

def verify_bytes(ecdsa_pub: ECC.EccKey, data: bytes, signature: bytes) -> bool:
    h = PySHA256.new(data)
    verifier = DSS.new(ecdsa_pub, 'fips-186-3')
    try:
        verifier.verify(h, signature)
        return True
    except ValueError:
        return False

# --- UCP helpers (wrapping) ---
def ucp_wrap(data: bytes, msg_type: int = 1) -> bytes:
    pad_len = random.randint(MIN_PAD, MAX_PAD)
    padding = get_random_bytes(pad_len)
    return bytes([msg_type]) + bytes([pad_len]) + padding + data

def ucp_unwrap(data: bytes) -> Tuple[int, bytes]:
    if len(data) < 2:
        raise ValueError('UCP data too short')
    msg_type = data[0]
    pad_len = data[1]
    if pad_len < MIN_PAD or pad_len > MAX_PAD:
        raise ValueError('Invalid padding length')
    header_len = 2 + pad_len
    if len(data) < header_len:
        raise ValueError('UCP payload truncated')
    return msg_type, data[header_len:]

# --- Session with nonce-counter and simple replay protection ---
class GreenFoxSession:
    def __init__(self, key: bytes, sid: int):
        self.key = key
        self.sid = sid & 0xffffffff
        self.send_counter = 0
        self.recv_max = -1

    def _make_nonce(self, counter: int) -> bytes:
        return self.sid.to_bytes(4, 'big') + (counter & 0xffffffffffffffff).to_bytes(8, 'big')

    def encrypt(self, data: bytes) -> bytes:
        nonce = self._make_nonce(self.send_counter)
        cipher = ChaCha20_Poly1305.new(key=self.key, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        packet = nonce + ciphertext + tag
        self.send_counter += 1
        return packet

    def decrypt(self, packet: bytes) -> bytes:
        if len(packet) < 12 + 16:
            raise ValueError('Packet too short')
        nonce = packet[:12]
        counter = int.from_bytes(nonce[4:], 'big')
        if counter <= self.recv_max:
            raise ValueError('Replay or old packet')
        cipher = ChaCha20_Poly1305.new(key=self.key, nonce=nonce)
        ciphertext = packet[12:-16]
        tag = packet[-16:]
        plain = cipher.decrypt_and_verify(ciphertext, tag)
        self.recv_max = counter
        return plain

# --- Transport base & transports ---
class BaseTransport:
    def send(self, data: bytes):
        raise NotImplementedError()
    def recv(self, bufsize=4096) -> Tuple[bytes, Tuple[str, int]]:
        raise NotImplementedError()
    def close(self):
        pass

class UDPTransport(BaseTransport):
    def __init__(self, remote_addr: Tuple[str, int], listen_port: Optional[int] = None):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.raddr = remote_addr
        if listen_port:
            self.sock.bind(('0.0.0.0', listen_port))
    def send(self, data: bytes):
        self.sock.sendto(data, self.raddr)
    def recv(self, bufsize=4096) -> Tuple[bytes, Tuple[str, int]]:
        d, addr = self.sock.recvfrom(bufsize)
        return d, addr
    def close(self):
        self.sock.close()

class TCPTransport(BaseTransport):
    def __init__(self, remote_addr: Tuple[str, int], timeout: Optional[float] = 10.0):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(timeout)
        self.sock.connect(remote_addr)
        self.raddr = remote_addr
    def send(self, data: bytes):
        self.sock.sendall(len(data).to_bytes(2, 'big') + data)
    def recv(self, bufsize=4096) -> Tuple[bytes, Tuple[str, int]]:
        l = b''
        while len(l) < 2:
            chunk = self.sock.recv(2 - len(l))
            if not chunk:
                raise ConnectionError('TCP closed')
            l += chunk
        length = int.from_bytes(l, 'big')
        d = b''
        while len(d) < length:
            chunk = self.sock.recv(length - len(d))
            if not chunk:
                raise ConnectionError('TCP closed while reading payload')
            d += chunk
        return d, self.raddr
    def close(self):
        try:
            self.sock.close()
        except Exception:
            pass

class TorTransport(BaseTransport):
    def __init__(self, remote_addr: Tuple[str, int], tor_proxy="127.0.0.1", tor_port=9050):
        try:
            import socks
        except ImportError:
            print("PySocks is required for Tor transport. Install with: pip install pysocks")
            raise
        self.sock = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.set_proxy(socks.SOCKS5, tor_proxy, tor_port)
        self.sock.connect(remote_addr)
        self.raddr = remote_addr
    def send(self, data: bytes):
        self.sock.sendall(len(data).to_bytes(2, 'big') + data)
    def recv(self, bufsize=4096) -> Tuple[bytes, Tuple[str, int]]:
        l = b''
        while len(l) < 2:
            l += self.sock.recv(2 - len(l))
        length = int.from_bytes(l, 'big')
        d = b''
        while len(d) < length:
            d += self.sock.recv(length - len(d))
        return d, self.raddr
    def close(self):
        self.sock.close()

# obfs4/domainfront/meek placeholders (production use obfs4proxy etc.)
class Obfs4Transport(BaseTransport):
    def __init__(self, bridge_line, is_server=False, listen_port=None):
        host, port = bridge_line.rsplit(":", 1)
        self.tcp = TCPTransport((host, int(port)))
    def send(self, data: bytes):
        self.tcp.send(data)
    def recv(self, bufsize=4096) -> Tuple[bytes, Tuple[str, int]]:
        return self.tcp.recv(bufsize)
    def close(self):
        self.tcp.close()

class DomainFrontTransport(BaseTransport):
    def __init__(self, front_domain, real_addr, port=443):
        self.tls = ssl.create_default_context().wrap_socket(
            socket.create_connection((front_domain, port)),
            server_hostname=front_domain
        )
        req = f"CONNECT {real_addr}:{port} HTTP/1.1\r\nHost: {front_domain}\r\n\r\n"
        self.tls.sendall(req.encode())
        resp = self.tls.recv(4096)
        if b"200" not in resp:
            raise Exception("[Fronting] CONNECT failed")
    def send(self, data: bytes):
        self.tls.sendall(data)
    def recv(self, bufsize=4096) -> Tuple[bytes, Tuple[str, int]]:
        d = self.tls.recv(bufsize)
        return d, (self.tls.getpeername()[0], self.tls.getpeername()[1])
    def close(self):
        self.tls.close()

class MeekTransport(BaseTransport):
    def __init__(self, meek_url, front_domain):
        self.session = requests.Session()
        self.url = meek_url
        self.front = front_domain
    def send(self, data: bytes):
        headers = {'Host': self.front}
        self.session.post(self.url, data=data, headers=headers)
    def recv(self, bufsize=4096) -> Tuple[bytes, Tuple[str, int]]:
        return b"", ('0.0.0.0', 0)
    def close(self):
        pass

class MultiTransport(BaseTransport):
    def __init__(self, transports):
        self.transports = transports
        self.active = None
        self.active_name = None
        last_exc = None
        for name, ctor in self.transports:
            try:
                t = ctor()
                self.active = t
                self.active_name = name
                print(f"[+] Connected via {name}")
                break
            except Exception as e:
                last_exc = e
                print(f"[!] {name} failed: {e}")
        if self.active is None:
            raise Exception(f"All transports failed, last: {last_exc}")
    def send(self, data: bytes):
        self.active.send(data)
    def recv(self, bufsize=4096) -> Tuple[bytes, Tuple[str, int]]:
        return self.active.recv(bufsize)
    def close(self):
        if self.active:
            self.active.close()

# --- High-level client/server classes ---
class GreenFoxClient:
    def __init__(self, server: str, port: int, server_pub_hex: str, server_ecdsa_pub: Optional[bytes] = None,
                 my_vip='10.8.0.2', tun_name='tun1', transports=None, auto_up=True):
        check_root()
        self.tun = tun_alloc(tun_name, auto_up=auto_up, ip=f"{my_vip}/24")
        save_default_route()
        save_resolv_conf()
        set_default_route_via_tun(tun_name)
        set_dns_linux()
        self.priv, self.pub = x25519_generate()
        self.ecdsa_priv = None
        self.ecdsa_pub = None
        self.server_pub = x25519_pub_from_bytes(bytes.fromhex(server_pub_hex))
        self.server_ecdsa_pub = None
        if server_ecdsa_pub:
            try:
                self.server_ecdsa_pub = ECC.import_key(server_ecdsa_pub)
            except Exception:
                try:
                    self.server_ecdsa_pub = ECC.import_key(bytes.fromhex(server_ecdsa_pub.decode() if isinstance(server_ecdsa_pub, bytes) else server_ecdsa_pub))
                except Exception:
                    self.server_ecdsa_pub = None
        self.key = None
        self.session = None
        self.my_vip = my_vip
        if transports is None:
            transports = [('udp', lambda: UDPTransport((server, port))),
                          ('tcp', lambda: TCPTransport((server, port)))]
        self.transport = MultiTransport(transports)
        self.handshake_done = False

    def handshake(self):
        payload = x25519_pub_to_bytes(self.pub)
        self.transport.send(b'HANDSHAKE:' + payload)
        data, addr = self.transport.recv()
        if not data.startswith(b'PUBKEY:'):
            print('[CLIENT] Handshake failed (no PUBKEY)')
            sys.exit(2)
        try:
            parts = data.split(b':SIG:')
            server_part = parts[0][len(b'PUBKEY:'):]
            sig = parts[1]
        except Exception:
            print('[CLIENT] Handshake response malformed')
            sys.exit(2)
        if self.server_ecdsa_pub is None:
            print('[CLIENT] Warning: no server ECDSA pubkey pinned. MITM susceptible. Continue at your own risk.')
        else:
            if not verify_bytes(self.server_ecdsa_pub, server_part + payload, sig):
                print('[CLIENT] Handshake signature verification failed!')
                sys.exit(3)
        server_x_pub = x25519_pub_from_bytes(server_part)
        self.key = x25519_derive(self.priv, server_x_pub)
        sid_int = int.from_bytes(PySHA256.new(self.key).digest()[:4], 'big')
        self.session = GreenFoxSession(self.key, sid_int)
        self.handshake_done = True
        print('[CLIENT] Handshake complete')

    def run(self):
        if not self.handshake_done:
            self.handshake()
        def tun_loop():
            while True:
                packet = os.read(self.tun, MAX_PACKET)
                wrapped = ucp_wrap(packet, msg_type=1)
                self.transport.send(self.session.encrypt(wrapped))
        threading.Thread(target=tun_loop, daemon=True).start()
        while True:
            data, addr = self.transport.recv()
            try:
                plain = self.session.decrypt(data)
                msg_type, ucp_payload = ucp_unwrap(plain)
                if msg_type == 1:
                    os.write(self.tun, ucp_payload)
            except Exception as e:
                print(f"[CLIENT] Decrypt error: {e}")

class GreenFoxServer:
    def __init__(self, port=9999, tun_name='tun0', my_vip='10.8.0.1', transports=None, auto_up=True,
                 ecdsa_priv_path=SERVER_ECDSA_PRIV_FILE, ecdsa_pub_path=SERVER_ECDSA_PUB_FILE):
        check_root()
        self.tun = tun_alloc(tun_name, auto_up=auto_up, ip=f"{my_vip}/24")
        iface = get_default_interface()
        if iface:
            enable_ip_forwarding()
            add_nat_rule(VPN_SUBNET, iface)
            add_forward_rules(tun_name)
        priv, pub = ecdsa_load(ecdsa_priv_path, ecdsa_pub_path)
        if priv is None:
            priv, pub = ecdsa_generate_and_save(ecdsa_priv_path, ecdsa_pub_path)
            print('[SERVER] Generated new ECDSA keypair and saved to files.')
        self.ecdsa_priv = priv
        self.ecdsa_pub = pub
        self.priv, self.pub = x25519_generate()
        self.my_vip = my_vip
        self.port = port
        self.sessions = {}
        self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.udp_sock.bind(('0.0.0.0', port))
        self.tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.tcp_sock.bind(('0.0.0.0', port))
        self.tcp_sock.listen(128)
        ip = get_public_ip()
        if ip:
            print(f"\n[SERVER] Public IP address: {ip}\n")
        else:
            print("\n[SERVER] Could not determine public IP address.\n")
        print(f"[SERVER] Listening on port {port} (UDP + TCP)\n")

    def _addr_key(self, addr: Tuple[str, int], proto: str='udp') -> Tuple[str, int, str]:
        return (addr[0], addr[1], proto)

    def _udp_send(self, addr: Tuple[str, int], data: bytes):
        self.udp_sock.sendto(data, addr)

    def _tcp_send_factory(self, conn: socket.socket, peeraddr: Tuple[str, int]):
        def send_fn(data: bytes):
            try:
                conn.sendall(len(data).to_bytes(2, 'big') + data)
            except Exception:
                pass
        return send_fn

    def run(self):
        threading.Thread(target=self._tcp_accept_loop, daemon=True).start()
        threading.Thread(target=self._tun_loop, daemon=True).start()
        while True:
            try:
                data, addr = self.udp_sock.recvfrom(65535)
                self._handle_incoming(data, addr, proto='udp')
            except Exception as e:
                print(f"[SERVER] UDP recv error: {e}")

    def _tcp_accept_loop(self):
        while True:
            conn, addr = self.tcp_sock.accept()
            threading.Thread(target=self._handle_tcp_connection, args=(conn, addr), daemon=True).start()

    def _handle_tcp_connection(self, conn: socket.socket, addr: Tuple[str, int]):
        peer_key = self._addr_key(addr, 'tcp')
        send_fn = self._tcp_send_factory(conn, addr)
        self.sessions[peer_key] = (None, send_fn)
        try:
            while True:
                l = conn.recv(2)
                if not l:
                    break
                length = int.from_bytes(l, 'big')
                data = b''
                while len(data) < length:
                    chunk = conn.recv(length - len(data))
                    if not chunk:
                        break
                    data += chunk
                if not data:
                    break
                self._handle_incoming(data, addr, proto='tcp', tcp_conn=conn)
        except Exception as e:
            print(f"[SERVER] TCP connection {addr} error: {e}")
        finally:
            try:
                conn.close()
            except Exception:
                pass
            if peer_key in self.sessions:
                del self.sessions[peer_key]

    def _handle_incoming(self, data: bytes, addr: Tuple[str, int], proto: str='udp', tcp_conn: Optional[socket.socket]=None):
        addr_key = self._addr_key(addr, proto)
        if addr_key not in self.sessions:
            if data.startswith(b'HANDSHAKE:'):
                client_pub = data[len(b'HANDSHAKE:'):]
                try:
                    client_x = x25519_pub_from_bytes(client_pub)
                except Exception:
                    print('[SERVER] Received invalid client pubkey during handshake')
                    return
                shared = x25519_derive(self.priv, client_x)
                sid_int = int.from_bytes(PySHA256.new(shared).digest()[:4], 'big')
                session = GreenFoxSession(shared, sid_int)
                if proto == 'udp':
                    send_fn = lambda d, a=addr: self._udp_send(a, d)
                else:
                    send_fn = self._tcp_send_factory(tcp_conn, addr)
                self.sessions[addr_key] = (session, send_fn)
                server_pub_raw = x25519_pub_to_bytes(self.pub)
                sig = sign_bytes(self.ecdsa_priv, server_pub_raw + client_pub)
                pkt = b'PUBKEY:' + server_pub_raw + b':SIG:' + sig
                send_fn(pkt)
                print(f"[SERVER] Handshake complete: {addr} (proto={proto})")
                return
            else:
                return
        session, send_fn = self.sessions.get(addr_key, (None, None))
        if session is None:
            return
        try:
            plain = session.decrypt(data)
            msg_type, ucp_payload = ucp_unwrap(plain)
            if msg_type == 1:
                os.write(self.tun, ucp_payload)
        except Exception as e:
            print(f"[SERVER] Decrypt error from {addr}: {e}")

    def _tun_loop(self):
        while True:
            packet = os.read(self.tun, MAX_PACKET)
            for addr_key, (session, send_fn) in list(self.sessions.items()):
                if session is None or send_fn is None:
                    continue
                wrapped = ucp_wrap(packet, msg_type=1)
                try:
                    send_fn(session.encrypt(wrapped))
                except Exception as e:
                    print(f"[SERVER] Error sending to {addr_key}: {e}")

# --- Arg parsing & helpers to build transports ---
def build_transport_stack_from_args(args, mode, server, port):
    stack = []
    if getattr(args, 'obfs4', None):
        stack.append(('obfs4', lambda: Obfs4Transport(args.obfs4)))
    if getattr(args, 'front', None):
        stack.append(('front', lambda: DomainFrontTransport(args.front, server, port)))
    if getattr(args, 'meek', None) and getattr(args, 'front', None):
        stack.append(('meek', lambda: MeekTransport(args.meek, args.front)))
    if getattr(args, 'tor', False):
        stack.append(('tor', lambda: TorTransport((server, port), args.torhost, args.torport)))
    stack.append(('tcp', lambda: TCPTransport((server, port))))
    stack.append(('udp', lambda: UDPTransport((server, port))))
    return stack

def parse_args():
    parser = ArgumentParser(description="GreenFox VPN Protocol - Hardened")
    subparsers = parser.add_subparsers(dest='mode', help="server/client")
    sp_srv = subparsers.add_parser('server')
    sp_srv.add_argument('port', type=int, help="Listen port")
    sp_srv.add_argument('--obfs4', help="obfs4 bridge (ip:port)")
    sp_srv.add_argument('--front', help="Domain fronting (front.domain)")
    sp_srv.add_argument('--meek', help="Meek URL")
    sp_srv.add_argument('--tor', action='store_true', help="Enable Tor fallback")
    sp_srv.add_argument('--torhost', default="127.0.0.1", help="Tor SOCKS5 host")
    sp_srv.add_argument('--torport', type=int, default=9050, help="Tor SOCKS5 port")
    sp_srv.add_argument('--tun', default='tun0', help="TUN device name")
    sp_cli = subparsers.add_parser('client')
    sp_cli.add_argument('server', help="Server address")
    sp_cli.add_argument('port', type=int, help="Server port")
    sp_cli.add_argument('server_pub_hex', help="Server pubkey (hex)")
    sp_cli.add_argument('--server_ecdsa_pub', help='Server ECDSA pubkey file path or PEM string (recommended)')
    sp_cli.add_argument('--obfs4', help="obfs4 bridge (ip:port)")
    sp_cli.add_argument('--front', help="Domain fronting (front.domain)")
    sp_cli.add_argument('--meek', help="Meek URL")
    sp_cli.add_argument('--tor', action='store_true', help="Enable Tor fallback")
    sp_cli.add_argument('--torhost', default="127.0.0.1", help="Tor SOCKS5 host")
    sp_cli.add_argument('--torport', type=int, default=9050, help="Tor SOCKS5 port")
    sp_cli.add_argument('--tor-trans', help='Enable serverless transparent Tor mode; format: container_ip|docker-host[:trans_port[:dns_port]]')
    sp_cli.add_argument('--tun', default='tun1', help="TUN device name")
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()

    # Tor-transparent helper mode (client)
    if args.mode == 'client' and getattr(args, 'tor_trans', None):
        # tor-trans argument: either 'docker-host' meaning start container on this host with host-network,
        # or an IP (remote VM/container). Optional ports: ip:trans_port:dns_port
        parts = args.tor_trans.split(':')
        cont_ip = parts[0]
        trans_port = int(parts[1]) if len(parts) > 1 and parts[1] else 9040
        dns_port = int(parts[2]) if len(parts) > 2 and parts[2] else 53
        print(f"[MAIN] Starting client in Tor-transparent mode -> {cont_ip}:{trans_port} (dns {dns_port})")
        check_root()
        tun = args.tun
        tun_fd = tun_alloc(tun, auto_up=True, ip="10.8.0.2/24")
        save_default_route()
        save_resolv_conf()
        set_default_route_via_tun(tun)
        enable_ip_forwarding()

        if cont_ip in ('docker-host', 'auto'):
            os.makedirs(_TOR_TMPDIR, exist_ok=True)
            torrc_path = os.path.join(_TOR_TMPDIR, 'torrc')
            prepare_torrc(torrc_path, trans_port=trans_port, dns_port=dns_port)
            ok = run_tor_container_hostnet(torrc_path)
            if not ok:
                print('[MAIN] Failed to start tor container. Exiting.')
                cleanup_and_exit()
            container_ip_used = '127.0.0.1'
            hostnet_mode = True
            atexit.register(stop_tor_container)
            signal.signal(signal.SIGINT, lambda s,f: (stop_tor_container(), cleanup_and_exit(s,f)))
            signal.signal(signal.SIGTERM, lambda s,f: (stop_tor_container(), cleanup_and_exit(s,f)))
        else:
            container_ip_used = cont_ip
            hostnet_mode = False

        enable_tor_transparent(container_ip=container_ip_used, trans_port=trans_port, dns_port=dns_port, tun=tun, hostnet=hostnet_mode)
        print("[MAIN] Tor-transparent mode active. Press Ctrl-C to exit.")
        try:
            while True:
                time.sleep(10)
        except KeyboardInterrupt:
            disable_tor_transparent()
            if cont_ip in ('docker-host', 'auto'):
                stop_tor_container()
            cleanup_and_exit()

    # Normal server/client flows
    if args.mode == "server":
        s = GreenFoxServer(
            port=args.port,
            tun_name=args.tun,
        )
        s.run()
    elif args.mode == "client":
        server_ecdsa_pub = None
        if getattr(args, 'server_ecdsa_pub', None):
            if os.path.exists(args.server_ecdsa_pub):
                with open(args.server_ecdsa_pub, 'rb') as f:
                    server_ecdsa_pub = f.read()
            else:
                server_ecdsa_pub = args.server_ecdsa_pub.encode()
        c = GreenFoxClient(
            server=args.server,
            port=args.port,
            server_pub_hex=args.server_pub_hex,
            server_ecdsa_pub=server_ecdsa_pub,
            tun_name=args.tun,
            transports=build_transport_stack_from_args(args, "client", args.server, args.port)
        )
        c.run()
    else:
        print("Usage:")
        print("  sudo python3 greenfox_protocol_fixed.py server <port> [--obfs4 ...] [--front ...] [--meek ...] [--tor]")
        print("  sudo python3 greenfox_protocol_fixed.py client <server> <port> <server_pub_hex> [--server_ecdsa_pub <path_or_pem>] [--obfs4 ...] [--front ...] [--meek ...] [--tor] [--tor-trans docker-host|<ip>[:trans_port[:dns_port]]]")
        sys.exit(1)
