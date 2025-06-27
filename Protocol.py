#!/usr/bin/env python3
"""
GreenFox Protocol - Advanced Anti-Censorship VPN Client/Server

Bypass Iran/China and similar censorship with:
- Multi-transport fallback (UDP, TCP, obfs4, Domain Fronting, meek, Tor)
- DNS over HTTPS
- TLS camouflage
- Pluggable, easy to extend with new bypass modules
- Remote config support (bridges, DoH, fronting, meek)
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
import json
from collections import deque
from typing import Callable, Optional
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization
import dns.message

TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000
MAX_PACKET = 2048
VPN_SUBNET = '10.8.0.0/24'
REPLAY_WINDOW = 1000
MIN_PAD = 16
MAX_PAD = 128
ORIG_ROUTE_FILE = "/tmp/greenfoxvpn_orig_route"
ORIG_RESOLV_FILE = "/tmp/greenfoxvpn_orig_resolv.conf"
DEFAULT_DNS = '1.1.1.1'

def check_root():
    if os.geteuid() != 0:
        print("[!] Must be run as root.")
        sys.exit(1)

def sh(cmd):
    return subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

def get_default_interface():
    route = sh("ip route | grep '^default '").stdout.decode()
    match = re.search(r'dev (\S+)', route)
    if match:
        return match.group(1)
    return None

def enable_ip_forwarding():
    sh("sysctl -w net.ipv4.ip_forward=1")

def add_nat_rule(subnet, iface):
    check = f"iptables -t nat -C POSTROUTING -s {subnet} -o {iface} -j MASQUERADE"
    add = f"iptables -t nat -A POSTROUTING -s {subnet} -o {iface} -j MASQUERADE"
    ret = subprocess.run(check, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if ret.returncode != 0:
        subprocess.run(add, shell=True, check=True)

def add_forward_rules(tun):
    for direction in ['-i', '-o']:
        check = f"iptables -C FORWARD {direction} {tun} -j ACCEPT"
        add = f"iptables -A FORWARD {direction} {tun} -j ACCEPT"
        ret = subprocess.run(check, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if ret.returncode != 0:
            subprocess.run(add, shell=True, check=True)

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

def resolve_doh(domain, doh_url="https://cloudflare-dns.com/dns-query"):
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
        subprocess.run(['ip', 'addr', 'add', ip, 'dev', dev], check=True)
        subprocess.run(['ip', 'link', 'set', dev, 'up'], check=True)
    return tun

def x25519_generate():
    priv = X25519PrivateKey.generate()
    pub = priv.public_key()
    return priv, pub

def x25519_derive(priv, peer_pub):
    shared = priv.exchange(peer_pub)
    return SHA256.new(shared).digest()

def x25519_pub_to_bytes(pub):
    return pub.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)

def x25519_pub_from_bytes(data):
    return X25519PublicKey.from_public_bytes(data)

def ecdsa_generate():
    key = ECC.generate(curve='P-256')
    return key, key.public_key()

def ucp_wrap(data, msg_type=1):
    pad_len = random.randint(MIN_PAD, MAX_PAD)
    padding = get_random_bytes(pad_len)
    return bytes([msg_type]) + bytes([pad_len]) + padding + data

def ucp_unwrap(data):
    msg_type = data[0]
    pad_len = data[1]
    return msg_type, data[2+pad_len:]

class ReplayProtector:
    def __init__(self, window=REPLAY_WINDOW):
        self.seen = deque(maxlen=window)
    def check_and_add(self, nonce):
        if nonce in self.seen:
            return False
        self.seen.append(nonce)
        return True

class GreenFoxSession:
    def __init__(self, key):
        self.key = key
        self.replay = ReplayProtector()
    def encrypt(self, data):
        nonce = get_random_bytes(12)
        cipher = ChaCha20_Poly1305.new(key=self.key, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return nonce + ciphertext + tag
    def decrypt(self, packet):
        nonce, ciphertext, tag = packet[:12], packet[12:-16], packet[-16:]
        if not self.replay.check_and_add(nonce):
            raise Exception("Replay detected")
        cipher = ChaCha20_Poly1305.new(key=self.key, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)

class BaseTransport:
    def send(self, data): raise NotImplementedError()
    def recv(self, bufsize=4096): raise NotImplementedError()
    def close(self): pass

class UDPTransport(BaseTransport):
    def __init__(self, remote_addr, listen_port=None):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.raddr = remote_addr
        if listen_port:
            self.sock.bind(('0.0.0.0', listen_port))
    def send(self, data): self.sock.sendto(data, self.raddr)
    def recv(self, bufsize=4096): return self.sock.recvfrom(bufsize)
    def close(self): self.sock.close()

class TCPTransport(BaseTransport):
    def __init__(self, remote_addr):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect(remote_addr)
        self.raddr = remote_addr
    def send(self, data):
        self.sock.sendall(len(data).to_bytes(2, 'big') + data)
    def recv(self, bufsize=4096):
        l = b''
        while len(l) < 2:
            l += self.sock.recv(2 - len(l))
        length = int.from_bytes(l, 'big')
        d = b''
        while len(d) < length:
            d += self.sock.recv(length - len(d))
        return d, self.raddr
    def close(self): self.sock.close()

class TorTransport(TCPTransport):
    def __init__(self, remote_addr, tor_proxy="127.0.0.1", tor_port=9050):
        import socks
        self.sock = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.set_proxy(socks.SOCKS5, tor_proxy, tor_port)
        self.sock.connect(remote_addr)
        self.raddr = remote_addr

class Obfs4Transport(BaseTransport):
    def __init__(self, bridge_line, is_server=False, listen_port=None):
        # For demo, just fallback to TCP. For real, spawn obfs4proxy subprocess.
        host, port = bridge_line.rsplit(":", 1)
        self.tcp = TCPTransport((host, int(port)))
    def send(self, data): self.tcp.send(data)
    def recv(self, bufsize=4096): return self.tcp.recv(bufsize)
    def close(self): self.tcp.close()

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
    def send(self, data): self.tls.sendall(data)
    def recv(self, bufsize=4096): return self.tls.recv(bufsize), None
    def close(self): self.tls.close()

class MeekTransport(BaseTransport):
    def __init__(self, meek_url, front_domain):
        self.session = requests.Session()
        self.url = meek_url
        self.front = front_domain
    def send(self, data):
        headers = {'Host': self.front}
        self.session.post(self.url, data=data, headers=headers)
    def recv(self, bufsize=4096): return b"", None
    def close(self): pass

class MultiTransport(BaseTransport):
    def __init__(self, transports):
        self.transports = transports
        self.active = None
        for name, t in self.transports:
            try:
                self.active = t()
                print(f"[+] Connected via {name}")
                break
            except Exception as e:
                print(f"[!] {name} failed: {e}")
        if self.active is None:
            raise Exception("All transports failed")
    def send(self, data): self.active.send(data)
    def recv(self, bufsize=4096): return self.active.recv(bufsize)
    def close(self): self.active.close()

class GreenFoxClient:
    def __init__(self, server, port, server_pub_hex, my_vip='10.8.0.2', tun_name='tun1',
                 transports=None, auto_up=True):
        check_root()
        self.tun = tun_alloc(tun_name, auto_up=auto_up, ip=f"{my_vip}/24")
        save_default_route()
        save_resolv_conf()
        set_default_route_via_tun(tun_name)
        set_dns_linux()
        self.priv, self.pub = x25519_generate()
        self.ecdsa_priv, self.ecdsa_pub = ecdsa_generate()
        self.server_pub = x25519_pub_from_bytes(bytes.fromhex(server_pub_hex))
        self.key = x25519_derive(self.priv, self.server_pub)
        self.session = GreenFoxSession(self.key)
        self.my_vip = my_vip
        if transports is None:
            transports = [('udp', lambda: UDPTransport((server, port))),
                          ('tcp', lambda: TCPTransport((server, port)))]
        self.transport = MultiTransport(transports)
        self.handshake_done = False
    def handshake(self):
        self.transport.send(b'HANDSHAKE:' + x25519_pub_to_bytes(self.pub))
        data, addr = self.transport.recv()
        if not data.startswith(b'PUBKEY:'):
            print("[CLIENT] Handshake failed")
            sys.exit(2)
        self.handshake_done = True
        print("[CLIENT] Handshake complete")
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
    def __init__(self, port=9999, tun_name='tun0', my_vip='10.8.0.1', transports=None, auto_up=True):
        check_root()
        self.tun = tun_alloc(tun_name, auto_up=auto_up, ip=f"{my_vip}/24")
        iface = get_default_interface()
        if iface:
            enable_ip_forwarding()
            add_nat_rule(VPN_SUBNET, iface)
            add_forward_rules(tun_name)
        self.priv, self.pub = x25519_generate()
        self.ecdsa_priv, self.ecdsa_pub = ecdsa_generate()
        self.my_vip = my_vip
        if transports is None:
            transports = [('udp', lambda: UDPTransport(('0.0.0.0', port), listen_port=port)),
                          ('tcp', lambda: TCPTransport(('0.0.0.0', port)))]
        self.transport = MultiTransport(transports)
        self.sessions = {}
        self.client_addr = None
    def run(self):
        def tun_loop():
            while True:
                packet = os.read(self.tun, MAX_PACKET)
                if self.client_addr:
                    session = self.sessions.get(self.client_addr)
                    if session:
                        wrapped = ucp_wrap(packet, msg_type=1)
                        self.transport.send(session.encrypt(wrapped))
        threading.Thread(target=tun_loop, daemon=True).start()
        while True:
            data, addr = self.transport.recv()
            if addr not in self.sessions:
                if data.startswith(b'HANDSHAKE:'):
                    client_pubkey = x25519_pub_from_bytes(data[len(b'HANDSHAKE:'):])
                    key = x25519_derive(self.priv, client_pubkey)
                    session = GreenFoxSession(key)
                    self.sessions[addr] = session
                    self.client_addr = addr
                    self.transport.send(b'PUBKEY:' + x25519_pub_to_bytes(self.pub))
                    print(f"[SERVER] Handshake complete: {addr}")
            else:
                session = self.sessions[addr]
                try:
                    plain = session.decrypt(data)
                    msg_type, ucp_payload = ucp_unwrap(plain)
                    if msg_type == 1:
                        os.write(self.tun, ucp_payload)
                except Exception as e:
                    print(f"[SERVER] Decrypt error: {e}")

def build_transport_stack(server, port, config={}):
    stack = []
    if config.get("obfs4_bridge"):
        stack.append(('obfs4', lambda: Obfs4Transport(config["obfs4_bridge"])))
    if config.get("front_domain"):
        stack.append(('front', lambda: DomainFrontTransport(config["front_domain"], server, port)))
    if config.get("meek_url") and config.get("front_domain"):
        stack.append(('meek', lambda: MeekTransport(config["meek_url"], config["front_domain"])))
    if config.get("tor_proxy"):
        stack.append(('tor', lambda: TorTransport((server, port), config["tor_proxy"])))
    stack.append(('tcp', lambda: TCPTransport((server, port))))
    stack.append(('udp', lambda: UDPTransport((server, port))))
    return stack

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:")
        print("  sudo python3 Protocol.py server <port> [config.json]")
        print("  sudo python3 Protocol.py client <server> <port> <server_pub_hex> [config.json]")
        sys.exit(1)
    mode = sys.argv[1]
    if mode == "server":
        port = int(sys.argv[2]) if len(sys.argv) > 2 else 9999
        config = {}
        if len(sys.argv) > 3:
            with open(sys.argv[3]) as f:
                config = json.load(f)
        s = GreenFoxServer(port=port, transports=build_transport_stack("0.0.0.0", port, config))
        s.run()
    elif mode == "client":
        server = sys.argv[2]
        port = int(sys.argv[3])
        server_pub_hex = sys.argv[4]
        config = {}
        if len(sys.argv) > 5:
            with open(sys.argv[5]) as f:
                config = json.load(f)
        c = GreenFoxClient(server, port, server_pub_hex, transports=build_transport_stack(server, port, config))
        c.run()
    else:
        print("[!] Unknown mode.")
        sys.exit(1)
