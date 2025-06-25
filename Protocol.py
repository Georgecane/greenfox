import os
import fcntl
import struct
import socket
import sys
import threading
import random
import subprocess
import socks
import re
import shutil
import signal
import atexit
from collections import deque
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization

TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000
REPLAY_WINDOW = 1000
MAX_PACKET = 2048
MIN_PAD = 16
MAX_PAD = 128
VPN_SUBNET = '10.8.0.0/24'
DEFAULT_DNS = '8.8.8.8'
ORIG_ROUTE_FILE = "/tmp/greenfoxvpn_orig_route"
ORIG_RESOLV_FILE = "/tmp/greenfoxvpn_orig_resolv.conf"

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
        print(f"[+] Default outbound interface: {match.group(1)}")
        return match.group(1)
    print("[!] Could not find default outbound interface!")
    sys.exit(1)

def enable_ip_forwarding():
    result = sh("sysctl -n net.ipv4.ip_forward")
    if result.stdout.strip() != b"1":
        sh("sysctl -w net.ipv4.ip_forward=1")
        print("[+] Enabled IP forwarding.")
    else:
        print("[+] IP forwarding already enabled.")

def add_nat_rule(subnet, iface):
    check = f"iptables -t nat -C POSTROUTING -s {subnet} -o {iface} -j MASQUERADE"
    add = f"iptables -t nat -A POSTROUTING -s {subnet} -o {iface} -j MASQUERADE"
    ret = subprocess.run(check, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if ret.returncode != 0:
        subprocess.run(add, shell=True, check=True)
        print(f"[+] NAT masquerading enabled for {subnet} via {iface}")
    else:
        print(f"[+] NAT rule already exists for {subnet} via {iface}")

def add_forward_rules(tun):
    for direction in ['-i', '-o']:
        check = f"iptables -C FORWARD {direction} {tun} -j ACCEPT"
        add = f"iptables -A FORWARD {direction} {tun} -j ACCEPT"
        ret = subprocess.run(check, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if ret.returncode != 0:
            subprocess.run(add, shell=True, check=True)
            print(f"[+] FORWARD rule added for {direction} {tun}")
        else:
            print(f"[+] FORWARD rule already exists for {direction} {tun}")

def check_firewall_policy():
    result = sh("iptables -L FORWARD").stdout.decode()
    if "policy DROP" in result or "policy REJECT" in result:
        print("[!] Warning: FORWARD chain default policy is DROP/REJECT. VPN traffic may be blocked unless explicitly allowed.")
    else:
        print("[+] FORWARD chain default policy is ACCEPT.")

def save_default_route():
    try:
        result = sh("ip route | grep '^default '").stdout.decode().strip()
        if result:
            with open(ORIG_ROUTE_FILE, "w") as f:
                f.write(result + "\n")
            print("[*] Saved original default route.")
    except Exception as e:
        print(f"[!] Could not save default route: {e}")

def restore_default_route():
    try:
        if os.path.exists(ORIG_ROUTE_FILE):
            with open(ORIG_ROUTE_FILE, "r") as f:
                route = f.read().strip()
            # Remove all default routes
            sh("ip route del default || true")
            # Add the original default route back
            if route:
                # Example: default via 192.168.1.1 dev eth0
                sh(f"ip route add {route[8:]}")
                print("[*] Restored original default route.")
            os.remove(ORIG_ROUTE_FILE)
    except Exception as e:
        print(f"[!] Could not restore default route: {e}")

def save_resolv_conf():
    try:
        if os.path.exists("/etc/resolv.conf"):
            shutil.copy("/etc/resolv.conf", ORIG_RESOLV_FILE)
            print("[*] Saved original /etc/resolv.conf.")
    except Exception as e:
        print(f"[!] Could not save resolv.conf: {e}")

def restore_resolv_conf():
    try:
        if os.path.exists(ORIG_RESOLV_FILE):
            shutil.copy(ORIG_RESOLV_FILE, "/etc/resolv.conf")
            os.remove(ORIG_RESOLV_FILE)
            print("[*] Restored original /etc/resolv.conf.")
    except Exception as e:
        print(f"[!] Could not restore resolv.conf: {e}")

def set_default_route_via_tun(tun_name="tun1"):
    try:
        sh("ip route del default || true")
        sh(f"ip route add default dev {tun_name}")
        print(f"[*] Default route set via {tun_name}.")
    except Exception as e:
        print(f"[!] Could not set default route via {tun_name}: {e}")

def set_dns_linux(tun_dev="tun1", dns=DEFAULT_DNS):
    # Always overwrite /etc/resolv.conf as fallback or in addition
    try:
        with open("/etc/resolv.conf", "w") as f:
            f.write(f"nameserver {dns}\n")
        print(f"[DNS] Overwrote /etc/resolv.conf to use {dns}")
    except Exception as e:
        print(f"[DNS] Could not overwrite /etc/resolv.conf: {e}")

def cleanup_and_exit(signum=None, frame=None):
    print("[*] Cleaning up: restoring routes and DNS.")
    restore_default_route()
    restore_resolv_conf()
    sys.exit(0)

signal.signal(signal.SIGINT, cleanup_and_exit)
signal.signal(signal.SIGTERM, cleanup_and_exit)
atexit.register(cleanup_and_exit)

def check_client_route(tun_name="tun1"):
    result = sh("ip route").stdout.decode()
    if f"default dev {tun_name}" in result:
        print(f"[+] Default route is via {tun_name}")
    else:
        print(f"[!] Default route NOT via {tun_name}. Set with:\n sudo ip route add default dev {tun_name}")

def greenfox_vpn_auto_server_setup(tun_name='tun0'):
    check_root()
    print("[*] GreenFox VPN Server Environment Auto-Check")
    iface = get_default_interface()
    enable_ip_forwarding()
    add_nat_rule(VPN_SUBNET, iface)
    add_forward_rules(tun_name)
    check_firewall_policy()
    print("[*] Server environment is ready.")

def greenfox_vpn_auto_client_check(tun_name='tun1'):
    check_root()
    print("[*] Checking client routing table ...")
    check_client_route(tun_name)
    print("[*] Client environment checked.")

def tun_alloc(dev='tun0', auto_up=False, ip=None):
    print(f"[TUN] Attempting to allocate interface {dev} ...")
    if len(dev) > 15:
        print(f"[!] Device name '{dev}' too long (max 15 chars).")
        sys.exit(1)
    if not os.path.exists('/dev/net/tun'):
        print("[!] /dev/net/tun does not exist. Try: sudo modprobe tun")
        sys.exit(1)
    try:
        tun = os.open('/dev/net/tun', os.O_RDWR)
    except PermissionError:
        print("[!] Permission denied: /dev/net/tun. Are you root?")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Could not open /dev/net/tun: {e}")
        sys.exit(1)
    ifr = struct.pack('16sH', dev.encode(), IFF_TUN | IFF_NO_PI)
    try:
        fcntl.ioctl(tun, TUNSETIFF, ifr)
    except OSError as e:
        print(f"[!] TUN allocation for '{dev}' failed: {e}")
        if dev == "tun0":
            print("[!] Trying 'tun1' instead ...")
            return tun_alloc('tun1', auto_up, ip)
        else:
            print(f"[!] Both tun0 and tun1 failed. Try deleting any old tun devices:\n sudo ip link delete tun0\n sudo ip link delete tun1")
            sys.exit(1)
    print(f"[TUN] Successfully allocated {dev}")
    if auto_up and ip:
        try:
            subprocess.run(['ip', 'addr', 'add', ip, 'dev', dev], check=True)
            subprocess.run(['ip', 'link', 'set', dev, 'up'], check=True)
            print(f"[+] Brought up {dev} with IP {ip}")
        except Exception as ee:
            print(f"[!] Auto interface setup failed: {ee}")
    return tun

def x25519_generate():
    priv = X25519PrivateKey.generate()
    pub = priv.public_key()
    return priv, pub

def x25519_derive(priv, peer_pub):
    shared = priv.exchange(peer_pub)
    return SHA256.new(shared).digest() # 32 bytes for ChaCha20

def x25519_pub_to_bytes(pub):
    return pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

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

class GreenFoxTransport:
    def __init__(self, mode, remote_addr=None, tor_proxy='127.0.0.1', tor_port=9050, listen_port=None):
        self.mode = mode
        self.remote_addr = remote_addr
        if mode == 'udp':
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            if listen_port:
                self.sock.bind(('0.0.0.0', listen_port))
        elif mode == 'tcp-client':
            self.sock = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
            if tor_proxy and tor_proxy != 'none':
                self.sock.set_proxy(socks.SOCKS5, tor_proxy, tor_port)
            self.sock.connect(remote_addr)
            self.remote_addr = remote_addr
        elif mode == 'tcp-server':
            self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.listener.bind(('0.0.0.0', listen_port))
            self.listener.listen(1)
            print(f"[SERVER] Waiting for TCP tunnel connection on port {listen_port}...")
            self.sock, addr = self.listener.accept()
            self.remote_addr = addr
            print(f"[SERVER] TCP tunnel client connected from {addr}")
        else:
            raise ValueError("Invalid mode")
    def send(self, data):
        if self.mode == 'udp':
            self.sock.sendto(data, self.remote_addr)
        else:
            self.sock.sendall(len(data).to_bytes(2, 'big') + data)
    def recv(self, bufsize=4096):
        if self.mode == 'udp':
            data, addr = self.sock.recvfrom(bufsize)
            return data, addr
        else:
            l = b''
            while len(l) < 2:
                chunk = self.sock.recv(2 - len(l))
                if not chunk: raise ConnectionError("Disconnected")
                l += chunk
            length = int.from_bytes(l, 'big')
            d = b''
            while len(d) < length:
                chunk = self.sock.recv(length - len(d))
                if not chunk: raise ConnectionError("Disconnected")
                d += chunk
            return d, self.remote_addr
    def close(self):
        self.sock.close()
        if hasattr(self, 'listener'):
            self.listener.close()

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

class GreenFoxServer:
    def __init__(self, port=9999, tun_name='tun0', my_vip='10.8.0.1', mode='udp', tor_port=9998, auto_up=False):
        self.tun = tun_alloc(tun_name, auto_up=auto_up, ip=f"{my_vip}/24" if auto_up else None)
        if auto_up:
            greenfox_vpn_auto_server_setup(tun_name)
        self.priv, self.pub = x25519_generate()
        self.ecdsa_priv, self.ecdsa_pub = ecdsa_generate()
        self.sarp_table = {my_vip: (self.ecdsa_pub, None)}
        self.my_vip = my_vip
        print(f"[SERVER] VPN PubKey: {x25519_pub_to_bytes(self.pub).hex()}")
        print(f"[SERVER] SARP ECDSA PubKey: {self.ecdsa_pub.export_key(format='DER').hex()}")
        print(f"[SERVER] TUN {tun_name}.")
        if not auto_up:
            print(f" Setup: sudo ip addr add {my_vip}/24 dev {tun_name}; sudo ip link set {tun_name} up")
        self.sessions = {}
        self.client_addr = None
        if mode == 'udp':
            self.transport = GreenFoxTransport('udp', listen_port=port)
        else:
            self.transport = GreenFoxTransport('tcp-server', listen_port=tor_port)
    def send_sarp_announce(self, addr):
        msg = self.my_vip.encode()
        h = SHA256.new(msg)
        signer = DSS.new(self.ecdsa_priv, 'fips-186-3')
        sig = signer.sign(h)
        vpn_pubkey = x25519_pub_to_bytes(self.pub)
        sarp_packet = b'SARP:' + self.my_vip.encode() + b':' + self.ecdsa_pub.export_key(format='DER').hex().encode() + b':' + sig.hex().encode() + b':' + vpn_pubkey.hex().encode()
        self.transport.send(sarp_packet)
    def tun_read_loop(self):
        while True:
            try:
                packet = os.read(self.tun, MAX_PACKET)
            except Exception as e:
                print(f"[SERVER] TUN read error: {e}")
                continue
            session = self.sessions.get(self.client_addr)
            if not session: continue
            wrapped = ucp_wrap(packet, msg_type=1)
            try:
                self.transport.send(session.encrypt(wrapped))
            except Exception as e:
                print(f"[SERVER] Send error: {e}")
    def handle_sarp(self, data, addr):
        try:
            parts = data.split(b':', 4)
            if len(parts) < 5:
                print(f"[SARP] Malformed SARP packet")
                return
            _, vip, pubder_hex, sig_hex, vpn_pubkey_hex = parts
            pubder = bytes.fromhex(pubder_hex.decode())
            sig = bytes.fromhex(sig_hex.decode())
            vpn_pubkey = bytes.fromhex(vpn_pubkey_hex.decode())
            expected_vpn_pubkey = x25519_pub_to_bytes(self.pub)
            if vpn_pubkey != expected_vpn_pubkey:
                print(f"[SARP] VPN PubKey mismatch, rejecting SARP.")
                return
            pub = ECC.import_key(pubder)
            h = SHA256.new(vip)
            verifier = DSS.new(pub, 'fips-186-3')
            verifier.verify(h, sig)
            if addr is not None:
                self.sarp_table[vip.decode()] = (pub, addr)
                print(f"[SARP] Registered peer VIP {vip.decode()} at {addr}")
            else:
                print(f"[SARP] Warning: received SARP from unknown address!")
        except Exception as e:
            print(f"[SARP] SARP verify failed: {e}")
    def run(self):
        threading.Thread(target=self.tun_read_loop, daemon=True).start()
        while True:
            data, addr = self.transport.recv()
            if data.startswith(b'SARP:'):
                self.handle_sarp(data, addr)
                continue
            if addr not in self.sessions:
                if data.startswith(b'HANDSHAKE:'):
                    client_pubkey = x25519_pub_from_bytes(data[len(b'HANDSHAKE:'):])
                    key = x25519_derive(self.priv, client_pubkey)
                    session = GreenFoxSession(key)
                    self.sessions[addr] = session
                    self.client_addr = addr
                    self.transport.remote_addr = addr
                    self.transport.send(b'PUBKEY:' + x25519_pub_to_bytes(self.pub))
                    print(f"[SERVER] Handshake complete: {addr}")
                    self.send_sarp_announce(addr)
            else:
                session = self.sessions[addr]
                try:
                    plain = session.decrypt(data)
                    msg_type, ucp_payload = ucp_unwrap(plain)
                    if msg_type == 1:
                        os.write(self.tun, ucp_payload)
                except Exception as e:
                    print(f"[SERVER] Decrypt error: {e}")

class GreenFoxClient:
    def __init__(self, host, port, server_pub_hex, my_vip='10.8.0.2', tun_name='tun1', mode='udp', tor_proxy='127.0.0.1', tor_port=9050, tor_remote_port=9998, auto_up=False):
        self.tun = tun_alloc(tun_name, auto_up=auto_up, ip=f"{my_vip}/24" if auto_up else None)
        if auto_up:
            greenfox_vpn_auto_client_check(tun_name)
            save_default_route()
            save_resolv_conf()
            set_default_route_via_tun(tun_name)
            set_dns_linux(tun_name)
        self.priv, self.pub = x25519_generate()
        self.ecdsa_priv, self.ecdsa_pub = ecdsa_generate()
        self.server_pub = x25519_pub_from_bytes(bytes.fromhex(server_pub_hex))
        self.key = x25519_derive(self.priv, self.server_pub)
        self.handshake_done = False
        self.my_vip = my_vip
        self.sarp_table = {my_vip: (self.ecdsa_pub, None)}
        self.session = GreenFoxSession(self.key)
        print(f"[CLIENT] TUN {tun_name}.")
        if not auto_up:
            print(f" Setup: sudo ip addr add {my_vip}/24 dev {tun_name}; sudo ip link set {tun_name} up")
        print(f"[CLIENT] SARP ECDSA PubKey: {self.ecdsa_pub.export_key(format='DER').hex()}")
        if mode == 'udp':
            self.transport = GreenFoxTransport('udp', remote_addr=(host, port))
        elif mode == 'tor':
            self.transport = GreenFoxTransport('tcp-client', remote_addr=(host, tor_remote_port), tor_proxy='127.0.0.1', tor_port=tor_port)
        elif mode == 'tcp':
            self.transport = GreenFoxTransport('tcp-client', remote_addr=(host, port), tor_proxy='none')
        else:
            raise ValueError("Invalid mode for client (choose udp, tcp, or tor)")
    def send_sarp_announce(self):
        msg = self.my_vip.encode()
        h = SHA256.new(msg)
        signer = DSS.new(self.ecdsa_priv, 'fips-186-3')
        sig = signer.sign(h)
        vpn_pubkey = x25519_pub_to_bytes(self.server_pub)
        sarp_packet = b'SARP:' + self.my_vip.encode() + b':' + self.ecdsa_pub.export_key(format='DER').hex().encode() + b':' + sig.hex().encode() + b':' + vpn_pubkey.hex().encode()
        self.transport.send(sarp_packet)
    def tun_read_loop(self):
        while True:
            try:
                packet = os.read(self.tun, MAX_PACKET)
            except Exception as e:
                print(f"[CLIENT] TUN read error: {e}")
                continue
            wrapped = ucp_wrap(packet, msg_type=1)
            try:
                self.transport.send(self.session.encrypt(wrapped))
            except Exception as e:
                print(f"[CLIENT] Send error: {e}")
    def handle_sarp(self, data, addr):
        try:
            parts = data.split(b':', 4)
            if len(parts) < 5:
                print(f"[CLIENT] Malformed SARP packet")
                return
            _, vip, pubder_hex, sig_hex, vpn_pubkey_hex = parts
            pubder = bytes.fromhex(pubder_hex.decode())
            sig = bytes.fromhex(sig_hex.decode())
            vpn_pubkey = bytes.fromhex(vpn_pubkey_hex.decode())
            expected_vpn_pubkey = x25519_pub_to_bytes(self.server_pub)
            if vpn_pubkey != expected_vpn_pubkey:
                print(f"[CLIENT] SARP VPN PubKey mismatch, rejecting SARP.")
                return
            pub = ECC.import_key(pubder)
            h = SHA256.new(vip)
            verifier = DSS.new(pub, 'fips-186-3')
            verifier.verify(h, sig)
            if addr is not None:
                self.sarp_table[vip.decode()] = (pub, addr)
                print(f"[CLIENT] Registered peer VIP {vip.decode()} at {addr}")
            else:
                print(f"[CLIENT] Warning: received SARP from unknown address!")
        except Exception as e:
            print(f"[CLIENT] SARP verify failed: {e}")
    def handshake(self):
        self.transport.send(b'HANDSHAKE:' + x25519_pub_to_bytes(self.pub))
        data, addr = self.transport.recv()
        if not data.startswith(b'PUBKEY:'):
            print("[CLIENT] Handshake failed")
            sys.exit(2)
        self.handshake_done = True
        self.send_sarp_announce()
    def run(self):
        if not self.handshake_done:
            self.handshake()
        threading.Thread(target=self.tun_read_loop, daemon=True).start()
        while True:
            data, addr = self.transport.recv()
            if data.startswith(b'SARP:'):
                self.handle_sarp(data, addr)
                continue
            try:
                plain = self.session.decrypt(data)
                msg_type, ucp_payload = ucp_unwrap(plain)
                if msg_type == 1:
                    os.write(self.tun, ucp_payload)
            except Exception as e:
                print(f"[CLIENT] Decrypt error: {e}")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[!] This script must be run as root (use sudo).")
        sys.exit(1)
    if len(sys.argv) < 2:
        print("""
GreenFox VPN - Protocol.py
Usage:
  sudo python3 Protocol.py server [udp|tor] [auto]
  sudo python3 Protocol.py client <server_ip> <server_port> <server_pub_hex> [udp|tcp|tor] [auto]

Examples:
  sudo python3 Protocol.py server udp auto
  sudo python3 Protocol.py server tor auto
  sudo python3 Protocol.py client 1.2.3.4 9999 <server_pub_hex> udp auto
  sudo python3 Protocol.py client 1.2.3.4 9998 <server_pub_hex> tcp auto
  sudo python3 Protocol.py client abcd1234.onion 9998 <server_pub_hex> tor auto

If you omit 'auto', bring up the TUN interface in another terminal:
  sudo ip addr add 10.8.0.1/24 dev tun0; sudo ip link set tun0 up
  sudo ip addr add 10.8.0.2/24 dev tun1; sudo ip link set tun1 up

To use Tor, start tor and use 'tor' instead of 'udp' or 'tcp' mode.
""")
        sys.exit(1)
    if sys.argv[1] == "server":
        mode = sys.argv[2] if len(sys.argv) > 2 else 'udp'
        auto = (len(sys.argv) > 3 and sys.argv[3] == "auto")
        GreenFoxServer(mode=mode, auto_up=auto).run()
    elif sys.argv[1] == "client":
        _, _, ip, port, server_pub_hex, *rest = sys.argv
        mode = rest[0] if rest else 'udp'
        auto = (len(rest) > 1 and rest[1] == "auto")
        GreenFoxClient(ip, int(port), server_pub_hex, mode=mode, auto_up=auto).run()
