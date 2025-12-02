# greenfox

The Green Fox VPN protocol is a secure, fast, open-source, and free technology designed to protect privacy and data security on public networks using advanced encryption and decentralized technologies.

## 🦊 Features

### Core VPN Features
- **X25519 Key Exchange** - Modern elliptic curve cryptography
- **ChaCha20-Poly1305** - Fast, authenticated encryption
- **TLS/WebSocket Camouflage** - Evades Deep Packet Inspection (DPI)
- **Anti-Censorship** - Designed to bypass Iran's Antigravity blocking
- **Serverless Compatible** - Works on standard HTTP/HTTPS ports
- **UDP Fallback** - Direct UDP transport when TCP blocked

### 🔒 Leak Prevention (v3.0+)

**Complete DNS & IP leak prevention:**

- ✅ **DNS Leak Protection** - All DNS queries forced through VPN tunnel only
- ✅ **IPv4 IP Leak Prevention** - Strict killswitch blocks non-VPN traffic
- ✅ **IPv6 Leak Prevention** - IPv6 completely disabled
- ✅ **WebRTC Leak Prevention** - STUN/TURN servers blocked
- ✅ **DNS Rebinding Protection** - Private IP resolution blocked
- ✅ **Split-Tunnel Prevention** - Impossible to bypass VPN
- ✅ **Leak Detection Tests** - Built-in verification system

**Run leak tests:**
```bash
python3 Protocol.py test-leaks
```

See **SECURITY_LEAKS_PREVENTION.md** for complete leak prevention documentation.

## 🚀 Quick Start

### Server
```bash
sudo python3 Protocol.py server --port 443 --tun tun0
```

### Client
```bash
# Get server public key first (printed when server starts)
sudo python Protocol.py client <SERVER_IP> <SERVER_PUB_HEX> --port 443

# With certificate pinning (optional):
sudo python Protocol.py client <SERVER_IP> <SERVER_PUB_HEX> --cert-pin <SHA256_HASH>
```

## 📋 Requirements

```
pycryptodome
paramiko
pysocks
cryptography
requests
dnspython
pyflakes
```

Install: `pip install -r requirements.txt`
