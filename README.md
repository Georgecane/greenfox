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

### 🌐 Decentralized P2P Mode (v4.0+ - NEW!)

**Ethereum testnet-powered decentralized VPN:**

- ✅ **No Central Server** - Nodes discovered via blockchain
- ✅ **Trustless Network** - Transparent node reputation on-chain
- ✅ **Censorship Resistant** - Can't be blocked or shut down
- ✅ **P2P Architecture** - Anyone can run a node instantly
- ✅ **Completely Legal** - Uses free testnet (no real money)

## 🚀 Quick Start

### Traditional Centralized Mode

**Start Server:**
```bash
sudo python Protocol.py server --port 443 --tun tun0
```

**Connect as Client:**
```bash
sudo python Protocol.py client <SERVER_IP> <SERVER_PUB_HEX> --port 443
```

### Decentralized P2P Mode (NEW!)

**Run a VPN Node (auto-registers on blockchain):**
```bash
sudo python Protocol.py server
```

**Connect as Decentralized Client (auto-discovers nodes):**
```bash
sudo python Protocol.py client-decentralized
```

**List Available Nodes:**
```bash
python Protocol.py discover-nodes
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
web3              # For decentralized P2P mode
eth-account       # For Ethereum integration
```

Install: `pip install -r requirements.txt`

## 🔐 Features

- ✅ Strong encryption (X25519 + ChaCha20-Poly1305)
- ✅ DPI evasion (TLS + WebSocket camouflage)
- ✅ Anti-censorship (Antigravity bypass)
- ✅ Complete leak prevention (DNS, IPv6, WebRTC)
- ✅ Decentralized P2P mode (blockchain-powered)
- ✅ Node reputation system
- ✅ 100% legal (testnet-based)
- ✅ Open source & transparent
