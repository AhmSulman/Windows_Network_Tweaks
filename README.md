<div align="center">

# 🔐 Encrypt_Adapters

### *Your network stack, on a leash — adapters, sockets, firewall, and privacy tweaks in one console.*

[![Platform](https://img.shields.io/badge/Platform-Windows-0078D4?style=for-the-badge&logo=windows)](https://www.microsoft.com/windows)
[![.NET](https://img.shields.io/badge/.NET-8.0-512BD4?style=for-the-badge&logo=dotnet)](https://dotnet.microsoft.com/)
[![Python](https://img.shields.io/badge/Python-3.x-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)

**Adapters · MAC · Sockets · Services · Edge/WebView · Firewall · Hosts · JSON exports**

</div>

---

## ✨ Why this repo?

Tired of juggling **netsh**, **Registry**, **firewall rules**, and **random MAC** scripts? **Encrypt_Adapters** wraps the messy Windows networking surface into a **single menu-driven tool** — with optional **Python** utilities for transport encryption and MAC workflows.

> ⚠️ **Run elevated.** Many features need **Administrator**. Use on **your own machines** only.

---

## 🚀 Quick start (C# — main app)

```bash
git clone https://github.com/YOUR_USERNAME/encrypt_adapters.git
cd encrypt_adapters
restore_packages.bat
dotnet run
```

Or build a release binary:

```bash
dotnet build -c Release
.\bin\Release\net8.0\EncryptAdapters.exe
```

---

## 🐍 Python (optional — `mainc.py`)

```bash
pip install -r requirements.txt
python mainc.py
```

Uses `cryptography` + optional `netaddr`. **Windows + Admin** recommended for adapter/registry features.

---

## 🧰 What’s inside?

| Area | What you get |
|------|----------------|
| **Adapters** | List Wi‑Fi / Ethernet, IPs, MAC randomization (registry + netsh) |
| **Sockets** | Connection data, listening ports, **JSON** export (`socket_metadata.json`, `socket_headers.json`) |
| **Protocols** | IANA-style port resolution, open web ports in browser, hosts-file blocks per protocol |
| **Services** | Revoke / restore RDP, Print Spooler, and other well-known services |
| **Edge / WebView** | See which remote hosts Edge & WebView2 talk to |
| **Firewall & OS** | Toggle firewall, block ports, flush DNS, DHCP release/renew, network profile, hosts file |
| **Encryption** | Transport-layer AES helpers in the C# app; Fernet-style flows in Python |

---

## 📦 Dependencies

**C# (`EncryptAdapters.csproj`)**

- `System.ServiceProcess.ServiceController`
- `System.Management`

**Python (`requirements.txt`)**

- `cryptography`
- `netaddr` (optional)

Restore NuGet: **`restore_packages.bat`** or `dotnet restore`.

---

## 🛡️ Disclaimer

This software can **change network configuration**, **firewall**, **services**, and **hosts**. You are responsible for compliance with local laws and policies. **No warranty.** Fork it, break it, fix it — but don’t blame us if you lock yourself out of RDP. 😅

---

## 🤝 Contributing

PRs welcome: docs, safer defaults, tests, or Linux/macOS stubs (today this is **Windows-first**).

---

## 📄 License

Specify your license here (e.g. MIT) — *add a `LICENSE` file when you publish.*

---

<div align="center">

**⭐ Star the repo if this saved you a Saturday afternoon of netsh pain.**

`encrypt_adapters` — *because `ipconfig /all` wasn’t enough.*

</div>
