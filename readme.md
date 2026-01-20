# Periscope 🔭

**Peer into any domain.**

Periscope is a sophisticated DNS and Network diagnostic tool. It combines a beautiful web interface (`https://periscope.run`) with a **Local Bridge** running on your machine. This allows the web UI to securely execute local system tools like `dig`, `whois`, and `curl` to gather deep intelligence on domains without rate limits or proxy restrictions.

![](screenshot-1.webp)

## 🚀 Quick Start

To start Periscope, simply run the bootstrapper. This will set up the environment, start the local bridge, and open the interface in your browser.

```bash
curl -sL https://periscope.run/boot.sh | bash
```

*This command installs necessary dependencies (PHP, dig, whois) if missing, sets up the local API engine, and connects it to the web UI.*

## ✨ Features

*   **Deep DNS Scanning:** Checks A, MX, NS, SOA, TXT, SRV, and CNAME records.
*   **Intelligent Analysis:** Automatically flattens CNAME chains and detects modern email security standards (MTA-STS, BIMI, DKIM).
*   **Zone File Generation:** Exports discovered records into a valid BIND Zone file.
*   **Network Coordinates:** Resolves IP addresses to their hosting providers/organizations.
*   **History & Snapshots:** Saves every lookup to a local SQLite database. Compare current DNS states against previous versions.
*   **CLI Mode:** Run quick diagnostics directly from your terminal.

## 🛠️ How it Works

Periscope uses a **Local Bridge** architecture:

1.  **The Interface:** Hosted at `https://periscope.run`. It provides the visualization and user experience.
2.  **The Engine:** A lightweight PHP script running locally on your machine (default port `8989`).
3.  **The Connection:** The Interface sends requests to `http://127.0.0.1:8989`. The Engine executes system commands (`dig`, `whois`) and returns structured JSON.

**Data Privacy:** All history and scan data are stored locally in `~/.periscope/history.db`. No scan data is sent to external servers.

## 📦 Manual Installation & Requirements

If you prefer not to use the auto-bootstrapper, you can run Periscope manually.

### Requirements
*   **OS:** macOS, Linux, or Windows (via WSL).
*   **PHP:** 8.0+ (with `php-curl`, `php-sqlite3`, `php-cli`).
*   **Tools:** `dig` (dnsutils/bind), `whois`, `curl`, `unzip`.

### Running from Source

```bash
# 1. Clone the repository
git clone https://github.com/austinginder/periscope.git
cd periscope

# 2. Run the boot script
./boot.sh
```

## 💻 CLI Usage

Once installed, you can use the underlying engine directly from your terminal for quick, headless scans.

```bash
# Standard lookup
php ~/.periscope/engine.php google.com

# Output
# Looking up domain: google.com...
# --- Summary for google.com ---
# Registrar:     MarkMonitor, Inc.
# IP Addresses:  142.250.190.46
# ---------------------------
# Full report saved to local database.
```

## 📸 Screenshots

| Domain Overview | DNS Records |
| :---: | :---: |
| ![](screenshot-2.webp) | ![](screenshot-3.webp) |

## 🤝 Contributing

Periscope is open source. Pull requests are welcome for new DNS record types, UI improvements, or better OS compatibility for the bootstrapper.

## License

MIT