# Changelog

## [1.1.0] - 2026-01-21

### Added

- **Deep Content Analysis** - Automatically detects CMS platforms (WordPress, Shopify, Wix), JavaScript frameworks (React, Vue, Next.js), and Analytics tools.
- **Infrastructure Detection** - Identifies hosting providers (Kinsta, Vercel, AWS) and CDNs (Cloudflare, Fastly) via HTTP header fingerprinting.
- **SSL/TLS Inspection** - Displays certificate issuer, validity status, and a countdown to expiration.
- **Security Header Grading** - Analyzes and scores security headers including HSTS, CSP, X-Frame-Options, and Permissions-Policy.
- **Metadata Explorer** - Checks for the presence and content of `robots.txt`, `sitemap.xml`, `security.txt`, Open Graph tags, and calculates favicon hashes.
- **Expanded DNS Scanning** - Added support for `CAA`, `HTTPS`, `SVCB`, and `TLSA` records, along with a vastly expanded list of common subdomains (staging, dev, admin, etc.).
- **Raw Data Storage** - Scans now save full raw outputs (HTML, WHOIS, Headers, SSL) to the local filesystem (`~/.periscope/scans`) for forensic review.
- **History Search & Pagination** - Added search functionality to the scan log and implemented pagination for better performance with large histories.
- **Deep Linking** - Support for direct domain linking via URL parameters (e.g., `?domain=example.com`).
- **Local Development Mode** - Added `--local` flag to `boot.sh` to serve the UI from the local filesystem instead of fetching from GitHub.

### Changed

- **Storage Architecture** - Migrated from storing full JSON blobs in SQLite to a hybrid approach: metadata in SQLite and raw scan data on the filesystem to reduce database bloat.
- **Boot Script** - Improved browser launch logic to wait for the local PHP server to be fully responsive before opening the window.

## [1.0.0] - 2026-01-20

### Added

- **Local Bridge Architecture** - One-line install script (`curl -sL https://periscope.run/boot.sh | bash`) that sets up everything automatically
- **Automatic Dependency Installation** - Detects and installs missing tools (php, dig, whois, curl, unzip) on macOS (Homebrew) and Linux (apt)
- **Badcow/DNS Library Integration** - Automatically downloads and sideloads the Badcow DNS library for zone file generation
- **RDAP Support** - Modern RDAP protocol for WHOIS lookups with fallback to traditional whois command
- **DNS Record Discovery** - Scans common subdomains and record types (A, AAAA, MX, NS, SOA, TXT, CNAME)
- **BIND Zone File Export** - Generate and download RFC-compliant zone files with proper TXT record chunking
- **IP Geolocation** - Reverse lookup of IP addresses to identify hosting providers
- **HTTP Header Analysis** - Fetch and display server response headers
- **History System** - SQLite-backed scan history with localStorage fallback for web-only mode
- **Snapshot Versioning** - View and compare historical scans of the same domain
- **Import/Export** - Backup and restore scan history as JSON
- **Dark Mode** - System-aware theme with manual toggle
- **Keyboard Navigation** - Arrow keys for snapshot selection, `/` to focus search, `Escape` to close modals
- **Context Menus** - Right-click on values to dig, whois, or copy
- **CLI Mode** - Run lookups from terminal: `php ~/.periscope/engine.php domain.com`
- **Web UI** - Modern Vue 3 + Tailwind CSS interface with responsive design

### Technical Details

- Self-contained PHP engine embedded in boot script
- No Composer required - manual PSR-4 autoloader for Badcow/DNS
- SQLite database stored at `~/.periscope/history.db`
- CORS-enabled API for cross-origin requests
- Prism.js syntax highlighting for zone files