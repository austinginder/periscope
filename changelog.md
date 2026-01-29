# Changelog

## [1.4.1] - 2026-01-28

### Added

- **Auto-Detect Local Bridge** - When visiting `periscope.run` (without `?local=true`), the app now automatically detects if the Local Bridge is running and seamlessly switches to local mode using `pushState` for a smooth transition.
- **Redirect Chain Tooltips** - Hovering over any hop in the redirect chain now shows a detailed tooltip with the full URL and server IP address.
- **Smart Redirect Display** - When consecutive redirect hops share the same hostname, the path is shown instead (e.g., `//` → `/`) to clarify what changed. Useful for identifying path normalization redirects.
- **Scan Log Auto-Select** - Opening the Scan Log (`Cmd+K`) while viewing a scan now auto-selects and scrolls to that scan, enabling quick navigation with arrow keys.
- **Scan Log Pagination Persistence** - The number of items loaded via "Load more" is now preserved when reopening the Scan Log.
- **Cloudflare Custom Hostname Detection** - Added `_cf-custom-hostname` TXT record to DNS checks.

### Fixed

- **JavaScript Redirect False Positives** - Fixed detection matching HTML attributes like `data-accordion-location="10"` as JavaScript redirects. Now requires `window.location` or `location.href` patterns specifically.
- **ads.txt/app-ads.txt False Positives** - Fixed detection accepting HTML 404 error pages as valid ads.txt files. Now validates that the response is not HTML.
- **HTTP→HTTPS Redirect Noise** - Simple protocol upgrades (http→https of the same host) are now filtered from the redirect chain display to reduce noise.

### Changed

- **Logo Click Behavior** - Clicking the Periscope logo now uses `pushState` to smoothly reset the view and update the URL (removing the `domain` parameter) without a page reload.
- **Cache Version Matching** - Patch versions are now ignored when validating cached scans. A v1.4 cache is considered valid for v1.4.1, preventing unnecessary reprocessing on patch releases. Only minor version changes (e.g., 1.4 → 1.5) trigger cache regeneration.
- **Pre-Connection UI** - The domain input, scan button, and scan log icon are now hidden until the Local Bridge connection is established, providing a cleaner loading state.

### Documentation

- **Versioning & Cache Upgrades** - Added new section to README explaining semantic versioning policy and cache validity rules.

## [1.4.0] - 2026-01-26

### Added

- **Response Info Bar** - New UI bar displaying HTTP status code (color-coded), protocol version (HTTP/1.1, HTTP/2), server IP address, and response timing with interactive breakdown tooltip showing DNS lookup, connect, and total time.
- **Server-Side Language Detection** - Identifies backend languages and frameworks via `X-Powered-By` and `Server` headers. Supports PHP, ASP.NET, Node.js (Express/Next.js), Python (Django/Flask/Gunicorn/Uvicorn), Ruby (Rails/Puma/Passenger), Java (Servlet/JSP), Go, and Rust.
- **HTML Report Export** - Export any scan as a self-contained HTML report with embedded styles. Available via the Export button in the UI or `?action=export_report&domain=X&timestamp=Y` API endpoint.
- **Indexability Filter** - Filter the scan log by search engine visibility (Indexable / Hidden from Search).
- **Domain Autocomplete** - Type-ahead suggestions from scan history when entering domains.
- **CLI Bulk Upgrade** - New command `php ~/.periscope/engine.php action=bulk_upgrade` to batch upgrade all historical scans to the latest cache format.
- **Database Filters Column** - Structured JSON filters column for faster history queries. Stores indexed fields: existence, platform, host, CDN, SSL issuer, HTTP status, IPv6 support, and more.
- **Debug Mode** - New `--debug` flag for `boot.sh` enables verbose PHP error output. Use `./boot.sh --local --debug` to diagnose 500 errors.
- **HTML Redirect Detection** - Detects and follows meta refresh and JavaScript redirects (`window.location`, `location.replace`) that occur after HTTP 200 responses. The scanner now fetches content from the final destination, analyzing the actual target site. Displayed in redirect chain with purple "META" or yellow "JS" badges.

### Fixed

- **Database Locking** - Enabled SQLite WAL (Write-Ahead Logging) mode and busy timeout to prevent "database is locked" errors when running CLI bulk operations and UI scans simultaneously.
- **Image Download Memory Safety** - Rewrote `downloadImage` to use cURL with a progress callback that aborts transfers exceeding the size limit mid-stream, preventing potential OOM crashes from malicious oversized responses.

### Changed

- **Engine Extraction** - Separated `engine.php` from `boot.sh` for easier development and debugging. The boot script now downloads the engine separately.
- **Connection Info Persistence** - HTTP timing, protocol version, and remote address are now saved to `redirects.json` raw files, preserving this data across cache regenerations.
- **Smart Cache Migration** - When upgrading old scans, timing/protocol/remote_address data is automatically backfilled from existing `response.json` to `redirects.json` before regeneration, preventing data loss.
- **Filters Backfill** - Opening legacy v1.3 scans automatically populates the filters column for improved search performance.

## [1.3.0] - 2026-01-24

### Added

- **Email Health Grading** - Automatic scoring (A-F) of email infrastructure security. Analyzes MX redundancy, SPF strictness, DKIM presence, and DMARC policies with actionable recommendations.
- **SPF Visualizer** - Deep analysis of Sender Policy Framework records. Breaks down mechanisms, identifies third-party providers, checks qualifiers, and counts DNS lookups against the RFC limit of 10.
- **Reverse DNS Verification** - Performs Forward-Confirmed Reverse DNS (FCrDNS) checks on resolved IP addresses to validate server identity (PTR record matching).
- **Advanced History Filtering** - Filter the scan log by Domain Existence, detected Platform (CMS), and Scan Frequency.
- **Expanded DKIM Detection** - Added signatures for 50+ major email providers including Google Workspace, Microsoft 365, SendGrid, Mailchimp, Postmark, and Zendesk.

### Changed

- **Engine Architecture** - Unified the DNS lookup logic into a single robust pipeline for both CLI and Web interfaces, improving consistency.
- **Cache System** - Implemented background cache regeneration to seamlessly upgrade legacy scan data to the latest format without blocking the UI.

## [1.2.0] - 2026-01-22

### Added

- **Real-time Scan Progress** - Implemented Server-Sent Events (SSE) to stream scan status updates and a visual progress bar to the UI.
- **Subdomain Intelligence** - Smart differentiation between root domains and subdomains. Now scans specific subdomain records while preserving root-level context (Email, Auth, etc.).
- **WordPress Deep Dive** - Automatically detects installed plugins, Multisite configurations, and Multi-tenant setups (WP Freighter).
- **Visual Metadata Previews** - View Open Graph images, Twitter Cards, and Favicons directly in the app. Images are downloaded and stored locally for privacy.
- **Input Normalization** - Smart parsing allows pasting full URLs (e.g., `https://example.com/page`), automatically stripping protocols and paths.
- **Raw Metadata Viewers** - Direct previews for stored `robots.txt`, `sitemap.xml`, and `security.txt` files.

### Changed

- **DNS Engine** - Optimized resolution logic to handle wildcard records on root domains more gracefully.
- **Favicon Detection** - Enhanced algorithm to find the highest resolution icons, including `apple-touch-icon`.
- **Storage** - Implemented content-addressable storage (hashing) for captured images to reduce duplication.

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