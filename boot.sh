#!/bin/bash

# --- Configuration ---
PERISCOPE_DIR="$HOME/.periscope"
LIB_DIR="$PERISCOPE_DIR/lib"
DB_FILE="$PERISCOPE_DIR/history.db"
ENGINE_FILE="$PERISCOPE_DIR/engine.php"
HTML_FILE="$PERISCOPE_DIR/index.html"
LOGO_FILE="$PERISCOPE_DIR/Periscope.webp"
ROUTER_FILE="$PERISCOPE_DIR/router.php"
PORT=8989

# Release Base URL (Ensure engine.php and index.html are attached to your GitHub Releases)
REPO_URL="https://github.com/austinginder/periscope"
DOWNLOAD_URL="$REPO_URL/releases/latest/download"
RAW_URL="https://raw.githubusercontent.com/austinginder/periscope/refs/heads/main"

# --- Args ---
LOCAL_MODE=false
DEBUG_MODE=false
for arg in "$@"; do
    case "$arg" in
        --local) LOCAL_MODE=true ;;
        --debug) DEBUG_MODE=true ;;
    esac
done

# --- Colors ---
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}----------------------------------------------------------------${NC}"
echo -e "${BLUE}🔭 Periscope Local Bridge${NC}"
echo -e "${BLUE}----------------------------------------------------------------${NC}"

# --- Dependency Manager ---
install_missing_tools() {
    local missing_tools=()
    local apt_packages=()
    local brew_packages=()
    
    for tool in php dig whois curl unzip; do
        if ! command -v $tool &> /dev/null; then missing_tools+=("$tool"); fi
    done
    
    if command -v php &> /dev/null; then
        if ! php -r "exit(function_exists('curl_init') ? 0 : 1);" 2>/dev/null; then missing_tools+=("php-curl"); apt_packages+=("php-curl"); fi
        if ! php -r "exit(class_exists('SQLite3') ? 0 : 1);" 2>/dev/null; then missing_tools+=("php-sqlite3"); apt_packages+=("php-sqlite3"); fi
    fi

    if [[ " ${missing_tools[*]} " =~ " php " ]]; then apt_packages+=("php-cli" "php-sqlite3" "php-curl"); brew_packages+=("php"); fi
    if [[ " ${missing_tools[*]} " =~ " dig " ]]; then apt_packages+=("dnsutils"); brew_packages+=("bind"); fi
    if [[ " ${missing_tools[*]} " =~ " whois " ]]; then apt_packages+=("whois"); brew_packages+=("whois"); fi
    if [[ " ${missing_tools[*]} " =~ " curl " ]]; then apt_packages+=("curl"); brew_packages+=("curl"); fi
    if [[ " ${missing_tools[*]} " =~ " unzip " ]]; then apt_packages+=("unzip"); brew_packages+=("unzip"); fi

    if [ ${#missing_tools[@]} -eq 0 ]; then return 0; fi

    echo -e "${RED}❌ Missing required tools: ${missing_tools[*]}${NC}"

    if command -v apt-get &> /dev/null; then
        if ! command -v sudo &> /dev/null; then echo "${RED}❌ Sudo required.${NC}"; exit 1; fi
        sudo apt-get update -qq && sudo apt-get install -y "${apt_packages[@]}"
        echo -e "${GREEN}✅ Linux tools installed.${NC}\n"
        return 0
    fi

    if [[ "$OSTYPE" == "darwin"* ]]; then
        if ! command -v brew &> /dev/null; then echo "🍎 Homebrew missing."; exit 1; fi
        for pkg in "${brew_packages[@]}"; do brew install "$pkg"; done
        echo -e "${GREEN}✅ macOS tools installed.${NC}\n"
        return 0
    fi
    
    echo "⚠️  Manual install required: ${missing_tools[*]}"
    exit 1
}

install_missing_tools

# --- Library Manager ---
setup_libraries() {
    if [ -f "$LIB_DIR/Badcow/DNS/lib/Zone.php" ]; then return 0; fi
    echo -e "${BLUE}📦 Downloading Badcow/DNS Library...${NC}"
    mkdir -p "$LIB_DIR"
    LATEST_URL=$(curl -sL -o /dev/null -w '%{url_effective}' https://github.com/Badcow/DNS/releases/latest)
    VERSION=${LATEST_URL##*/v}
    curl -sL "https://github.com/Badcow/DNS/archive/refs/tags/v${VERSION}.zip" -o "$LIB_DIR/dns.zip"
    unzip -q -o "$LIB_DIR/dns.zip" -d "$LIB_DIR"
    mkdir -p "$LIB_DIR/Badcow"
    rm -rf "$LIB_DIR/Badcow/DNS" 2>/dev/null
    mv "$LIB_DIR/DNS-$VERSION" "$LIB_DIR/Badcow/DNS"
    rm "$LIB_DIR/dns.zip"
    echo -e "${GREEN}✅ Library installed.${NC}\n"
}

setup_libraries

# --- Component Manager (Engine, Frontend, Images) ---
# Args: target_path, local_filename, remote_url, component_name
update_component() {
    local target="$1"
    local filename="$2"
    local url="$3"
    local name="$4"

    mkdir -p "$(dirname "$target")"

    if [ "$LOCAL_MODE" = true ]; then
        # Local Mode: Copy from script directory
        SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
        if [ -f "$SCRIPT_DIR/$filename" ]; then
            cp "$SCRIPT_DIR/$filename" "$target"
            echo -e "${GREEN}✅ Using local $name${NC}"
        else
            echo -e "${RED}❌ Local $filename not found in $SCRIPT_DIR${NC}"
            # Don't exit here, might be an image we don't have locally
        fi
    else
        # Production Mode: Download
        # Only download if missing OR if it's the Core Engine (always check for updates)
        if [ ! -f "$target" ] || [ "$filename" == "engine.php" ]; then
            echo -e "${BLUE}⬇️  Updating $name...${NC}"
            HTTP_STATUS=$(curl -sL -w "%{http_code}" -o "$target.tmp" "$url")
            if [ "$HTTP_STATUS" -eq 200 ]; then
                mv "$target.tmp" "$target"
                echo -e "${GREEN}✅ $name updated.${NC}"
            else
                rm -f "$target.tmp"
                # If file doesn't exist at all, we can't proceed for critical files
                if [ ! -f "$target" ] && [ "$filename" == "engine.php" ]; then
                    echo -e "${RED}❌ Failed to download $name. Check internet connection.${NC}"
                    exit 1
                fi
            fi
        fi
    fi
}

# 1. Update Engine (Core Logic)
update_component "$ENGINE_FILE" "engine.php" "$DOWNLOAD_URL/engine.php" "Engine"

# 2. Update Frontend (HTML)
update_component "$HTML_FILE" "index.html" "$DOWNLOAD_URL/index.html" "Frontend"

# 3. Update Logo (Image)
update_component "$LOGO_FILE" "Periscope.webp" "$RAW_URL/Periscope.webp" "Logo"

# --- Create Router (Embedded) ---
# We keep this embedded as it is small and acts as the "glue"
cat << 'ROUTER_EOF' > "$ROUTER_FILE"
<?php
// Router for PHP built-in server
$path = parse_url($_SERVER["REQUEST_URI"], PHP_URL_PATH);
$query = $_SERVER['QUERY_STRING'] ?? '';

// Serve Index when:
// 1. Explicitly requesting /index.html
// 2. Root path with no query params
// 3. Root path with local=true (deep linking support - may have &domain=xxx)
if ($path === '/index.html' || ($path === '/' && (empty($query) || strpos($query, 'local=true') !== false))) {
    if (file_exists(__DIR__ . '/index.html')) {
        header('Content-Type: text/html');
        readfile(__DIR__ . '/index.html');
        exit;
    }
}

// Serve Logo
if ($path === '/Periscope.webp') {
    if (file_exists(__DIR__ . '/Periscope.webp')) {
        header('Content-Type: image/webp');
        readfile(__DIR__ . '/Periscope.webp');
        exit;
    }
}

// Otherwise treat as API request to engine
// We need to simulate the engine running in the root context
chdir(__DIR__);
if (file_exists('engine.php')) {
    require 'engine.php';
} else {
    http_response_code(500);
    echo json_encode(['error' => 'Engine file missing']);
}
?>
ROUTER_EOF

# --- Launch Logic ---

LAUNCH_PID=""

cleanup() {
    if [ -n "$LAUNCH_PID" ]; then
        kill $LAUNCH_PID 2>/dev/null
    fi
    echo ""
    exit 0
}

trap cleanup INT TERM

launch_when_ready() {
    # Wait for the server to be responsive before opening the browser
    local max_retries=50
    local i=0
    
    while [ $i -lt $max_retries ]; do
        if curl -s -I "http://127.0.0.1:$PORT" &>/dev/null; then
             if grep -q "Microsoft" /proc/version &> /dev/null; then
                if command -v wslview &> /dev/null; then wslview "$URL";
                elif command -v cmd.exe &> /dev/null; then cmd.exe /c start "$URL" 2> /dev/null; fi
             elif command -v xdg-open &> /dev/null; then xdg-open "$URL";
             elif command -v open &> /dev/null; then open "$URL"; fi
             return 0
        fi
        sleep 0.1
        i=$((i+1))
    done
}

if [ "$LOCAL_MODE" = true ]; then
    URL="http://127.0.0.1:$PORT/?local=true"
else
    URL="https://periscope.run?local=true"
fi

# Run launch logic in background so we can start PHP immediately
launch_when_ready &
LAUNCH_PID=$!

if [ "$LOCAL_MODE" = true ]; then
    echo -e "${GREEN}🔗 Local UI:  $URL${NC}"
else
    echo -e "${GREEN}🔗 Web UI:    $URL${NC}"
fi

echo -e "${GREEN}💻 CLI Usage: php $ENGINE_FILE domain.com${NC}"
echo -e "${GREEN}📂 Database:  $DB_FILE${NC}"
echo ""

# Build and display launch command
if [ "$DEBUG_MODE" = true ]; then
    echo -e "${RED}🐛 Debug mode enabled - PHP errors will be displayed${NC}"
    PERISCOPE_DB="$DB_FILE" PERISCOPE_DEBUG=1 php -S 127.0.0.1:$PORT "$ROUTER_FILE"
else
    PERISCOPE_DB="$DB_FILE" php -S 127.0.0.1:$PORT "$ROUTER_FILE"
fi

# Clean exit
cleanup