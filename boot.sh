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

# --- Args ---
LOCAL_MODE=false
if [[ "$1" == "--local" ]]; then
    LOCAL_MODE=true
fi

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

# --- Asset Manager (Frontend & Images) ---
setup_assets() {
    # 1. HTML Frontend
    if [ "$LOCAL_MODE" = true ]; then
        # In local dev mode, use local index.html from script directory
        SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
        if [ -f "$SCRIPT_DIR/index.html" ]; then
            cp "$SCRIPT_DIR/index.html" "$HTML_FILE"
            echo -e "${GREEN}✅ Using local index.html from $SCRIPT_DIR${NC}"
        else
            echo -e "${RED}❌ No local index.html found in $SCRIPT_DIR${NC}"
        fi
    elif [ ! -f "$HTML_FILE" ]; then
        echo -e "${BLUE}⬇️  Checking for latest UI...${NC}"
        HTTP_STATUS=$(curl -sL -w "%{http_code}" -o "$HTML_FILE.tmp" "https://github.com/austinginder/periscope/releases/latest/download/index.html")
        if [ "$HTTP_STATUS" -eq 200 ]; then
            mv "$HTML_FILE.tmp" "$HTML_FILE"
            echo -e "${GREEN}✅ Frontend updated.${NC}"
        else
            rm -f "$HTML_FILE.tmp"
        fi
    fi

    # 2. Logo Image
    if [ ! -f "$LOGO_FILE" ]; then
        echo -e "${BLUE}⬇️  Downloading Logo...${NC}"
        HTTP_STATUS=$(curl -sL -w "%{http_code}" -o "$LOGO_FILE.tmp" "https://raw.githubusercontent.com/austinginder/periscope/refs/heads/main/Periscope.webp")
        if [ "$HTTP_STATUS" -eq 200 ]; then
            mv "$LOGO_FILE.tmp" "$LOGO_FILE"
            echo -e "${GREEN}✅ Logo updated.${NC}\n"
        else
            rm -f "$LOGO_FILE.tmp"
        fi
    fi
}

setup_assets

# --- Create the Engine (PHP) ---
cat << 'EOF' > "$ENGINE_FILE"
<?php
// SILENCE DEPRECATIONS
error_reporting(E_ERROR | E_PARSE);
ini_set('display_errors', '0');

// --- PLUGIN VERSION ---
define('PERISCOPE_VERSION', '1.2');

// --- AUTOLOADER ---
spl_autoload_register(function ($class) {
    $prefix = 'Badcow\\DNS\\';
    $base_dir = __DIR__ . '/lib/Badcow/DNS/lib/';
    $len = strlen($prefix);
    if (strncmp($prefix, $class, $len) !== 0) return;
    $relative_class = substr($class, $len);
    $file = $base_dir . str_replace('\\', '/', $relative_class) . '.php';
    if (file_exists($file)) require $file;
});

use Badcow\DNS\Zone;
use Badcow\DNS\Rdata\Factory;
use Badcow\DNS\ResourceRecord;
use Badcow\DNS\AlignedBuilder;
use Badcow\DNS\Rdata\TXT;

// --- DATABASE SETUP ---
$db_path = getenv('PERISCOPE_DB') ?: __DIR__ . '/history.db';
$pdo = null;
try {
    $pdo = new PDO('sqlite:' . $db_path);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->exec("CREATE TABLE IF NOT EXISTS history (id INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT NOT NULL, timestamp INTEGER NOT NULL, data TEXT NOT NULL)");
} catch (Exception $e) {}

// --- HELPER FUNCTIONS ---
function specialTxtFormatter(TXT $rdata, int $padding): string {
    $text = $rdata->getText();
    if (strlen($text) <= 255) return sprintf('"%s"', addcslashes($text, '"\\'));
    $chunks = str_split($text, 255);
    $out = "(\n";
    foreach ($chunks as $chunk) { $out .= str_repeat(' ', $padding) . sprintf('"%s"', addcslashes($chunk, '"\\')) . "\n"; }
    return $out . str_repeat(' ', $padding) . ")";
}

function formatDate($raw) {
    try {
        if (empty($raw)) return $raw;
        $dt = new DateTime($raw);
        $dt->setTimezone(new DateTimeZone('UTC'));
        return $dt->format('M j, Y, g:i a') . ' UTC';
    } catch (Exception $e) { return $raw; }
}

// --- INPUT NORMALIZATION ---
function normalizeInput($input) {
    // Strip protocol (http://, https://)
    $input = preg_replace('#^https?://#i', '', $input);
    // Strip path, query string, fragment (escape # inside char class since # is delimiter)
    $input = preg_replace('#[/?\#].*$#', '', $input);
    // Strip trailing dots and whitespace
    $input = trim($input, ". \t\n\r");
    // Lowercase
    return strtolower($input);
}

function extractRootDomain($host) {
    // List of multi-part TLDs (add more as needed)
    $multiPartTlds = [
        'co.uk', 'org.uk', 'me.uk', 'ac.uk', 'gov.uk', 'net.uk', 'sch.uk',
        'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au', 'asn.au', 'id.au',
        'co.nz', 'net.nz', 'org.nz', 'govt.nz', 'ac.nz', 'school.nz',
        'co.za', 'org.za', 'web.za', 'net.za', 'gov.za',
        'com.br', 'net.br', 'org.br', 'gov.br', 'edu.br',
        'co.jp', 'or.jp', 'ne.jp', 'ac.jp', 'go.jp',
        'co.kr', 'or.kr', 'ne.kr', 'go.kr', 're.kr',
        'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn',
        'com.tw', 'net.tw', 'org.tw', 'gov.tw', 'edu.tw',
        'com.hk', 'net.hk', 'org.hk', 'gov.hk', 'edu.hk',
        'com.sg', 'net.sg', 'org.sg', 'gov.sg', 'edu.sg',
        'co.in', 'net.in', 'org.in', 'gov.in', 'ac.in', 'res.in',
        'com.mx', 'net.mx', 'org.mx', 'gob.mx', 'edu.mx',
        'com.ar', 'net.ar', 'org.ar', 'gov.ar', 'edu.ar',
        'co.il', 'org.il', 'net.il', 'ac.il', 'gov.il',
        'com.tr', 'net.tr', 'org.tr', 'gov.tr', 'edu.tr',
        'com.pl', 'net.pl', 'org.pl', 'gov.pl', 'edu.pl',
        'co.id', 'or.id', 'web.id', 'ac.id', 'go.id',
        'com.my', 'net.my', 'org.my', 'gov.my', 'edu.my',
        'com.ph', 'net.ph', 'org.ph', 'gov.ph', 'edu.ph',
        'com.vn', 'net.vn', 'org.vn', 'gov.vn', 'edu.vn',
        'co.th', 'or.th', 'ac.th', 'go.th', 'in.th',
        'com.ua', 'net.ua', 'org.ua', 'gov.ua', 'edu.ua',
        'com.ru', 'net.ru', 'org.ru', 'gov.ru', 'edu.ru',
        'com.de', 'org.de',
        'co.at', 'or.at', 'ac.at',
        'com.es', 'org.es', 'nom.es', 'gob.es', 'edu.es',
        'com.pt', 'org.pt', 'gov.pt', 'edu.pt',
        'co.it', 'org.it', 'gov.it', 'edu.it',
        'co.fr', 'asso.fr', 'nom.fr', 'gouv.fr',
        'co.nl', 'org.nl',
        'co.be', 'org.be',
        'eu.com', 'us.com', 'gb.com', 'uk.com', 'de.com', 'jpn.com', 'kr.com', 'cn.com',
        'eu.org', 'us.org',
    ];

    $parts = explode('.', $host);
    $numParts = count($parts);

    if ($numParts <= 2) {
        return $host; // Already a root domain
    }

    // Check for multi-part TLDs
    $lastTwo = $parts[$numParts - 2] . '.' . $parts[$numParts - 1];
    if (in_array($lastTwo, $multiPartTlds)) {
        // Root is last 3 parts (e.g., example.co.uk)
        if ($numParts >= 3) {
            return $parts[$numParts - 3] . '.' . $lastTwo;
        }
        return $host;
    }

    // Standard TLD - root is last 2 parts (e.g., example.com)
    return $parts[$numParts - 2] . '.' . $parts[$numParts - 1];
}

function isSubdomain($host) {
    $root = extractRootDomain($host);
    return $host !== $root;
}

// --- RAW FILE STORAGE ---
function getScanPath($domain, $timestamp) {
    // SAFETY: Reject empty or suspicious domain values
    if (empty($domain) || $domain === '.' || $domain === '..' || strpos($domain, '/') !== false) {
        throw new Exception('Invalid domain for scan path');
    }
    return getenv('HOME') . "/.periscope/scans/$domain/$timestamp";
}

function saveRawFiles($path, $html, $headers, $whoisDomain, $whoisIps, $ssl, $dns, $rdap = null, $metadata_files = [], $redirectChain = null, $ptrRecords = null) {
    // SAFETY: Ensure path is within expected directory
    $expectedBase = getenv('HOME') . "/.periscope/scans/";
    if (empty($path) || strpos(realpath(dirname($path)) ?: $path, $expectedBase) !== 0) {
        return; // Silently abort if path is suspicious
    }
    if (!is_dir($path)) mkdir($path, 0755, true);
    if ($html) file_put_contents("$path/html.txt", $html);
    if ($headers) file_put_contents("$path/headers.json", json_encode($headers));
    if ($whoisDomain) file_put_contents("$path/whois_domain.txt", $whoisDomain);
    foreach ($whoisIps as $ip => $output) {
        file_put_contents("$path/whois_ip_$ip.txt", $output);
    }
    if ($ssl) file_put_contents("$path/ssl.txt", $ssl);
    if ($dns) file_put_contents("$path/dns.json", json_encode($dns));
    if ($rdap) file_put_contents("$path/rdap.json", $rdap);
    if (!empty($metadata_files['robots_txt'])) file_put_contents("$path/robots.txt", $metadata_files['robots_txt']);
    if (!empty($metadata_files['sitemap_xml'])) file_put_contents("$path/sitemap.xml", $metadata_files['sitemap_xml']);
    if (!empty($metadata_files['security_txt'])) file_put_contents("$path/security.txt", $metadata_files['security_txt']);
    if (!empty($metadata_files['ads_txt'])) file_put_contents("$path/ads.txt", $metadata_files['ads_txt']);
    if (!empty($metadata_files['app_ads_txt'])) file_put_contents("$path/app-ads.txt", $metadata_files['app_ads_txt']);
    if (!empty($metadata_files['app_site_association'])) file_put_contents("$path/apple-app-site-association.json", $metadata_files['app_site_association']);
    if (!empty($metadata_files['assetlinks'])) file_put_contents("$path/assetlinks.json", $metadata_files['assetlinks']);
    if (!empty($metadata_files['manifest'])) file_put_contents("$path/manifest.json", $metadata_files['manifest']);
    if (!empty($metadata_files['humans_txt'])) file_put_contents("$path/humans.txt", $metadata_files['humans_txt']);
    if (!empty($metadata_files['browserconfig'])) file_put_contents("$path/browserconfig.xml", $metadata_files['browserconfig']);
    if (!empty($metadata_files['keybase_txt'])) file_put_contents("$path/keybase.txt", $metadata_files['keybase_txt']);
    if (!empty($metadata_files['favicon'])) file_put_contents("$path/favicon.ico", $metadata_files['favicon']);
    if ($redirectChain && count($redirectChain) > 0) file_put_contents("$path/redirects.json", json_encode($redirectChain));
    if ($ptrRecords && count($ptrRecords) > 0) file_put_contents("$path/ptr_records.json", json_encode($ptrRecords));
}

// --- HASH-BASED FILE STORAGE ---
function getFilesPath($domain) {
    // SAFETY: Reject empty or suspicious domain values
    if (empty($domain) || $domain === '.' || $domain === '..' || strpos($domain, '/') !== false) {
        throw new Exception('Invalid domain for files path');
    }
    return getenv('HOME') . "/.periscope/scans/$domain/files";
}

function storeFileByHash($domain, $content, $extension) {
    $hash = md5($content);
    $filesPath = getFilesPath($domain);
    if (!is_dir($filesPath)) mkdir($filesPath, 0755, true);

    $filename = "$hash.$extension";
    $filepath = "$filesPath/$filename";

    // Only write if doesn't exist (deduplication)
    if (!file_exists($filepath)) {
        file_put_contents($filepath, $content);
    }

    return [
        'hash' => $hash,
        'filename' => $filename,
        'extension' => $extension,
        'size' => strlen($content)
    ];
}

function getFileByHash($domain, $hash, $extension) {
    $filepath = getFilesPath($domain) . "/$hash.$extension";
    return file_exists($filepath) ? file_get_contents($filepath) : null;
}

function downloadImage($url, $maxSize = 2000000) {
    $ctx = stream_context_create([
        'http' => [
            'timeout' => 5,
            'ignore_errors' => true,
            'follow_location' => true,
            'user_agent' => 'Periscope/' . PERISCOPE_VERSION . ' (Image Fetcher)',
            'header' => "Accept: image/webp,image/png,image/jpeg,image/gif,image/*\r\n"
        ],
        'ssl' => ['verify_peer' => false, 'verify_peer_name' => false]
    ]);

    $content = @file_get_contents($url, false, $ctx);
    if (!$content || strlen($content) > $maxSize) return null;

    // Detect extension from content type or URL
    $extension = 'jpg'; // default
    if (preg_match('/\.(\w{3,4})(?:\?|$)/', $url, $m)) {
        $extension = strtolower($m[1]);
    }
    // Also check content magic bytes
    if (substr($content, 0, 8) === "\x89PNG\r\n\x1a\n") $extension = 'png';
    elseif (substr($content, 0, 3) === "\xff\xd8\xff") $extension = 'jpg';
    elseif (substr($content, 0, 4) === "GIF8") $extension = 'gif';
    elseif (substr($content, 0, 4) === "RIFF" && substr($content, 8, 4) === "WEBP") $extension = 'webp';

    return ['content' => $content, 'extension' => $extension];
}

function saveResponseCache($path, $data) {
    $cache = [
        'plugin_version' => PERISCOPE_VERSION,
        'generated_at' => time(),
        'data' => $data
    ];
    file_put_contents("$path/response.json", json_encode($cache));
}

function loadResponseCache($path) {
    $file = "$path/response.json";
    if (!file_exists($file)) return null;
    $cache = @json_decode(file_get_contents($file), true);
    if (!$cache || !isset($cache['plugin_version'])) return null;
    return $cache;
}

function isCacheValid($cache) {
    return $cache && isset($cache['plugin_version']) && $cache['plugin_version'] === PERISCOPE_VERSION;
}

function loadRawFiles($path) {
    $whoisIps = [];
    foreach (glob("$path/whois_ip_*.txt") as $file) {
        $ip = str_replace(['whois_ip_', '.txt'], '', basename($file));
        $whoisIps[$ip] = @file_get_contents($file);
    }
    return [
        'html' => @file_get_contents("$path/html.txt"),
        'headers' => @json_decode(@file_get_contents("$path/headers.json"), true) ?: [],
        'whois_domain' => @file_get_contents("$path/whois_domain.txt"),
        'whois_ips' => $whoisIps,
        'ssl' => @file_get_contents("$path/ssl.txt"),
        'dns' => @json_decode(@file_get_contents("$path/dns.json"), true) ?: [],
        'rdap' => @file_get_contents("$path/rdap.json"),
        'robots_txt' => @file_get_contents("$path/robots.txt"),
        'sitemap_xml' => @file_get_contents("$path/sitemap.xml"),
        'security_txt' => @file_get_contents("$path/security.txt"),
        'ads_txt' => @file_get_contents("$path/ads.txt"),
        'app_ads_txt' => @file_get_contents("$path/app-ads.txt"),
        'app_site_association' => @file_get_contents("$path/apple-app-site-association.json"),
        'assetlinks' => @file_get_contents("$path/assetlinks.json"),
        'manifest' => @file_get_contents("$path/manifest.json"),
        'humans_txt' => @file_get_contents("$path/humans.txt"),
        'browserconfig' => @file_get_contents("$path/browserconfig.xml"),
        'keybase_txt' => @file_get_contents("$path/keybase.txt"),
        'favicon' => file_exists("$path/favicon.ico"),
        'redirect_chain' => @json_decode(@file_get_contents("$path/redirects.json"), true) ?: [],
        'ptr_records' => @json_decode(@file_get_contents("$path/ptr_records.json"), true) ?: []
    ];
}

function hasRawFiles($domain, $timestamp) {
    $path = getScanPath($domain, $timestamp);
    return is_dir($path);
}

function getRawWhoisDomain($domain) {
    return shell_exec("whois " . escapeshellarg($domain));
}

function getRawRdap($domain) {
    $ch = curl_init("https://rdap.org/domain/" . $domain);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    curl_setopt($ch, CURLOPT_USERAGENT, 'Periscope/' . PERISCOPE_VERSION);
    $json = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    return ($code === 200 && $json) ? $json : null;
}

function checkDomainExists($domain) {
    $ch = curl_init("https://rdap.org/domain/" . $domain);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    curl_setopt($ch, CURLOPT_USERAGENT, 'Periscope/' . PERISCOPE_VERSION);
    curl_setopt($ch, CURLOPT_TIMEOUT, 5);
    $json = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($code === 404) {
        // Fallback: check DNS NS records before declaring not found
        $ns = @dns_get_record($domain, DNS_NS);
        if ($ns && count($ns) > 0) {
            return ['exists' => true, 'rdap' => null, 'source' => 'dns'];
        }
        return ['exists' => false, 'reason' => 'not_found'];
    }
    if ($code === 200 && $json) {
        $data = json_decode($json, true);
        if ($data && isset($data['errorCode'])) {
            // RDAP returned an error, fallback to DNS check
            $ns = @dns_get_record($domain, DNS_NS);
            if ($ns && count($ns) > 0) {
                return ['exists' => true, 'rdap' => null, 'source' => 'dns'];
            }
            return ['exists' => false, 'reason' => 'rdap_error'];
        }
        return ['exists' => true, 'rdap' => $json, 'source' => 'rdap'];
    }
    // RDAP request failed (timeout, etc.) - fallback to DNS check
    $ns = @dns_get_record($domain, DNS_NS);
    if ($ns && count($ns) > 0) {
        return ['exists' => true, 'rdap' => null, 'source' => 'dns'];
    }
    return ['exists' => true, 'rdap' => null];
}

function parseRdap($json) {
    $out = [];
    $data = is_string($json) ? json_decode($json, true) : $json;
    if (!$data) return $out;
    
    if (isset($data['ldhName'])) $out[] = ['name' => 'Domain Name', 'value' => strtolower($data['ldhName'])];
    if (isset($data['handle'])) $out[] = ['name' => 'Registry Domain ID', 'value' => $data['handle']];
    if (isset($data['secureDNS']['delegationSigned'])) {
        $signed = $data['secureDNS']['delegationSigned'] ? 'Signed' : 'Unsigned';
        $out[] = ['name' => 'DNSSEC', 'value' => $signed];
    }
    if (isset($data['status'])) foreach ($data['status'] as $status) $out[] = ['name' => 'Domain Status', 'value' => $status];
    if (isset($data['events'])) foreach($data['events'] as $e) {
        $d = formatDate($e['eventDate']);
        if($e['eventAction'] == 'registration') $out[] = ['name' => 'Creation Date', 'value' => $d];
        if($e['eventAction'] == 'expiration') $out[] = ['name' => 'Expiration Date', 'value' => $d];
        if($e['eventAction'] == 'last changed') $out[] = ['name' => 'Updated Date', 'value' => $d];
    }
    if (isset($data['nameservers'])) {
        $ns_list = []; foreach($data['nameservers'] as $ns) if (isset($ns['ldhName'])) $ns_list[] = $ns['ldhName'];
        if (!empty($ns_list)) $out[] = ['name' => 'Registered Nameservers', 'value' => implode(', ', $ns_list)];
    }
    if (isset($data['entities'])) {
        $processEntities = function($entities) use (&$out, &$processEntities) {
            foreach($entities as $ent) {
                if (!isset($ent['roles'])) continue;
                if (in_array('registrar', $ent['roles'])) {
                    if (isset($ent['vcardArray'][1])) foreach($ent['vcardArray'][1] as $v) if($v[0] == 'fn') $out[] = ['name' => 'Registrar', 'value' => $v[3]];
                    if (isset($ent['publicIds'])) foreach($ent['publicIds'] as $pid) if (isset($pid['type']) && strpos($pid['type'], 'IANA') !== false) $out[] = ['name' => 'Registrar IANA ID', 'value' => $pid['identifier']];
                }
                if (in_array('abuse', $ent['roles'])) {
                    if (isset($ent['vcardArray'][1])) foreach ($ent['vcardArray'][1] as $entry) {
                        if (is_array($entry) && isset($entry[0]) && $entry[0] === 'email') $out[] = ['name' => 'Abuse Email', 'value' => $entry[3]];
                    }
                }
                if (isset($ent['entities'])) $processEntities($ent['entities']);
            }
        };
        $processEntities($data['entities']);
    }
    $out = array_map("unserialize", array_unique(array_map("serialize", $out)));
    return array_values($out);
}

function parseRawWhois($raw) {
    $out = [];
    if (!$raw) return $out;
    $lines = explode("\n", $raw);
    $nameservers = [];
    $capture = ['Domain Name', 'Name Server', 'Creation Date', 'Registrar', 'Registry Expiry Date', 'Updated Date', 'Domain Status', 'Registrar IANA ID', 'Reseller', 'DNSSEC', 'Registry Domain ID', 'Registrar Abuse Contact Email'];
    foreach ($lines as $line) {
        if (strpos($line, ':')) {
            $parts = explode(':', $line, 2); $key = trim($parts[0]); $val = trim($parts[1]);
            if (empty($val)) continue;
            foreach ($capture as $c) {
                if (stripos($key, $c) === 0) {
                    if (stripos($key, 'Date') !== false) $val = formatDate($val);
                    if (stripos($key, 'Abuse') !== false) $key = 'Abuse Email';
                    // Normalize expiry date key to match RDAP output
                    if (stripos($key, 'Registry Expiry Date') === 0) $key = 'Expiration Date';
                    // Collect nameservers to combine later
                    if (stripos($key, 'Name Server') === 0) {
                        $nameservers[] = strtoupper($val);
                    } else {
                        $out[] = ['name' => $key, 'value' => $val];
                    }
                    break;
                }
            }
        }
    }
    // Add combined nameservers if found
    if (!empty($nameservers)) {
        $out[] = ['name' => 'Registered Nameservers', 'value' => implode(', ', $nameservers)];
    }
    return $out;
}

function getWhois($domain, $rdapJson = null) {
    // If RDAP JSON provided (from stored file), parse it
    if ($rdapJson) {
        $out = parseRdap($rdapJson);
        if (!empty($out)) return $out;
    }

    // Try fetching RDAP
    $rdapJson = getRawRdap($domain);
    if ($rdapJson) {
        $out = parseRdap($rdapJson);
        if (!empty($out)) return $out;
    }

    // Fallback to raw whois
    $raw = shell_exec("whois " . escapeshellarg($domain));
    if ($raw) {
        return parseRawWhois($raw);
    }
    return [];
}

/**
 * Run a dig query with retry on timeout and filter out error messages
 */
function digQuery($type, $host, $retries = 2) {
    for ($i = 0; $i < $retries; $i++) {
        $output = shell_exec("dig +short +time=3 +tries=1 -t " . escapeshellarg($type) . " " . escapeshellarg($host) . " 2>/dev/null");
        if ($output === null) continue;

        // Filter out dig error/warning messages (lines starting with ;;)
        $lines = [];
        foreach (explode("\n", $output) as $line) {
            $line = trim($line);
            if (empty($line)) continue;
            if (strpos($line, ';;') === 0) continue; // Skip dig comments/errors
            if (strpos($line, ';') === 0) continue;  // Skip any comment lines
            $lines[] = $line;
        }

        if (!empty($lines)) {
            return implode("\n", $lines);
        }
    }
    return null;
}

function getHttpStatusText($code) {
    $statusTexts = [
        200 => 'OK', 201 => 'Created', 204 => 'No Content',
        301 => 'Moved Permanently', 302 => 'Found', 303 => 'See Other',
        307 => 'Temporary Redirect', 308 => 'Permanent Redirect',
        400 => 'Bad Request', 401 => 'Unauthorized', 403 => 'Forbidden',
        404 => 'Not Found', 500 => 'Internal Server Error', 502 => 'Bad Gateway',
        503 => 'Service Unavailable', 504 => 'Gateway Timeout'
    ];
    return $statusTexts[$code] ?? 'Unknown';
}

function getRedirectChain($url, $maxRedirects = 10) {
    $chain = [];
    $currentUrl = $url;

    for ($i = 0; $i < $maxRedirects; $i++) {
        $ch = curl_init($currentUrl);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HEADER, true);
        curl_setopt($ch, CURLOPT_NOBODY, true);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false); // Don't auto-follow
        curl_setopt($ch, CURLOPT_TIMEOUT, 5);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_USERAGENT, 'Periscope/' . PERISCOPE_VERSION);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        // Skip if we got no response
        if ($httpCode === 0) break;

        $chain[] = [
            'url' => $currentUrl,
            'status_code' => $httpCode,
            'status_text' => getHttpStatusText($httpCode)
        ];

        // Check for redirect (3xx status codes)
        if ($httpCode >= 300 && $httpCode < 400) {
            // Extract Location header
            if (preg_match('/^Location:\s*(.+)$/mi', $response, $m)) {
                $location = trim($m[1]);
                // Handle relative URLs
                if (strpos($location, 'http') !== 0) {
                    $parsed = parse_url($currentUrl);
                    $base = $parsed['scheme'] . '://' . $parsed['host'];
                    $location = $base . (strpos($location, '/') === 0 ? $location : '/' . $location);
                }
                $currentUrl = $location;
                continue;
            }
        }
        break; // No redirect, we're done
    }

    return $chain;
}

function getSSLInfo($domain, $rawOutput = null) {
    $result = ['valid' => false];
    if ($rawOutput === null) {
        $rawOutput = shell_exec("echo | openssl s_client -servername " . escapeshellarg($domain) . " -connect " . escapeshellarg($domain) . ":443 2>/dev/null | openssl x509 -noout -dates -issuer -subject 2>/dev/null");
    }
    if (!$rawOutput) return $result;

    $result['valid'] = true;
    foreach (explode("\n", $rawOutput) as $line) {
        if (preg_match('/notAfter=(.+)/', $line, $m)) {
            $expiry = strtotime($m[1]);
            $result['expires'] = date('M j, Y', $expiry);
            $result['days_remaining'] = max(0, floor(($expiry - time()) / 86400));
        }
        if (preg_match('/notBefore=(.+)/', $line, $m)) {
            $result['issued'] = date('M j, Y', strtotime($m[1]));
        }
        if (preg_match('/issuer=.*?O\s*=\s*([^,\/]+)/', $line, $m)) {
            $result['issuer'] = trim($m[1]);
        }
    }
    return $result;
}

function getRawSSL($domain) {
    return shell_exec("echo | openssl s_client -servername " . escapeshellarg($domain) . " -connect " . escapeshellarg($domain) . ":443 2>/dev/null | openssl x509 -noout -dates -issuer -subject 2>/dev/null");
}

function detectCMS($domain, $html = null, $headers = []) {
    if ($html === null) {
        $html = @file_get_contents("https://" . $domain, false, stream_context_create([
            'http' => ['timeout' => 3, 'ignore_errors' => true],
            'ssl' => ['verify_peer' => false, 'verify_peer_name' => false]
        ]));
        if (!$html) $html = @file_get_contents("http://" . $domain, false, stream_context_create([
            'http' => ['timeout' => 3, 'ignore_errors' => true]
        ]));
    }
    if (!$html) return null;

    $is_wp = false;
    
    // 1. Standard Paths
    if (preg_match('/wp-content|wp-includes/i', $html)) $is_wp = true;
    
    // 2. REST API Link (Common on masked sites or custom structures like Bedrock)
    if (!$is_wp && preg_match('/<link[^>]+rel=["\']https:\/\/api\.w\.org\//i', $html)) $is_wp = true;
    
    // 3. Block Library CSS (Common on Gutenberg sites)
    if (!$is_wp && preg_match('/id=["\']wp-block-library-css/i', $html)) $is_wp = true;
    
    // 4. Generator Tag
    if (!$is_wp && preg_match('/<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress/i', $html)) $is_wp = true;

    // 5. Header Check
    if (!$is_wp && !empty($headers)) {
        foreach ($headers as $k => $v) {
            if (stripos($k, 'x-powered-by') !== false && stripos($v, 'WordPress') !== false) $is_wp = true;
            // Common WordPress Link header for REST API
            if (stripos($k, 'link') !== false && stripos($v, 'api.w.org') !== false) $is_wp = true;
        }
    }

    // WordPress
    if ($is_wp) {
        $version = null;
        if (preg_match('/<meta[^>]+generator[^>]+WordPress\s*([\d.]+)?/i', $html, $m)) {
            $version = $m[1] ?? null;
        }

        // Detect WordPress plugins from wp-content/plugins paths
        $plugins = [];
        if (preg_match_all('/wp-content\/plugins\/([a-zA-Z0-9_-]+)/i', $html, $pluginMatches)) {
            $plugins = array_unique($pluginMatches[1]);
            // Filter out common false positives
            $plugins = array_filter($plugins, function($p) {
                return !in_array(strtolower($p), ['js', 'css', 'images', 'assets']);
            });
            $plugins = array_values($plugins);
            sort($plugins);
        }

        // Detect WordPress Multisite (uploads/sites/<id>/)
        $multisite = false;
        if (preg_match('/\/uploads\/sites\/\d+\//i', $html)) {
            $multisite = true;
        }

        // Detect WP Freighter Multitenancy (content/<id>/plugins/)
        $multitenancy = false;
        if (preg_match('/\/content\/\d+\/plugins\//i', $html)) {
            $multitenancy = true;
        }

        return ['name' => 'WordPress', 'version' => $version, 'plugins' => $plugins, 'multisite' => $multisite, 'multitenancy' => $multitenancy];
    }

    // Shopify
    if (preg_match('/cdn\.shopify\.com|Shopify\.theme/i', $html)) {
        return ['name' => 'Shopify', 'version' => null];
    }

    // Squarespace
    if (preg_match('/squarespace\.com|static\.squarespace/i', $html)) {
        return ['name' => 'Squarespace', 'version' => null];
    }

    // Wix
    if (preg_match('/wix\.com|wixstatic\.com/i', $html)) {
        return ['name' => 'Wix', 'version' => null];
    }

    // Drupal
    if (preg_match('/Drupal\.settings|\/sites\/default\//i', $html) || preg_match('/<meta[^>]+generator[^>]+Drupal/i', $html)) {
        $version = null;
        if (preg_match('/Drupal\s*([\d.]+)/i', $html, $m)) $version = $m[1];
        return ['name' => 'Drupal', 'version' => $version];
    }

    // Joomla
    if (preg_match('/<meta[^>]+generator[^>]+Joomla/i', $html)) {
        $version = null;
        if (preg_match('/Joomla[!\s]*([\d.]+)?/i', $html, $m)) $version = $m[1] ?? null;
        return ['name' => 'Joomla', 'version' => $version];
    }

    // Webflow
    if (preg_match('/webflow\.com/i', $html)) {
        return ['name' => 'Webflow', 'version' => null];
    }

    // Ghost
    if (preg_match('/ghost\.io|Ghost\s[\d.]+/i', $html)) {
        return ['name' => 'Ghost', 'version' => null];
    }

    return null;
}

function detectInfrastructure($headers) {
    $result = ['cdn' => null, 'host' => null, 'server' => null];
    $h = array_change_key_case($headers, CASE_LOWER);

    // Server software
    if (isset($h['server'])) {
        $s = strtolower($h['server']);
        if (strpos($s, 'nginx') !== false) $result['server'] = 'nginx';
        elseif (strpos($s, 'apache') !== false) $result['server'] = 'Apache';
        elseif (strpos($s, 'litespeed') !== false) $result['server'] = 'LiteSpeed';
        elseif (strpos($s, 'microsoft-iis') !== false) $result['server'] = 'IIS';
        elseif (strpos($s, 'cloudflare') !== false) $result['server'] = 'Cloudflare';
        elseif (strpos($s, 'vercel') !== false) $result['server'] = 'Vercel';
        elseif (strpos($s, 'netlify') !== false) $result['server'] = 'Netlify';
        elseif (strpos($s, 'openresty') !== false) $result['server'] = 'OpenResty';
        elseif (strpos($s, 'caddy') !== false) $result['server'] = 'Caddy';
        elseif (strpos($s, 'tengine') !== false) $result['server'] = 'Tengine';
        elseif (strpos($s, 'cowboy') !== false) $result['server'] = 'Cowboy';
    }

    // CDN Detection
    if (isset($h['cf-ray']) || isset($h['cf-cache-status']) || (isset($h['server']) && stripos($h['server'], 'cloudflare') !== false)) {
        $result['cdn'] = 'Cloudflare';
    } elseif (isset($h['x-amz-cf-id']) || isset($h['x-amz-cf-pop'])) {
        $result['cdn'] = 'CloudFront';
    } elseif (isset($h['x-served-by']) && stripos($h['x-served-by'], 'cache') !== false) {
        $result['cdn'] = 'Fastly';
    } elseif (isset($h['x-sucuri-id']) || (isset($h['server']) && stripos($h['server'], 'sucuri') !== false)) {
        $result['cdn'] = 'Sucuri';
    } elseif (isset($h['x-edge-location'])) {
        $result['cdn'] = 'KeyCDN';
    } elseif (isset($h['x-cache']) && stripos($h['x-cache'], 'hit') !== false && isset($h['via']) && stripos($h['via'], 'varnish') !== false) {
        $result['cdn'] = 'Varnish';
    }
    // Akamai
    elseif (isset($h['x-akamai-transformed']) || isset($h['akamai-grn']) || isset($h['x-akamai-request-id']) || (isset($h['server']) && stripos($h['server'], 'akamaighost') !== false)) {
        $result['cdn'] = 'Akamai';
    }
    // BunnyCDN
    elseif (isset($h['cdn-pullzone']) || isset($h['cdn-uid']) || isset($h['cdn-requestid']) || (isset($h['server']) && stripos($h['server'], 'bunnycdn') !== false)) {
        $result['cdn'] = 'BunnyCDN';
    }
    // StackPath (formerly MaxCDN/Highwinds)
    elseif (isset($h['x-hw']) || isset($h['x-sp-pop']) || isset($h['x-sp-cache'])) {
        $result['cdn'] = 'StackPath';
    }
    // Azure CDN
    elseif (isset($h['x-msedge-ref']) || isset($h['x-azure-ref'])) {
        $result['cdn'] = 'Azure CDN';
    }
    // Google Cloud CDN
    elseif (isset($h['via']) && stripos($h['via'], 'google') !== false) {
        $result['cdn'] = 'Google Cloud CDN';
    }
    // Imperva/Incapsula
    elseif (isset($h['x-iinfo']) || isset($h['x-cdn']) && stripos($h['x-cdn'], 'incapsula') !== false) {
        $result['cdn'] = 'Imperva';
    }
    // ArvanCloud
    elseif (isset($h['x-arvan-cache']) || isset($h['ar-cache']) || isset($h['ar-sid'])) {
        $result['cdn'] = 'ArvanCloud';
    }
    // CDN77
    elseif (isset($h['x-77-pop']) || isset($h['x-cdn77-pop']) || isset($h['x-77-nzt'])) {
        $result['cdn'] = 'CDN77';
    }
    // Limelight
    elseif (isset($h['x-llnw-nginx']) || (isset($h['via']) && stripos($h['via'], 'limelight') !== false)) {
        $result['cdn'] = 'Limelight';
    }
    // Edgecast (Verizon/Edgio)
    elseif (isset($h['x-ec-custom-error']) || isset($h['x-cache']) && stripos($h['x-cache'], 'ecp') !== false) {
        $result['cdn'] = 'Edgecast';
    }
    // Cachefly
    elseif (isset($h['x-cf-pop']) || (isset($h['server']) && stripos($h['server'], 'cachefly') !== false)) {
        $result['cdn'] = 'Cachefly';
    }

    // Hosting Detection (from headers)
    // Kinsta
    if (isset($h['x-kinsta-cache']) || isset($h['ki-cf-cache-status']) || isset($h['ki-cache-tag'])) {
        $result['host'] = 'Kinsta';
    }
    // WP Engine
    elseif (isset($h['x-powered-by']) && stripos($h['x-powered-by'], 'wp engine') !== false) {
        $result['host'] = 'WP Engine';
    }
    // Flywheel
    elseif (isset($h['x-fw-hash']) || isset($h['x-fw-serve'])) {
        $result['host'] = 'Flywheel';
    }
    // Pantheon
    elseif (isset($h['x-pantheon-styx-hostname']) || isset($h['x-styx-req-id'])) {
        $result['host'] = 'Pantheon';
    }
    // Vercel
    elseif (isset($h['x-vercel-id']) || isset($h['x-vercel-cache'])) {
        $result['host'] = 'Vercel';
    }
    // Netlify
    elseif (isset($h['x-nf-request-id']) || (isset($h['server']) && stripos($h['server'], 'netlify') !== false)) {
        $result['host'] = 'Netlify';
    }
    // Heroku
    elseif (isset($h['via']) && stripos($h['via'], 'heroku') !== false) {
        $result['host'] = 'Heroku';
    }
    // AWS (generic - EC2/ELB/Lambda)
    elseif (isset($h['x-amzn-requestid']) || isset($h['x-amz-request-id']) || isset($h['x-amz-apigw-id'])) {
        $result['host'] = 'AWS';
    }
    // Google Cloud (App Engine/Cloud Run/Cloud Functions)
    elseif (isset($h['x-cloud-trace-context']) || isset($h['x-appengine-resource-usage']) || isset($h['x-goog-generation'])) {
        $result['host'] = 'Google Cloud';
    }
    // Pagely
    elseif (isset($h['x-pagely-cache']) || isset($h['x-pagely-id'])) {
        $result['host'] = 'Pagely';
    }
    // Pressable
    elseif (isset($h['x-powered-by']) && stripos($h['x-powered-by'], 'flavor atlas') !== false) {
        $result['host'] = 'Pressable';
    }
    // SiteGround
    elseif (isset($h['x-siteground-optimizer'])) {
        $result['host'] = 'SiteGround';
    }
    // Rocket.net
    elseif (isset($h['x-rocket-cache-status'])) {
        $result['host'] = 'Rocket.net';
    }
    // Convesio
    elseif (isset($h['x-convesio-cache'])) {
        $result['host'] = 'Convesio';
    }
    // Cloudways
    elseif (isset($h['x-cw-cache']) || isset($h['x-cloudways-cache'])) {
        $result['host'] = 'Cloudways';
    }
    // Azure App Service
    elseif (isset($h['x-ms-request-id']) || isset($h['x-aspnet-version']) || isset($h['arr-disable-session-affinity'])) {
        $result['host'] = 'Azure';
    }
    // DigitalOcean App Platform
    elseif (isset($h['x-do-app-origin']) || isset($h['x-do-orig-status']) || isset($h['x-dobs-request-id'])) {
        $result['host'] = 'DigitalOcean';
    }
    // Render
    elseif (isset($h['x-render-origin-server']) || isset($h['rndr-id'])) {
        $result['host'] = 'Render';
    }
    // Railway
    elseif (isset($h['x-railway-request-id']) || isset($h['x-railway-region'])) {
        $result['host'] = 'Railway';
    }
    // Fly.io
    elseif (isset($h['fly-request-id']) || (isset($h['server']) && stripos($h['server'], 'fly/') !== false) || (isset($h['via']) && stripos($h['via'], 'fly.io') !== false)) {
        $result['host'] = 'Fly.io';
    }
    // Platform.sh
    elseif (isset($h['x-platform-server']) || isset($h['x-platform-cluster']) || isset($h['x-platform-processor'])) {
        $result['host'] = 'Platform.sh';
    }
    // Acquia
    elseif (isset($h['x-ah-environment']) || isset($h['x-acquia-host']) || isset($h['x-acquia-site'])) {
        $result['host'] = 'Acquia';
    }
    // Liquid Web
    elseif (isset($h['x-lw-cache']) || isset($h['x-lw-cache-status'])) {
        $result['host'] = 'Liquid Web';
    }
    // 10Web
    elseif (isset($h['x-10web-cache']) || isset($h['x-tenweb-cache'])) {
        $result['host'] = '10Web';
    }
    // Bluehost
    elseif (isset($h['x-endurance-cache-level']) || (isset($h['x-powered-by']) && stripos($h['x-powered-by'], 'bluehost') !== false)) {
        $result['host'] = 'Bluehost';
    }
    // GoDaddy
    elseif (isset($h['x-godaddy-datacenter']) || isset($h['x-sucuri-cache']) && isset($h['server']) && stripos($h['server'], 'godaddy') !== false) {
        $result['host'] = 'GoDaddy';
    }
    // DreamHost
    elseif (isset($h['x-served-by']) && stripos($h['x-served-by'], 'dreamhost') !== false) {
        $result['host'] = 'DreamHost';
    }
    // WPX Hosting
    elseif (isset($h['x-wpx-cache']) || (isset($h['x-cache-by']) && stripos($h['x-cache-by'], 'wpx') !== false)) {
        $result['host'] = 'WPX';
    }
    // Closte
    elseif (isset($h['x-closte-cache']) || isset($h['x-closte-cache-status'])) {
        $result['host'] = 'Closte';
    }
    // Templ
    elseif (isset($h['x-templ-cache']) || isset($h['x-templ-cache-status'])) {
        $result['host'] = 'Templ';
    }
    // Servebolt
    elseif (isset($h['x-servebolt-id']) || isset($h['x-sb-id'])) {
        $result['host'] = 'Servebolt';
    }
    // SpinupWP
    elseif (isset($h['x-spinupwp-cache']) || isset($h['x-spinupwp-cache-status'])) {
        $result['host'] = 'SpinupWP';
    }
    // GridPane
    elseif (isset($h['x-gridpane-cache']) || isset($h['x-gp-cache'])) {
        $result['host'] = 'GridPane';
    }
    // RunCloud
    elseif (isset($h['x-runcloud-cache']) || isset($h['x-rc-cache'])) {
        $result['host'] = 'RunCloud';
    }
    // WordPress.com / Automattic
    elseif (isset($h['x-ac']) || (isset($h['via']) && stripos($h['via'], 'wordpress.com') !== false)) {
        $result['host'] = 'WordPress.com';
    }
    // Squarespace (from server header)
    elseif (isset($h['server']) && stripos($h['server'], 'squarespace') !== false) {
        $result['host'] = 'Squarespace';
    }
    // Wix (from server header)
    elseif (isset($h['server']) && stripos($h['server'], 'pepyaka') !== false) {
        $result['host'] = 'Wix';
    }
    // Shopify
    elseif (isset($h['x-shopify-stage']) || isset($h['x-shopid']) || isset($h['x-sorting-hat-shopid'])) {
        $result['host'] = 'Shopify';
    }
    // GitHub Pages
    elseif ((isset($h['server']) && stripos($h['server'], 'github.com') !== false) || isset($h['x-github-request-id'])) {
        $result['host'] = 'GitHub Pages';
    }
    // GitLab Pages
    elseif (isset($h['x-gitlab-version']) || (isset($h['server']) && stripos($h['server'], 'gitlab') !== false)) {
        $result['host'] = 'GitLab Pages';
    }
    // Webflow
    elseif (isset($h['x-wf-proxy-request-id']) || (isset($h['server']) && stripos($h['server'], 'webflow') !== false)) {
        $result['host'] = 'Webflow';
    }
    // Deno Deploy
    elseif (isset($h['x-deno-ray']) || isset($h['server']) && stripos($h['server'], 'deno') !== false) {
        $result['host'] = 'Deno Deploy';
    }
    // Cloudflare Pages/Workers
    elseif (isset($h['cf-ray']) && isset($h['cf-cache-status']) && !$result['host']) {
        if (isset($h['server']) && stripos($h['server'], 'cloudflare') !== false) {
            $result['host'] = 'Cloudflare Pages';
        }
    }

    // Only return if we found something
    if ($result['cdn'] || $result['host'] || $result['server']) {
        return $result;
    }
    return null;
}

function detectSecurityHeaders($headers) {
    $h = array_change_key_case($headers, CASE_LOWER);
    $result = [];

    // Content-Security-Policy
    if (isset($h['content-security-policy'])) {
        $result['csp'] = ['present' => true, 'value' => substr($h['content-security-policy'], 0, 200) . (strlen($h['content-security-policy']) > 200 ? '...' : '')];
    } else {
        $result['csp'] = ['present' => false];
    }

    // X-Frame-Options
    if (isset($h['x-frame-options'])) {
        $result['x_frame_options'] = ['present' => true, 'value' => $h['x-frame-options']];
    } else {
        $result['x_frame_options'] = ['present' => false];
    }

    // X-Content-Type-Options
    if (isset($h['x-content-type-options'])) {
        $result['x_content_type_options'] = ['present' => true, 'value' => $h['x-content-type-options']];
    } else {
        $result['x_content_type_options'] = ['present' => false];
    }

    // Strict-Transport-Security (HSTS)
    if (isset($h['strict-transport-security'])) {
        $hsts = $h['strict-transport-security'];
        $maxAge = null;
        $includeSubdomains = strpos(strtolower($hsts), 'includesubdomains') !== false;
        $preload = strpos(strtolower($hsts), 'preload') !== false;
        if (preg_match('/max-age=(\d+)/i', $hsts, $m)) $maxAge = (int)$m[1];
        $result['hsts'] = ['present' => true, 'max_age' => $maxAge, 'include_subdomains' => $includeSubdomains, 'preload' => $preload];
    } else {
        $result['hsts'] = ['present' => false];
    }

    // Permissions-Policy (formerly Feature-Policy)
    if (isset($h['permissions-policy'])) {
        $result['permissions_policy'] = ['present' => true, 'value' => substr($h['permissions-policy'], 0, 200) . (strlen($h['permissions-policy']) > 200 ? '...' : '')];
    } elseif (isset($h['feature-policy'])) {
        $result['permissions_policy'] = ['present' => true, 'value' => substr($h['feature-policy'], 0, 200) . (strlen($h['feature-policy']) > 200 ? '...' : ''), 'legacy' => true];
    } else {
        $result['permissions_policy'] = ['present' => false];
    }

    // X-XSS-Protection (legacy but still used)
    if (isset($h['x-xss-protection'])) {
        $result['x_xss_protection'] = ['present' => true, 'value' => $h['x-xss-protection']];
    } else {
        $result['x_xss_protection'] = ['present' => false];
    }

    // Referrer-Policy
    if (isset($h['referrer-policy'])) {
        $result['referrer_policy'] = ['present' => true, 'value' => $h['referrer-policy']];
    } else {
        $result['referrer_policy'] = ['present' => false];
    }

    // Calculate security score (simple count of present headers)
    $score = 0;
    $total = 7;
    foreach (['csp', 'x_frame_options', 'x_content_type_options', 'hsts', 'permissions_policy', 'x_xss_protection', 'referrer_policy'] as $header) {
        if ($result[$header]['present']) $score++;
    }
    $result['score'] = ['value' => $score, 'total' => $total];

    return $result;
}

function detectTechnology($html, $headers = []) {
    $result = ['frameworks' => [], 'analytics' => [], 'ecommerce' => [], 'widgets' => []];
    if (!$html) return $result;
    $h = array_change_key_case($headers, CASE_LOWER);

    if (preg_match('/data-reactroot|_reactInternalInstance|__REACT_DEVTOOLS_GLOBAL_HOOK__/i', $html)) $result['frameworks'][] = 'React';
    if (preg_match('/data-v-\w{8}|__VUE__|v-cloak|vue-server-renderer/i', $html)) $result['frameworks'][] = 'Vue.js';
    if (preg_match('/ng-version=|ng-app|ng-controller|class="ng-binding"/i', $html)) $result['frameworks'][] = 'Angular';
    if (preg_match('/<script[^>]+id="__NEXT_DATA__"/i', $html)) $result['frameworks'][] = 'Next.js';
    if (preg_match('/<script[^>]+id="__NUXT__"|window\.__NUXT__/i', $html)) $result['frameworks'][] = 'Nuxt.js';
    if (preg_match('/<meta[^>]+content="Gatsby|id="___gatsby"/i', $html)) $result['frameworks'][] = 'Gatsby';
    if (preg_match('/class="[^"]*svelte-\w+/i', $html)) $result['frameworks'][] = 'Svelte';
    // Alpine.js - require x-data with x-show/x-bind/x-on or alpinejs script
    if ((preg_match('/x-data=/i', $html) && preg_match('/x-(?:show|bind|on|text|model|if|for)=/i', $html)) ||
        preg_match('/alpinejs|alpine\.js|alpine\.min\.js/i', $html)) {
        $result['frameworks'][] = 'Alpine.js';
    }
    // Tailwind - require multiple utility classes together to reduce false positives
    if (preg_match('/class="[^"]*(?:flex|grid|hidden|block)\s[^"]*(?:items-|justify-|gap-|p[xytrbl]?-\d|m[xytrbl]?-\d)/i', $html) ||
        preg_match('/tailwindcss|tailwind\.config/i', $html)) {
        $result['frameworks'][] = 'Tailwind CSS';
    }
    if (preg_match('/bootstrap(?:\.min)?\.css|bootstrap(?:\.min)?\.js/i', $html)) $result['frameworks'][] = 'Bootstrap';

    if (preg_match('/googletagmanager\.com\/gtag\/js|google-analytics\.com\/analytics\.js|ga\(\s*[\'"]create[\'"]|gtag\(\s*[\'"]config[\'"]\s*,\s*[\'"](UA-|G-)/i', $html, $m)) {
        $gaId = null;
        if (preg_match('/(?:config|create)[\'"]\s*,\s*[\'"](UA-\d+-\d+|G-[A-Z0-9]{6,})[\'"]/i', $html, $idMatch)) {
            $gaId = $idMatch[1];
        }
        $result['analytics'][] = ['name' => 'Google Analytics', 'id' => $gaId];
    }
    
    if (preg_match('/cdn\.usefathom\.com|captaincore-analytics\.js/i', $html)) {
        $fId = null;
        if (preg_match('/data-site=["\']([^"\']+)["\']/i', $html, $m)) $fId = $m[1];
        $result['analytics'][] = ['name' => 'Fathom Analytics', 'id' => $fId];
    }

    if (preg_match('/<script[^>]+src=["\'][^"\']*(plausible\.io|plausible\.js)/i', $html)) $result['analytics'][] = ['name' => 'Plausible', 'id' => null];
    if (preg_match('/matomo\.js|piwik\.js/i', $html)) $result['analytics'][] = ['name' => 'Matomo', 'id' => null];
    if (preg_match('/static\.hotjar\.com/i', $html)) $result['analytics'][] = ['name' => 'Hotjar', 'id' => null];
    if (preg_match('/cdn\.mxpnl\.com/i', $html)) $result['analytics'][] = ['name' => 'Mixpanel', 'id' => null];
    if (preg_match('/cdn\.segment\.com\/analytics\.js/i', $html)) $result['analytics'][] = ['name' => 'Segment', 'id' => null];
    if (preg_match('/connect\.facebook\.net\/[^\/]+\/fbevents\.js/i', $html)) $result['analytics'][] = ['name' => 'Facebook Pixel', 'id' => null];

    if (preg_match('/<script[^>]+type=["\']text\/x-magento-init["\']|Mage\.Cookies|static\/version[a-z0-9]+\/frontend/i', $html) || 
        (isset($h['set-cookie']) && stripos($h['set-cookie'], 'mage-') !== false)) {
        $result['ecommerce'][] = 'Magento';
    }
    if (preg_match('/cdn\.shopify\.com|Shopify\.theme/i', $html)) $result['ecommerce'][] = 'Shopify';
    if (preg_match('/bigcommerce\.com\/r\//i', $html)) $result['ecommerce'][] = 'BigCommerce';
    if (preg_match('/<meta[^>]+content="WooCommerce|woocommerce-page|wc-block/i', $html)) $result['ecommerce'][] = 'WooCommerce';
    if (preg_match('/var prestashop =/i', $html)) $result['ecommerce'][] = 'PrestaShop';
    if (preg_match('/route=common\/home/i', $html)) $result['ecommerce'][] = 'OpenCart';
    if (preg_match('/js\.stripe\.com/i', $html)) $result['ecommerce'][] = 'Stripe';

    if (preg_match('/widget\.intercom\.io/i', $html)) $result['widgets'][] = 'Intercom';
    if (preg_match('/js\.drift\.com/i', $html)) $result['widgets'][] = 'Drift';
    if (preg_match('/client\.crisp\.chat/i', $html)) $result['widgets'][] = 'Crisp';
    if (preg_match('/embed\.tawk\.to/i', $html)) $result['widgets'][] = 'Tawk.to';
    if (preg_match('/cdn\.livechatinc\.com/i', $html)) $result['widgets'][] = 'LiveChat';
    if (preg_match('/static\.zdassets\.com/i', $html)) $result['widgets'][] = 'Zendesk';
    if (preg_match('/js\.hs-scripts\.com/i', $html)) $result['widgets'][] = 'HubSpot';
    if (preg_match('/typeform\.com\/embed/i', $html)) $result['widgets'][] = 'Typeform';

    return $result;
}

function detectMetadata($domain, $html = null, &$rawFiles = []) {
    $result = [
        'robots_txt' => null,
        'sitemap' => null,
        'security_txt' => null,
        'ads_txt' => null,
        'app_ads_txt' => null,
        'app_site_association' => null,
        'assetlinks' => null,
        'manifest' => null,
        'webfinger' => null,
        'change_password' => null,
        'humans_txt' => null,
        'browserconfig' => null,
        'keybase_txt' => null,
        'meta_tags' => [],
        'favicon' => null
    ];
    $rawFiles = ['robots_txt' => null, 'sitemap_xml' => null, 'security_txt' => null, 'ads_txt' => null, 'app_ads_txt' => null, 'app_site_association' => null, 'assetlinks' => null, 'manifest' => null, 'humans_txt' => null, 'browserconfig' => null, 'keybase_txt' => null, 'favicon' => null];

    $ctx = stream_context_create([
        'http' => ['timeout' => 2, 'ignore_errors' => true],
        'ssl' => ['verify_peer' => false, 'verify_peer_name' => false]
    ]);

    // Check robots.txt
    $robots = @file_get_contents("https://" . $domain . "/robots.txt", false, $ctx);
    if (!$robots) $robots = @file_get_contents("http://" . $domain . "/robots.txt", false, $ctx);
    if ($robots && stripos($robots, 'user-agent') !== false) {
        $rawFiles['robots_txt'] = $robots;
        $disallows = [];
        $sitemaps = [];
        foreach (explode("\n", $robots) as $line) {
            $line = trim($line);
            if (preg_match('/^Disallow:\s*(.+)/i', $line, $m)) {
                $path = trim($m[1]);
                if (!empty($path) && $path !== '/') $disallows[] = $path;
            }
            if (preg_match('/^Sitemap:\s*(.+)/i', $line, $m)) {
                $sitemaps[] = trim($m[1]);
            }
        }
        $result['robots_txt'] = [
            'present' => true,
            'disallow_count' => count($disallows),
            'disallows' => array_slice(array_unique($disallows), 0, 20),
            'sitemaps' => array_slice($sitemaps, 0, 5)
        ];
    } else {
        $result['robots_txt'] = ['present' => false];
    }

    // Check sitemap.xml
    $sitemapUrl = "https://" . $domain . "/sitemap.xml";
    $fromRobots = false;
    
    // If robots.txt declared a sitemap, prioritize the first one found
    if (!empty($result['robots_txt']['sitemaps'])) {
        $sitemapUrl = $result['robots_txt']['sitemaps'][0];
        $fromRobots = true;
    }

    // Increase timeout slightly for sitemaps as they can be larger/slower
    $sitemapCtx = stream_context_create([
        'http' => ['timeout' => 5, 'ignore_errors' => true, 'follow_location' => 1],
        'ssl' => ['verify_peer' => false, 'verify_peer_name' => false]
    ]);

    $sitemapContent = @file_get_contents($sitemapUrl, false, $sitemapCtx);

    // Fallback: If not found via robots.txt and HTTPS default failed, try HTTP default
    if (!$sitemapContent && !$fromRobots) {
         $sitemapContent = @file_get_contents("http://" . $domain . "/sitemap.xml", false, $sitemapCtx);
    }

    // Validate and Store
    if ($sitemapContent && (stripos($sitemapContent, '<urlset') !== false || stripos($sitemapContent, '<sitemapindex') !== false)) {
        $rawFiles['sitemap_xml'] = $sitemapContent;
        $urlCount = substr_count($sitemapContent, '<url>') + substr_count($sitemapContent, '<sitemap>');
        $result['sitemap'] = [
            'present' => true, 
            'url' => $sitemapUrl, 
            'url_count' => $urlCount,
            // Keep the urls array if it came from robots, but we now also have the raw content
            'urls' => $fromRobots ? $result['robots_txt']['sitemaps'] : null
        ];
    } elseif ($fromRobots) {
        // We failed to download it, but robots.txt says it exists
        $result['sitemap'] = ['present' => true, 'urls' => $result['robots_txt']['sitemaps']];
    } else {
        $result['sitemap'] = ['present' => false];
    }

    // Check security.txt
    $securityTxt = @file_get_contents("https://" . $domain . "/.well-known/security.txt", false, $ctx);
    if (!$securityTxt) $securityTxt = @file_get_contents("https://" . $domain . "/security.txt", false, $ctx);
    if ($securityTxt && (stripos($securityTxt, 'contact:') !== false || stripos($securityTxt, 'policy:') !== false)) {
        $rawFiles['security_txt'] = $securityTxt;
        $contact = null;
        $policy = null;
        foreach (explode("\n", $securityTxt) as $line) {
            if (preg_match('/^Contact:\s*(.+)/i', $line, $m)) $contact = trim($m[1]);
            if (preg_match('/^Policy:\s*(.+)/i', $line, $m)) $policy = trim($m[1]);
        }
        $result['security_txt'] = ['present' => true, 'contact' => $contact, 'policy' => $policy];
    } else {
        $result['security_txt'] = ['present' => false];
    }

    // Check ads.txt (IAB Authorized Digital Sellers)
    $adsTxt = @file_get_contents("https://" . $domain . "/ads.txt", false, $ctx);
    if (!$adsTxt) $adsTxt = @file_get_contents("http://" . $domain . "/ads.txt", false, $ctx);
    if ($adsTxt && preg_match('/^[a-z0-9.-]+,\s*[a-z0-9]+,/im', $adsTxt)) {
        $rawFiles['ads_txt'] = $adsTxt;
        $sellers = [];
        $directCount = 0;
        $resellerCount = 0;
        foreach (explode("\n", $adsTxt) as $line) {
            $line = trim($line);
            if (empty($line) || $line[0] === '#') continue;
            if (preg_match('/^([a-z0-9.-]+),\s*([a-z0-9]+),\s*(DIRECT|RESELLER)/i', $line, $m)) {
                $domain_name = strtolower($m[1]);
                if (!in_array($domain_name, $sellers)) $sellers[] = $domain_name;
                if (strtoupper($m[3]) === 'DIRECT') $directCount++;
                else $resellerCount++;
            }
        }
        $result['ads_txt'] = [
            'present' => true,
            'seller_count' => count($sellers),
            'direct_count' => $directCount,
            'reseller_count' => $resellerCount,
            'sellers' => array_slice($sellers, 0, 10)
        ];
    } else {
        $result['ads_txt'] = ['present' => false];
    }

    // Check app-ads.txt (IAB Authorized Digital Sellers for Apps)
    $appAdsTxt = @file_get_contents("https://" . $domain . "/app-ads.txt", false, $ctx);
    if (!$appAdsTxt) $appAdsTxt = @file_get_contents("http://" . $domain . "/app-ads.txt", false, $ctx);
    if ($appAdsTxt && preg_match('/^[a-z0-9.-]+,\s*[a-z0-9]+,/im', $appAdsTxt)) {
        $rawFiles['app_ads_txt'] = $appAdsTxt;
        $sellers = [];
        $directCount = 0;
        $resellerCount = 0;
        foreach (explode("\n", $appAdsTxt) as $line) {
            $line = trim($line);
            if (empty($line) || $line[0] === '#') continue;
            if (preg_match('/^([a-z0-9.-]+),\s*([a-z0-9]+),\s*(DIRECT|RESELLER)/i', $line, $m)) {
                $domain_name = strtolower($m[1]);
                if (!in_array($domain_name, $sellers)) $sellers[] = $domain_name;
                if (strtoupper($m[3]) === 'DIRECT') $directCount++;
                else $resellerCount++;
            }
        }
        $result['app_ads_txt'] = [
            'present' => true,
            'seller_count' => count($sellers),
            'direct_count' => $directCount,
            'reseller_count' => $resellerCount,
            'sellers' => array_slice($sellers, 0, 10)
        ];
    } else {
        $result['app_ads_txt'] = ['present' => false];
    }

    // Check apple-app-site-association (iOS Universal Links)
    $aasa = @file_get_contents("https://" . $domain . "/.well-known/apple-app-site-association", false, $ctx);
    if (!$aasa) $aasa = @file_get_contents("https://" . $domain . "/apple-app-site-association", false, $ctx);
    if ($aasa) {
        $aasaData = @json_decode($aasa, true);
        if ($aasaData && (isset($aasaData['applinks']) || isset($aasaData['webcredentials']) || isset($aasaData['appclips']))) {
            $rawFiles['app_site_association'] = $aasa;
            $appIds = [];
            // Extract app IDs from applinks
            if (isset($aasaData['applinks']['details'])) {
                foreach ($aasaData['applinks']['details'] as $detail) {
                    if (isset($detail['appID'])) $appIds[] = $detail['appID'];
                    if (isset($detail['appIDs'])) $appIds = array_merge($appIds, $detail['appIDs']);
                }
            }
            // Also check older format
            if (isset($aasaData['applinks']['apps'])) {
                $appIds = array_merge($appIds, $aasaData['applinks']['apps']);
            }
            // Check webcredentials
            if (isset($aasaData['webcredentials']['apps'])) {
                $appIds = array_merge($appIds, $aasaData['webcredentials']['apps']);
            }
            $appIds = array_unique(array_filter($appIds));
            $result['app_site_association'] = [
                'present' => true,
                'has_applinks' => isset($aasaData['applinks']),
                'has_webcredentials' => isset($aasaData['webcredentials']),
                'has_appclips' => isset($aasaData['appclips']),
                'app_ids' => array_slice(array_values($appIds), 0, 5)
            ];
        } else {
            $result['app_site_association'] = ['present' => false];
        }
    } else {
        $result['app_site_association'] = ['present' => false];
    }

    // Check assetlinks.json (Android App Links)
    $assetlinks = @file_get_contents("https://" . $domain . "/.well-known/assetlinks.json", false, $ctx);
    if ($assetlinks) {
        $assetlinksData = @json_decode($assetlinks, true);
        if ($assetlinksData && is_array($assetlinksData) && count($assetlinksData) > 0) {
            $rawFiles['assetlinks'] = $assetlinks;
            $packages = [];
            foreach ($assetlinksData as $entry) {
                if (isset($entry['target']['package_name'])) {
                    $packages[] = $entry['target']['package_name'];
                }
            }
            $packages = array_unique($packages);
            $result['assetlinks'] = [
                'present' => true,
                'entry_count' => count($assetlinksData),
                'packages' => array_slice(array_values($packages), 0, 5)
            ];
        } else {
            $result['assetlinks'] = ['present' => false];
        }
    } else {
        $result['assetlinks'] = ['present' => false];
    }

    // Check webfinger (Fediverse/Mastodon identity)
    // We check if the endpoint exists by querying for a dummy resource
    $webfingerCtx = stream_context_create([
        'http' => ['timeout' => 2, 'ignore_errors' => true, 'follow_location' => 0],
        'ssl' => ['verify_peer' => false, 'verify_peer_name' => false]
    ]);
    
    // Check for a non-existent user to see how the server handles it
    // A valid WebFinger server should return 404 (User not found) but with JSON content
    // Or 200 if we happen to hit a real user, also with JSON content
    $webfinger = @file_get_contents("https://" . $domain . "/.well-known/webfinger?resource=acct:periscope_check@" . $domain, false, $webfingerCtx);
    $webfingerHeaders = $http_response_header ?? [];
    $webfingerStatus = 0;
    $webfingerContentType = '';

    if (!empty($webfingerHeaders[0]) && preg_match('/HTTP\/\d\.?\d?\s+(\d{3})/', $webfingerHeaders[0], $m)) {
        $webfingerStatus = (int)$m[1];
    }

    // Extract Content-Type
    foreach ($webfingerHeaders as $header) {
        if (stripos($header, 'Content-Type:') === 0) {
            $webfingerContentType = strtolower(trim(substr($header, 13)));
            break;
        }
    }

    // It is only WebFinger if:
    // 1. Status is 200 (OK) OR 404 (User not found - valid endpoint) OR 400 (Bad Request - valid endpoint)
    // 2. AND Content-Type contains 'json' (application/jrd+json or application/json)
    // A standard WordPress 404 will be status 404 but Content-Type text/html -> This will now fail correctly.
    if (($webfingerStatus === 200 || $webfingerStatus === 404 || $webfingerStatus === 400) && 
        strpos($webfingerContentType, 'json') !== false) {
        
        $result['webfinger'] = [
            'present' => true,
            'status' => $webfingerStatus,
            'content_type' => $webfingerContentType
        ];
    } else {
        $result['webfinger'] = ['present' => false];
    }

    // Check change-password (security best practice)
    $changePassCtx = stream_context_create([
        'http' => ['timeout' => 2, 'ignore_errors' => true, 'follow_location' => 0],
        'ssl' => ['verify_peer' => false, 'verify_peer_name' => false]
    ]);
    @file_get_contents("https://" . $domain . "/.well-known/change-password", false, $changePassCtx);
    $changePassHeaders = $http_response_header ?? [];
    $changePassStatus = 0;
    $changePassRedirect = null;
    if (!empty($changePassHeaders[0]) && preg_match('/HTTP\/\d\.?\d?\s+(\d{3})/', $changePassHeaders[0], $m)) {
        $changePassStatus = (int)$m[1];
    }
    // Check for redirect location
    foreach ($changePassHeaders as $header) {
        if (preg_match('/^Location:\s*(.+)/i', $header, $m)) {
            $changePassRedirect = trim($m[1]);
            break;
        }
    }
    if ($changePassStatus >= 200 && $changePassStatus < 500) {
        $result['change_password'] = [
            'present' => true,
            'status' => $changePassStatus,
            'redirect' => $changePassRedirect
        ];
    } else {
        $result['change_password'] = ['present' => false];
    }

    // Check humans.txt (team credits)
    $humansTxt = @file_get_contents("https://" . $domain . "/humans.txt", false, $ctx);
    if (!$humansTxt) $humansTxt = @file_get_contents("http://" . $domain . "/humans.txt", false, $ctx);
    if ($humansTxt && strlen($humansTxt) > 10 && strlen($humansTxt) < 50000 && !preg_match('/<html|<!DOCTYPE/i', $humansTxt)) {
        $rawFiles['humans_txt'] = $humansTxt;
        $result['humans_txt'] = ['present' => true];
    } else {
        $result['humans_txt'] = ['present' => false];
    }

    // Check browserconfig.xml (Windows tiles)
    $browserconfig = @file_get_contents("https://" . $domain . "/browserconfig.xml", false, $ctx);
    if (!$browserconfig) $browserconfig = @file_get_contents("http://" . $domain . "/browserconfig.xml", false, $ctx);
    if ($browserconfig && stripos($browserconfig, '<browserconfig') !== false) {
        $rawFiles['browserconfig'] = $browserconfig;
        $tileColor = null;
        if (preg_match('/<TileColor>([^<]+)<\/TileColor>/i', $browserconfig, $m)) {
            $tileColor = trim($m[1]);
        }
        $result['browserconfig'] = ['present' => true, 'tile_color' => $tileColor];
    } else {
        $result['browserconfig'] = ['present' => false];
    }

    // Check keybase.txt (identity verification)
    $keybaseTxt = @file_get_contents("https://" . $domain . "/.well-known/keybase.txt", false, $ctx);
    if (!$keybaseTxt) $keybaseTxt = @file_get_contents("https://" . $domain . "/keybase.txt", false, $ctx);
    if ($keybaseTxt && preg_match('/==BEGIN.*KEYBASE|keybase\.io\/[a-z0-9_]+/i', $keybaseTxt)) {
        $rawFiles['keybase_txt'] = $keybaseTxt;
        $username = null;
        if (preg_match('/keybase\.io\/([a-z0-9_]+)/i', $keybaseTxt, $m)) {
            $username = $m[1];
        }
        $result['keybase_txt'] = ['present' => true, 'username' => $username];
    } else {
        $result['keybase_txt'] = ['present' => false];
    }

    // Parse meta tags from HTML
    if ($html) {
        // Open Graph
        $og = [];
        $ogImageSource = null;
        if (preg_match('/<meta[^>]+property=["\']og:title["\'][^>]+content=["\']([^"\']+)/i', $html, $m)) $og['title'] = $m[1];
        if (preg_match('/<meta[^>]+property=["\']og:description["\'][^>]+content=["\']([^"\']+)/i', $html, $m)) $og['description'] = $m[1];
        if (preg_match('/<meta[^>]+property=["\']og:image["\'][^>]+content=["\']([^"\']+)/i', $html, $m)) {
            $og['image'] = $m[1];
            $ogImageSource = 'og:image';
        }
        if (preg_match('/<meta[^>]+property=["\']og:type["\'][^>]+content=["\']([^"\']+)/i', $html, $m)) $og['type'] = $m[1];

        // Download and store OG image
        if (isset($og['image']) && $og['image']) {
            if ($ogImageSource && $ogImageSource !== 'og:image') {
                $og['image_source'] = $ogImageSource;
            }
            $ogImageUrl = $og['image'];
            // Handle relative and protocol-relative URLs
            if (strpos($ogImageUrl, '//') === 0) {
                $ogImageUrl = 'https:' . $ogImageUrl;
            } elseif (strpos($ogImageUrl, '/') === 0) {
                $ogImageUrl = 'https://' . $domain . $ogImageUrl;
            } elseif (strpos($ogImageUrl, 'http') !== 0) {
                $ogImageUrl = 'https://' . $domain . '/' . $ogImageUrl;
            }
            $ogImageData = downloadImage($ogImageUrl);
            if ($ogImageData) {
                $stored = storeFileByHash($domain, $ogImageData['content'], $ogImageData['extension']);
                $og['image_hash'] = $stored['hash'];
                $og['image_extension'] = $stored['extension'];
                $og['image_size'] = $stored['size'];
            }
        }

        if (!empty($og)) $result['meta_tags']['open_graph'] = $og;

        // Twitter Cards
        $twitter = [];
        if (preg_match('/<meta[^>]+name=["\']twitter:card["\'][^>]+content=["\']([^"\']+)/i', $html, $m)) $twitter['card'] = $m[1];
        if (preg_match('/<meta[^>]+name=["\']twitter:site["\'][^>]+content=["\']([^"\']+)/i', $html, $m)) $twitter['site'] = $m[1];
        if (preg_match('/<meta[^>]+name=["\']twitter:title["\'][^>]+content=["\']([^"\']+)/i', $html, $m)) $twitter['title'] = $m[1];
        if (preg_match('/<meta[^>]+name=["\']twitter:image["\'][^>]+content=["\']([^"\']+)/i', $html, $m)) $twitter['image'] = $m[1];

        // Download and store Twitter image if different from OG
        if (isset($twitter['image']) && $twitter['image'] && $twitter['image'] !== ($og['image'] ?? '')) {
            $twitterImageUrl = $twitter['image'];
            // Handle relative and protocol-relative URLs
            if (strpos($twitterImageUrl, '//') === 0) {
                $twitterImageUrl = 'https:' . $twitterImageUrl;
            } elseif (strpos($twitterImageUrl, '/') === 0) {
                $twitterImageUrl = 'https://' . $domain . $twitterImageUrl;
            } elseif (strpos($twitterImageUrl, 'http') !== 0) {
                $twitterImageUrl = 'https://' . $domain . '/' . $twitterImageUrl;
            }
            $twitterImageData = downloadImage($twitterImageUrl);
            if ($twitterImageData) {
                $stored = storeFileByHash($domain, $twitterImageData['content'], $twitterImageData['extension']);
                $twitter['image_hash'] = $stored['hash'];
                $twitter['image_extension'] = $stored['extension'];
                $twitter['image_size'] = $stored['size'];
            }
        }

        if (!empty($twitter)) $result['meta_tags']['twitter'] = $twitter;

        // Basic meta
        $basic = [];
        if (preg_match('/<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']+)/i', $html, $m)) $basic['description'] = substr($m[1], 0, 200);
        if (preg_match('/<meta[^>]+name=["\']keywords["\'][^>]+content=["\']([^"\']+)/i', $html, $m)) $basic['keywords'] = substr($m[1], 0, 200);
        if (preg_match('/<meta[^>]+name=["\']author["\'][^>]+content=["\']([^"\']+)/i', $html, $m)) $basic['author'] = $m[1];
        if (preg_match('/<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)/i', $html, $m)) $basic['generator'] = $m[1];
        if (preg_match('/<title[^>]*>([^<]+)<\/title>/i', $html, $m)) $basic['title'] = trim($m[1]);
        if (!empty($basic)) $result['meta_tags']['basic'] = $basic;

        // Canonical URL
        if (preg_match('/<link[^>]+rel=["\']canonical["\'][^>]+href=["\']([^"\']+)/i', $html, $m)) {
            $result['meta_tags']['canonical'] = $m[1];
        }
    }

    // Check manifest.json / site.webmanifest (PWA)
    $manifestUrl = null;
    $manifest = null;
    // First check HTML for link rel="manifest"
    if ($html && preg_match('/<link[^>]+rel=["\']manifest["\'][^>]+href=["\']([^"\']+)/i', $html, $m)) {
        $manifestUrl = $m[1];
        if (strpos($manifestUrl, '//') === false) {
            $manifestUrl = "https://" . $domain . (strpos($manifestUrl, '/') === 0 ? '' : '/') . $manifestUrl;
        }
        $manifest = @file_get_contents($manifestUrl, false, $ctx);
    }
    // Fallback to common locations
    if (!$manifest) {
        $manifest = @file_get_contents("https://" . $domain . "/manifest.json", false, $ctx);
        if ($manifest) $manifestUrl = '/manifest.json';
    }
    if (!$manifest) {
        $manifest = @file_get_contents("https://" . $domain . "/site.webmanifest", false, $ctx);
        if ($manifest) $manifestUrl = '/site.webmanifest';
    }
    if ($manifest) {
        $manifestData = @json_decode($manifest, true);
        if ($manifestData && (isset($manifestData['name']) || isset($manifestData['short_name']))) {
            $rawFiles['manifest'] = $manifest;
            $result['manifest'] = [
                'present' => true,
                'url' => $manifestUrl,
                'name' => $manifestData['name'] ?? $manifestData['short_name'] ?? null,
                'short_name' => $manifestData['short_name'] ?? null,
                'display' => $manifestData['display'] ?? null,
                'theme_color' => $manifestData['theme_color'] ?? null,
                'background_color' => $manifestData['background_color'] ?? null,
                'start_url' => $manifestData['start_url'] ?? null,
                'icon_count' => isset($manifestData['icons']) ? count($manifestData['icons']) : 0
            ];
        } else {
            $result['manifest'] = ['present' => false];
        }
    } else {
        $result['manifest'] = ['present' => false];
    }

    // Favicon detection - prefer high-quality icons from HTML, fallback to /favicon.ico
    $favicon = null;
    $faviconUrl = null;
    $faviconSource = null;

    if ($html) {
        // Parse all icon links from HTML with their sizes
        $iconCandidates = [];

        // Match rel="icon" with sizes attribute
        if (preg_match_all('/<link[^>]+rel=["\'](?:shortcut )?icon["\'][^>]*>/i', $html, $matches)) {
            foreach ($matches[0] as $tag) {
                if (preg_match('/href=["\']([^"\']+)/i', $tag, $hrefMatch)) {
                    $url = $hrefMatch[1];
                    $hasExplicitSize = false;
                    $size = 128; // default for icons without sizes (assume decent quality)
                    if (preg_match('/sizes=["\'](\d+)x\d+/i', $tag, $sizeMatch)) {
                        $size = (int)$sizeMatch[1];
                        $hasExplicitSize = true;
                    }
                    // Boost priority for modern high-quality formats without explicit sizes
                    if (!$hasExplicitSize && preg_match('/\.(webp|png|svg)(\?|$)/i', $url)) {
                        $size = 192; // prefer these formats
                    }
                    $iconCandidates[] = ['url' => $url, 'size' => $size, 'type' => 'icon'];
                }
            }
        }

        // Match apple-touch-icon (usually 180x180)
        if (preg_match_all('/<link[^>]+rel=["\']apple-touch-icon["\'][^>]*>/i', $html, $matches)) {
            foreach ($matches[0] as $tag) {
                if (preg_match('/href=["\']([^"\']+)/i', $tag, $hrefMatch)) {
                    $size = 180; // default for apple-touch-icon
                    if (preg_match('/sizes=["\'](\d+)x\d+/i', $tag, $sizeMatch)) {
                        $size = (int)$sizeMatch[1];
                    }
                    $iconCandidates[] = ['url' => $hrefMatch[1], 'size' => $size, 'type' => 'apple-touch-icon'];
                }
            }
        }

        // Sort by size descending to prefer larger icons
        usort($iconCandidates, fn($a, $b) => $b['size'] - $a['size']);

        // Try to download the best icon
        foreach ($iconCandidates as $candidate) {
            $url = $candidate['url'];
            // Handle relative URLs
            if (strpos($url, '//') === 0) {
                $url = 'https:' . $url;
            } elseif (strpos($url, '/') === 0) {
                $url = 'https://' . $domain . $url;
            } elseif (strpos($url, 'http') !== 0) {
                $url = 'https://' . $domain . '/' . $url;
            }

            $iconData = downloadImage($url, 500000);
            if ($iconData && $iconData['content']) {
                $favicon = $iconData['content'];
                $faviconUrl = $candidate['url'];
                $faviconSource = $candidate['type'] . ' (' . $candidate['size'] . 'x' . $candidate['size'] . ')';
                break;
            }
        }
    }

    // Fallback to /favicon.ico if no HTML icon found
    if (!$favicon) {
        $favicon = @file_get_contents("https://" . $domain . "/favicon.ico", false, $ctx);
        if (!$favicon) $favicon = @file_get_contents("http://" . $domain . "/favicon.ico", false, $ctx);
        if ($favicon) {
            $faviconUrl = '/favicon.ico';
            $faviconSource = 'favicon.ico';
        }
    }

    if ($favicon && strlen($favicon) > 0 && strlen($favicon) < 500000) {
        $rawFiles['favicon'] = $favicon;

        // Detect actual format from magic bytes
        $extension = 'ico';
        if (substr($favicon, 0, 8) === "\x89PNG\r\n\x1a\n") $extension = 'png';
        elseif (substr($favicon, 0, 3) === "\xff\xd8\xff") $extension = 'jpg';
        elseif (substr($favicon, 0, 4) === "GIF8") $extension = 'gif';
        elseif (substr($favicon, 0, 4) === "RIFF" && substr($favicon, 8, 4) === "WEBP") $extension = 'webp';

        // Store in hash-based location
        $stored = storeFileByHash($domain, $favicon, $extension);
        $result['favicon'] = [
            'present' => true,
            'hash' => $stored['hash'],
            'extension' => $extension,
            'size' => $stored['size'],
            'source' => $faviconSource
        ];
    } else {
        $result['favicon'] = ['present' => false];
    }

    return $result;
}

/**
 * Detect if a website is blocking search engine indexing
 * Checks: robots.txt (Disallow: /), meta robots noindex, X-Robots-Tag header
 */
function detectSearchEngineBlocking($html, $headers, $robotsTxt = null) {
    $result = [
        'blocked' => false,
        'reasons' => []
    ];

    // Check X-Robots-Tag header
    foreach ($headers as $name => $value) {
        if (strtolower($name) === 'x-robots-tag') {
            if (preg_match('/noindex/i', $value)) {
                $result['blocked'] = true;
                $result['reasons'][] = ['type' => 'header', 'detail' => 'X-Robots-Tag: noindex'];
            }
        }
    }

    // Check meta robots tag in HTML
    if ($html) {
        // Match both name="robots" and name="googlebot" etc.
        if (preg_match('/<meta[^>]+name=["\']robots["\'][^>]+content=["\']([^"\']+)["\'][^>]*>/i', $html, $m) ||
            preg_match('/<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\']robots["\'][^>]*>/i', $html, $m)) {
            $content = strtolower($m[1]);
            if (strpos($content, 'noindex') !== false) {
                $result['blocked'] = true;
                $result['reasons'][] = ['type' => 'meta', 'detail' => 'meta robots: noindex'];
            }
        }
    }

    // Check robots.txt for blanket disallow
    if ($robotsTxt) {
        $lines = explode("\n", $robotsTxt);
        $currentAgent = '';
        $disallowAll = false;

        foreach ($lines as $line) {
            $line = trim($line);
            if (empty($line) || $line[0] === '#') continue;

            if (preg_match('/^User-agent:\s*(.+)/i', $line, $m)) {
                $currentAgent = strtolower(trim($m[1]));
            } elseif (preg_match('/^Disallow:\s*\/\s*$/i', $line)) {
                // Disallow: / (root = everything)
                if ($currentAgent === '*') {
                    $disallowAll = true;
                }
            }
        }

        if ($disallowAll) {
            $result['blocked'] = true;
            $result['reasons'][] = ['type' => 'robots_txt', 'detail' => 'robots.txt: Disallow: /'];
        }
    }

    return $result;
}

function computeFromRaw($raw, $domain, $timestamp = null, $saveCache = true) {
    $html = $raw['html'] ?: '';
    $headers = $raw['headers'] ?: [];
    $whoisDomain = $raw['whois_domain'] ?: '';
    $rdapJson = $raw['rdap'] ?? null;
    $rawSsl = $raw['ssl'] ?: '';
    $dnsRecords = $raw['dns']['records'] ?? [];
    $zoneFile = $raw['dns']['zone'] ?? '';

    // Parse IP lookup from stored whois_ips
    $ip_lookup = [];
    if (!empty($raw['whois_ips'])) {
        foreach ($raw['whois_ips'] as $ip => $whoisOutput) {
            // Extract OrgName/NetName/Organization from raw whois
            $res = '';
            foreach (explode("\n", $whoisOutput) as $line) {
                if (preg_match('/^(OrgName|NetName|Organization):\s*(.+)/i', $line, $m)) {
                    $res = trim($m[0]);
                    break;
                }
            }
            $ip_lookup[$ip] = $res ?: 'N/A';
        }
    }
    
    // Load PTR records
    $ptr_records = $raw['ptr_records'] ?? [];

    // Parse domain WHOIS: prefer RDAP, fallback to raw whois
    $domainData = [];
    if ($rdapJson) {
        $domainData = parseRdap($rdapJson);
    }
    if (empty($domainData) && $whoisDomain) {
        $domainData = parseRawWhois($whoisDomain);
    }

    $metadataRawFiles = [];
    $metadata = detectMetadata($domain, $html, $metadataRawFiles);
    $robotsTxtContent = $raw['robots_txt'] ?? ($metadataRawFiles['robots_txt'] ?? null);

    $data = [
        'domain' => $domainData,
        'dns_records' => $dnsRecords,
        'zone' => $zoneFile,
        'ip_lookup' => $ip_lookup,
        'ptr_records' => $ptr_records,
        'http_headers' => $headers,
        'ssl' => getSSLInfo($domain, $rawSsl),
        'cms' => detectCMS($domain, $html, $headers),
        'infrastructure' => detectInfrastructure($headers),
        'security' => detectSecurityHeaders($headers),
        'technology' => detectTechnology($html, $headers),
        'metadata' => $metadata,
        'indexability' => detectSearchEngineBlocking($html, $headers, $robotsTxtContent),
        'errors' => [],
        'raw_available' => true,
        'plugin_version' => PERISCOPE_VERSION
    ];

    // Save cache if we have timestamp info
    if ($saveCache && $timestamp) {
        $path = getScanPath($domain, $timestamp);
        saveResponseCache($path, $data);
    }

    return $data;
}

function performLookup($domain) {
    $errors = []; $raw_records = []; $check_map = [];

    // Normalize input and extract target host vs root domain
    $targetHost = normalizeInput($domain);
    $rootDomain = extractRootDomain($targetHost);
    $isSubdomain = ($targetHost !== $rootDomain);

    // SAFETY CHECK: Abort if domain is empty or invalid
    if (empty($targetHost) || empty($rootDomain) || !preg_match('/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/i', $targetHost)) {
        return ['error' => 'Invalid or empty domain', 'domain' => [], 'dns_records' => [], 'zone' => '', 'errors' => ['Invalid domain provided']];
    }

    cliProgress('Checking domain registration...');
    
    // Check if domain exists via RDAP
    $domainCheck = checkDomainExists($rootDomain);
    
    if (!$domainCheck['exists']) {
        cliProgressDone('Domain not registered');
        $timestamp = time();
        $result = [
            'target_host' => $targetHost,
            'root_domain' => $rootDomain,
            'is_subdomain' => $isSubdomain,
            'domain_exists' => false,
            'domain' => [],
            'dns_records' => [],
            'zone' => '',
            'ip_lookup' => [],
            'http_headers' => [],
            'ssl' => [],
            'cms' => [],
            'infrastructure' => [],
            'security' => [],
            'technology' => [],
            'metadata' => [],
            'redirect_chain' => [],
            'indexability' => [],
            'errors' => [],
            'timestamp' => $timestamp,
            'raw_available' => false,
            'plugin_version' => PERISCOPE_VERSION
        ];
        
        // Save response cache so it can be loaded from history
        $scanPath = getScanPath($targetHost, $timestamp);
        if (!is_dir($scanPath)) mkdir($scanPath, 0755, true);
        saveResponseCache($scanPath, $result);
        
        return $result;
    }
    
    // Store RDAP result for later use
    $cachedRdap = $domainCheck['rdap'] ?? null;

    cliProgress('Scanning DNS records...');

    // Check for wildcard A record on root domain
    $wildcardA = digQuery('A', "*.$rootDomain");
    $hasWildcardA = !empty(trim($wildcardA));

    // If wildcard A exists, record it
    if ($hasWildcardA) {
        foreach (explode("\n", trim($wildcardA)) as $val) {
            $val = trim($val); if (empty($val)) continue;
            // Skip if it looks like a hostname (CNAME target returned by dig)
            if (preg_match('/[a-zA-Z]/', $val) && substr($val, -1) === '.') continue;
            $key = "A|*|$val"; if (isset($check_map[$key])) continue;
            $check_map[$key] = true;
            $raw_records[] = ['type' => 'A', 'name' => '*', 'value' => $val];
        }
    }

    // Check for wildcard TXT record on root domain
    $wildcardTXT = digQuery('TXT', "*.$rootDomain");
    $wildcardTXTValue = null;
    if (!empty(trim($wildcardTXT))) {
        $wildcardTXTValue = trim($wildcardTXT);
        // Record the wildcard TXT
        $key = "TXT|*|$wildcardTXTValue";
        if (!isset($check_map[$key])) {
            $check_map[$key] = true;
            $raw_records[] = ['type' => 'TXT', 'name' => '*', 'value' => $wildcardTXTValue];
        }
    }

    // Check for wildcard CNAME record on root domain
    $wildcardCNAME = digQuery('CNAME', "*.$rootDomain");
    $wildcardCNAMEValue = null;
    if (!empty(trim($wildcardCNAME))) {
        $wildcardCNAMEValue = trim(explode("\n", trim($wildcardCNAME))[0]);
        // Record the wildcard CNAME
        $key = "CNAME|*|$wildcardCNAMEValue";
        if (!isset($check_map[$key])) {
            $check_map[$key] = true;
            $raw_records[] = ['type' => 'CNAME', 'name' => '*', 'value' => $wildcardCNAMEValue];
        }
    }

    $checks = [
        // Core records (skip wildcard since we already checked it)
        ['type' => 'A', 'name' => ''], ['type' => 'A', 'name' => 'www'],
        ['type' => 'AAAA', 'name' => ''], ['type' => 'AAAA', 'name' => 'www'],
        ['type' => 'NS', 'name' => ''], ['type' => 'SOA', 'name' => ''], ['type' => 'MX', 'name' => ''], ['type' => 'TXT', 'name' => ''],
        ['type' => 'CAA', 'name' => ''],
        ['type' => 'HTTPS', 'name' => ''], ['type' => 'SVCB', 'name' => ''],
        ['type' => 'TLSA', 'name' => '_443._tcp'], ['type' => 'TLSA', 'name' => '_25._tcp'],

        // Common subdomains
        ['type' => 'A', 'name' => 'mail'], ['type' => 'A', 'name' => 'webmail'], ['type' => 'A', 'name' => 'smtp'],
        ['type' => 'A', 'name' => 'imap'], ['type' => 'A', 'name' => 'ftp'], ['type' => 'A', 'name' => 'cpanel'],
        ['type' => 'A', 'name' => 'whm'], ['type' => 'A', 'name' => 'plesk'], ['type' => 'A', 'name' => 'blog'],
        ['type' => 'A', 'name' => 'shop'], ['type' => 'A', 'name' => 'portal'], ['type' => 'A', 'name' => 'dev'],
        ['type' => 'A', 'name' => 'api'], ['type' => 'A', 'name' => 'app'], ['type' => 'A', 'name' => 'remote'],
        ['type' => 'A', 'name' => 'vpn'],

        // Additional subdomains
        ['type' => 'A', 'name' => 'staging'], ['type' => 'A', 'name' => 'stage'],
        ['type' => 'A', 'name' => 'test'], ['type' => 'A', 'name' => 'testing'],
        ['type' => 'A', 'name' => 'uat'], ['type' => 'A', 'name' => 'demo'],
        ['type' => 'A', 'name' => 'admin'], ['type' => 'A', 'name' => 'administrator'],
        ['type' => 'A', 'name' => 'dashboard'], ['type' => 'A', 'name' => 'panel'],
        ['type' => 'A', 'name' => 'login'], ['type' => 'A', 'name' => 'signin'],
        ['type' => 'A', 'name' => 'auth'], ['type' => 'A', 'name' => 'sso'], ['type' => 'A', 'name' => 'oauth'],
        ['type' => 'A', 'name' => 'secure'], ['type' => 'A', 'name' => 'ssl'],
        ['type' => 'A', 'name' => 'static'], ['type' => 'A', 'name' => 'assets'], ['type' => 'A', 'name' => 'img'], ['type' => 'A', 'name' => 'images'],
        ['type' => 'A', 'name' => 'media'], ['type' => 'A', 'name' => 'files'], ['type' => 'A', 'name' => 'downloads'],
        ['type' => 'A', 'name' => 'docs'], ['type' => 'A', 'name' => 'documentation'],
        ['type' => 'A', 'name' => 'support'], ['type' => 'A', 'name' => 'help'], ['type' => 'A', 'name' => 'kb'],
        ['type' => 'A', 'name' => 'beta'], ['type' => 'A', 'name' => 'alpha'], ['type' => 'A', 'name' => 'sandbox'],
        ['type' => 'A', 'name' => 'internal'], ['type' => 'A', 'name' => 'intranet'],
        ['type' => 'A', 'name' => 'gateway'], ['type' => 'A', 'name' => 'proxy'],
        ['type' => 'A', 'name' => 'git'], ['type' => 'A', 'name' => 'gitlab'], ['type' => 'A', 'name' => 'jenkins'], ['type' => 'A', 'name' => 'ci'],

        // Microsoft / Office 365
        ['type' => 'CNAME', 'name' => 'cdn'], ['type' => 'CNAME', 'name' => 'status'],
        ['type' => 'CNAME', 'name' => 'autodiscover'], ['type' => 'CNAME', 'name' => 'lyncdiscover'], ['type' => 'CNAME', 'name' => 'sip'],
        ['type' => 'CNAME', 'name' => 'enterpriseregistration'], ['type' => 'CNAME', 'name' => 'enterpriseenrollment'], ['type' => 'CNAME', 'name' => 'msoid'],
        ['type' => 'SRV', 'name' => '_sip._tls'], ['type' => 'SRV', 'name' => '_sipfederationtls._tcp'], ['type' => 'SRV', 'name' => '_autodiscover._tcp'],
        ['type' => 'SRV', 'name' => '_submissions._tcp'], ['type' => 'SRV', 'name' => '_imaps._tcp'],

        // Email authentication - DMARC, MTA-STS, TLS-RPT, BIMI
        ['type' => 'TXT', 'name' => '_dmarc'], ['type' => 'TXT', 'name' => '_mta-sts'], ['type' => 'CNAME', 'name' => 'mta-sts'],
        ['type' => 'TXT', 'name' => '_smtp._tls'], ['type' => 'TXT', 'name' => 'default._bimi'],

        // DKIM selectors - Common
        ['type' => 'TXT', 'name' => 'google._domainkey'], ['type' => 'TXT', 'name' => 'default._domainkey'],
        ['type' => 'TXT', 'name' => 'k1._domainkey'], ['type' => 'TXT', 'name' => 'k2._domainkey'], ['type' => 'TXT', 'name' => 'k3._domainkey'],
        ['type' => 'TXT', 'name' => 's1._domainkey'], ['type' => 'TXT', 'name' => 's2._domainkey'],
        ['type' => 'TXT', 'name' => 'selector1._domainkey'], ['type' => 'TXT', 'name' => 'selector2._domainkey'],
        ['type' => 'CNAME', 'name' => 'k1._domainkey'], ['type' => 'CNAME', 'name' => 's1._domainkey'],
        ['type' => 'CNAME', 'name' => 'selector1._domainkey'], ['type' => 'CNAME', 'name' => 'selector2._domainkey'],

        // DKIM selectors - Email service providers
        ['type' => 'TXT', 'name' => 'mandrill._domainkey'], ['type' => 'CNAME', 'name' => 'mandrill._domainkey'],
        ['type' => 'TXT', 'name' => 'mxvault._domainkey'], ['type' => 'CNAME', 'name' => 'mxvault._domainkey'],
        ['type' => 'TXT', 'name' => 'postmark._domainkey'], ['type' => 'CNAME', 'name' => 'postmark._domainkey'],
        ['type' => 'TXT', 'name' => 'pm._domainkey'], ['type' => 'CNAME', 'name' => 'pm._domainkey'],
        ['type' => 'TXT', 'name' => 'mailjet._domainkey'], ['type' => 'CNAME', 'name' => 'mailjet._domainkey'],
        ['type' => 'TXT', 'name' => 'sendgrid._domainkey'], ['type' => 'CNAME', 'name' => 'sendgrid._domainkey'],
        ['type' => 'TXT', 'name' => 'smtpapi._domainkey'], ['type' => 'CNAME', 'name' => 'smtpapi._domainkey'],
        ['type' => 'CNAME', 'name' => 's1._domainkey'], ['type' => 'CNAME', 'name' => 's2._domainkey'],
        ['type' => 'TXT', 'name' => 'amazonses._domainkey'], ['type' => 'CNAME', 'name' => 'amazonses._domainkey'],
        ['type' => 'TXT', 'name' => 'sparkpost._domainkey'], ['type' => 'CNAME', 'name' => 'sparkpost._domainkey'],
        ['type' => 'TXT', 'name' => 'cm._domainkey'], ['type' => 'CNAME', 'name' => 'cm._domainkey'],
        ['type' => 'TXT', 'name' => 'dkim._domainkey'], ['type' => 'CNAME', 'name' => 'dkim._domainkey'],
        ['type' => 'TXT', 'name' => 'mail._domainkey'], ['type' => 'CNAME', 'name' => 'mail._domainkey'],
        ['type' => 'TXT', 'name' => 'zendesk1._domainkey'], ['type' => 'TXT', 'name' => 'zendesk2._domainkey'],
        ['type' => 'CNAME', 'name' => 'zendesk1._domainkey'], ['type' => 'CNAME', 'name' => 'zendesk2._domainkey'],
        ['type' => 'TXT', 'name' => 'mailgun._domainkey'], ['type' => 'CNAME', 'name' => 'mailgun._domainkey'],
        ['type' => 'TXT', 'name' => 'krs._domainkey'], ['type' => 'CNAME', 'name' => 'krs._domainkey'],
        ['type' => 'TXT', 'name' => 'protonmail._domainkey'], ['type' => 'TXT', 'name' => 'protonmail2._domainkey'], ['type' => 'TXT', 'name' => 'protonmail3._domainkey'],

        // Mailgun subdomain
        ['type' => 'MX', 'name' => 'mg'], ['type' => 'CNAME', 'name' => 'email.mg'],
        ['type' => 'TXT', 'name' => 'smtp._domainkey.mg'], ['type' => 'TXT', 'name' => 'mg'],

        // Other email/verification records
        ['type' => 'TXT', 'name' => '_amazonses'], ['type' => 'TXT', 'name' => '_mailchannels'],
        ['type' => 'TXT', 'name' => 'zmail._domainkey'], ['type' => 'TXT', 'name' => 'zoho._domainkey'],

        // ACME/Let's Encrypt
        ['type' => 'CNAME', 'name' => '_acme-challenge'], ['type' => 'TXT', 'name' => '_acme-challenge'],

        // Domain verification records
        ['type' => 'TXT', 'name' => '_google'], ['type' => 'TXT', 'name' => '_github-challenge'],
        ['type' => 'TXT', 'name' => '_facebook'], ['type' => 'TXT', 'name' => '_dnslink']
    ];

    // If scanning a subdomain, first check DNS for the target host specifically
    if ($isSubdomain) {
        $subdomainPart = str_replace('.' . $rootDomain, '', $targetHost);
        foreach (['A', 'AAAA', 'CNAME'] as $type) {
            $output = digQuery($type, $targetHost);
            if (!$output) continue;
            foreach (explode("\n", trim($output)) as $val) {
                $val = trim($val); if (empty($val)) continue;
                $key = "$type|$subdomainPart|$val"; if (isset($check_map[$key])) continue;
                $check_map[$key] = true;
                $raw_records[] = ['type' => $type, 'name' => $subdomainPart, 'value' => $val];
            }
        }
    }

    foreach ($checks as $check) {
        $type = $check['type']; $name = $check['name'];

        // Skip subdomain A record checks if wildcard A exists (they would all match wildcard)
        if ($hasWildcardA && $type === 'A' && !empty($name) && $name !== 'www') {
            continue;
        }

        // DNS queries are relative to root domain
        $host = $name ? "$name.$rootDomain" : $rootDomain;

        // For subdomain A/AAAA/TXT checks: first check if CNAME exists, record it and skip the query
        // (dig follows CNAMEs and returns records from the target, which we don't want)
        if (($type === 'A' || $type === 'AAAA' || $type === 'TXT') && !empty($name) && $type !== 'CNAME') {
            $cnameOutput = digQuery('CNAME', $host);
            if ($cnameOutput && !empty(trim($cnameOutput))) {
                $cnameVal = trim(explode("\n", trim($cnameOutput))[0]);
                // Skip if this matches the wildcard CNAME (duplicate from wildcard)
                if ($wildcardCNAMEValue !== null && $cnameVal === $wildcardCNAMEValue) {
                    continue;
                }
                $key = "CNAME|$name|$cnameVal";
                if (!isset($check_map[$key])) {
                    $check_map[$key] = true;
                    $raw_records[] = ['type' => 'CNAME', 'name' => $name, 'value' => $cnameVal];
                }
                continue; // Skip the A/AAAA/TXT query since we found a CNAME
            }
        }

        $output = digQuery($type, $host);
        if (!$output) continue;
        foreach (explode("\n", trim($output)) as $val) {
            $val = trim($val); if (empty($val)) continue;

            // For A/AAAA records: skip values that look like hostnames (CNAME targets returned by dig)
            if (($type === 'A' || $type === 'AAAA') && preg_match('/[a-zA-Z]/', $val)) {
                continue;
            }

            // Skip TXT records that match the wildcard TXT value (duplicates from wildcard)
            if ($type === 'TXT' && $wildcardTXTValue !== null && !empty($name) && $val === $wildcardTXTValue) {
                continue;
            }

            // Skip CNAME records that match the wildcard CNAME value (duplicates from wildcard)
            if ($type === 'CNAME' && $wildcardCNAMEValue !== null && !empty($name) && $name !== '*' && $val === $wildcardCNAMEValue) {
                continue;
            }

            $key = "$type|$name|$val"; if (isset($check_map[$key])) continue;
            $check_map[$key] = true;
            $raw_records[] = ['type' => $type, 'name' => $name ?: '@', 'value' => $val];
        }
    }

    // CNAME Exclusivity Logic
    $cname_hosts = [];
    foreach ($raw_records as $r) if ($r['type'] === 'CNAME') $cname_hosts[$r['name']] = true;

    $dns_records = [];
    $zone = new Zone($rootDomain . ".");
    $zone->setDefaultTtl(3600);

    foreach ($raw_records as $r) {
        if (isset($cname_hosts[$r['name']]) && $r['type'] !== 'CNAME') continue;
        $dns_records[] = $r;
        try {
            $rr = new ResourceRecord(); $rr->setName($r['name']); $rr->setClass('IN');
            switch ($r['type']) {
                case 'A': $rr->setRdata(Factory::A($r['value'])); break;
                case 'CNAME': $rr->setRdata(Factory::Cname($r['value'])); break;
                case 'NS': $rr->setRdata(Factory::Ns($r['value'])); break;
                case 'TXT': $rr->setRdata(Factory::Txt(trim($r['value'], '"'))); break;
                case 'MX': $p = explode(' ', $r['value']); if(count($p)==2) $rr->setRdata(Factory::Mx($p[0], $p[1])); break;
                case 'SOA': $p = explode(' ', $r['value']); if(count($p)>=7) $rr->setRdata(Factory::Soa($p[0],$p[1],$p[2],$p[3],$p[4],$p[5],$p[6])); break;
                case 'SRV': $p = preg_split('/\s+/', $r['value']); if(count($p) >= 4) { $target = rtrim($p[3], '.'); $rr->setRdata(Factory::Srv((int)$p[0], (int)$p[1], (int)$p[2], $target)); } break;
            }
            $zone->addResourceRecord($rr);
        } catch (Exception $e) {}
    }

    $builder = new AlignedBuilder();
    $builder->addRdataFormatter('TXT', 'specialTxtFormatter');
    $zoneFile = $builder->build($zone);

    cliProgressDone('DNS records scanned (' . count($dns_records) . ' found)');
    cliProgress('Resolving IP addresses...');

    // Capture raw IP WHOIS data and PTR records - resolve IPs for the target host
    $ips = gethostbynamel($targetHost); $ip_lookup = []; $rawWhoisIps = []; $ptrRecords = [];
    if ($ips) foreach ($ips as $ip) {
        $rawIpWhois = shell_exec("whois " . escapeshellarg($ip));
        $rawWhoisIps[$ip] = $rawIpWhois;
        // Extract summary line for display
        $res = '';
        if ($rawIpWhois) {
            foreach (explode("\n", $rawIpWhois) as $line) {
                if (preg_match('/^(OrgName|NetName|Organization):\s*(.+)/i', $line, $m)) {
                    $res = trim($m[0]);
                    break;
                }
            }
        }
        $ip_lookup[$ip] = $res ?: 'N/A';
        
        // PTR (reverse DNS) lookup
        $ptr = trim(shell_exec("dig -x " . escapeshellarg($ip) . " +short 2>/dev/null") ?: '');
        $ptr = rtrim($ptr, '.'); // Remove trailing dot
        if ($ptr && !empty($ptr)) {
            // Verify forward match (PTR hostname should resolve back to this IP)
            $forwardIps = @gethostbynamel($ptr);
            $forwardMatch = $forwardIps && in_array($ip, $forwardIps);
            $ptrRecords[$ip] = [
                'ptr' => $ptr,
                'forward_match' => $forwardMatch
            ];
        }
    }

    cliProgressDone('IP addresses resolved (' . count($ip_lookup) . ' found)');
    cliProgress('Fetching HTTP headers & SSL...');

    // Capture redirect chain - try HTTPS first, fallback to HTTP
    $redirectChain = getRedirectChain("https://" . $targetHost);
    if (empty($redirectChain) || (count($redirectChain) === 1 && $redirectChain[0]['status_code'] === 0)) {
        $redirectChain = getRedirectChain("http://" . $targetHost);
    }

    // Capture raw HTTP headers - from target host
    $headers = [];
    $h_out = shell_exec("curl -I -s -L --max-time 3 " . escapeshellarg("https://".$targetHost));
    if (!$h_out) $h_out = shell_exec("curl -I -s -L --max-time 2 " . escapeshellarg("http://".$targetHost));
    if($h_out) foreach(explode("\n", $h_out) as $line) {
        if(strpos($line, ':')) { [$k, $v] = explode(':', $line, 2); $headers[trim($k)] = trim($v); }
    }

    // Fetch HTML once for multiple detection functions - from target host
    $html = @file_get_contents("https://" . $targetHost, false, stream_context_create([
        'http' => ['timeout' => 3, 'ignore_errors' => true],
        'ssl' => ['verify_peer' => false, 'verify_peer_name' => false]
    ]));
    if (!$html) $html = @file_get_contents("http://" . $targetHost, false, stream_context_create([
        'http' => ['timeout' => 3, 'ignore_errors' => true]
    ]));

    // Capture raw SSL output - from target host
    $rawSsl = getRawSSL($targetHost);

    cliProgressDone('HTTP headers & SSL fetched');
    cliProgress('Looking up domain registration...');

    // Capture raw WHOIS for domain - always from root domain
    $rawWhoisDomain = getRawWhoisDomain($rootDomain);

    // Use cached RDAP from domain existence check if available
    $rawRdap = $cachedRdap ?? getRawRdap($rootDomain);

    // Get timestamp for this scan
    $timestamp = time();

    cliProgressDone('Domain registration retrieved');
    cliProgress('Analyzing results...');

    // Run detection functions - tech detection uses target host
    $ssl = getSSLInfo($targetHost, $rawSsl);
    $cms = detectCMS($targetHost, $html, $headers);
    $infra = detectInfrastructure($headers);
    $security = detectSecurityHeaders($headers);
    $technology = detectTechnology($html, $headers);
    $metadataRawFiles = [];
    $metadata = detectMetadata($targetHost, $html, $metadataRawFiles);
    $indexability = detectSearchEngineBlocking($html, $headers, $metadataRawFiles['robots_txt'] ?? null);

    // Save raw files to disk - under target host
    $scanPath = getScanPath($targetHost, $timestamp);
    saveRawFiles($scanPath, $html, $headers, $rawWhoisDomain, $rawWhoisIps, $rawSsl, [
        'records' => $dns_records,
        'zone' => $zoneFile
    ], $rawRdap, $metadataRawFiles, $redirectChain, $ptrRecords);

    $domainData = $rawRdap ? parseRdap($rawRdap) : [];
    if (empty($domainData)) $domainData = parseRawWhois($rawWhoisDomain);

    // Add flags for which metadata files were captured
    if ($metadata['robots_txt'] && $metadata['robots_txt']['present']) {
        $metadata['robots_txt']['raw_stored'] = !empty($metadataRawFiles['robots_txt']);
    }
    if ($metadata['sitemap'] && $metadata['sitemap']['present']) {
        $metadata['sitemap']['raw_stored'] = !empty($metadataRawFiles['sitemap_xml']);
    }
    if ($metadata['security_txt'] && $metadata['security_txt']['present']) {
        $metadata['security_txt']['raw_stored'] = !empty($metadataRawFiles['security_txt']);
    }
    if ($metadata['ads_txt'] && $metadata['ads_txt']['present']) {
        $metadata['ads_txt']['raw_stored'] = !empty($metadataRawFiles['ads_txt']);
    }
    if ($metadata['app_ads_txt'] && $metadata['app_ads_txt']['present']) {
        $metadata['app_ads_txt']['raw_stored'] = !empty($metadataRawFiles['app_ads_txt']);
    }
    if ($metadata['app_site_association'] && $metadata['app_site_association']['present']) {
        $metadata['app_site_association']['raw_stored'] = !empty($metadataRawFiles['app_site_association']);
    }
    if ($metadata['assetlinks'] && $metadata['assetlinks']['present']) {
        $metadata['assetlinks']['raw_stored'] = !empty($metadataRawFiles['assetlinks']);
    }
    if ($metadata['manifest'] && $metadata['manifest']['present']) {
        $metadata['manifest']['raw_stored'] = !empty($metadataRawFiles['manifest']);
    }
    if ($metadata['humans_txt'] && $metadata['humans_txt']['present']) {
        $metadata['humans_txt']['raw_stored'] = !empty($metadataRawFiles['humans_txt']);
    }
    if ($metadata['browserconfig'] && $metadata['browserconfig']['present']) {
        $metadata['browserconfig']['raw_stored'] = !empty($metadataRawFiles['browserconfig']);
    }
    if ($metadata['keybase_txt'] && $metadata['keybase_txt']['present']) {
        $metadata['keybase_txt']['raw_stored'] = !empty($metadataRawFiles['keybase_txt']);
    }
    if ($metadata['favicon'] && $metadata['favicon']['present'] && isset($metadata['favicon']['hash'])) {
        $metadata['favicon']['raw_stored'] = !empty($metadataRawFiles['favicon']);
    }

    $result = [
        'target_host' => $targetHost,
        'root_domain' => $rootDomain,
        'is_subdomain' => $isSubdomain,
        'domain' => $domainData, 'dns_records' => $dns_records, 'zone' => $zoneFile,
        'ip_lookup' => $ip_lookup, 'ptr_records' => $ptrRecords, 'http_headers' => $headers, 'ssl' => $ssl, 'cms' => $cms,
        'infrastructure' => $infra, 'security' => $security, 'technology' => $technology,
        'metadata' => $metadata, 'redirect_chain' => $redirectChain, 'indexability' => $indexability,
        'errors' => [], 'timestamp' => $timestamp, 'raw_available' => true,
        'plugin_version' => PERISCOPE_VERSION
    ];

    // Save response cache for fast future loads
    saveResponseCache($scanPath, $result);

    cliProgressDone('Scan complete');

    return $result;
}

// --- SSE PROGRESS HELPERS ---
function sendProgress($step, $total, $message) {
    echo "data: " . json_encode([
        'type' => 'progress',
        'step' => $step,
        'total' => $total,
        'message' => $message,
        'percent' => round(($step / $total) * 100)
    ]) . "\n\n";
    @ob_flush();
    flush();
}

function sendComplete($data) {
    echo "data: " . json_encode([
        'type' => 'complete',
        'data' => $data
    ]) . "\n\n";
    @ob_flush();
    flush();
}

function sendError($message) {
    echo "data: " . json_encode([
        'type' => 'error',
        'message' => $message
    ]) . "\n\n";
    @ob_flush();
    flush();
}

// --- PHASED LOOKUP WITH PROGRESS ---
function performLookupWithProgress($domain) {
    global $pdo;
    $errors = []; $raw_records = []; $check_map = [];
    $total_steps = 6;

    // === INPUT NORMALIZATION ===
    // Normalize input and extract target host vs root domain
    $targetHost = normalizeInput($domain);
    $rootDomain = extractRootDomain($targetHost);
    $isSubdomain = ($targetHost !== $rootDomain);

    // SAFETY CHECK: Abort if domain is empty or invalid
    if (empty($targetHost) || empty($rootDomain) || !preg_match('/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/i', $targetHost)) {
        sendError('Invalid or empty domain provided');
        return ['error' => 'Invalid or empty domain'];
    }

    // === PHASE 0: Check if domain exists via RDAP ===
    sendProgress(1, $total_steps, 'Checking domain registration...');
    $domainCheck = checkDomainExists($rootDomain);
    
    if (!$domainCheck['exists']) {
        $timestamp = time();
        $result = [
            'target_host' => $targetHost,
            'root_domain' => $rootDomain,
            'is_subdomain' => $isSubdomain,
            'domain_exists' => false,
            'domain' => [],
            'dns_records' => [],
            'zone' => '',
            'ip_lookup' => [],
            'http_headers' => [],
            'ssl' => [],
            'cms' => [],
            'infrastructure' => [],
            'security' => [],
            'technology' => [],
            'metadata' => [],
            'redirect_chain' => [],
            'indexability' => [],
            'errors' => [],
            'timestamp' => $timestamp,
            'raw_available' => false,
            'plugin_version' => PERISCOPE_VERSION
        ];
        
        // Save response cache so it can be loaded from history
        $scanPath = getScanPath($targetHost, $timestamp);
        if (!is_dir($scanPath)) mkdir($scanPath, 0755, true);
        saveResponseCache($scanPath, $result);
        
        // Save to history database
        if ($pdo) {
            $stmt = $pdo->prepare("INSERT INTO history (domain, timestamp, data) VALUES (?, ?, '')");
            $stmt->execute([$targetHost, $timestamp]);
        }
        
        return $result;
    }
    
    // Store RDAP result for later use (avoid duplicate request)
    $cachedRdap = $domainCheck['rdap'] ?? null;

    // === PHASE 1: Core DNS & Subdomains ===
    sendProgress(1, $total_steps, 'Scanning core DNS records...');

    // Check for wildcard A record on root domain
    $wildcardA = digQuery('A', "*.$rootDomain");
    $hasWildcardA = !empty(trim($wildcardA));

    // If wildcard A exists, record it
    if ($hasWildcardA) {
        foreach (explode("\n", trim($wildcardA)) as $val) {
            $val = trim($val); if (empty($val)) continue;
            // Skip if it looks like a hostname (CNAME target returned by dig)
            if (preg_match('/[a-zA-Z]/', $val) && substr($val, -1) === '.') continue;
            $key = "A|*|$val"; if (isset($check_map[$key])) continue;
            $check_map[$key] = true;
            $raw_records[] = ['type' => 'A', 'name' => '*', 'value' => $val];
        }
    }

    // Check for wildcard TXT record on root domain
    $wildcardTXT = digQuery('TXT', "*.$rootDomain");
    $wildcardTXTValue = null;
    if (!empty(trim($wildcardTXT))) {
        $wildcardTXTValue = trim($wildcardTXT);
        // Record the wildcard TXT
        $key = "TXT|*|$wildcardTXTValue";
        if (!isset($check_map[$key])) {
            $check_map[$key] = true;
            $raw_records[] = ['type' => 'TXT', 'name' => '*', 'value' => $wildcardTXTValue];
        }
    }

    // Check for wildcard CNAME record on root domain
    $wildcardCNAME = digQuery('CNAME', "*.$rootDomain");
    $wildcardCNAMEValue = null;
    if (!empty(trim($wildcardCNAME))) {
        $wildcardCNAMEValue = trim(explode("\n", trim($wildcardCNAME))[0]);
        // Record the wildcard CNAME
        $key = "CNAME|*|$wildcardCNAMEValue";
        if (!isset($check_map[$key])) {
            $check_map[$key] = true;
            $raw_records[] = ['type' => 'CNAME', 'name' => '*', 'value' => $wildcardCNAMEValue];
        }
    }

    $checks_core = [
        // Core records (skip wildcard since we already checked it)
        ['type' => 'A', 'name' => ''], ['type' => 'A', 'name' => 'www'],
        ['type' => 'AAAA', 'name' => ''], ['type' => 'AAAA', 'name' => 'www'],
        ['type' => 'NS', 'name' => ''], ['type' => 'SOA', 'name' => ''], ['type' => 'MX', 'name' => ''], ['type' => 'TXT', 'name' => ''],
        ['type' => 'CAA', 'name' => ''],
        ['type' => 'HTTPS', 'name' => ''], ['type' => 'SVCB', 'name' => ''],
        ['type' => 'TLSA', 'name' => '_443._tcp'], ['type' => 'TLSA', 'name' => '_25._tcp'],

        // Common subdomains
        ['type' => 'A', 'name' => 'mail'], ['type' => 'A', 'name' => 'webmail'], ['type' => 'A', 'name' => 'smtp'],
        ['type' => 'A', 'name' => 'imap'], ['type' => 'A', 'name' => 'ftp'], ['type' => 'A', 'name' => 'cpanel'],
        ['type' => 'A', 'name' => 'whm'], ['type' => 'A', 'name' => 'plesk'], ['type' => 'A', 'name' => 'blog'],
        ['type' => 'A', 'name' => 'shop'], ['type' => 'A', 'name' => 'portal'], ['type' => 'A', 'name' => 'dev'],
        ['type' => 'A', 'name' => 'api'], ['type' => 'A', 'name' => 'app'], ['type' => 'A', 'name' => 'remote'],
        ['type' => 'A', 'name' => 'vpn'],

        // Additional subdomains
        ['type' => 'A', 'name' => 'staging'], ['type' => 'A', 'name' => 'stage'],
        ['type' => 'A', 'name' => 'test'], ['type' => 'A', 'name' => 'testing'],
        ['type' => 'A', 'name' => 'uat'], ['type' => 'A', 'name' => 'demo'],
        ['type' => 'A', 'name' => 'admin'], ['type' => 'A', 'name' => 'administrator'],
        ['type' => 'A', 'name' => 'dashboard'], ['type' => 'A', 'name' => 'panel'],
        ['type' => 'A', 'name' => 'login'], ['type' => 'A', 'name' => 'signin'],
        ['type' => 'A', 'name' => 'auth'], ['type' => 'A', 'name' => 'sso'], ['type' => 'A', 'name' => 'oauth'],
        ['type' => 'A', 'name' => 'secure'], ['type' => 'A', 'name' => 'ssl'],
        ['type' => 'A', 'name' => 'static'], ['type' => 'A', 'name' => 'assets'], ['type' => 'A', 'name' => 'img'], ['type' => 'A', 'name' => 'images'],
        ['type' => 'A', 'name' => 'media'], ['type' => 'A', 'name' => 'files'], ['type' => 'A', 'name' => 'downloads'],
        ['type' => 'A', 'name' => 'docs'], ['type' => 'A', 'name' => 'documentation'],
        ['type' => 'A', 'name' => 'support'], ['type' => 'A', 'name' => 'help'], ['type' => 'A', 'name' => 'kb'],
        ['type' => 'A', 'name' => 'beta'], ['type' => 'A', 'name' => 'alpha'], ['type' => 'A', 'name' => 'sandbox'],
        ['type' => 'A', 'name' => 'internal'], ['type' => 'A', 'name' => 'intranet'],
        ['type' => 'A', 'name' => 'gateway'], ['type' => 'A', 'name' => 'proxy'],
        ['type' => 'A', 'name' => 'git'], ['type' => 'A', 'name' => 'gitlab'], ['type' => 'A', 'name' => 'jenkins'], ['type' => 'A', 'name' => 'ci'],

        // Microsoft / Office 365
        ['type' => 'CNAME', 'name' => 'cdn'], ['type' => 'CNAME', 'name' => 'status'],
        ['type' => 'CNAME', 'name' => 'autodiscover'], ['type' => 'CNAME', 'name' => 'lyncdiscover'], ['type' => 'CNAME', 'name' => 'sip'],
        ['type' => 'CNAME', 'name' => 'enterpriseregistration'], ['type' => 'CNAME', 'name' => 'enterpriseenrollment'], ['type' => 'CNAME', 'name' => 'msoid'],
        ['type' => 'SRV', 'name' => '_sip._tls'], ['type' => 'SRV', 'name' => '_sipfederationtls._tcp'], ['type' => 'SRV', 'name' => '_autodiscover._tcp'],
        ['type' => 'SRV', 'name' => '_submissions._tcp'], ['type' => 'SRV', 'name' => '_imaps._tcp'],
    ];

    // If scanning a subdomain, first check DNS for the target host specifically
    if ($isSubdomain) {
        $subdomainPart = str_replace('.' . $rootDomain, '', $targetHost);
        foreach (['A', 'AAAA', 'CNAME'] as $type) {
            $output = digQuery($type, $targetHost);
            if (!$output) continue;
            foreach (explode("\n", trim($output)) as $val) {
                $val = trim($val); if (empty($val)) continue;
                $key = "$type|$subdomainPart|$val"; if (isset($check_map[$key])) continue;
                $check_map[$key] = true;
                $raw_records[] = ['type' => $type, 'name' => $subdomainPart, 'value' => $val];
            }
        }
    }

    foreach ($checks_core as $check) {
        $type = $check['type']; $name = $check['name'];

        // Skip subdomain A record checks if wildcard A exists (they would all match wildcard)
        if ($hasWildcardA && $type === 'A' && !empty($name) && $name !== 'www') {
            continue;
        }

        // DNS queries are relative to root domain
        $host = $name ? "$name.$rootDomain" : $rootDomain;

        // For subdomain A/AAAA/TXT checks: first check if CNAME exists, record it and skip the query
        // (dig follows CNAMEs and returns records from the target, which we don't want)
        if (($type === 'A' || $type === 'AAAA' || $type === 'TXT') && !empty($name) && $type !== 'CNAME') {
            $cnameOutput = digQuery('CNAME', $host);
            if ($cnameOutput && !empty(trim($cnameOutput))) {
                $cnameVal = trim(explode("\n", trim($cnameOutput))[0]);
                // Skip if this matches the wildcard CNAME (duplicate from wildcard)
                if ($wildcardCNAMEValue !== null && $cnameVal === $wildcardCNAMEValue) {
                    continue;
                }
                $key = "CNAME|$name|$cnameVal";
                if (!isset($check_map[$key])) {
                    $check_map[$key] = true;
                    $raw_records[] = ['type' => 'CNAME', 'name' => $name, 'value' => $cnameVal];
                }
                continue; // Skip the A/AAAA/TXT query since we found a CNAME
            }
        }

        $output = digQuery($type, $host);
        if (!$output) continue;
        foreach (explode("\n", trim($output)) as $val) {
            $val = trim($val); if (empty($val)) continue;

            // For A/AAAA records: skip values that look like hostnames (CNAME targets returned by dig)
            if (($type === 'A' || $type === 'AAAA') && preg_match('/[a-zA-Z]/', $val)) {
                continue;
            }

            // Skip TXT records that match the wildcard TXT value (duplicates from wildcard)
            if ($type === 'TXT' && $wildcardTXTValue !== null && !empty($name) && $val === $wildcardTXTValue) {
                continue;
            }

            $key = "$type|$name|$val"; if (isset($check_map[$key])) continue;
            $check_map[$key] = true;
            $raw_records[] = ['type' => $type, 'name' => $name ?: '@', 'value' => $val];
        }
    }

    // === PHASE 2: Email & DKIM Records ===
    sendProgress(2, $total_steps, 'Scanning email & DKIM records...');

    $checks_email = [
        // Email authentication - DMARC, MTA-STS, TLS-RPT, BIMI
        ['type' => 'TXT', 'name' => '_dmarc'], ['type' => 'TXT', 'name' => '_mta-sts'], ['type' => 'CNAME', 'name' => 'mta-sts'],
        ['type' => 'TXT', 'name' => '_smtp._tls'], ['type' => 'TXT', 'name' => 'default._bimi'],

        // DKIM selectors - Common
        ['type' => 'TXT', 'name' => 'google._domainkey'], ['type' => 'TXT', 'name' => 'default._domainkey'],
        ['type' => 'TXT', 'name' => 'k1._domainkey'], ['type' => 'TXT', 'name' => 'k2._domainkey'], ['type' => 'TXT', 'name' => 'k3._domainkey'],
        ['type' => 'TXT', 'name' => 's1._domainkey'], ['type' => 'TXT', 'name' => 's2._domainkey'],
        ['type' => 'TXT', 'name' => 'selector1._domainkey'], ['type' => 'TXT', 'name' => 'selector2._domainkey'],
        ['type' => 'CNAME', 'name' => 'k1._domainkey'], ['type' => 'CNAME', 'name' => 's1._domainkey'],
        ['type' => 'CNAME', 'name' => 'selector1._domainkey'], ['type' => 'CNAME', 'name' => 'selector2._domainkey'],

        // DKIM selectors - Email service providers
        ['type' => 'TXT', 'name' => 'mandrill._domainkey'], ['type' => 'CNAME', 'name' => 'mandrill._domainkey'],
        ['type' => 'TXT', 'name' => 'mxvault._domainkey'], ['type' => 'CNAME', 'name' => 'mxvault._domainkey'],
        ['type' => 'TXT', 'name' => 'postmark._domainkey'], ['type' => 'CNAME', 'name' => 'postmark._domainkey'],
        ['type' => 'TXT', 'name' => 'pm._domainkey'], ['type' => 'CNAME', 'name' => 'pm._domainkey'],
        ['type' => 'TXT', 'name' => 'mailjet._domainkey'], ['type' => 'CNAME', 'name' => 'mailjet._domainkey'],
        ['type' => 'TXT', 'name' => 'sendgrid._domainkey'], ['type' => 'CNAME', 'name' => 'sendgrid._domainkey'],
        ['type' => 'TXT', 'name' => 'smtpapi._domainkey'], ['type' => 'CNAME', 'name' => 'smtpapi._domainkey'],
        ['type' => 'CNAME', 'name' => 's1._domainkey'], ['type' => 'CNAME', 'name' => 's2._domainkey'],
        ['type' => 'TXT', 'name' => 'amazonses._domainkey'], ['type' => 'CNAME', 'name' => 'amazonses._domainkey'],
        ['type' => 'TXT', 'name' => 'sparkpost._domainkey'], ['type' => 'CNAME', 'name' => 'sparkpost._domainkey'],
        ['type' => 'TXT', 'name' => 'cm._domainkey'], ['type' => 'CNAME', 'name' => 'cm._domainkey'],
        ['type' => 'TXT', 'name' => 'dkim._domainkey'], ['type' => 'CNAME', 'name' => 'dkim._domainkey'],
        ['type' => 'TXT', 'name' => 'mail._domainkey'], ['type' => 'CNAME', 'name' => 'mail._domainkey'],
        ['type' => 'TXT', 'name' => 'zendesk1._domainkey'], ['type' => 'TXT', 'name' => 'zendesk2._domainkey'],
        ['type' => 'CNAME', 'name' => 'zendesk1._domainkey'], ['type' => 'CNAME', 'name' => 'zendesk2._domainkey'],
        ['type' => 'TXT', 'name' => 'mailgun._domainkey'], ['type' => 'CNAME', 'name' => 'mailgun._domainkey'],
        ['type' => 'TXT', 'name' => 'krs._domainkey'], ['type' => 'CNAME', 'name' => 'krs._domainkey'],
        ['type' => 'TXT', 'name' => 'protonmail._domainkey'], ['type' => 'TXT', 'name' => 'protonmail2._domainkey'], ['type' => 'TXT', 'name' => 'protonmail3._domainkey'],

        // Mailgun subdomain
        ['type' => 'MX', 'name' => 'mg'], ['type' => 'CNAME', 'name' => 'email.mg'],
        ['type' => 'TXT', 'name' => 'smtp._domainkey.mg'], ['type' => 'TXT', 'name' => 'mg'],

        // Other email/verification records
        ['type' => 'TXT', 'name' => '_amazonses'], ['type' => 'TXT', 'name' => '_mailchannels'],
        ['type' => 'TXT', 'name' => 'zmail._domainkey'], ['type' => 'TXT', 'name' => 'zoho._domainkey'],

        // ACME/Let's Encrypt
        ['type' => 'CNAME', 'name' => '_acme-challenge'], ['type' => 'TXT', 'name' => '_acme-challenge'],

        // Domain verification records
        ['type' => 'TXT', 'name' => '_google'], ['type' => 'TXT', 'name' => '_github-challenge'],
        ['type' => 'TXT', 'name' => '_facebook'], ['type' => 'TXT', 'name' => '_dnslink']
    ];

    foreach ($checks_email as $check) {
        $type = $check['type']; $name = $check['name'];
        // Email/DKIM records are always on the root domain
        $host = $name ? "$name.$rootDomain" : $rootDomain;

        // For subdomain A/AAAA/TXT checks: first check if CNAME exists, record it and skip the query
        // (dig follows CNAMEs and returns records from the target, which we don't want)
        if (($type === 'A' || $type === 'AAAA' || $type === 'TXT') && !empty($name) && $type !== 'CNAME') {
            $cnameOutput = digQuery('CNAME', $host);
            if ($cnameOutput && !empty(trim($cnameOutput))) {
                $cnameVal = trim(explode("\n", trim($cnameOutput))[0]);
                // Skip if this matches the wildcard CNAME (duplicate from wildcard)
                if ($wildcardCNAMEValue !== null && $cnameVal === $wildcardCNAMEValue) {
                    continue;
                }
                $key = "CNAME|$name|$cnameVal";
                if (!isset($check_map[$key])) {
                    $check_map[$key] = true;
                    $raw_records[] = ['type' => 'CNAME', 'name' => $name, 'value' => $cnameVal];
                }
                continue; // Skip the A/AAAA/TXT query since we found a CNAME
            }
        }

        $output = digQuery($type, $host);
        if (!$output) continue;
        foreach (explode("\n", trim($output)) as $val) {
            $val = trim($val); if (empty($val)) continue;

            // For A/AAAA records: skip values that look like hostnames (CNAME targets returned by dig)
            if (($type === 'A' || $type === 'AAAA') && preg_match('/[a-zA-Z]/', $val)) {
                continue;
            }

            // Skip TXT records that match the wildcard TXT value (duplicates from wildcard)
            if ($type === 'TXT' && $wildcardTXTValue !== null && !empty($name) && $val === $wildcardTXTValue) {
                continue;
            }

            // Skip CNAME records that match the wildcard CNAME value (duplicates from wildcard)
            if ($type === 'CNAME' && $wildcardCNAMEValue !== null && !empty($name) && $name !== '*' && $val === $wildcardCNAMEValue) {
                continue;
            }

            $key = "$type|$name|$val"; if (isset($check_map[$key])) continue;
            $check_map[$key] = true;
            $raw_records[] = ['type' => $type, 'name' => $name ?: '@', 'value' => $val];
        }
    }

    // CNAME Exclusivity Logic
    $cname_hosts = [];
    foreach ($raw_records as $r) if ($r['type'] === 'CNAME') $cname_hosts[$r['name']] = true;

    $dns_records = [];
    $zone = new Zone($rootDomain . ".");
    $zone->setDefaultTtl(3600);

    foreach ($raw_records as $r) {
        if (isset($cname_hosts[$r['name']]) && $r['type'] !== 'CNAME') continue;
        $dns_records[] = $r;
        try {
            $rr = new ResourceRecord(); $rr->setName($r['name']); $rr->setClass('IN');
            switch ($r['type']) {
                case 'A': $rr->setRdata(Factory::A($r['value'])); break;
                case 'CNAME': $rr->setRdata(Factory::Cname($r['value'])); break;
                case 'NS': $rr->setRdata(Factory::Ns($r['value'])); break;
                case 'TXT': $rr->setRdata(Factory::Txt(trim($r['value'], '"'))); break;
                case 'MX': $p = explode(' ', $r['value']); if(count($p)==2) $rr->setRdata(Factory::Mx($p[0], $p[1])); break;
                case 'SOA': $p = explode(' ', $r['value']); if(count($p)>=7) $rr->setRdata(Factory::Soa($p[0],$p[1],$p[2],$p[3],$p[4],$p[5],$p[6])); break;
                case 'SRV': $p = preg_split('/\s+/', $r['value']); if(count($p) >= 4) { $target = rtrim($p[3], '.'); $rr->setRdata(Factory::Srv((int)$p[0], (int)$p[1], (int)$p[2], $target)); } break;
            }
            $zone->addResourceRecord($rr);
        } catch (Exception $e) {}
    }

    $builder = new AlignedBuilder();
    $builder->addRdataFormatter('TXT', 'specialTxtFormatter');
    $zoneFile = $builder->build($zone);

    // === PHASE 3: IP Resolution & WHOIS ===
    sendProgress(3, $total_steps, 'Resolving IP addresses...');

    // Resolve IPs for the target host (not root domain)
    $ips = gethostbynamel($targetHost); $ip_lookup = []; $rawWhoisIps = []; $ptrRecords = [];
    if ($ips) foreach ($ips as $ip) {
        $rawIpWhois = shell_exec("whois " . escapeshellarg($ip));
        $rawWhoisIps[$ip] = $rawIpWhois;
        $res = '';
        if ($rawIpWhois) {
            foreach (explode("\n", $rawIpWhois) as $line) {
                if (preg_match('/^(OrgName|NetName|Organization):\s*(.+)/i', $line, $m)) {
                    $res = trim($m[0]);
                    break;
                }
            }
        }
        $ip_lookup[$ip] = $res ?: 'N/A';
        
        // PTR (reverse DNS) lookup
        $ptr = trim(shell_exec("dig -x " . escapeshellarg($ip) . " +short 2>/dev/null") ?: '');
        $ptr = rtrim($ptr, '.'); // Remove trailing dot
        if ($ptr && !empty($ptr)) {
            // Verify forward match (PTR hostname should resolve back to this IP)
            $forwardIps = @gethostbynamel($ptr);
            $forwardMatch = $forwardIps && in_array($ip, $forwardIps);
            $ptrRecords[$ip] = [
                'ptr' => $ptr,
                'forward_match' => $forwardMatch
            ];
        }
    }

    // === PHASE 4: HTTP & SSL ===
    sendProgress(4, $total_steps, 'Fetching HTTP headers & SSL...');

    // Capture redirect chain - try HTTPS first, fallback to HTTP
    $redirectChain = getRedirectChain("https://" . $targetHost);
    if (empty($redirectChain) || (count($redirectChain) === 1 && $redirectChain[0]['status_code'] === 0)) {
        $redirectChain = getRedirectChain("http://" . $targetHost);
    }

    // HTTP/HTML from the target host
    $headers = [];
    $h_out = shell_exec("curl -I -s -L --max-time 3 " . escapeshellarg("https://".$targetHost));
    if (!$h_out) $h_out = shell_exec("curl -I -s -L --max-time 2 " . escapeshellarg("http://".$targetHost));
    if($h_out) foreach(explode("\n", $h_out) as $line) {
        if(strpos($line, ':')) { [$k, $v] = explode(':', $line, 2); $headers[trim($k)] = trim($v); }
    }

    $html = @file_get_contents("https://" . $targetHost, false, stream_context_create([
        'http' => ['timeout' => 3, 'ignore_errors' => true],
        'ssl' => ['verify_peer' => false, 'verify_peer_name' => false]
    ]));
    if (!$html) $html = @file_get_contents("http://" . $targetHost, false, stream_context_create([
        'http' => ['timeout' => 3, 'ignore_errors' => true]
    ]));

    // SSL from the target host
    $rawSsl = getRawSSL($targetHost);

    // === PHASE 5: Domain Registration ===
    sendProgress(5, $total_steps, 'Looking up domain registration...');

    // WHOIS/RDAP always from root domain (subdomain lookups usually fail)
    $rawWhoisDomain = getRawWhoisDomain($rootDomain);
    // Use cached RDAP from domain existence check if available
    $rawRdap = $cachedRdap ?? getRawRdap($rootDomain);

    // === PHASE 6: Analysis & Save ===
    sendProgress(6, $total_steps, 'Analyzing results...');

    $timestamp = time();

    // Tech detection uses targetHost (the actual site being scanned)
    $ssl = getSSLInfo($targetHost, $rawSsl);
    $cms = detectCMS($targetHost, $html, $headers);
    $infra = detectInfrastructure($headers);
    $security = detectSecurityHeaders($headers);
    $technology = detectTechnology($html, $headers);
    $metadataRawFiles = [];
    $metadata = detectMetadata($targetHost, $html, $metadataRawFiles);
    $indexability = detectSearchEngineBlocking($html, $headers, $metadataRawFiles['robots_txt'] ?? null);

    // Store scans under targetHost
    $scanPath = getScanPath($targetHost, $timestamp);
    saveRawFiles($scanPath, $html, $headers, $rawWhoisDomain, $rawWhoisIps, $rawSsl, [
        'records' => $dns_records,
        'zone' => $zoneFile
    ], $rawRdap, $metadataRawFiles, $redirectChain, $ptrRecords);

    $domainData = $rawRdap ? parseRdap($rawRdap) : [];
    if (empty($domainData)) $domainData = parseRawWhois($rawWhoisDomain);

    // Add flags for which metadata files were captured
    if ($metadata['robots_txt'] && $metadata['robots_txt']['present']) {
        $metadata['robots_txt']['raw_stored'] = !empty($metadataRawFiles['robots_txt']);
    }
    if ($metadata['sitemap'] && $metadata['sitemap']['present']) {
        $metadata['sitemap']['raw_stored'] = !empty($metadataRawFiles['sitemap_xml']);
    }
    if ($metadata['security_txt'] && $metadata['security_txt']['present']) {
        $metadata['security_txt']['raw_stored'] = !empty($metadataRawFiles['security_txt']);
    }
    if ($metadata['ads_txt'] && $metadata['ads_txt']['present']) {
        $metadata['ads_txt']['raw_stored'] = !empty($metadataRawFiles['ads_txt']);
    }
    if ($metadata['app_ads_txt'] && $metadata['app_ads_txt']['present']) {
        $metadata['app_ads_txt']['raw_stored'] = !empty($metadataRawFiles['app_ads_txt']);
    }
    if ($metadata['app_site_association'] && $metadata['app_site_association']['present']) {
        $metadata['app_site_association']['raw_stored'] = !empty($metadataRawFiles['app_site_association']);
    }
    if ($metadata['assetlinks'] && $metadata['assetlinks']['present']) {
        $metadata['assetlinks']['raw_stored'] = !empty($metadataRawFiles['assetlinks']);
    }
    if ($metadata['manifest'] && $metadata['manifest']['present']) {
        $metadata['manifest']['raw_stored'] = !empty($metadataRawFiles['manifest']);
    }
    if ($metadata['humans_txt'] && $metadata['humans_txt']['present']) {
        $metadata['humans_txt']['raw_stored'] = !empty($metadataRawFiles['humans_txt']);
    }
    if ($metadata['browserconfig'] && $metadata['browserconfig']['present']) {
        $metadata['browserconfig']['raw_stored'] = !empty($metadataRawFiles['browserconfig']);
    }
    if ($metadata['keybase_txt'] && $metadata['keybase_txt']['present']) {
        $metadata['keybase_txt']['raw_stored'] = !empty($metadataRawFiles['keybase_txt']);
    }
    if ($metadata['favicon'] && $metadata['favicon']['present'] && isset($metadata['favicon']['hash'])) {
        $metadata['favicon']['raw_stored'] = !empty($metadataRawFiles['favicon']);
    }

    $result = [
        'target_host' => $targetHost,
        'root_domain' => $rootDomain,
        'is_subdomain' => $isSubdomain,
        'domain' => $domainData, 'dns_records' => $dns_records, 'zone' => $zoneFile,
        'ip_lookup' => $ip_lookup, 'ptr_records' => $ptrRecords, 'http_headers' => $headers, 'ssl' => $ssl, 'cms' => $cms,
        'infrastructure' => $infra, 'security' => $security, 'technology' => $technology,
        'metadata' => $metadata, 'redirect_chain' => $redirectChain, 'indexability' => $indexability,
        'errors' => [], 'timestamp' => $timestamp, 'raw_available' => true,
        'plugin_version' => PERISCOPE_VERSION
    ];

    saveResponseCache($scanPath, $result);

    // Save to history database using targetHost
    if ($pdo) {
        $stmt = $pdo->prepare("INSERT INTO history (domain, timestamp, data) VALUES (?, ?, '')");
        $stmt->execute([$targetHost, $timestamp]);
    }

    return $result;
}

// --- CLI PROGRESS HELPER ---
$CLI_MODE = false;

function cliProgress($message) {
    global $CLI_MODE;
    if (!$CLI_MODE) return;
    // Use carriage return to overwrite line, pad with spaces to clear previous text
    $padded = str_pad($message, 50);
    echo "\r\033[K  ⏳ $padded";
    flush();
}

function cliProgressDone($message) {
    global $CLI_MODE;
    if (!$CLI_MODE) return;
    echo "\r\033[K  ✓ $message\n";
    flush();
}

// --- CLI EXECUTION ---
if (php_sapi_name() === 'cli' && !isset($_SERVER['REQUEST_METHOD'])) {
    if ($argc < 2) { echo "Usage: php engine.php <domain>\n"; exit(1); }
    $CLI_MODE = true;
    $domain = $argv[1];

    // Hide cursor during scan
    echo "\033[?25l";
    // Ensure cursor is restored on exit (Ctrl+C, errors, etc.)
    register_shutdown_function(function() { echo "\033[?25h"; });

    echo "\n  🔍 Scanning \033[1m$domain\033[0m\n\n";
    $data = performLookup($domain);
    if ($pdo) {
        // Insert with data=NULL - raw files stored on disk
        $stmt = $pdo->prepare("INSERT INTO history (domain, timestamp, data) VALUES (?, ?, '')");
        $stmt->execute([$domain, $data['timestamp']]);
    }
    $registrar = 'N/A';
    foreach ($data['domain'] as $item) if (stripos($item['name'], 'Registrar') !== false) { $registrar = $item['value']; break; }
    $ips = array_keys($data['ip_lookup']);

    echo "\n  \033[1m━━━ Summary ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m\n\n";
    echo "  Domain:        \033[36m" . $data['target_host'] . "\033[0m\n";
    echo "  Registrar:     " . $registrar . "\n";
    echo "  IP Addresses:  " . (empty($ips) ? 'N/A' : implode(', ', $ips)) . "\n";
    echo "  DNS Records:   " . count($data['dns_records']) . " found\n";
    if ($data['ssl'] && $data['ssl']['valid']) {
        $sslColor = $data['ssl']['days_remaining'] < 30 ? '33' : '32'; // yellow if < 30 days, green otherwise
        echo "  SSL:           \033[{$sslColor}m" . $data['ssl']['days_remaining'] . " days remaining\033[0m\n";
    }
    if ($data['cms']) {
        echo "  Platform:      " . $data['cms']['name'] . ($data['cms']['version'] ? ' ' . $data['cms']['version'] : '') . "\n";
    }
    if ($data['redirect_chain'] && count($data['redirect_chain']) > 1) {
        $finalUrl = end($data['redirect_chain'])['url'];
        echo "  Redirects:     " . count($data['redirect_chain']) . " hops → \033[33m" . parse_url($finalUrl, PHP_URL_HOST) . "\033[0m\n";
    }
    if (isset($data['indexability']) && $data['indexability']['blocked']) {
        $reasons = array_map(fn($r) => $r['detail'], $data['indexability']['reasons']);
        echo "\n  \033[41;37m ⚠ HIDDEN FROM SEARCH ENGINES \033[0m\n";
        echo "  \033[31m" . implode(', ', $reasons) . "\033[0m\n";
    }
    echo "\n  \033[90mSaved to: ~/.periscope/scans/" . $data['target_host'] . "/" . $data['timestamp'] . "/\033[0m\n";
    exit(0);
}

// --- SERVER HANDLER ---
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
$allowed = ['https://periscope.run', 'http://localhost:8989', 'http://127.0.0.1:8989', 'null'];
if (in_array($origin, $allowed)) { header("Access-Control-Allow-Origin: $origin"); } 
else { header("Access-Control-Allow-Origin: https://periscope.run"); }
header("Access-Control-Allow-Methods: GET, POST");
header('Content-Type: application/json');

$action = $_GET['action'] ?? '';
if ($action === 'check_status') {
    $info = ['has_db' => ($pdo !== null), 'plugin_version' => PERISCOPE_VERSION];
    if ($pdo) {
        $info['db_path'] = $db_path;
        $info['db_size'] = file_exists($db_path) ? filesize($db_path) : 0;
        $countStmt = $pdo->query("SELECT COUNT(*) FROM history");
        $info['scan_count'] = (int)$countStmt->fetchColumn();
    }
    // Scans directory info
    $scansPath = getenv('HOME') . '/.periscope/scans';
    $info['scans_path'] = $scansPath;
    $info['scans_size'] = 0;
    if (is_dir($scansPath)) {
        $size = 0;
        $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($scansPath, RecursiveDirectoryIterator::SKIP_DOTS));
        foreach ($iterator as $file) {
            if ($file->isFile()) $size += $file->getSize();
        }
        $info['scans_size'] = $size;
    }
    echo json_encode($info);
    exit;
}

if ($pdo) {
    if ($action === 'get_history') {
        $limit = 50;
        $offset = isset($_GET['offset']) ? (int)$_GET['offset'] : 0;
        $search = isset($_GET['search']) ? trim($_GET['search']) : '';
        $existence = isset($_GET['existence']) ? $_GET['existence'] : 'all';
        $platform = isset($_GET['platform']) ? $_GET['platform'] : 'all';
        $scanCount = isset($_GET['scan_count']) ? $_GET['scan_count'] : 'all';

        // Build dynamic query with filters
        $where = [];
        $params = [];

        if ($search) {
            $where[] = "domain LIKE ?";
            $params[] = '%' . $search . '%';
        }

        // For existence and platform filters, we need to check raw files or cache
        // This requires a subquery or post-processing since data isn't in the main table
        $needsDataFilter = ($existence !== 'all' || $platform !== 'all');

        // For scan count filter, use a subquery
        $havingScanCount = '';
        if ($scanCount !== 'all') {
            // Parse dynamic filter value formats: "1", "2-5", "6+"
            if (preg_match('/^(\d+)$/', $scanCount, $m)) {
                // Exact match
                $havingScanCount = 'HAVING COUNT(*) = ' . (int)$m[1];
            } elseif (preg_match('/^(\d+)-(\d+)$/', $scanCount, $m)) {
                // Range
                $havingScanCount = 'HAVING COUNT(*) >= ' . (int)$m[1] . ' AND COUNT(*) <= ' . (int)$m[2];
            } elseif (preg_match('/^(\d+)\+$/', $scanCount, $m)) {
                // Open-ended range
                $havingScanCount = 'HAVING COUNT(*) >= ' . (int)$m[1];
            }
        }

        $whereClause = count($where) > 0 ? 'WHERE ' . implode(' AND ', $where) : '';

        if ($scanCount !== 'all') {
            // Use subquery to filter by scan count per domain
            $sql = "SELECT h.id, h.domain, h.timestamp FROM history h
                    INNER JOIN (SELECT domain FROM history $whereClause GROUP BY domain $havingScanCount) filtered
                    ON h.domain = filtered.domain
                    " . ($whereClause ? str_replace('WHERE', 'WHERE', $whereClause) : '') . "
                    ORDER BY h.timestamp DESC";
            $countSql = "SELECT COUNT(*) FROM history h
                         INNER JOIN (SELECT domain FROM history $whereClause GROUP BY domain $havingScanCount) filtered
                         ON h.domain = filtered.domain
                         " . ($whereClause ? str_replace('WHERE', 'WHERE', $whereClause) : '');
        } else {
            $sql = "SELECT id, domain, timestamp FROM history $whereClause ORDER BY timestamp DESC";
            $countSql = "SELECT COUNT(*) FROM history $whereClause";
        }

        // Execute count query
        $countStmt = $pdo->prepare($countSql);
        $countStmt->execute($params);
        $total = (int)$countStmt->fetchColumn();

        // Execute main query with limit/offset
        $sql .= " LIMIT ? OFFSET ?";
        $params[] = $limit;
        $params[] = $offset;
        $stmt = $pdo->prepare($sql);
        $stmt->execute($params);
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

        // Post-filter for existence and platform if needed
        if ($needsDataFilter) {
            $filtered = [];
            foreach ($rows as $row) {
                $path = getScanPath($row['domain'], $row['timestamp']);
                $cache = loadResponseCache($path);
                $data = $cache ? $cache['data'] : null;

                // If no cache, try to load from raw files (expensive but necessary)
                if (!$data) {
                    $raw = loadRawFiles($path);
                    if (!empty($raw)) {
                        $data = computeFromRaw($raw, $row['domain'], $row['timestamp'], true);
                    }
                }

                // Apply existence filter
                if ($existence !== 'all') {
                    $domainExists = !isset($data['domain_exists']) || $data['domain_exists'] !== false;
                    if ($existence === 'exists' && !$domainExists) continue;
                    if ($existence === 'nonexistent' && $domainExists) continue;
                }

                // Apply platform filter
                if ($platform !== 'all') {
                    $cmsName = isset($data['cms']['name']) ? $data['cms']['name'] : null;
                    if ($cmsName !== $platform) continue;
                }

                $filtered[] = $row;
            }
            $rows = $filtered;
            $total = count($rows); // Approximate - full count would require scanning all records
        }

        echo json_encode(['items' => $rows, 'total' => $total, 'offset' => $offset, 'limit' => $limit]);
        exit;
    }
    if ($action === 'get_platforms') {
        // Get distinct platforms from cached scan data
        $platforms = [];
        $stmt = $pdo->query("SELECT DISTINCT domain, timestamp FROM history ORDER BY timestamp DESC LIMIT 500");
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

        foreach ($rows as $row) {
            $path = getScanPath($row['domain'], $row['timestamp']);
            $cache = loadResponseCache($path);
            if ($cache && isset($cache['data']['cms']['name']) && $cache['data']['cms']['name']) {
                $platforms[$cache['data']['cms']['name']] = true;
            }
        }

        echo json_encode(array_keys($platforms));
        exit;
    }
    if ($action === 'get_scan_counts') {
        // Get distribution of scan counts per domain
        $stmt = $pdo->query("SELECT domain, COUNT(*) as cnt FROM history GROUP BY domain");
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        // Build distribution: count -> number of domains with that count
        $distribution = [];
        foreach ($rows as $row) {
            $cnt = (int)$row['cnt'];
            $distribution[$cnt] = ($distribution[$cnt] ?? 0) + 1;
        }
        
        ksort($distribution);
        $uniqueCounts = array_keys($distribution);
        $options = [];
        
        // If only a few unique counts, show each individually
        if (count($uniqueCounts) <= 5) {
            foreach ($uniqueCounts as $count) {
                $domains = $distribution[$count];
                $options[] = [
                    'value' => (string)$count,
                    'label' => $count . ' scan' . ($count > 1 ? 's' : '') . ' (' . $domains . ' domain' . ($domains > 1 ? 's' : '') . ')'
                ];
            }
        } else {
            // Build smart ranges
            $max = max($uniqueCounts);
            $ranges = [];
            
            // Always include "1 scan" if it exists
            if (isset($distribution[1])) {
                $ranges[] = ['min' => 1, 'max' => 1, 'label' => '1 scan'];
            }
            
            // Group remaining into ranges
            if ($max >= 2) {
                $mid = min(5, (int)floor($max / 2));
                if ($mid > 1) {
                    $ranges[] = ['min' => 2, 'max' => $mid, 'label' => "2-$mid scans"];
                }
                if ($max > $mid) {
                    $ranges[] = ['min' => $mid + 1, 'max' => $max, 'label' => ($mid + 1) . '+ scans'];
                }
            }
            
            foreach ($ranges as $range) {
                $domainCount = 0;
                for ($i = $range['min']; $i <= $range['max']; $i++) {
                    $domainCount += $distribution[$i] ?? 0;
                }
                if ($domainCount > 0) {
                    $value = $range['min'] === $range['max'] ? (string)$range['min'] : "{$range['min']}-{$range['max']}";
                    // For open-ended ranges, use + notation
                    if ($range['max'] === $max && $range['min'] !== $range['max']) {
                        $value = $range['min'] . '+';
                    }
                    $options[] = [
                        'value' => $value,
                        'label' => $range['label'] . ' (' . $domainCount . ' domain' . ($domainCount > 1 ? 's' : '') . ')'
                    ];
                }
            }
        }
        
        echo json_encode($options);
        exit;
    }
    if ($action === 'get_domain_versions') {
        $stmt = $pdo->prepare("SELECT id, domain, timestamp FROM history WHERE domain = ? ORDER BY timestamp DESC");
        $stmt->execute([$_GET['domain']]);
        echo json_encode($stmt->fetchAll(PDO::FETCH_ASSOC)); exit;
    }
    if ($action === 'get_history_item') {
        $stmt = $pdo->prepare("SELECT domain, data, timestamp FROM history WHERE id = ?");
        $stmt->execute([$_GET['id']]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        if($row) {
            // Check if data column is populated (old scan) or NULL/empty (new scan with raw files)
            if ($row['data'] && $row['data'] !== '') {
                // Old scan with baked-in data
                $d = json_decode($row['data'], true);
                $data = is_string($d) ? json_decode($d, true) : $d;
                $data['timestamp'] = $row['timestamp'];
                $data['raw_available'] = false;  // Flag for UI
                $data['cache_status'] = 'legacy';
            } else {
                // New scan - try cached response first
                $path = getScanPath($row['domain'], $row['timestamp']);
                $cache = loadResponseCache($path);
                
                if (isCacheValid($cache)) {
                    // Cache hit - return immediately
                    $data = $cache['data'];
                    $data['timestamp'] = $row['timestamp'];
                    $data['cache_status'] = 'hit';
                } else {
                    // Cache miss or outdated - compute from raw files
                    $raw = loadRawFiles($path);
                    $data = computeFromRaw($raw, $row['domain'], $row['timestamp'], true);
                    $data['timestamp'] = $row['timestamp'];
                    $data['cache_status'] = $cache ? 'regenerated' : 'computed';
                }
            }
            echo json_encode($data);
        } else echo json_encode([]);
        exit;
    }
    if ($action === 'save_history') {
        $in = json_decode(file_get_contents('php://input'), true);
        if (!$in || !isset($in['domain'])) {
            echo json_encode(['error' => 'Invalid input']);
            exit;
        }
        // Use timestamp from data (set by performLookup) to match raw files folder
        $timestamp = isset($in['data']['timestamp']) ? $in['data']['timestamp'] : time();
        // Insert with empty data - raw files already stored by performLookup
        $pdo->prepare("INSERT INTO history (domain, timestamp, data) VALUES (?, ?, '')")
            ->execute([$in['domain'], $timestamp]);
        echo json_encode(['success' => true]);
        exit;
    }
    if ($action === 'delete_history') {
        // Get domain and timestamp before deleting
        $stmt = $pdo->prepare("SELECT domain, timestamp FROM history WHERE id = ?");
        $stmt->execute([$_POST['id']]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        // Delete from database
        $pdo->prepare("DELETE FROM history WHERE id = ?")->execute([$_POST['id']]);

        // Delete raw files folder if it exists
        if ($row && !empty($row['domain']) && !empty($row['timestamp'])) {
            try {
                $scanPath = getScanPath($row['domain'], $row['timestamp']);
                $expectedBase = getenv('HOME') . "/.periscope/scans/";
                // SAFETY: Double-check path is within expected directory before deletion
                if (is_dir($scanPath) && strpos(realpath($scanPath), $expectedBase) === 0) {
                    $files = glob("$scanPath/*");
                    foreach ($files as $file) {
                        if (is_file($file)) unlink($file);
                    }
                    rmdir($scanPath);
                }
            } catch (Exception $e) {
                // Silently ignore path errors - database entry already deleted
            }
        }

        echo json_encode(['success'=>true]); exit;
    }
    if ($action === 'export_history') {
        $stmt = $pdo->query("SELECT domain, timestamp, data FROM history ORDER BY timestamp DESC");
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
        foreach($rows as &$r) {
            if ($r['data']) {
                // Old scan with baked-in data
                $d = json_decode($r['data'], true);
                $r['data'] = is_string($d) ? json_decode($d, true) : $d;
            } else {
                // New scan - compute data from raw files for export
                $path = getScanPath($r['domain'], $r['timestamp']);
                $raw = loadRawFiles($path);
                $r['data'] = computeFromRaw($raw, $r['domain']);
                $r['data']['timestamp'] = $r['timestamp'];
            }
        }
        header('Content-Disposition: attachment; filename="periscope.json"');
        echo json_encode($rows, JSON_PRETTY_PRINT); exit;
    }
    if ($action === 'import_history') {
        if ($_FILES['importFile']['size'] > 1048576 * 5) { echo json_encode(['success'=>false, 'error'=>'File too large']); exit; }
        if (isset($_FILES['importFile'])) {
            $json = file_get_contents($_FILES['importFile']['tmp_name']);
            $data = json_decode($json, true);
            if (is_array($data)) {
                $stmt = $pdo->prepare("INSERT INTO history (domain, timestamp, data) VALUES (:d, :t, :v)");
                foreach($data as $i) $stmt->execute([':d'=>$i['domain'], ':t'=>$i['timestamp'], ':v'=>json_encode($i['data'])]);
                echo json_encode(['success'=>true, 'count'=>count($data)]);
            }
        }
        exit;
    }
    if ($action === 'get_file') {
        // Retrieve hash-based file: ?action=get_file&domain=X&hash=Y&extension=Z
        $domain = $_GET['domain'] ?? '';
        $hash = $_GET['hash'] ?? '';
        $extension = $_GET['extension'] ?? '';

        if (!$domain || !$hash || !$extension) {
            header('HTTP/1.1 400 Bad Request');
            exit('Missing parameters');
        }

        $content = getFileByHash($domain, $hash, $extension);
        if ($content) {
            $mimeTypes = [
                'ico' => 'image/x-icon',
                'png' => 'image/png',
                'jpg' => 'image/jpeg',
                'jpeg' => 'image/jpeg',
                'gif' => 'image/gif',
                'webp' => 'image/webp'
            ];
            header('Content-Type: ' . ($mimeTypes[$extension] ?? 'application/octet-stream'));
            header('Cache-Control: public, max-age=31536000'); // 1 year cache
            echo $content;
            exit;
        }
        header('HTTP/1.1 404 Not Found');
        exit('File not found');
    }
    if ($action === 'get_raw') {
        // Retrieve raw file: ?action=get_raw&domain=example.com&timestamp=1737465600&type=whois_domain
        $domain = $_GET['domain'] ?? '';
        $timestamp = $_GET['timestamp'] ?? '';
        $type = $_GET['type'] ?? '';
        if (!$domain || !$timestamp || !$type) {
            echo json_encode(['error' => 'Missing parameters']);
            exit;
        }
        $path = getScanPath($domain, $timestamp);
        $allowedTypes = ['html', 'whois_domain', 'ssl'];
        // Handle IP-specific WHOIS files
        if (preg_match('/^whois_ip_(.+)$/', $type, $m)) {
            $file = "$path/$type.txt";
        } elseif (in_array($type, $allowedTypes)) {
            $file = "$path/$type.txt";
        } elseif ($type === 'headers') {
            $file = "$path/headers.json";
        } elseif ($type === 'dns') {
            $file = "$path/dns.json";
        } elseif ($type === 'rdap') {
            $file = "$path/rdap.json";
        } elseif ($type === 'robots_txt') {
            $file = "$path/robots.txt";
        } elseif ($type === 'sitemap_xml') {
            $file = "$path/sitemap.xml";
        } elseif ($type === 'security_txt') {
            $file = "$path/security.txt";
        } elseif ($type === 'ads_txt') {
            $file = "$path/ads.txt";
        } elseif ($type === 'app_ads_txt') {
            $file = "$path/app-ads.txt";
        } elseif ($type === 'app_site_association') {
            $file = "$path/apple-app-site-association.json";
        } elseif ($type === 'assetlinks') {
            $file = "$path/assetlinks.json";
        } elseif ($type === 'manifest') {
            $file = "$path/manifest.json";
        } elseif ($type === 'humans_txt') {
            $file = "$path/humans.txt";
        } elseif ($type === 'browserconfig') {
            $file = "$path/browserconfig.xml";
        } elseif ($type === 'keybase_txt') {
            $file = "$path/keybase.txt";
        } elseif ($type === 'favicon') {
            $file = "$path/favicon.ico";
            if (file_exists($file)) {
                header('Content-Type: image/x-icon');
                echo file_get_contents($file);
                exit;
            } else {
                header('HTTP/1.1 404 Not Found');
                echo 'No favicon stored for this scan.';
                exit;
            }
        } else {
            echo json_encode(['error' => 'Invalid type']);
            exit;
        }
        header('Content-Type: text/plain');
        if (file_exists($file)) {
            echo file_get_contents($file);
        } else {
            echo 'No raw data stored for this scan.';
        }
        exit;
    }
    if ($action === 'regenerate_cache') {
        // Background regeneration endpoint - regenerates cache for a specific scan
        $id = $_GET['id'] ?? '';
        if (!$id) {
            echo json_encode(['error' => 'Missing id parameter']);
            exit;
        }
        $stmt = $pdo->prepare("SELECT domain, timestamp FROM history WHERE id = ?");
        $stmt->execute([$id]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$row) {
            echo json_encode(['error' => 'Scan not found']);
            exit;
        }
        $path = getScanPath($row['domain'], $row['timestamp']);
        $raw = loadRawFiles($path);
        $data = computeFromRaw($raw, $row['domain'], $row['timestamp'], true);
        $data['timestamp'] = $row['timestamp'];
        echo json_encode(['success' => true, 'data' => $data]);
        exit;
    }
}

if (isset($_GET['dig'])) {
    $d = trim($_GET['dig']);
    if (preg_match('/^[a-zA-Z0-9\.\-\*]+$/', $d)) echo shell_exec("dig +short " . escapeshellarg($d) . " TXT");
    exit;
}
if (isset($_GET['whois'])) {
    $ip = trim($_GET['whois']);
    if (filter_var($ip, FILTER_VALIDATE_IP)) echo shell_exec("whois " . escapeshellarg($ip));
    exit;
}
if (isset($_GET['raw_domain'])) { echo json_encode(getWhois($_GET['raw_domain']), JSON_PRETTY_PRINT); exit; }

// --- SSE SCAN ENDPOINT ---
if (isset($_GET['scan'])) {
    $domain = trim($_GET['scan']);
    if (empty($domain)) {
        header('Content-Type: application/json');
        echo json_encode(['error' => 'No domain provided']);
        exit;
    }

    // Set SSE headers
    header('Content-Type: text/event-stream');
    header('Cache-Control: no-cache');
    header('X-Accel-Buffering: no');
    header('Connection: keep-alive');

    // Disable output buffering
    @ini_set('output_buffering', 'off');
    @ini_set('zlib.output_compression', false);
    while (ob_get_level()) ob_end_flush();
    ob_implicit_flush(true);

    try {
        $result = performLookupWithProgress($domain);
        sendComplete($result);
    } catch (Exception $e) {
        sendError($e->getMessage());
    }
    exit;
}

if(isset($_GET['domain'])) { echo json_encode(performLookup($_GET['domain'])); } else { echo json_encode(['error' => 'No domain provided']); }
?>
EOF

# --- Create Router ---
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
require 'engine.php';
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
    # Loop for max 5 seconds (50 * 0.1s)
    local max_retries=50
    local i=0
    
    while [ $i -lt $max_retries ]; do
        # Check if port is listening/responsive via curl
        if curl -s -I "http://127.0.0.1:$PORT" &>/dev/null; then
             # Server is ready, open browser
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

PERISCOPE_DB="$DB_FILE" php -S 127.0.0.1:$PORT "$ROUTER_FILE"

# Clean exit
cleanup