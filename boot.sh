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
define('PERISCOPE_VERSION', '1.1');

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

// --- RAW FILE STORAGE ---
function getScanPath($domain, $timestamp) {
    return getenv('HOME') . "/.periscope/scans/$domain/$timestamp";
}

function saveRawFiles($path, $html, $headers, $whoisDomain, $whoisIps, $ssl, $dns, $rdap = null) {
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
        'rdap' => @file_get_contents("$path/rdap.json")
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
    curl_setopt($ch, CURLOPT_USERAGENT, 'Periscope/1.1');
    $json = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    return ($code === 200 && $json) ? $json : null;
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

function detectCMS($domain, $html = null) {
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

    // WordPress
    if (preg_match('/wp-content|wp-includes/i', $html)) {
        $version = null;
        if (preg_match('/<meta[^>]+generator[^>]+WordPress\s*([\d.]+)?/i', $html, $m)) {
            $version = $m[1] ?? null;
        }
        return ['name' => 'WordPress', 'version' => $version];
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

function detectMetadata($domain, $html = null) {
    $result = [
        'robots_txt' => null,
        'sitemap' => null,
        'security_txt' => null,
        'meta_tags' => [],
        'favicon' => null
    ];

    $ctx = stream_context_create([
        'http' => ['timeout' => 2, 'ignore_errors' => true],
        'ssl' => ['verify_peer' => false, 'verify_peer_name' => false]
    ]);

    // Check robots.txt
    $robots = @file_get_contents("https://" . $domain . "/robots.txt", false, $ctx);
    if (!$robots) $robots = @file_get_contents("http://" . $domain . "/robots.txt", false, $ctx);
    if ($robots && stripos($robots, 'user-agent') !== false) {
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

    // Check sitemap.xml if not found in robots.txt
    if (empty($result['robots_txt']['sitemaps'])) {
        $sitemap = @file_get_contents("https://" . $domain . "/sitemap.xml", false, $ctx);
        if (!$sitemap) $sitemap = @file_get_contents("http://" . $domain . "/sitemap.xml", false, $ctx);
        if ($sitemap && (stripos($sitemap, '<urlset') !== false || stripos($sitemap, '<sitemapindex') !== false)) {
            $urlCount = substr_count($sitemap, '<url>') + substr_count($sitemap, '<sitemap>');
            $result['sitemap'] = ['present' => true, 'url' => '/sitemap.xml', 'url_count' => $urlCount];
        } else {
            $result['sitemap'] = ['present' => false];
        }
    } else {
        $result['sitemap'] = ['present' => true, 'urls' => $result['robots_txt']['sitemaps']];
    }

    // Check security.txt
    $securityTxt = @file_get_contents("https://" . $domain . "/.well-known/security.txt", false, $ctx);
    if (!$securityTxt) $securityTxt = @file_get_contents("https://" . $domain . "/security.txt", false, $ctx);
    if ($securityTxt && (stripos($securityTxt, 'contact:') !== false || stripos($securityTxt, 'policy:') !== false)) {
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

    // Parse meta tags from HTML
    if ($html) {
        // Open Graph
        $og = [];
        if (preg_match('/<meta[^>]+property=["\']og:title["\'][^>]+content=["\']([^"\']+)/i', $html, $m)) $og['title'] = $m[1];
        if (preg_match('/<meta[^>]+property=["\']og:description["\'][^>]+content=["\']([^"\']+)/i', $html, $m)) $og['description'] = $m[1];
        if (preg_match('/<meta[^>]+property=["\']og:image["\'][^>]+content=["\']([^"\']+)/i', $html, $m)) $og['image'] = $m[1];
        if (preg_match('/<meta[^>]+property=["\']og:type["\'][^>]+content=["\']([^"\']+)/i', $html, $m)) $og['type'] = $m[1];
        if (!empty($og)) $result['meta_tags']['open_graph'] = $og;

        // Twitter Cards
        $twitter = [];
        if (preg_match('/<meta[^>]+name=["\']twitter:card["\'][^>]+content=["\']([^"\']+)/i', $html, $m)) $twitter['card'] = $m[1];
        if (preg_match('/<meta[^>]+name=["\']twitter:site["\'][^>]+content=["\']([^"\']+)/i', $html, $m)) $twitter['site'] = $m[1];
        if (preg_match('/<meta[^>]+name=["\']twitter:title["\'][^>]+content=["\']([^"\']+)/i', $html, $m)) $twitter['title'] = $m[1];
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

    // Favicon hash (MD5 for fingerprinting)
    $favicon = @file_get_contents("https://" . $domain . "/favicon.ico", false, $ctx);
    if (!$favicon) $favicon = @file_get_contents("http://" . $domain . "/favicon.ico", false, $ctx);
    if ($favicon && strlen($favicon) > 0 && strlen($favicon) < 500000) {
        $result['favicon'] = [
            'present' => true,
            'hash' => md5($favicon),
            'size' => strlen($favicon)
        ];
    } else {
        // Try to find favicon in HTML
        if ($html && preg_match('/<link[^>]+rel=["\'](?:shortcut )?icon["\'][^>]+href=["\']([^"\']+)/i', $html, $m)) {
            $result['favicon'] = ['present' => true, 'url' => $m[1], 'hash' => null];
        } else {
            $result['favicon'] = ['present' => false];
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

    // Parse domain WHOIS: prefer RDAP, fallback to raw whois
    $domainData = [];
    if ($rdapJson) {
        $domainData = parseRdap($rdapJson);
    }
    if (empty($domainData) && $whoisDomain) {
        $domainData = parseRawWhois($whoisDomain);
    }

    $data = [
        'domain' => $domainData,
        'dns_records' => $dnsRecords,
        'zone' => $zoneFile,
        'ip_lookup' => $ip_lookup,
        'http_headers' => $headers,
        'ssl' => getSSLInfo($domain, $rawSsl),
        'cms' => detectCMS($domain, $html),
        'infrastructure' => detectInfrastructure($headers),
        'security' => detectSecurityHeaders($headers),
        'technology' => detectTechnology($html, $headers),
        'metadata' => detectMetadata($domain, $html),
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

    $checks = [
        // Core records
        ['type' => 'A', 'name' => ''], ['type' => 'A', 'name' => '*'], ['type' => 'A', 'name' => 'www'],
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

    foreach ($checks as $check) {
        $type = $check['type']; $name = $check['name'];
        $host = $name ? "$name.$domain" : $domain;
        $output = shell_exec("dig +short -t $type " . escapeshellarg($host));
        if (!$output) continue;
        foreach (explode("\n", trim($output)) as $val) {
            $val = trim($val); if (empty($val)) continue;
            $key = "$type|$name|$val"; if (isset($check_map[$key])) continue;
            $check_map[$key] = true;
            $raw_records[] = ['type' => $type, 'name' => $name ?: '@', 'value' => $val];
        }
    }

    // CNAME Exclusivity Logic
    $cname_hosts = [];
    foreach ($raw_records as $r) if ($r['type'] === 'CNAME') $cname_hosts[$r['name']] = true;
    
    $dns_records = [];
    $zone = new Zone($domain . ".");
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

    // Capture raw IP WHOIS data
    $ips = gethostbynamel($domain); $ip_lookup = []; $rawWhoisIps = [];
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
    }

    // Capture raw HTTP headers
    $headers = [];
    $h_out = shell_exec("curl -I -s -L --max-time 3 " . escapeshellarg("https://".$domain));
    if (!$h_out) $h_out = shell_exec("curl -I -s -L --max-time 2 " . escapeshellarg("http://".$domain));
    if($h_out) foreach(explode("\n", $h_out) as $line) {
        if(strpos($line, ':')) { [$k, $v] = explode(':', $line, 2); $headers[trim($k)] = trim($v); }
    }

    // Fetch HTML once for multiple detection functions
    $html = @file_get_contents("https://" . $domain, false, stream_context_create([
        'http' => ['timeout' => 3, 'ignore_errors' => true],
        'ssl' => ['verify_peer' => false, 'verify_peer_name' => false]
    ]));
    if (!$html) $html = @file_get_contents("http://" . $domain, false, stream_context_create([
        'http' => ['timeout' => 3, 'ignore_errors' => true]
    ]));

    // Capture raw SSL output
    $rawSsl = getRawSSL($domain);

    // Capture raw WHOIS for domain
    $rawWhoisDomain = getRawWhoisDomain($domain);

    // Capture RDAP JSON (for rich domain info)
    $rawRdap = getRawRdap($domain);

    // Get timestamp for this scan
    $timestamp = time();

    // Save raw files to disk
    $scanPath = getScanPath($domain, $timestamp);
    saveRawFiles($scanPath, $html, $headers, $rawWhoisDomain, $rawWhoisIps, $rawSsl, [
        'records' => $dns_records,
        'zone' => $zoneFile
    ], $rawRdap);

    // Run detection functions
    $ssl = getSSLInfo($domain, $rawSsl);
    $cms = detectCMS($domain, $html);
    $infra = detectInfrastructure($headers);
    $security = detectSecurityHeaders($headers);
    $technology = detectTechnology($html, $headers);
    $metadata = detectMetadata($domain, $html);

    // Parse domain WHOIS: prefer RDAP, fallback to raw whois
    $domainData = $rawRdap ? parseRdap($rawRdap) : [];
    if (empty($domainData)) $domainData = parseRawWhois($rawWhoisDomain);

    $result = [
        'domain' => $domainData, 'dns_records' => $dns_records, 'zone' => $zoneFile,
        'ip_lookup' => $ip_lookup, 'http_headers' => $headers, 'ssl' => $ssl, 'cms' => $cms,
        'infrastructure' => $infra, 'security' => $security, 'technology' => $technology,
        'metadata' => $metadata, 'errors' => [], 'timestamp' => $timestamp, 'raw_available' => true,
        'plugin_version' => PERISCOPE_VERSION
    ];

    // Save response cache for fast future loads
    saveResponseCache($scanPath, $result);

    return $result;
}

// --- CLI EXECUTION ---
if (php_sapi_name() === 'cli' && !isset($_SERVER['REQUEST_METHOD'])) {
    if ($argc < 2) { echo "Usage: php engine.php <domain>\n"; exit(1); }
    $domain = $argv[1];
    echo "Looking up domain: $domain...\n\n";
    $data = performLookup($domain);
    if ($pdo) {
        // Insert with data=NULL - raw files stored on disk
        $stmt = $pdo->prepare("INSERT INTO history (domain, timestamp, data) VALUES (?, ?, NULL)");
        $stmt->execute([$domain, $data['timestamp']]);
    }
    $registrar = 'N/A';
    foreach ($data['domain'] as $item) if (stripos($item['name'], 'Registrar') !== false) { $registrar = $item['value']; break; }
    $ips = array_keys($data['ip_lookup']);
    echo "--- Summary for $domain ---\n";
    echo "Registrar:     " . $registrar . "\n";
    echo "IP Addresses:  " . (empty($ips) ? 'N/A' : implode(', ', $ips)) . "\n";
    echo "---------------------------\n\n";
    echo "Full report saved to local database.\n";
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

        if ($search) {
            // Search mode - find matching domains
            $stmt = $pdo->prepare("SELECT id, domain, timestamp FROM history WHERE domain LIKE ? ORDER BY timestamp DESC LIMIT ? OFFSET ?");
            $stmt->execute(['%' . $search . '%', $limit, $offset]);
            $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

            $countStmt = $pdo->prepare("SELECT COUNT(*) FROM history WHERE domain LIKE ?");
            $countStmt->execute(['%' . $search . '%']);
        } else {
            // Normal mode - paginated list
            $stmt = $pdo->prepare("SELECT id, domain, timestamp FROM history ORDER BY timestamp DESC LIMIT ? OFFSET ?");
            $stmt->execute([$limit, $offset]);
            $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

            $countStmt = $pdo->query("SELECT COUNT(*) FROM history");
        }

        $total = $countStmt->fetchColumn();
        echo json_encode(['items' => $rows, 'total' => (int)$total, 'offset' => $offset, 'limit' => $limit]);
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
        $pdo->prepare("DELETE FROM history WHERE id = ?")->execute([$_POST['id']]);
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

if [ "$LOCAL_MODE" = true ]; then
    echo -e "${GREEN}🔗 Local UI:  $URL${NC}"
else
    echo -e "${GREEN}🔗 Web UI:    $URL${NC}"
fi

echo -e "${GREEN}💻 CLI Usage: php $ENGINE_FILE domain.com${NC}"
echo -e "${GREEN}📂 Database:  $DB_FILE${NC}"
echo ""

PERISCOPE_DB="$DB_FILE" php -S 127.0.0.1:$PORT "$ROUTER_FILE"