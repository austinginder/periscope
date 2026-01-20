#!/bin/bash

# --- Configuration ---
PERISCOPE_DIR="$HOME/.periscope"
LIB_DIR="$PERISCOPE_DIR/lib"
DB_FILE="$PERISCOPE_DIR/history.db"
ENGINE_FILE="$PERISCOPE_DIR/engine.php"
PORT=8989

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
    
    # 1. Check for Binaries
    for tool in php dig whois curl unzip; do
        if ! command -v $tool &> /dev/null; then 
            missing_tools+=("$tool")
        fi
    done
    
    # 2. Check for PHP Extensions (Crucial fix for your error)
    if command -v php &> /dev/null; then
        if ! php -r "exit(function_exists('curl_init') ? 0 : 1);" 2>/dev/null; then
            missing_tools+=("php-curl")
            apt_packages+=("php-curl")
        fi
        if ! php -r "exit(class_exists('SQLite3') ? 0 : 1);" 2>/dev/null; then
            missing_tools+=("php-sqlite3")
            apt_packages+=("php-sqlite3")
        fi
    fi

    # 3. Build Package Lists
    if [[ " ${missing_tools[*]} " =~ " php " ]]; then
        apt_packages+=("php-cli" "php-sqlite3" "php-curl")
        brew_packages+=("php")
    fi
    if [[ " ${missing_tools[*]} " =~ " dig " ]]; then apt_packages+=("dnsutils"); brew_packages+=("bind"); fi
    if [[ " ${missing_tools[*]} " =~ " whois " ]]; then apt_packages+=("whois"); brew_packages+=("whois"); fi
    if [[ " ${missing_tools[*]} " =~ " curl " ]]; then apt_packages+=("curl"); brew_packages+=("curl"); fi
    if [[ " ${missing_tools[*]} " =~ " unzip " ]]; then apt_packages+=("unzip"); brew_packages+=("unzip"); fi

    if [ ${#missing_tools[@]} -eq 0 ]; then return 0; fi

    echo -e "${RED}❌ Missing required tools: ${missing_tools[*]}${NC}"

    # Linux / WSL
    if command -v apt-get &> /dev/null; then
        echo "🐧 Debian/Ubuntu/WSL detected."
        if ! command -v sudo &> /dev/null; then
             echo "${RED}❌ Sudo required for auto-install.${NC}"; exit 1
        fi
        # Quietly update and install
        sudo apt-get update -qq && sudo apt-get install -y "${apt_packages[@]}"
        echo -e "${GREEN}✅ Linux tools installed.${NC}\n"
        return 0
    fi

    # macOS
    if [[ "$OSTYPE" == "darwin"* ]]; then
        if ! command -v brew &> /dev/null; then
            echo "🍎 macOS detected but Homebrew missing."; exit 1
        fi
        for pkg in "${brew_packages[@]}"; do brew install "$pkg"; done
        echo -e "${GREEN}✅ macOS tools installed.${NC}\n"
        return 0
    fi
    
    echo "⚠️  Manual install required: ${missing_tools[*]}"
    exit 1
}

install_missing_tools

# --- Library Manager (The "Sideload" Logic) ---
setup_libraries() {
    # Check if Badcow DNS is already installed
    if [ -f "$LIB_DIR/Badcow/DNS/lib/Zone.php" ]; then
        return 0
    fi

    echo -e "${BLUE}📦 Downloading Badcow/DNS Library...${NC}"
    mkdir -p "$LIB_DIR"
    
    # 1. Fetch latest version tag
    echo "   > Fetching latest version tag..."
    LATEST_URL=$(curl -sL -o /dev/null -w '%{url_effective}' https://github.com/Badcow/DNS/releases/latest)
    VERSION=${LATEST_URL##*/v}
    
    # 2. Download Zip
    echo "   > Downloading v$VERSION..."
    curl -sL "https://github.com/Badcow/DNS/archive/refs/tags/v${VERSION}.zip" -o "$LIB_DIR/dns.zip"
    
    # 3. Extract and Organize
    echo "   > Extracting..."
    unzip -q -o "$LIB_DIR/dns.zip" -d "$LIB_DIR"
    
    # Rename folder to standard structure (Badcow/DNS)
    mkdir -p "$LIB_DIR/Badcow"
    rm -rf "$LIB_DIR/Badcow/DNS" 2>/dev/null
    mv "$LIB_DIR/DNS-$VERSION" "$LIB_DIR/Badcow/DNS"
    
    # Cleanup
    rm "$LIB_DIR/dns.zip"
    echo -e "${GREEN}✅ Library installed to ~/.periscope/lib/Badcow/DNS${NC}\n"
}

setup_libraries

# --- Create the Engine (PHP) ---
cat << 'EOF' > "$ENGINE_FILE"
<?php
// SILENCE DEPRECATIONS (Fixes the JSON parsing issue)
error_reporting(E_ERROR | E_PARSE);
ini_set('display_errors', '0');

// --- SERVER HANDLER ---
// SECURITY: Prevent Drive-by CORS attacks
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
$allowed = ['https://periscope.run', 'http://localhost:8989', 'http://127.0.0.1:8989'];
if (in_array($origin, $allowed) || $origin === 'null') {
    header("Access-Control-Allow-Origin: $origin");
} else {
    // Default to strict
    header("Access-Control-Allow-Origin: https://periscope.run");
}
header("Access-Control-Allow-Methods: GET, POST");
header("Access-Control-Allow-Headers: Content-Type");
header('Content-Type: application/json');

// --- 1. MANUAL AUTOLOADER ---
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

// Custom TXT formatter to split long strings (RFC compliant)
function specialTxtFormatter(TXT $rdata, int $padding): string {
    $text = $rdata->getText();
    if (strlen($text) <= 255) return sprintf('"%s"', addcslashes($text, '"\\'));
    
    // Split into chunks
    $chunks = str_split($text, 255);
    $out = "(\n";
    foreach ($chunks as $chunk) {
        $out .= str_repeat(' ', $padding) . sprintf('"%s"', addcslashes($chunk, '"\\')) . "\n";
    }
    return $out . str_repeat(' ', $padding) . ")";
}

function formatDate($raw) {
    try {
        if (empty($raw)) return $raw;
        // Parse ISO 8601 or similar
        $dt = new DateTime($raw);
        // Normalize everything to UTC so the numbers are consistent
        $dt->setTimezone(new DateTimeZone('UTC'));
        // Manually append " UTC" instead of relying on 'T' which might output 'Z'
        return $dt->format('M j, Y, g:i a') . ' UTC';
    } catch (Exception $e) {
        return $raw;
    }
}

function getWhois($domain) {
    // Try RDAP (JSON) first
    $ch = curl_init("https://rdap.org/domain/" . $domain);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    curl_setopt($ch, CURLOPT_USERAGENT, 'Periscope/1.0');
    $json = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);

    $out = [];
    $data = json_decode($json, true);

    if ($code === 200 && $data) {
        if (isset($data['ldhName'])) $out[] = ['name' => 'Domain Name', 'value' => strtolower($data['ldhName'])];
        
        // 1. Registry Domain ID
        if (isset($data['handle'])) $out[] = ['name' => 'Registry Domain ID', 'value' => $data['handle']];

        // 2. DNSSEC Status
        if (isset($data['secureDNS']['delegationSigned'])) {
            $signed = $data['secureDNS']['delegationSigned'] ? 'Signed' : 'Unsigned';
            $out[] = ['name' => 'DNSSEC', 'value' => $signed];
        }

        // 3. Statuses
        if (isset($data['status'])) {
            foreach ($data['status'] as $status) {
                $out[] = ['name' => 'Domain Status', 'value' => $status];
            }
        }

        // 4. Dates
        if (isset($data['events'])) {
            foreach($data['events'] as $e) {
                $d = formatDate($e['eventDate']);
                if($e['eventAction'] == 'registration') $out[] = ['name' => 'Creation Date', 'value' => $d];
                if($e['eventAction'] == 'expiration') $out[] = ['name' => 'Expiration Date', 'value' => $d];
                if($e['eventAction'] == 'last changed') $out[] = ['name' => 'Updated Date', 'value' => $d];
            }
        }

        // 5. Registered Nameservers
        if (isset($data['nameservers'])) {
            $ns_list = [];
            foreach($data['nameservers'] as $ns) {
                if (isset($ns['ldhName'])) $ns_list[] = $ns['ldhName'];
            }
            if (!empty($ns_list)) {
                $out[] = ['name' => 'Registered Nameservers', 'value' => implode(', ', $ns_list)];
            }
        }

        // 6. Entities (Registrar, IANA ID, Abuse Contact)
        if (isset($data['entities'])) {
            
            // Recursive function
            $processEntities = function($entities) use (&$out, &$processEntities) {
                foreach($entities as $ent) {
                    if (!isset($ent['roles'])) continue;
                    
                    // Registrar
                    if (in_array('registrar', $ent['roles'])) {
                        if (isset($ent['vcardArray'][1])) {
                            foreach($ent['vcardArray'][1] as $v) {
                                if($v[0] == 'fn') $out[] = ['name' => 'Registrar', 'value' => $v[3]];
                            }
                        }
                        if (isset($ent['publicIds'])) {
                            foreach($ent['publicIds'] as $pid) {
                                if (isset($pid['type']) && strpos($pid['type'], 'IANA') !== false) {
                                    $out[] = ['name' => 'Registrar IANA ID', 'value' => $pid['identifier']];
                                }
                            }
                        }
                    }

                    // Abuse Contact
                    if (in_array('abuse', $ent['roles'])) {
                        if (isset($ent['vcardArray'][1])) {
                            // Inline extraction to avoid scope issues
                            foreach ($ent['vcardArray'][1] as $entry) {
                                if (is_array($entry) && isset($entry[0]) && $entry[0] === 'email') {
                                    $out[] = ['name' => 'Abuse Email', 'value' => $entry[3]];
                                }
                                if (is_array($entry) && isset($entry[0]) && $entry[0] === 'tel') {
                                    $out[] = ['name' => 'Abuse Phone', 'value' => $entry[3]];
                                }
                            }
                        }
                    }

                    // Recurse
                    if (isset($ent['entities'])) {
                        $processEntities($ent['entities']);
                    }
                }
            };
            
            // Start recursion
            $processEntities($data['entities']);
        }
        
        // Deduplicate
        $out = array_map("unserialize", array_unique(array_map("serialize", $out)));
        return array_values($out);
    }
    
    // Fallback to Shell Whois
    $raw = shell_exec("whois " . escapeshellarg($domain));
    if($raw) {
        $lines = explode("\n", $raw);
        $capture = [
            'Domain Name', 'Name Server', 'Creation Date', 'Registrar', 
            'Registry Expiry Date', 'Domain Status', 'Registrar IANA ID', 
            'Reseller', 'DNSSEC', 'Registry Domain ID', 'Registrar Abuse Contact Email'
        ];
        foreach($lines as $line) {
            if(strpos($line, ':')) {
                $parts = explode(':', $line, 2);
                $key = trim($parts[0]);
                $val = trim($parts[1]);
                if (empty($val)) continue;

                foreach($capture as $c) {
                    if(stripos($key, $c) === 0) {
                        if (stripos($key, 'Date') !== false) $val = formatDate($val);
                        if (stripos($key, 'Abuse') !== false) $key = 'Abuse Email';
                        $out[] = ['name' => $key, 'value' => $val];
                        break;
                    }
                }
            }
        }
    }
    return $out;
}

function performLookup($domain) {
    $errors = [];
    $raw_records = []; // Temporary storage before filtering

    // Dictionary of Subdomains to check
    $checks = [
        // --- Core ---
        ['type' => 'A',    'name' => ''],      
        ['type' => 'A',    'name' => '*'],
        ['type' => 'A',    'name' => 'www'],   
        ['type' => 'NS',   'name' => ''], 
        ['type' => 'SOA',  'name' => ''],    
        ['type' => 'MX',   'name' => ''], 
        ['type' => 'TXT',  'name' => ''], 

        // --- Common Infrastructure ---
        ['type' => 'A',    'name' => 'mail'],
        ['type' => 'A',    'name' => 'webmail'],
        ['type' => 'A',    'name' => 'smtp'],
        ['type' => 'A',    'name' => 'imap'],
        ['type' => 'A',    'name' => 'ftp'],
        ['type' => 'A',    'name' => 'cpanel'],
        ['type' => 'A',    'name' => 'whm'],
        ['type' => 'A',    'name' => 'plesk'],
        ['type' => 'A',    'name' => 'blog'],  
        ['type' => 'A',    'name' => 'shop'],
        ['type' => 'A',    'name' => 'portal'],
        ['type' => 'A',    'name' => 'dev'],   
        ['type' => 'A',    'name' => 'api'],
        ['type' => 'A',    'name' => 'app'],
        ['type' => 'A',    'name' => 'remote'],
        ['type' => 'A',    'name' => 'vpn'],
        ['type' => 'CNAME','name' => 'cdn'],   
        ['type' => 'CNAME','name' => 'status'],

        // --- Microsoft / Auto-Discovery ---
        ['type' => 'CNAME','name' => 'autodiscover'], 
        ['type' => 'CNAME','name' => 'lyncdiscover'], 
        ['type' => 'CNAME','name' => 'sip'],
        ['type' => 'CNAME','name' => 'enterpriseregistration'],
        ['type' => 'CNAME','name' => 'enterpriseenrollment'],
        ['type' => 'CNAME','name' => 'msoid'],
        
        // --- SRV Records ---
        ['type' => 'SRV',  'name' => '_sip._tls'],
        ['type' => 'SRV',  'name' => '_sipfederationtls._tcp'],
        ['type' => 'SRV',  'name' => '_autodiscover._tcp'],
        ['type' => 'SRV',  'name' => '_submissions._tcp'],
        ['type' => 'SRV',  'name' => '_imaps._tcp'],

        // --- Email Security & Auth ---
        ['type' => 'TXT',  'name' => '_dmarc'], 
        ['type' => 'TXT',  'name' => '_mta-sts'],
        ['type' => 'CNAME','name' => 'mta-sts'],
        ['type' => 'TXT',  'name' => '_smtp._tls'],
        ['type' => 'TXT',  'name' => 'default._bimi'],

        // --- Common DKIM Selectors ---
        ['type' => 'TXT',  'name' => 'google._domainkey'],
        ['type' => 'TXT',  'name' => 'default._domainkey'],
        ['type' => 'TXT',  'name' => 'k1._domainkey'],
        ['type' => 'TXT',  'name' => 's1._domainkey'],
        ['type' => 'TXT',  'name' => 'selector1._domainkey'],
        ['type' => 'CNAME','name' => 'k1._domainkey'],
        ['type' => 'CNAME','name' => 's1._domainkey'], 

        // --- Provider Specifics ---
        ['type' => 'MX',   'name' => 'mg'],
        ['type' => 'CNAME','name' => 'email.mg'],
        ['type' => 'TXT',  'name' => 'smtp._domainkey.mg'],
        ['type' => 'TXT',  'name' => '_amazonses'],
        ['type' => 'TXT',  'name' => '_mailchannels'],

        // --- SSL / ACME ---
        ['type' => 'CNAME','name' => '_acme-challenge'],
        ['type' => 'TXT',  'name' => '_acme-challenge']
    ];

    $check_map = [];

    // 1. GATHER ALL RECORDS
    foreach ($checks as $check) {
        $type = $check['type'];
        $name = $check['name'];
        $host = $name ? "$name.$domain" : $domain;

        // Run Dig
        $output = shell_exec("dig +short -t $type " . escapeshellarg($host));
        if (!$output) continue;

        foreach (explode("\n", trim($output)) as $val) {
            $val = trim($val);
            if (empty($val)) continue;

            // Deduplicate at the raw level
            $key = "$type|$name|$val";
            if (isset($check_map[$key])) continue;
            $check_map[$key] = true;

            $raw_records[] = ['type' => $type, 'name' => $name ?: '@', 'value' => $val];
        }
    }

    // 2. INTELLIGENT FILTERING (CNAME Exclusivity)
    // Identify which subdomains have a CNAME
    $cname_hosts = [];
    foreach ($raw_records as $r) {
        if ($r['type'] === 'CNAME') {
            $cname_hosts[$r['name']] = true;
        }
    }

    $dns_records = [];
    $zone = new Zone($domain . ".");
    $zone->setDefaultTtl(3600);

    foreach ($raw_records as $r) {
        // If this host has a CNAME, but this specific record is NOT the CNAME (e.g. it's a leaked TXT), skip it.
        if (isset($cname_hosts[$r['name']]) && $r['type'] !== 'CNAME') {
            continue; 
        }

        // Add to UI Array
        $dns_records[] = $r;

        // Add to Badcow Zone Object
        try {
            $rr = new ResourceRecord();
            $rr->setName($r['name']);
            $rr->setClass('IN');
            
            // Factory Mapping
            switch ($r['type']) {
                case 'A': $rr->setRdata(Factory::A($r['value'])); break;
                case 'CNAME': $rr->setRdata(Factory::Cname($r['value'])); break;
                case 'NS': $rr->setRdata(Factory::Ns($r['value'])); break;
                case 'TXT': $rr->setRdata(Factory::Txt(trim($r['value'], '"'))); break;
                case 'MX': 
                    $parts = explode(' ', $r['value']);
                    if(count($parts)==2) $rr->setRdata(Factory::Mx($parts[0], $parts[1])); 
                    break;
                case 'SOA':
                    $p = explode(' ', $r['value']);
                    if(count($p)>=7) $rr->setRdata(Factory::Soa($p[0],$p[1],$p[2],$p[3],$p[4],$p[5],$p[6]));
                    break;
                case 'SRV':
                    // dig +short SRV returns: 10 100 5061 sip.example.com.
                    $p = preg_split('/\s+/', $r['value']);
                    if(count($p) >= 4) {
                        $target = rtrim($p[3], '.');
                        $rr->setRdata(Factory::Srv((int)$p[0], (int)$p[1], (int)$p[2], $target));
                    }
                    break;
            }
            $zone->addResourceRecord($rr);
        } catch (Exception $e) { /* Ignore parsing errors */ }
    }

    // Build the Pretty Zone File using the Library
    $builder = new AlignedBuilder();
    $builder->addRdataFormatter('TXT', 'specialTxtFormatter');
    $zoneFile = $builder->build($zone);

    // Get IP Info
    $ips = gethostbynamel($domain);
    $ip_lookup = [];
    if ($ips) foreach ($ips as $ip) {
        $res = shell_exec("whois " . escapeshellarg($ip) . " | grep -m 1 -E 'OrgName:|NetName:|Organization:'");
        $ip_lookup[$ip] = trim($res ?: 'N/A');
    }

    // Get Headers
    $headers = [];
    $h_out = shell_exec("curl -I -s -L --max-time 2 " . escapeshellarg("http://".$domain));
    if($h_out) foreach(explode("\n", $h_out) as $line) {
        if(strpos($line, ':')) {
            [$k, $v] = explode(':', $line, 2);
            $headers[trim($k)] = trim($v);
        }
    }

    return [
        'domain' => getWhois($domain),
        'dns_records' => $dns_records,
        'zone' => $zoneFile,
        'ip_lookup' => $ip_lookup,
        'http_headers' => $headers,
        'errors' => [],
        'timestamp' => time()
    ];
}

// --- CLI EXECUTION ---
if (php_sapi_name() === 'cli') {
    if ($argc < 2) { echo "Usage: php engine.php <domain>\n"; exit(1); }
    $domain = $argv[1];
    echo "Looking up domain: $domain...\n\n";
    $data = performLookup($domain);
    if ($pdo) {
        $stmt = $pdo->prepare("INSERT INTO history (domain, timestamp, data) VALUES (?, ?, ?)");
        $stmt->execute([$domain, time(), json_encode($data)]);
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
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, POST");
header('Content-Type: application/json');

$action = $_GET['action'] ?? '';

if ($action === 'check_status') {
    echo json_encode(['has_db' => ($pdo !== null)]); exit;
}

if ($pdo) {
    if ($action === 'get_history') {
        $stmt = $pdo->query("SELECT id, domain, timestamp, data FROM history ORDER BY timestamp DESC LIMIT 50");
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
        foreach($rows as &$r) { 
            $d = json_decode($r['data'], true);
            $r['data'] = is_string($d) ? json_decode($d, true) : $d; 
        }
        echo json_encode($rows); exit;
    }
    if ($action === 'get_domain_versions') {
        $stmt = $pdo->prepare("SELECT id, domain, timestamp FROM history WHERE domain = ? ORDER BY timestamp DESC");
        $stmt->execute([$_GET['domain']]);
        echo json_encode($stmt->fetchAll(PDO::FETCH_ASSOC)); exit;
    }
    if ($action === 'get_history_item') {
        $stmt = $pdo->prepare("SELECT data, timestamp FROM history WHERE id = ?");
        $stmt->execute([$_GET['id']]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        if($row) {
            $d = json_decode($row['data'], true);
            $data = is_string($d) ? json_decode($d, true) : $d;
            $data['timestamp'] = $row['timestamp'];
            echo json_encode($data);
        } else echo json_encode([]); 
        exit;
    }
    if ($action === 'save_history') {
        $in = json_decode(file_get_contents('php://input'), true);
        $pdo->prepare("INSERT INTO history (domain, timestamp, data) VALUES (?, ?, ?)")
            ->execute([$in['domain'], time(), json_encode($in['data'])]);
        exit;
    }
    if ($action === 'delete_history') {
        $pdo->prepare("DELETE FROM history WHERE id = ?")->execute([$_POST['id']]);
        echo json_encode(['success'=>true]); exit;
    }
    // Export / Import Support
    if ($action === 'export_history') {
        $stmt = $pdo->query("SELECT domain, timestamp, data FROM history ORDER BY timestamp DESC");
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
        foreach($rows as &$r) {
             $d = json_decode($r['data'], true);
             $r['data'] = is_string($d) ? json_decode($d, true) : $d;
        }
        header('Content-Disposition: attachment; filename="periscope.json"');
        echo json_encode($rows, JSON_PRETTY_PRINT); exit;
    }
    if ($action === 'import_history') {
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
}

if (isset($_GET['dig'])) {
    $d = trim($_GET['dig']);
    // Validate: only allow domain-like characters
    if (preg_match('/^[a-zA-Z0-9\.\-\*]+$/', $d)) {
        echo shell_exec("dig +short " . escapeshellarg($d) . " TXT");
    } else { echo "Invalid domain"; }
    exit;
}
if (isset($_GET['whois'])) {
    $ip = trim($_GET['whois']);
    if (filter_var($ip, FILTER_VALIDATE_IP)) {
        echo shell_exec("whois " . escapeshellarg($ip));
    } else { echo "Invalid IP"; }
    exit;
}
if (isset($_GET['raw_domain'])) {
    // Return raw RDAP data
    echo json_encode(getWhois($_GET['raw_domain']), JSON_PRETTY_PRINT);
    exit;
}
if(isset($_GET['domain'])) {
    echo json_encode(performLookup($_GET['domain']));
} else {
    echo json_encode(['error' => 'No domain provided']);
}
?>
EOF

# --- Launch ---
URL="https://periscope.run?local=true"

if grep -q "Microsoft" /proc/version &> /dev/null; then
    if command -v wslview &> /dev/null; then wslview "$URL";
    elif command -v cmd.exe &> /dev/null; then cmd.exe /c start "$URL" 2> /dev/null; fi
elif command -v xdg-open &> /dev/null; then xdg-open "$URL";
elif command -v open &> /dev/null; then open "$URL"; fi

echo -e "${GREEN}🔗 Web UI:    http://127.0.0.1:$PORT${NC}"
echo -e "${GREEN}💻 CLI Usage: php $ENGINE_FILE domain.com${NC}"
echo -e "${GREEN}📂 Database:  $DB_FILE${NC}"
echo ""

PERISCOPE_DB="$DB_FILE" php -S 127.0.0.1:$PORT "$ENGINE_FILE"