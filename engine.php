<?php
// ERROR REPORTING - Enable verbose errors when PERISCOPE_DEBUG is set
if (getenv('PERISCOPE_DEBUG')) {
    error_reporting(E_ALL);
    ini_set('display_errors', '1');
} else {
    // SILENCE DEPRECATIONS
    error_reporting(E_ERROR | E_PARSE);
    ini_set('display_errors', '0');
}

// --- CLI ARGUMENT PARSING ---
if (php_sapi_name() === 'cli' && isset($argv[1])) {
    parse_str($argv[1], $cli_params);
    $_GET = array_merge($_GET, $cli_params);
}

// --- PLUGIN VERSION ---
define('PERISCOPE_VERSION', '1.6.0');

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

// === CONSTANTS ===

// Multi-part TLDs for domain extraction
const MULTI_PART_TLDS = [
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

// DNS Checks - Core records and common subdomains
const DNS_CHECKS_CORE = [
    ['type' => 'A', 'name' => ''], ['type' => 'A', 'name' => 'www'],
    ['type' => 'AAAA', 'name' => ''], ['type' => 'AAAA', 'name' => 'www'],
    ['type' => 'NS', 'name' => ''], ['type' => 'SOA', 'name' => ''], ['type' => 'MX', 'name' => ''], ['type' => 'TXT', 'name' => ''],
    ['type' => 'CAA', 'name' => ''],
    ['type' => 'HTTPS', 'name' => ''], ['type' => 'SVCB', 'name' => ''],
    ['type' => 'TLSA', 'name' => '_443._tcp'], ['type' => 'TLSA', 'name' => '_25._tcp'],
    // Common subdomains
    ['type' => 'A', 'name' => 'mail'], ['type' => 'A', 'name' => 'webmail'], ['type' => 'A', 'name' => 'smtp'],
    ['type' => 'A', 'name' => 'imap'], ['type' => 'A', 'name' => 'pop'], ['type' => 'A', 'name' => 'email'],
    ['type' => 'A', 'name' => 'ftp'], ['type' => 'A', 'name' => 'cpanel'],
    ['type' => 'A', 'name' => 'whm'], ['type' => 'A', 'name' => 'plesk'], ['type' => 'A', 'name' => 'blog'],
    ['type' => 'A', 'name' => 'shop'], ['type' => 'A', 'name' => 'portal'], ['type' => 'A', 'name' => 'dev'],
    ['type' => 'A', 'name' => 'api'], ['type' => 'A', 'name' => 'app'], ['type' => 'A', 'name' => 'remote'],
    ['type' => 'A', 'name' => 'vpn'],
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
    ['type' => 'TXT', 'name' => 'www'],
    // Microsoft / Office 365
    ['type' => 'CNAME', 'name' => 'cdn'], ['type' => 'CNAME', 'name' => 'status'], ['type' => 'CNAME', 'name' => '_domainconnect'],
    ['type' => 'CNAME', 'name' => 'autodiscover'], ['type' => 'CNAME', 'name' => 'lyncdiscover'], ['type' => 'CNAME', 'name' => 'sip'],
    ['type' => 'CNAME', 'name' => 'enterpriseregistration'], ['type' => 'CNAME', 'name' => 'enterpriseenrollment'], ['type' => 'CNAME', 'name' => 'msoid'],
    ['type' => 'SRV', 'name' => '_sip._tls'], ['type' => 'SRV', 'name' => '_sipfederationtls._tcp'], ['type' => 'SRV', 'name' => '_autodiscover._tcp'],
    ['type' => 'SRV', 'name' => '_submissions._tcp'], ['type' => 'SRV', 'name' => '_imaps._tcp'],
];

// DNS Checks - Email and DKIM records
const DNS_CHECKS_EMAIL = [
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
    ['type' => 'TXT', 'name' => '_facebook'], ['type' => 'TXT', 'name' => '_dnslink'],
    ['type' => 'TXT', 'name' => '_cf-custom-hostname']
];

// --- DATABASE SETUP ---
$db_path = getenv('PERISCOPE_DB') ?: __DIR__ . '/history.db';
$pdo = null;
try {
    $pdo = new PDO('sqlite:' . $db_path);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    // Enable WAL mode for better concurrency (allows reads during writes)
    $pdo->exec("PRAGMA journal_mode=WAL");
    // Wait up to 5 seconds for locks to clear instead of failing immediately
    $pdo->exec("PRAGMA busy_timeout=5000");
    $pdo->exec("CREATE TABLE IF NOT EXISTS history (id INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT NOT NULL, timestamp INTEGER NOT NULL, data TEXT NOT NULL, filters TEXT DEFAULT '')");
    // Migration: add filters column if it doesn't exist (for existing databases)
    $cols = $pdo->query("PRAGMA table_info(history)")->fetchAll(PDO::FETCH_COLUMN, 1);
    if (!in_array('filters', $cols)) {
        $pdo->exec("ALTER TABLE history ADD COLUMN filters TEXT DEFAULT ''");
    }
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

function buildFiltersJson($data) {
    if (!$data || !is_array($data)) return '';
    
    $filters = [];
    
    // Domain exists
    $filters['exists'] = !isset($data['domain_exists']) || $data['domain_exists'] !== false;
    
    // Hidden from search engines
    $filters['blocked'] = isset($data['indexability']['blocked']) && $data['indexability']['blocked'] === true;
    
    // Platform/CMS
    $filters['platform'] = isset($data['cms']['name']) ? $data['cms']['name'] : null;
    
    // Hosting provider
    $filters['host'] = isset($data['infrastructure']['host']) ? $data['infrastructure']['host'] : null;
    
    // CDN
    $filters['cdn'] = isset($data['infrastructure']['cdn']) ? $data['infrastructure']['cdn'] : null;
    
    // Server software
    $filters['server'] = isset($data['infrastructure']['server']) ? $data['infrastructure']['server'] : null;
    
    // SSL issuer
    $filters['ssl_issuer'] = isset($data['ssl']['issuer']) ? $data['ssl']['issuer'] : null;
    
    // SSL valid
    $filters['ssl_valid'] = isset($data['ssl']['valid']) ? $data['ssl']['valid'] === true : null;
    
    // HTTP status code
    $filters['status'] = isset($data['request']['status_code']) ? (int)$data['request']['status_code'] : null;
    
    // IPv6 support (check for AAAA records)
    $filters['ipv6'] = false;
    if (isset($data['dns_records']) && is_array($data['dns_records'])) {
        foreach ($data['dns_records'] as $rec) {
            if (isset($rec['type']) && $rec['type'] === 'AAAA') {
                $filters['ipv6'] = true;
                break;
            }
        }
    }
    
    // Has sitemap
    $filters['has_sitemap'] = isset($data['metadata']['sitemap']['present']) && $data['metadata']['sitemap']['present'] === true;
    
    // Has robots.txt
    $filters['has_robots'] = isset($data['metadata']['robots_txt']['present']) && $data['metadata']['robots_txt']['present'] === true;
    
    return json_encode($filters);
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
    $parts = explode('.', $host);
    $numParts = count($parts);

    if ($numParts <= 2) {
        return $host; // Already a root domain
    }

    // Check for multi-part TLDs
    $lastTwo = $parts[$numParts - 2] . '.' . $parts[$numParts - 1];
    if (in_array($lastTwo, MULTI_PART_TLDS)) {
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

function saveRawFiles($path, $html, $headers, $whoisDomain, $whoisIps, $ssl, $dns, $rdap = null, $metadata_files = [], $redirectChain = null, $ptrRecords = null, $connectionInfo = null) {
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
    // Save redirect chain with connection info merged into final hop
    if ($redirectChain && count($redirectChain) > 0) {
        // Merge connection info (protocol, timing) into final redirect entry
        if ($connectionInfo && !empty($redirectChain)) {
            $lastIndex = count($redirectChain) - 1;
            if (isset($connectionInfo['http_version'])) {
                $redirectChain[$lastIndex]['protocol'] = $connectionInfo['http_version'];
            }
            if (isset($connectionInfo['timing'])) {
                $redirectChain[$lastIndex]['timing'] = $connectionInfo['timing'];
            }
        }
        file_put_contents("$path/redirects.json", json_encode($redirectChain));
    }
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

function downloadImage($url, $maxSize = 10000000) {
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS => 5,
        CURLOPT_TIMEOUT => 5,
        CURLOPT_CONNECTTIMEOUT => 3,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_SSL_VERIFYHOST => false,
        CURLOPT_USERAGENT => 'Periscope/' . PERISCOPE_VERSION . ' (Image Fetcher)',
        CURLOPT_HTTPHEADER => ['Accept: image/webp,image/png,image/jpeg,image/gif,image/*'],
        // Abort download if size exceeds limit (prevents OOM on malicious large files)
        CURLOPT_NOPROGRESS => false,
        CURLOPT_PROGRESSFUNCTION => function($ch, $dlTotal, $dlNow, $ulTotal, $ulNow) use ($maxSize) {
            return ($dlTotal > $maxSize || $dlNow > $maxSize) ? 1 : 0;
        },
    ]);

    $content = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if (!$content || $httpCode !== 200 || strlen($content) > $maxSize) return null;

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
    if (!$cache || !isset($cache['plugin_version'])) return false;
    // Compare only major.minor version (ignore patch for minor updates)
    $currentParts = explode('.', PERISCOPE_VERSION);
    $cachedParts = explode('.', $cache['plugin_version']);
    $currentMinor = $currentParts[0] . '.' . ($currentParts[1] ?? '0');
    $cachedMinor = $cachedParts[0] . '.' . ($cachedParts[1] ?? '0');
    return $currentMinor === $cachedMinor;
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

// Open a file or URL in the user's default browser. Mirrors boot.sh's launch
// detection (macOS `open`, WSL `wslview`/`cmd.exe`, Linux `xdg-open`) and runs
// detached so the CLI returns immediately.
function openInBrowser($target) {
    if (PHP_OS_FAMILY === 'Darwin') {
        shell_exec('open ' . escapeshellarg($target) . ' > /dev/null 2>&1 &');
        return;
    }
    if (PHP_OS_FAMILY === 'Windows') {
        shell_exec('start "" ' . escapeshellarg($target));
        return;
    }
    // Linux / WSL
    $isWsl = @is_file('/proc/version') && stripos((string)@file_get_contents('/proc/version'), 'microsoft') !== false;
    if ($isWsl) {
        if (trim((string)shell_exec('command -v wslview 2>/dev/null')) !== '') {
            shell_exec('wslview ' . escapeshellarg($target) . ' > /dev/null 2>&1 &');
        } else {
            shell_exec('cmd.exe /c start "" ' . escapeshellarg($target) . ' > /dev/null 2>&1 &');
        }
        return;
    }
    shell_exec('xdg-open ' . escapeshellarg($target) . ' > /dev/null 2>&1 &');
}

// Is something listening on the local bridge port? Lightweight liveness check
// (a raw socket connect — avoids the check_status action, which walks the whole
// scans dir). Used only for an advisory hint when opening the report URL.
function bridgeRunning($port = 8989) {
    $fp = @fsockopen('127.0.0.1', $port, $errno, $errstr, 0.3);
    if ($fp) { fclose($fp); return true; }
    return false;
}

// Most recent saved scan timestamp for a host (newest scan dir that has a
// usable response cache). Returns null when the host has no cached scan.
function mostRecentScanTimestamp($host) {
    if (empty($host)) return null;
    $dir = getenv('HOME') . "/.periscope/scans/$host";
    if (!is_dir($dir)) return null;
    $timestamps = [];
    foreach (glob("$dir/*", GLOB_ONLYDIR) as $d) {
        $b = basename($d);
        if (ctype_digit($b)) $timestamps[] = (int)$b;
    }
    if (empty($timestamps)) return null;
    rsort($timestamps);
    foreach ($timestamps as $ts) {
        if (file_exists("$dir/$ts/response.json")) return $ts;
    }
    return null;
}

function getRawWhoisDomain($domain) {
    return shell_exec("whois " . escapeshellarg($domain));
}

function getRdapUrl($domain) {
    static $bootstrap = null;
    $tld = strtolower(substr($domain, strrpos($domain, '.') + 1));
    
    if ($bootstrap === null) {
        $ch = curl_init("https://data.iana.org/rdap/dns.json");
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_TIMEOUT, 5);
        curl_setopt($ch, CURLOPT_USERAGENT, 'Periscope/' . PERISCOPE_VERSION);
        $data = curl_exec($ch);
        curl_close($ch);
        $bootstrap = $data ? json_decode($data, true) : null;
    }
    
    if ($bootstrap && isset($bootstrap['services'])) {
        foreach ($bootstrap['services'] as $service) {
            if (in_array($tld, $service[0])) {
                return rtrim($service[1][0], '/') . '/domain/' . $domain;
            }
        }
    }
    
    return "https://rdap.org/domain/" . $domain;
}

function getRawRdap($domain) {
    $url = getRdapUrl($domain);
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    curl_setopt($ch, CURLOPT_USERAGENT, 'Periscope/' . PERISCOPE_VERSION);
    $json = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    return ($code === 200 && $json) ? $json : null;
}

function checkDomainExists($domain) {
    $url = getRdapUrl($domain);
    $ch = curl_init($url);
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
function digQuery($type, $host, $retries = 2, $dnsServer = null, $timeout = 3) {
    for ($i = 0; $i < $retries; $i++) {
        $cmd = "dig +short +time=" . intval($timeout) . " +tries=1 -t " . escapeshellarg($type) . " " . escapeshellarg($host);
        if ($dnsServer) {
            $cmd .= " @" . escapeshellarg($dnsServer);
        }
        $cmd .= " 2>/dev/null";
        $output = shell_exec($cmd);
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
    $connectionInfo = null;

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

        // Capture connection info from the final request
        $remoteIp = curl_getinfo($ch, CURLINFO_PRIMARY_IP);
        $remotePort = curl_getinfo($ch, CURLINFO_PRIMARY_PORT);
        $totalTime = curl_getinfo($ch, CURLINFO_TOTAL_TIME);
        $connectTime = curl_getinfo($ch, CURLINFO_CONNECT_TIME);
        $dnsTime = curl_getinfo($ch, CURLINFO_NAMELOOKUP_TIME);
        $httpVersion = curl_getinfo($ch, CURLINFO_HTTP_VERSION);

        curl_close($ch);

        // Skip if we got no response
        if ($httpCode === 0) break;

        $chain[] = [
            'url' => $currentUrl,
            'status_code' => $httpCode,
            'status_text' => getHttpStatusText($httpCode),
            'remote_address' => $remoteIp ? ($remoteIp . ($remotePort ? ':' . $remotePort : '')) : null
        ];

        // Update connection info (will reflect the final hop)
        $connectionInfo = [
            'remote_ip' => $remoteIp ?: null,
            'remote_port' => $remotePort ?: null,
            'remote_address' => $remoteIp ? ($remoteIp . ($remotePort ? ':' . $remotePort : '')) : null,
            'http_version' => $httpVersion ? getHttpVersionString($httpVersion) : null,
            'timing' => [
                'dns_lookup' => round($dnsTime * 1000, 2),
                'connect' => round($connectTime * 1000, 2),
                'total' => round($totalTime * 1000, 2)
            ]
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

    return ['chain' => $chain, 'connection' => $connectionInfo];
}

function detectHtmlRedirect($html) {
    if (!$html || strlen($html) < 10) return null;

    // Meta refresh: <meta http-equiv="refresh" content="0;url=https://example.com">
    if (preg_match('/<meta[^>]+http-equiv=["\']?refresh["\']?[^>]+content=["\']?\d+\s*;\s*url=([^"\'>\s]+)/i', $html, $m)) {
        return ['type' => 'meta_refresh', 'url' => html_entity_decode(trim($m[1]))];
    }
    // Also check reversed attribute order
    if (preg_match('/<meta[^>]+content=["\']?\d+\s*;\s*url=([^"\'>\s]+)["\']?[^>]+http-equiv=["\']?refresh/i', $html, $m)) {
        return ['type' => 'meta_refresh', 'url' => html_entity_decode(trim($m[1]))];
    }

    // JavaScript: window.location.replace("...")
    if (preg_match('/(?:window\.)?location\.replace\s*\(\s*["\']([^"\']+)["\']\s*\)/i', $html, $m)) {
        return ['type' => 'javascript', 'url' => $m[1]];
    }
    // JavaScript: window.location = "..." or window.location.href = "..." or location.href = "..."
    // Must have "window." prefix OR ".href" suffix to avoid matching HTML attributes like data-location="..."
    if (preg_match('/window\.location(?:\.href)?\s*=\s*["\']([^"\']+)["\']/i', $html, $m)) {
        return ['type' => 'javascript', 'url' => $m[1]];
    }
    if (preg_match('/[^-\w]location\.href\s*=\s*["\']([^"\']+)["\']/i', $html, $m)) {
        return ['type' => 'javascript', 'url' => $m[1]];
    }

    return null;
}

function getUrlStatus($url, $timeout = 5) {
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_NOBODY => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS => 5,
        CURLOPT_TIMEOUT => $timeout,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_USERAGENT => 'Periscope/' . PERISCOPE_VERSION
    ]);
    curl_exec($ch);
    $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $finalUrl = curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
    curl_close($ch);
    return ['status_code' => $status ?: null, 'final_url' => $finalUrl];
}

function getHttpVersionString($version) {
    $versions = [
        CURL_HTTP_VERSION_1_0 => 'HTTP/1.0',
        CURL_HTTP_VERSION_1_1 => 'HTTP/1.1',
        CURL_HTTP_VERSION_2_0 => 'HTTP/2',
        CURL_HTTP_VERSION_2 => 'HTTP/2',
    ];
    // CURL_HTTP_VERSION_3 may not exist in older PHP versions
    if (defined('CURL_HTTP_VERSION_3') && $version === CURL_HTTP_VERSION_3) {
        return 'HTTP/3';
    }
    return $versions[$version] ?? 'HTTP/1.1';
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

function detectCMS($domain, $html = null, $headers = [], $robotsTxt = null, $sitemapXml = null) {
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
            if (is_array($v)) continue;
            if (stripos($k, 'x-powered-by') !== false && stripos($v, 'WordPress') !== false) $is_wp = true;
            // Common WordPress Link header for REST API
            if (stripos($k, 'link') !== false && stripos($v, 'api.w.org') !== false) $is_wp = true;
        }
    }

    // 6. Metadata fallback: robots.txt and sitemap.xml signals
    if (!$is_wp && $robotsTxt) {
        if (preg_match('/wp-json|rest_route|YOAST/i', $robotsTxt)) $is_wp = true;
    }
    if (!$is_wp && $sitemapXml) {
        if (preg_match('/wp-content|wordpress-seo|Yoast SEO/i', $sitemapXml)) $is_wp = true;
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
    // Look for actual Squarespace CMS markers, not just text mentions
    $is_squarespace = false;

    // 1. Static resources from Squarespace CDN in src/href attributes
    if (preg_match('/(src|href)=["\'][^"\']*static\d*\.squarespace\.com/i', $html)) $is_squarespace = true;

    // 2. Squarespace-specific data attributes
    if (!$is_squarespace && preg_match('/data-squarespace-cacheversion/i', $html)) $is_squarespace = true;

    // 3. Squarespace meta tags (squarespace: namespace)
    if (!$is_squarespace && preg_match('/<meta[^>]+property=["\']squarespace:/i', $html)) $is_squarespace = true;

    // 4. Squarespace JavaScript globals/initialization
    if (!$is_squarespace && preg_match('/Static\.SQUARESPACE_CONTEXT|Squarespace\.afterBodyLoad/i', $html)) $is_squarespace = true;

    // 5. sqs- class prefix (Squarespace's common pattern)
    if (!$is_squarespace && preg_match('/class=["\'][^"\']*\bsqs-/i', $html)) $is_squarespace = true;

    if ($is_squarespace) {
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

    // Minnow (X-Generator header)
    if (!empty($headers)) {
        $h = array_change_key_case($headers, CASE_LOWER);
        if (isset($h['x-generator']) && stripos($h['x-generator'], 'Minnow') !== false) {
            $version = null;
            if (preg_match('/Minnow\s+([\d.]+)/i', $h['x-generator'], $m)) $version = $m[1];
            return ['name' => 'Minnow', 'version' => $version];
        }
    }

    return null;
}

function detectInfrastructure($headers) {
    $result = ['cdn' => null, 'host' => null, 'server' => null, 'language' => null];
    $h = array_change_key_case($headers, CASE_LOWER);

    // Server-side language detection
    // X-Powered-By header (PHP, ASP.NET, Express, etc.)
    if (isset($h['x-powered-by'])) {
        $xpb = $h['x-powered-by'];
        if (preg_match('/PHP\/?([\d.]+)?/i', $xpb, $m)) {
            $result['language'] = 'PHP' . (!empty($m[1]) ? ' ' . $m[1] : '');
        } elseif (preg_match('/ASP\.NET/i', $xpb)) {
            $result['language'] = 'ASP.NET';
            if (preg_match('/version[:\s]*([\d.]+)/i', $xpb, $m)) {
                $result['language'] .= ' ' . $m[1];
            }
        } elseif (preg_match('/Express/i', $xpb)) {
            $result['language'] = 'Node.js (Express)';
        } elseif (preg_match('/Next\.?js/i', $xpb)) {
            $result['language'] = 'Node.js (Next.js)';
        } elseif (preg_match('/Servlet/i', $xpb)) {
            $result['language'] = 'Java (Servlet)';
        } elseif (preg_match('/JSP/i', $xpb)) {
            $result['language'] = 'Java (JSP)';
        } elseif (preg_match('/Phusion Passenger/i', $xpb)) {
            $result['language'] = 'Ruby (Passenger)';
        } elseif (preg_match('/Puma/i', $xpb)) {
            $result['language'] = 'Ruby (Puma)';
        } elseif (preg_match('/Unicorn/i', $xpb)) {
            $result['language'] = 'Ruby (Unicorn)';
        } elseif (preg_match('/Uvicorn/i', $xpb)) {
            $result['language'] = 'Python (Uvicorn)';
        } elseif (preg_match('/gunicorn/i', $xpb)) {
            $result['language'] = 'Python (Gunicorn)';
        } elseif (preg_match('/Werkzeug/i', $xpb)) {
            $result['language'] = 'Python (Flask)';
        } elseif (preg_match('/Django/i', $xpb)) {
            $result['language'] = 'Python (Django)';
        } elseif (preg_match('/Kestrel/i', $xpb)) {
            $result['language'] = '.NET (Kestrel)';
        } elseif (preg_match('/PleskLin/i', $xpb)) {
            $result['language'] = 'Plesk (Linux)';
        } elseif (preg_match('/PleskWin/i', $xpb)) {
            $result['language'] = 'Plesk (Windows)';
        }
    }

    // X-AspNet-Version header
    if (!$result['language'] && isset($h['x-aspnet-version'])) {
        $result['language'] = 'ASP.NET ' . $h['x-aspnet-version'];
    }

    // X-AspNetMvc-Version header
    if (!$result['language'] && isset($h['x-aspnetmvc-version'])) {
        $result['language'] = 'ASP.NET MVC ' . $h['x-aspnetmvc-version'];
    }

    // Set-Cookie can hint at language/framework
    if (!$result['language'] && isset($h['set-cookie'])) {
        $cookie = is_array($h['set-cookie']) ? implode(' ', $h['set-cookie']) : $h['set-cookie'];
        if (preg_match('/PHPSESSID/i', $cookie)) {
            $result['language'] = 'PHP';
        } elseif (preg_match('/JSESSIONID/i', $cookie)) {
            $result['language'] = 'Java';
        } elseif (preg_match('/ASP\.NET_SessionId/i', $cookie)) {
            $result['language'] = 'ASP.NET';
        } elseif (preg_match('/rack\.session/i', $cookie)) {
            $result['language'] = 'Ruby';
        } elseif (preg_match('/connect\.sid/i', $cookie)) {
            $result['language'] = 'Node.js';
        } elseif (preg_match('/django_session|csrftoken/i', $cookie)) {
            $result['language'] = 'Python (Django)';
        } elseif (preg_match('/laravel_session/i', $cookie)) {
            $result['language'] = 'PHP (Laravel)';
        }
    }

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
    if ($result['cdn'] || $result['host'] || $result['server'] || $result['language']) {
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

function analyzeCookieSecurity($headers) {
    $h = array_change_key_case($headers, CASE_LOWER);
    if (!isset($h['set-cookie'])) return null;

    $rawCookies = is_array($h['set-cookie']) ? $h['set-cookie'] : [$h['set-cookie']];
    if (empty($rawCookies)) return null;

    $sessionPatterns = '/^(PHPSESSID|JSESSIONID|ASP\.NET_SessionId|connect\.sid|rack\.session|django_session|laravel_session|CFID|CFTOKEN|ci_session|wp_sec|SERVERID|session_id|sid|sess_id)/i';

    $cookies = [];
    foreach ($rawCookies as $raw) {
        $parts = explode(';', $raw);
        $nameValue = trim($parts[0]);
        $eqPos = strpos($nameValue, '=');
        $name = $eqPos !== false ? substr($nameValue, 0, $eqPos) : $nameValue;

        $flags = strtolower($raw);
        $secure = stripos($flags, '; secure') !== false || stripos($flags, ';secure') !== false;
        $httponly = stripos($flags, '; httponly') !== false || stripos($flags, ';httponly') !== false;
        $samesite = null;
        if (preg_match('/;\s*samesite\s*=\s*(strict|lax|none)/i', $raw, $m)) {
            $samesite = ucfirst(strtolower($m[1]));
        }
        $isSession = (bool)preg_match($sessionPatterns, $name);

        $cookies[] = [
            'name' => $name,
            'secure' => $secure,
            'httponly' => $httponly,
            'samesite' => $samesite,
            'session' => $isSession
        ];
    }

    // Score based on session cookies only
    $sessionCookies = array_filter($cookies, fn($c) => $c['session']);
    if (empty($sessionCookies)) {
        // No session cookies — still show cookie info but perfect score
        return ['cookies' => $cookies, 'issues' => [], 'score' => null];
    }

    $issues = [];
    $allSecure = true; $allHttpOnly = true; $allSameSite = true;
    foreach ($sessionCookies as $c) {
        if (!$c['secure']) { $allSecure = false; $issues[] = 'Session cookie "' . $c['name'] . '" missing Secure flag'; }
        if (!$c['httponly']) { $allHttpOnly = false; $issues[] = 'Session cookie "' . $c['name'] . '" missing HttpOnly flag'; }
        if (!$c['samesite']) { $allSameSite = false; $issues[] = 'Session cookie "' . $c['name'] . '" missing SameSite attribute'; }
    }

    $score = ($allSecure ? 1 : 0) + ($allHttpOnly ? 1 : 0) + ($allSameSite ? 1 : 0);

    return [
        'cookies' => $cookies,
        'issues' => $issues,
        'score' => ['value' => $score, 'total' => 3]
    ];
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

    $setCookieStr = isset($h['set-cookie']) ? (is_array($h['set-cookie']) ? implode(' ', $h['set-cookie']) : $h['set-cookie']) : '';
    if (preg_match('/<script[^>]+type=["\']text\/x-magento-init["\']|Mage\.Cookies|static\/version[a-z0-9]+\/frontend/i', $html) ||
        ($setCookieStr && stripos($setCookieStr, 'mage-') !== false)) {
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

function detectMetadata($domain, $html = null, &$rawFiles = [], $storageDomain = null) {
    // Use storageDomain for saving files (defaults to $domain if not specified)
    $storageDomain = $storageDomain ?: $domain;
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
    // Validate: must match ads.txt format AND not be HTML (404 pages often return HTML)
    if ($adsTxt && preg_match('/^[a-z0-9.-]+,\s*[a-z0-9]+,/im', $adsTxt) && stripos($adsTxt, '<!DOCTYPE') === false && stripos($adsTxt, '<html') === false) {
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
    // Validate: must match app-ads.txt format AND not be HTML (404 pages often return HTML)
    if ($appAdsTxt && preg_match('/^[a-z0-9.-]+,\s*[a-z0-9]+,/im', $appAdsTxt) && stripos($appAdsTxt, '<!DOCTYPE') === false && stripos($appAdsTxt, '<html') === false) {
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
        'http' => ['timeout' => 2, 'ignore_errors' => true, 'follow_location' => 1],
        'ssl' => ['verify_peer' => false, 'verify_peer_name' => false]
    ]);
    @file_get_contents("https://" . $domain . "/.well-known/change-password", false, $changePassCtx);
    $changePassHeaders = $http_response_header ?? [];
    $changePassStatus = 0;
    if (!empty($changePassHeaders)) {
        foreach ($changePassHeaders as $h) {
            if (preg_match('/HTTP\/\d\.?\d?\s+(\d{3})/', $h, $m)) $changePassStatus = (int)$m[1];
        }
    }
    $changePassRedirect = null;
    foreach ($changePassHeaders as $header) {
        if (preg_match('/^Location:\s*(.+)/i', $header, $m)) $changePassRedirect = trim($m[1]);
    }
    // Only consider it present if status is 200 OK or 3xx Redirect (strictly less than 400)
    if ($changePassStatus >= 200 && $changePassStatus < 400) {
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
                $stored = storeFileByHash($storageDomain, $ogImageData['content'], $ogImageData['extension']);
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
                $stored = storeFileByHash($storageDomain, $twitterImageData['content'], $twitterImageData['extension']);
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

        // Store in hash-based location (use storageDomain for consistency)
        $stored = storeFileByHash($storageDomain, $favicon, $extension);
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
        if (is_array($value)) continue;
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

    // Calculate target_host/root_domain/is_subdomain for consistency with live scans
    $targetHost = normalizeInput($domain);
    $rootDomain = extractRootDomain($targetHost);
    $isSubdomain = ($targetHost !== $rootDomain);

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
    $sitemapXmlContent = $raw['sitemap_xml'] ?? ($metadataRawFiles['sitemap_xml'] ?? null);

    // Build request info from redirect chain (if available)
    $redirectChain = $raw['redirect_chain'] ?? [];

    // Check for HTML redirects if not already detected (for cache regeneration)
    $hasHtmlRedirect = false;
    foreach ($redirectChain as $hop) {
        if (isset($hop['type']) && in_array($hop['type'], ['meta_refresh', 'javascript'])) {
            $hasHtmlRedirect = true;
            break;
        }
    }
    if (!$hasHtmlRedirect && !empty($html)) {
        $htmlRedirect = detectHtmlRedirect($html);
        if ($htmlRedirect && !empty($htmlRedirect['url'])) {
            $targetUrl = $htmlRedirect['url'];
            if (strpos($targetUrl, 'http') !== 0) {
                $targetUrl = "https://{$domain}" . (strpos($targetUrl, '/') === 0 ? '' : '/') . $targetUrl;
            }
            $targetStatus = getUrlStatus($targetUrl);
            $redirectChain[] = [
                'url' => $targetUrl,
                'status_code' => $targetStatus['status_code'],
                'status_text' => $targetStatus['status_code'] ? getHttpStatusText($targetStatus['status_code']) : null,
                'type' => $htmlRedirect['type']
            ];
        }
    }

    $finalHop = !empty($redirectChain) ? end($redirectChain) : null;
    $requestInfo = $finalHop ? [
        'url' => $finalHop['url'] ?? "https://$domain",
        'method' => 'GET',
        'status_code' => $finalHop['status_code'] ?? null,
        'status_text' => $finalHop['status_text'] ?? null,
        'remote_address' => $finalHop['remote_address'] ?? null,
        'protocol' => $finalHop['protocol'] ?? null,
        'timing' => $finalHop['timing'] ?? null
    ] : null;

    $data = [
        'target_host' => $targetHost,
        'root_domain' => $rootDomain,
        'is_subdomain' => $isSubdomain,
        'domain' => $domainData,
        'dns_records' => $dnsRecords,
        'zone' => $zoneFile,
        'ip_lookup' => $ip_lookup,
        'ptr_records' => $ptr_records,
        'http_headers' => $headers,
        'request' => $requestInfo,
        'ssl' => getSSLInfo($domain, $rawSsl),
        'cms' => detectCMS($domain, $html, $headers, $robotsTxtContent, $sitemapXmlContent),
        'infrastructure' => detectInfrastructure($headers),
        'security' => detectSecurityHeaders($headers),
        'cookie_security' => analyzeCookieSecurity($headers),
        'technology' => detectTechnology($html, $headers),
        'metadata' => $metadata,
        'redirect_chain' => $redirectChain,
        'indexability' => detectSearchEngineBlocking($html, $headers, $robotsTxtContent),
        'errors' => [],
        'raw_available' => true,
        'plugin_version' => PERISCOPE_VERSION,
        'dns_server' => $dnsServer
    ];

    // Save cache if we have timestamp info
    if ($saveCache && $timestamp) {
        $path = getScanPath($domain, $timestamp);
        saveResponseCache($path, $data);
        
        // Update filters column in database if exists
        global $pdo;
        if ($pdo) {
            $filters = buildFiltersJson($data);
            $stmt = $pdo->prepare("UPDATE history SET filters = ? WHERE domain = ? AND timestamp = ? AND (filters = '' OR filters IS NULL)");
            $stmt->execute([$filters, $domain, $timestamp]);
        }
    }

    return $data;
}

// Helper function to process DNS checks with deduplication
function processDnsChecks($checks, $rootDomain, $wildcardAValues, $wildcardTXTValue, $wildcardCNAMEValue, &$check_map, &$raw_records, $dnsServer = null, $progressUpdate = null) {
    foreach ($checks as $check) {
        $type = $check['type']; $name = $check['name'];

        $host = $name ? "$name.$rootDomain" : $rootDomain;
        $isWildcardSubA = ($type === 'A' && !empty($wildcardAValues) && !empty($name) && $name !== 'www');

        if ($progressUpdate) $progressUpdate('', "dig $type $host");

        // Check for CNAME before A/AAAA/TXT queries (skip for subdomain A when wildcard A exists)
        if (($type === 'A' || $type === 'AAAA' || $type === 'TXT') && !empty($name) && $type !== 'CNAME'
            && !$isWildcardSubA) {
            $cnameOutput = digQuery('CNAME', $host, 1, $dnsServer, 2);
            if ($cnameOutput && !empty(trim($cnameOutput))) {
                $cnameVal = trim(explode("\n", trim($cnameOutput))[0]);
                if ($wildcardCNAMEValue !== null && $cnameVal === $wildcardCNAMEValue) continue;
                $key = "CNAME|$name|$cnameVal";
                if (!isset($check_map[$key])) {
                    $check_map[$key] = true;
                    $raw_records[] = ['type' => 'CNAME', 'name' => $name, 'value' => $cnameVal];
                }
                continue;
            }
        }

        // Use single retry and shorter timeout for wildcard subdomain A checks (just detecting differences)
        $output = $isWildcardSubA
            ? digQuery($type, $host, 1, $dnsServer, 2)
            : digQuery($type, $host, 2, $dnsServer);
        if (!$output) continue;
        foreach (explode("\n", trim($output)) as $val) {
            $val = trim($val); if (empty($val)) continue;
            if (($type === 'A' || $type === 'AAAA') && preg_match('/[a-zA-Z]/', $val)) continue;
            if ($type === 'A' && !empty($wildcardAValues) && !empty($name) && $name !== 'www' && in_array($val, $wildcardAValues, true)) continue;
            if ($type === 'TXT' && $wildcardTXTValue !== null && !empty($name) && $val === $wildcardTXTValue) continue;
            if ($wildcardCNAMEValue !== null && !empty($name) && $name !== '*' && $val === $wildcardCNAMEValue) continue;
            
            $key = "$type|$name|$val"; if (isset($check_map[$key])) continue;
            $check_map[$key] = true;
            $raw_records[] = ['type' => $type, 'name' => $name ?: '@', 'value' => $val];
        }
    }
}

// Helper function to add metadata storage flags
function addMetadataStorageFlags(&$metadata, $metadataRawFiles) {
    $fields = [
        'robots_txt' => 'robots_txt',
        'sitemap' => 'sitemap_xml',
        'security_txt' => 'security_txt',
        'ads_txt' => 'ads_txt',
        'app_ads_txt' => 'app_ads_txt',
        'app_site_association' => 'app_site_association',
        'assetlinks' => 'assetlinks',
        'manifest' => 'manifest',
        'humans_txt' => 'humans_txt',
        'browserconfig' => 'browserconfig',
        'keybase_txt' => 'keybase_txt'
    ];
    foreach ($fields as $key => $rawKey) {
        if (isset($metadata[$key]) && $metadata[$key] && $metadata[$key]['present']) {
            $metadata[$key]['raw_stored'] = !empty($metadataRawFiles[$rawKey]);
        }
    }
    if (isset($metadata['favicon']) && $metadata['favicon'] && $metadata['favicon']['present'] && isset($metadata['favicon']['hash'])) {
        $metadata['favicon']['raw_stored'] = !empty($metadataRawFiles['favicon']);
    }
}

/**
 * Unified domain lookup function
 * @param string $domain Domain to scan
 * @param array $options Options: 'sse' (bool) for SSE progress, 'save_db' (bool) to save to history DB
 * @return array Scan results
 */
function performLookup($domain, $options = []) {
    global $pdo;
    $useSSE = $options['sse'] ?? false;
    $saveDB = $options['save_db'] ?? false;
    $dnsServer = $options['dns_server'] ?? null;
    $totalSteps = 7;
    $currentStep = 0;

    // Progress reporting closures
    $lastProgressMsg = '';
    $progress = $useSSE
        ? function($msg) use (&$currentStep, $totalSteps, &$lastProgressMsg) { $lastProgressMsg = $msg; sendProgress(++$currentStep, $totalSteps, $msg); }
        : function($msg) use (&$lastProgressMsg) { $lastProgressMsg = $msg; cliProgress($msg); };
    $progressUpdate = $useSSE
        ? function($msg, $detail = '') use (&$currentStep, $totalSteps, &$lastProgressMsg) { sendProgress($currentStep, $totalSteps, $msg ?: $lastProgressMsg, $detail); }
        : function($msg, $detail = '') { cliProgress($detail ?: $msg); };
    $progressDone = $useSSE
        ? function($msg) {} // SSE doesn't need "done" messages
        : function($msg) { cliProgressDone($msg); };

    $raw_records = []; $check_map = [];

    // Normalize input
    $targetHost = normalizeInput($domain);
    $rootDomain = extractRootDomain($targetHost);
    $isSubdomain = ($targetHost !== $rootDomain);

    // Validate domain
    if (empty($targetHost) || empty($rootDomain) || !preg_match('/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/i', $targetHost)) {
        if ($useSSE) {
            sendError('Invalid or empty domain provided');
            return ['error' => 'Invalid or empty domain'];
        }
        return ['error' => 'Invalid or empty domain', 'domain' => [], 'dns_records' => [], 'zone' => '', 'errors' => ['Invalid domain provided']];
    }

    // Phase 1: Check domain registration
    $progress('Checking domain registration...');
    $domainCheck = checkDomainExists($rootDomain);

    if (!$domainCheck['exists']) {
        $progressDone('Domain not registered');
        $timestamp = time();
        $result = [
            'target_host' => $targetHost, 'root_domain' => $rootDomain, 'is_subdomain' => $isSubdomain,
            'domain_exists' => false, 'domain' => [], 'dns_records' => [], 'zone' => '',
            'ip_lookup' => [], 'http_headers' => [], 'request' => null, 'ssl' => [], 'cms' => [],
            'infrastructure' => [], 'security' => [], 'technology' => [], 'metadata' => [],
            'redirect_chain' => [], 'indexability' => [], 'errors' => [],
            'timestamp' => $timestamp, 'raw_available' => false, 'plugin_version' => PERISCOPE_VERSION
        ];
        $scanPath = getScanPath($targetHost, $timestamp);
        if (!is_dir($scanPath)) mkdir($scanPath, 0755, true);
        saveResponseCache($scanPath, $result);
        if ($saveDB && $pdo) {
            $filters = buildFiltersJson($result);
            $stmt = $pdo->prepare("INSERT INTO history (domain, timestamp, data, filters) VALUES (?, ?, '', ?)");
            $stmt->execute([$targetHost, $timestamp, $filters]);
        }
        return $result;
    }

    $cachedRdap = $domainCheck['rdap'] ?? null;

    // Phase 2: Core DNS records
    $progress('Scanning core DNS records...');

    // Check wildcards
    $wildcardA = digQuery('A', "*.$rootDomain", 2, $dnsServer);
    $wildcardAValues = [];
    if (!empty(trim($wildcardA))) {
        foreach (explode("\n", trim($wildcardA)) as $val) {
            $val = trim($val); if (empty($val)) continue;
            if (preg_match('/[a-zA-Z]/', $val) && substr($val, -1) === '.') continue;
            $wildcardAValues[] = $val;
            $key = "A|*|$val"; if (isset($check_map[$key])) continue;
            $check_map[$key] = true;
            $raw_records[] = ['type' => 'A', 'name' => '*', 'value' => $val];
        }
    }

    $wildcardTXT = digQuery('TXT', "*.$rootDomain", 2, $dnsServer);
    $wildcardTXTValue = null;
    if (!empty(trim($wildcardTXT))) {
        $wildcardTXTValue = trim($wildcardTXT);
        $key = "TXT|*|$wildcardTXTValue";
        if (!isset($check_map[$key])) {
            $check_map[$key] = true;
            $raw_records[] = ['type' => 'TXT', 'name' => '*', 'value' => $wildcardTXTValue];
        }
    }

    $wildcardCNAME = digQuery('CNAME', "*.$rootDomain", 2, $dnsServer);
    $wildcardCNAMEValue = null;
    if (!empty(trim($wildcardCNAME))) {
        $wildcardCNAMEValue = trim(explode("\n", trim($wildcardCNAME))[0]);
        $key = "CNAME|*|$wildcardCNAMEValue";
        if (!isset($check_map[$key])) {
            $check_map[$key] = true;
            $raw_records[] = ['type' => 'CNAME', 'name' => '*', 'value' => $wildcardCNAMEValue];
        }
    }

    // If subdomain, check its DNS first
    if ($isSubdomain) {
        $subdomainPart = str_replace('.' . $rootDomain, '', $targetHost);
        foreach (['A', 'AAAA', 'CNAME'] as $type) {
            $output = digQuery($type, $targetHost, 2, $dnsServer);
            if (!$output) continue;
            foreach (explode("\n", trim($output)) as $val) {
                $val = trim($val); if (empty($val)) continue;
                $key = "$type|$subdomainPart|$val"; if (isset($check_map[$key])) continue;
                $check_map[$key] = true;
                $raw_records[] = ['type' => $type, 'name' => $subdomainPart, 'value' => $val];
            }
        }
    }

    // Process core DNS checks
    processDnsChecks(DNS_CHECKS_CORE, $rootDomain, $wildcardAValues, $wildcardTXTValue, $wildcardCNAMEValue, $check_map, $raw_records, $dnsServer, $progressUpdate);

    // Phase 3: Email & DKIM records
    $progress('Scanning email & DKIM records...');
    processDnsChecks(DNS_CHECKS_EMAIL, $rootDomain, $wildcardAValues, $wildcardTXTValue, $wildcardCNAMEValue, $check_map, $raw_records, $dnsServer, $progressUpdate);

    // Build zone file
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
    $progressDone('DNS records scanned (' . count($dns_records) . ' found)');

    // Phase 4: IP Resolution
    $progress('Resolving IP addresses...');
    $ips = gethostbynamel($targetHost); $ip_lookup = []; $rawWhoisIps = []; $ptrRecords = [];
    if ($ips) foreach ($ips as $ip) {
        $rawIpWhois = shell_exec("whois " . escapeshellarg($ip));
        $rawWhoisIps[$ip] = $rawIpWhois;
        $res = '';
        if ($rawIpWhois) {
            foreach (explode("\n", $rawIpWhois) as $line) {
                if (preg_match('/^(OrgName|NetName|Organization):\s*(.+)/i', $line, $m)) {
                    $res = trim($m[0]); break;
                }
            }
        }
        $ip_lookup[$ip] = $res ?: 'N/A';
        $ptrCmd = "dig -x " . escapeshellarg($ip) . " +short";
        if ($dnsServer) $ptrCmd .= " @" . escapeshellarg($dnsServer);
        $ptrCmd .= " 2>/dev/null";
        $ptr = trim(shell_exec($ptrCmd) ?: '');
        $ptr = rtrim($ptr, '.');
        if ($ptr && !empty($ptr)) {
            $forwardIps = @gethostbynamel($ptr);
            $ptrRecords[$ip] = ['ptr' => $ptr, 'forward_match' => $forwardIps && in_array($ip, $forwardIps)];
        }
    }
    $progressDone('IP addresses resolved (' . count($ip_lookup) . ' found)');

    // Phase 5: HTTP & SSL
    $progress('Fetching HTTP headers & SSL...');
    $redirectResult = getRedirectChain("https://" . $targetHost);
    $redirectChain = $redirectResult['chain'];
    $connectionInfo = $redirectResult['connection'];
    if (empty($redirectChain) || (count($redirectChain) === 1 && $redirectChain[0]['status_code'] === 0)) {
        $redirectResult = getRedirectChain("http://" . $targetHost);
        $redirectChain = $redirectResult['chain'];
        $connectionInfo = $redirectResult['connection'];
    }

    // Browser-like User-Agent for requests that may be blocked by bot detection
    $browserUA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';

    $headers = [];
    $httpStatus = 0;
    $h_out = shell_exec("curl -sS -D - -o /dev/null -L --max-time 5 -A " . escapeshellarg($browserUA) . " " . escapeshellarg("https://".$targetHost) . " 2>/dev/null");
    if (!$h_out) $h_out = shell_exec("curl -sS -D - -o /dev/null -L --max-time 5 -A " . escapeshellarg($browserUA) . " " . escapeshellarg("http://".$targetHost) . " 2>/dev/null");
    if($h_out) {
        foreach(explode("\n", $h_out) as $line) {
            // Capture HTTP status from status line
            if (preg_match('/^HTTP\/[\d.]+ (\d+)/', $line, $m)) {
                $httpStatus = (int)$m[1];
            }
            if(strpos($line, ':')) {
                [$k, $v] = explode(':', $line, 2);
                $key = trim($k); $val = trim($v);
                if (strtolower($key) === 'set-cookie') {
                    if (!isset($headers[$key])) { $headers[$key] = [$val]; } else { $headers[$key][] = $val; }
                } else {
                    $headers[$key] = $val;
                }
            }
        }
    }

    // Fetch HTML with browser-like headers
    $browserHeaders = "User-Agent: $browserUA\r\n" .
                      "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\n" .
                      "Accept-Language: en-US,en;q=0.5\r\n" .
                      "Accept-Encoding: identity\r\n" .
                      "Connection: keep-alive\r\n";

    $html = @file_get_contents("https://" . $targetHost, false, stream_context_create([
        'http' => ['timeout' => 5, 'ignore_errors' => true, 'header' => $browserHeaders],
        'ssl' => ['verify_peer' => false, 'verify_peer_name' => false]
    ]));
    if (!$html) $html = @file_get_contents("http://" . $targetHost, false, stream_context_create([
        'http' => ['timeout' => 5, 'ignore_errors' => true, 'header' => $browserHeaders]
    ]));

    // Check if we got a 403 Forbidden - some hosts (like Squarespace) block non-browser requests
    // Retry with curl which may handle cookies/redirects differently
    $htmlStatus = 0;
    if (isset($http_response_header)) {
        foreach ($http_response_header as $h) {
            if (preg_match('/^HTTP\/[\d.]+ (\d+)/', $h, $m)) {
                $htmlStatus = (int)$m[1];
            }
        }
    }

    if ($htmlStatus === 403 || ($html && stripos($html, '<title>403') !== false)) {
        // Retry with curl using full browser emulation
        $curlHtml = shell_exec("curl -s -L --max-time 10 " .
            "-A " . escapeshellarg($browserUA) . " " .
            "-H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' " .
            "-H 'Accept-Language: en-US,en;q=0.5' " .
            "-H 'Cache-Control: no-cache' " .
            "-H 'Pragma: no-cache' " .
            escapeshellarg("https://".$targetHost) . " 2>/dev/null");
        if ($curlHtml && strlen($curlHtml) > 100 && stripos($curlHtml, '<title>403') === false) {
            $html = $curlHtml;
        }
    }

    // Detect HTML-based redirects (meta refresh, JavaScript)
    $htmlRedirect = detectHtmlRedirect($html);
    $htmlRedirectHost = null;
    if ($htmlRedirect && !empty($htmlRedirect['url'])) {
        $targetUrl = $htmlRedirect['url'];
        // Handle relative URLs
        if (strpos($targetUrl, 'http') !== 0) {
            $targetUrl = "https://{$targetHost}" . (strpos($targetUrl, '/') === 0 ? '' : '/') . $targetUrl;
        }
        // Fetch target URL status
        $targetStatus = getUrlStatus($targetUrl);
        // Add HTML redirect to chain
        $redirectChain[] = [
            'url' => $targetUrl,
            'status_code' => $targetStatus['status_code'],
            'status_text' => $targetStatus['status_code'] ? getHttpStatusText($targetStatus['status_code']) : null,
            'type' => $htmlRedirect['type']
        ];

        // Follow the HTML redirect - fetch content from final destination
        $htmlRedirectHost = parse_url($targetUrl, PHP_URL_HOST);
        if ($htmlRedirectHost && $targetStatus['status_code'] === 200) {
            $progressUpdate('Following HTML redirect to ' . $htmlRedirectHost . '...');

            // Re-fetch HTML from the redirect target
            $redirectHtml = @file_get_contents($targetUrl, false, stream_context_create([
                'http' => ['timeout' => 5, 'ignore_errors' => true, 'header' => $browserHeaders],
                'ssl' => ['verify_peer' => false, 'verify_peer_name' => false]
            ]));
            if ($redirectHtml && strlen($redirectHtml) > 100) {
                $html = $redirectHtml;
            }

            // Re-fetch headers from redirect target
            $h_out = shell_exec("curl -sS -D - -o /dev/null -L --max-time 5 -A " . escapeshellarg($browserUA) . " " . escapeshellarg($targetUrl) . " 2>/dev/null");
            if ($h_out) {
                $headers = [];
                foreach (explode("\n", $h_out) as $line) {
                    $line = trim($line);
                    if (!$line) continue;
                    if (preg_match('/^HTTP\/[\d.]+ (\d+)/', $line, $m)) {
                        $httpStatus = (int)$m[1];
                        continue;
                    }
                    if (strpos($line, ':') !== false) {
                        list($k, $v) = explode(':', $line, 2);
                        $key = strtolower(trim($k)); $val = trim($v);
                        if ($key === 'set-cookie') {
                            if (!isset($headers[$key])) { $headers[$key] = [$val]; } else { $headers[$key][] = $val; }
                        } else {
                            $headers[$key] = $val;
                        }
                    }
                }
            }

            // Update connection info for the redirect target
            $redirectResult = getRedirectChain($targetUrl);
            if (!empty($redirectResult['connection'])) {
                $connectionInfo = $redirectResult['connection'];
                // Merge connection info into the HTML redirect hop
                $lastIndex = count($redirectChain) - 1;
                if (isset($connectionInfo['http_version'])) {
                    $redirectChain[$lastIndex]['protocol'] = $connectionInfo['http_version'];
                }
                if (isset($connectionInfo['timing'])) {
                    $redirectChain[$lastIndex]['timing'] = $connectionInfo['timing'];
                }
                if (isset($connectionInfo['remote_address'])) {
                    $redirectChain[$lastIndex]['remote_address'] = $connectionInfo['remote_address'];
                }
            }
        }
    }

    // Use redirect target host for SSL if we followed an HTML redirect
    $sslHost = $htmlRedirectHost ?: $targetHost;
    $rawSsl = getRawSSL($sslHost);
    $progressDone('HTTP headers & SSL fetched');

    // Phase 6: Domain Registration
    $progress('Looking up domain registration...');
    $rawWhoisDomain = getRawWhoisDomain($rootDomain);
    $rawRdap = $cachedRdap ?? getRawRdap($rootDomain);
    $timestamp = time();
    $progressDone('Domain registration retrieved');

    // Analysis - use redirect target host if we followed an HTML redirect
    $analysisHost = $htmlRedirectHost ?: $targetHost;
    $progress('Analyzing results...');
    $ssl = getSSLInfo($sslHost, $rawSsl);
    $metadataRawFiles = [];
    $metadata = detectMetadata($analysisHost, $html, $metadataRawFiles, $targetHost);
    $cms = detectCMS($analysisHost, $html, $headers, $metadataRawFiles['robots_txt'] ?? null, $metadataRawFiles['sitemap_xml'] ?? null);
    $infra = detectInfrastructure($headers);
    $security = detectSecurityHeaders($headers);
    $cookieSecurity = analyzeCookieSecurity($headers);
    $technology = detectTechnology($html, $headers);
    $indexability = detectSearchEngineBlocking($html, $headers, $metadataRawFiles['robots_txt'] ?? null);

    $scanPath = getScanPath($targetHost, $timestamp);
    saveRawFiles($scanPath, $html, $headers, $rawWhoisDomain, $rawWhoisIps, $rawSsl, [
        'records' => $dns_records, 'zone' => $zoneFile
    ], $rawRdap, $metadataRawFiles, $redirectChain, $ptrRecords, $connectionInfo);

    $domainData = $rawRdap ? parseRdap($rawRdap) : [];
    if (empty($domainData)) $domainData = parseRawWhois($rawWhoisDomain);

    addMetadataStorageFlags($metadata, $metadataRawFiles);

    // Build request info from final redirect chain entry and connection info
    $finalHop = !empty($redirectChain) ? end($redirectChain) : null;
    $requestInfo = [
        'url' => $finalHop ? $finalHop['url'] : "https://$targetHost",
        'method' => 'GET',
        'status_code' => $finalHop ? $finalHop['status_code'] : null,
        'status_text' => $finalHop ? $finalHop['status_text'] : null,
        'remote_address' => $connectionInfo['remote_address'] ?? null,
        'protocol' => $connectionInfo['http_version'] ?? null,
        'timing' => $connectionInfo['timing'] ?? null
    ];

    $result = [
        'target_host' => $targetHost, 'root_domain' => $rootDomain, 'is_subdomain' => $isSubdomain,
        'domain' => $domainData, 'dns_records' => $dns_records, 'zone' => $zoneFile,
        'ip_lookup' => $ip_lookup, 'ptr_records' => $ptrRecords, 'http_headers' => $headers,
        'request' => $requestInfo,
        'ssl' => $ssl, 'cms' => $cms, 'infrastructure' => $infra, 'security' => $security,
        'cookie_security' => $cookieSecurity,
        'technology' => $technology, 'metadata' => $metadata, 'redirect_chain' => $redirectChain,
        'indexability' => $indexability, 'errors' => [], 'timestamp' => $timestamp,
        'raw_available' => true, 'plugin_version' => PERISCOPE_VERSION
    ];

    saveResponseCache($scanPath, $result);

    if ($saveDB && $pdo) {
        $filters = buildFiltersJson($result);
        $stmt = $pdo->prepare("INSERT INTO history (domain, timestamp, data, filters) VALUES (?, ?, '', ?)");
        $stmt->execute([$targetHost, $timestamp, $filters]);
    }

    $progressDone('Scan complete');
    return $result;
}

// --- SSE PROGRESS HELPERS ---
function sendProgress($step, $total, $message, $detail = '') {
    echo "data: " . json_encode([
        'type' => 'progress',
        'step' => $step,
        'total' => $total,
        'message' => $message,
        'detail' => $detail,
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
    if ($argc < 2) { echo "Usage: php engine.php <domain|action=bulk_upgrade>\n"; exit(1); }
    
    // Check if this is an action command (not a domain scan)
    if (isset($_GET['action'])) {
        goto handle_actions;
    }
    
    $CLI_MODE = true;

    // Parse flags; the domain is the first non-flag argument (order-independent,
    // so `engine.php example.com --open` and `engine.php --open example.com` both work)
    $openReport = false;
    $skipScan = false;
    $domain = null;
    for ($i = 1; $i < $argc; $i++) {
        if ($argv[$i] === '--open' || $argv[$i] === '-o') { $openReport = true; continue; }
        if ($argv[$i] === '--skip') { $skipScan = true; continue; }
        if ($domain === null && substr($argv[$i], 0, 1) !== '-') { $domain = $argv[$i]; }
    }
    if ($domain === null) { echo "Usage: php engine.php <domain> [--open] [--skip]\n"; exit(1); }

    if ($skipScan) {
        // --skip: show the most recent saved scan instead of running a new one
        $host = normalizeInput($domain);
        $ts = mostRecentScanTimestamp($host);
        if (!$ts) {
            echo "\n  \033[31m⚠ No previous scan found for $host — run without --skip first.\033[0m\n";
            exit(1);
        }
        $cache = loadResponseCache(getScanPath($host, $ts));
        $data = $cache['data'] ?? $cache;
        if (!$data || !isset($data['target_host'])) {
            echo "\n  \033[31m⚠ Could not load cached scan for $host.\033[0m\n";
            exit(1);
        }
        echo "\n  📁 Cached scan for \033[1m" . $data['target_host'] . "\033[0m \033[90m(" . formatDate(date('c', (int)$data['timestamp'])) . ")\033[0m\n";
    } else {
        // Hide cursor during scan
        echo "\033[?25l";
        // Ensure cursor is restored on exit (Ctrl+C, errors, etc.)
        register_shutdown_function(function() { echo "\033[?25h"; });

        echo "\n  🔍 Scanning \033[1m$domain\033[0m\n\n";
        $data = performLookup($domain, ['save_db' => true]);
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

    // --open: pop the report in the browser. periscope.run with ?local=true talks
    // to whichever local bridge is running on :8989 and renders the full interactive
    // report — works whether the engine is installed locally or not, as long as a
    // bridge is up.
    if ($openReport) {
        $host = $data['target_host'];
        $url = "https://periscope.run/?local=true&domain=" . rawurlencode($host);
        openInBrowser($url);
        echo "  \033[90mOpening:  $url\033[0m\n";
        if (!bridgeRunning()) {
            echo "  \033[33m⚠ No local bridge detected on :8989 — start one (e.g. boot.sh) so the report can load.\033[0m\n";
        }
        echo "\n  \033[32m🔭 Opened report in browser\033[0m\n";
    }
    exit(0);
}

// --- SERVER HANDLER ---
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
$allowed = ['https://periscope.run', 'http://localhost:8989', 'http://127.0.0.1:8989', 'null'];
if (in_array($origin, $allowed)) { header("Access-Control-Allow-Origin: $origin"); } 
else { header("Access-Control-Allow-Origin: https://periscope.run"); }
header("Access-Control-Allow-Methods: GET, POST");
header('Content-Type: application/json');

handle_actions:
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
        $limit = isset($_GET['limit']) ? max(1, (int)$_GET['limit']) : 50;
        $offset = isset($_GET['offset']) ? (int)$_GET['offset'] : 0;
        $search = isset($_GET['search']) ? trim($_GET['search']) : '';
        $existence = isset($_GET['existence']) ? $_GET['existence'] : 'all';
        $platform = isset($_GET['platform']) ? $_GET['platform'] : 'all';
        $scanCount = isset($_GET['scan_count']) ? $_GET['scan_count'] : 'all';
        $indexability = isset($_GET['indexability']) ? $_GET['indexability'] : 'all';

        // Build dynamic query with filters
        $where = [];
        $params = [];

        if ($search) {
            $where[] = "domain LIKE ?";
            $params[] = '%' . $search . '%';
        }

        // Apply filters via SQL pattern matching on the filters column
        if ($existence === 'exists') {
            $where[] = "(filters LIKE '%\"exists\":true%' OR filters = '')";
        } elseif ($existence === 'nonexistent') {
            $where[] = "filters LIKE '%\"exists\":false%'";
        }

        if ($indexability === 'hidden') {
            $where[] = "filters LIKE '%\"blocked\":true%'";
        } elseif ($indexability === 'indexable') {
            $where[] = "(filters LIKE '%\"blocked\":false%' OR filters = '')";
        }

        if ($platform !== 'all') {
            $where[] = "filters LIKE ?";
            $params[] = '%"platform":"' . $platform . '"%';
        }

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

        echo json_encode(['items' => $rows, 'total' => $total, 'offset' => $offset, 'limit' => $limit]);
        exit;
    }
    if ($action === 'get_platforms') {
        // Get distinct platforms from filters column
        $platforms = [];
        $stmt = $pdo->query("SELECT DISTINCT filters FROM history WHERE filters != '' AND filters LIKE '%\"platform\":%'");
        $rows = $stmt->fetchAll(PDO::FETCH_COLUMN);

        foreach ($rows as $filtersJson) {
            $filters = json_decode($filtersJson, true);
            if ($filters && isset($filters['platform']) && $filters['platform']) {
                $platforms[$filters['platform']] = true;
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
    if ($action === 'rebuild_filters') {
        // Rebuild filters column for all history entries from cached scan data
        $stmt = $pdo->query("SELECT id, domain, timestamp FROM history WHERE filters = '' OR filters IS NULL");
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        $updated = 0;
        $updateStmt = $pdo->prepare("UPDATE history SET filters = ? WHERE id = ?");
        
        foreach ($rows as $row) {
            $path = getScanPath($row['domain'], $row['timestamp']);
            $cache = loadResponseCache($path);
            $data = $cache ? $cache['data'] : null;
            
            if ($data) {
                $filters = buildFiltersJson($data);
                $updateStmt->execute([$filters, $row['id']]);
                $updated++;
            }
        }
        
        echo json_encode(['success' => true, 'updated' => $updated, 'total' => count($rows)]);
        exit;
    }
    if ($action === 'get_domain_versions') {
        $stmt = $pdo->prepare("SELECT id, domain, timestamp FROM history WHERE domain = ? ORDER BY timestamp DESC");
        $stmt->execute([$_GET['domain']]);
        echo json_encode($stmt->fetchAll(PDO::FETCH_ASSOC)); exit;
    }
    if ($action === 'get_history_item') {
        $stmt = $pdo->prepare("SELECT id, domain, data, timestamp, filters FROM history WHERE id = ?");
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

                // Backfill filters column if empty (for old v1.3 captures)
                if (empty($row['filters'])) {
                    $filters = buildFiltersJson($data);
                    if ($filters) {
                        $updateStmt = $pdo->prepare("UPDATE history SET filters = ? WHERE id = ?");
                        $updateStmt->execute([$filters, $row['id']]);
                    }
                }
            } else {
                // New scan - try cached response first
                $path = getScanPath($row['domain'], $row['timestamp']);
                $cache = loadResponseCache($path);

                if (isCacheValid($cache)) {
                    // Cache hit - return immediately
                    $data = $cache['data'];
                    $data['timestamp'] = $row['timestamp'];
                    $data['cache_status'] = 'hit';

                    // Backfill redirects.json if cache has request data that raw files are missing
                    if (isset($data['request']) && ($data['request']['timing'] || $data['request']['protocol'])) {
                        $redirectsFile = "$path/redirects.json";
                        if (file_exists($redirectsFile)) {
                            $redirects = @json_decode(file_get_contents($redirectsFile), true);
                            if ($redirects && count($redirects) > 0) {
                                $lastIdx = count($redirects) - 1;
                                $needsUpdate = false;
                                if ($data['request']['timing'] && !isset($redirects[$lastIdx]['timing'])) {
                                    $redirects[$lastIdx]['timing'] = $data['request']['timing'];
                                    $needsUpdate = true;
                                }
                                if ($data['request']['protocol'] && !isset($redirects[$lastIdx]['protocol'])) {
                                    $redirects[$lastIdx]['protocol'] = $data['request']['protocol'];
                                    $needsUpdate = true;
                                }
                                if ($data['request']['remote_address'] && !isset($redirects[$lastIdx]['remote_address'])) {
                                    $redirects[$lastIdx]['remote_address'] = $data['request']['remote_address'];
                                    $needsUpdate = true;
                                }
                                if ($needsUpdate) {
                                    file_put_contents($redirectsFile, json_encode($redirects));
                                }
                            }
                        }
                    }
                } else {
                    // Cache miss or outdated - backfill redirects.json from old cache BEFORE regenerating
                    if ($cache && isset($cache['data']['request'])) {
                        $oldRequest = $cache['data']['request'];
                        if ($oldRequest['timing'] || $oldRequest['protocol'] || $oldRequest['remote_address']) {
                            $redirectsFile = "$path/redirects.json";
                            if (file_exists($redirectsFile)) {
                                $redirects = @json_decode(file_get_contents($redirectsFile), true);
                                if ($redirects && count($redirects) > 0) {
                                    $lastIdx = count($redirects) - 1;
                                    $needsUpdate = false;
                                    if ($oldRequest['timing'] && !isset($redirects[$lastIdx]['timing'])) {
                                        $redirects[$lastIdx]['timing'] = $oldRequest['timing'];
                                        $needsUpdate = true;
                                    }
                                    if ($oldRequest['protocol'] && !isset($redirects[$lastIdx]['protocol'])) {
                                        $redirects[$lastIdx]['protocol'] = $oldRequest['protocol'];
                                        $needsUpdate = true;
                                    }
                                    if ($oldRequest['remote_address'] && !isset($redirects[$lastIdx]['remote_address'])) {
                                        $redirects[$lastIdx]['remote_address'] = $oldRequest['remote_address'];
                                        $needsUpdate = true;
                                    }
                                    if ($needsUpdate) {
                                        file_put_contents($redirectsFile, json_encode($redirects));
                                    }
                                }
                            }
                        }
                    }

                    // Now compute from raw files (which now have the backfilled data)
                    $raw = loadRawFiles($path);
                    $data = computeFromRaw($raw, $row['domain'], $row['timestamp'], true);
                    $data['timestamp'] = $row['timestamp'];
                    $data['cache_status'] = $cache ? 'regenerated' : 'computed';
                }
            }
            // Ensure target_host/root_domain/is_subdomain exist (for old caches/legacy data)
            if (!isset($data['target_host'])) {
                $targetHost = normalizeInput($row['domain']);
                $rootDomain = extractRootDomain($targetHost);
                $data['target_host'] = $targetHost;
                $data['root_domain'] = $rootDomain;
                $data['is_subdomain'] = ($targetHost !== $rootDomain);
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
        $filters = isset($in['data']) ? buildFiltersJson($in['data']) : '';
        $pdo->prepare("INSERT INTO history (domain, timestamp, data, filters) VALUES (?, ?, '', ?)")
            ->execute([$in['domain'], $timestamp, $filters]);
        echo json_encode(['success' => true]);
        exit;
    }
    if ($action === 'delete_history') {
        // Get domain and timestamp before deleting
        $stmt = $pdo->prepare("SELECT domain, timestamp FROM history WHERE id = ?");
        $stmt->execute([$_POST['id']]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$row) {
            echo json_encode(['success' => false, 'error' => 'Scan not found']);
            exit;
        }

        $domain = $row['domain'];
        $timestamp = $row['timestamp'];

        // 1. Delete from database
        $pdo->prepare("DELETE FROM history WHERE id = ?")->execute([$_POST['id']]);

        // 2. Delete the specific timestamp folder (Raw text files unique to this scan)
        $scanPath = getScanPath($domain, $timestamp);
        $expectedBase = getenv('HOME') . "/.periscope/scans/";
        
        // SAFETY: Path traversal check
        if (is_dir($scanPath) && strpos(realpath($scanPath), $expectedBase) === 0) {
            $files = glob("$scanPath/*");
            foreach ($files as $file) {
                if (is_file($file)) @unlink($file);
            }
            @rmdir($scanPath);
        }

        // 3. Garbage Collection: Handle Shared Files
        // Check if any other scans exist for this domain
        $countStmt = $pdo->prepare("SELECT COUNT(*) FROM history WHERE domain = ?");
        $countStmt->execute([$domain]);
        $remainingScans = (int)$countStmt->fetchColumn();

        if ($remainingScans === 0) {
            // CASE A: No scans left. Safe to delete the ENTIRE domain folder.
            $domainPath = dirname($scanPath); // ~/.periscope/scans/domain.com
            $filesPath = "$domainPath/files";
            
            // Delete shared files
            if (is_dir($filesPath)) {
                $sharedFiles = glob("$filesPath/*");
                foreach ($sharedFiles as $f) @unlink($f);
                @rmdir($filesPath);
            }
            
            // Try to remove domain folder (will only work if empty)
            @rmdir($domainPath);
        } else {
            // CASE B: Scans remain. We must perform Reference Counting.
            // 1. Collect all hashes still in use by remaining scans
            $usedHashes = [];
            
            // Get timestamps of all remaining scans
            $tsStmt = $pdo->prepare("SELECT timestamp FROM history WHERE domain = ?");
            $tsStmt->execute([$domain]);
            $timestamps = $tsStmt->fetchAll(PDO::FETCH_COLUMN);

            foreach ($timestamps as $ts) {
                $path = getScanPath($domain, $ts);
                $cache = loadResponseCache($path);
                
                // If cache exists, extract hash references
                if ($cache && isset($cache['data']['metadata'])) {
                    $m = $cache['data']['metadata'];
                    
                    // Collect Favicon Hash
                    if (isset($m['favicon']['hash'])) $usedHashes[] = $m['favicon']['hash'];
                    
                    // Collect OG Image Hash
                    if (isset($m['meta_tags']['open_graph']['image_hash'])) {
                        $usedHashes[] = $m['meta_tags']['open_graph']['image_hash'];
                    }
                    
                    // Collect Twitter Image Hash
                    if (isset($m['meta_tags']['twitter']['image_hash'])) {
                        $usedHashes[] = $m['meta_tags']['twitter']['image_hash'];
                    }
                }
            }

            // 2. Scan the physical files folder
            $filesPath = getFilesPath($domain);
            if (is_dir($filesPath)) {
                $physicalFiles = glob("$filesPath/*");
                foreach ($physicalFiles as $file) {
                    $filename = basename($file);
                    // Get hash from filename (e.g., "abc12345.png" -> "abc12345")
                    $fileHash = pathinfo($filename, PATHINFO_FILENAME);

                    // 3. Delete ONLY if not in the used list
                    if (!in_array($fileHash, $usedHashes)) {
                        @unlink($file);
                    }
                }
            }
        }

        echo json_encode(['success' => true]);
        exit;
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
                $stmt = $pdo->prepare("INSERT INTO history (domain, timestamp, data, filters) VALUES (:d, :t, :v, :f)");
                foreach($data as $i) {
                    $filters = isset($i['data']) ? buildFiltersJson($i['data']) : '';
                    $stmt->execute([':d'=>$i['domain'], ':t'=>$i['timestamp'], ':v'=>json_encode($i['data']), ':f'=>$filters]);
                }
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

        // Backfill redirects.json from old cache BEFORE regenerating
        $cache = loadResponseCache($path);
        if ($cache && isset($cache['data']['request'])) {
            $oldRequest = $cache['data']['request'];
            if ($oldRequest['timing'] || $oldRequest['protocol'] || $oldRequest['remote_address']) {
                $redirectsFile = "$path/redirects.json";
                if (file_exists($redirectsFile)) {
                    $redirects = @json_decode(file_get_contents($redirectsFile), true);
                    if ($redirects && count($redirects) > 0) {
                        $lastIdx = count($redirects) - 1;
                        $needsUpdate = false;
                        if ($oldRequest['timing'] && !isset($redirects[$lastIdx]['timing'])) {
                            $redirects[$lastIdx]['timing'] = $oldRequest['timing'];
                            $needsUpdate = true;
                        }
                        if ($oldRequest['protocol'] && !isset($redirects[$lastIdx]['protocol'])) {
                            $redirects[$lastIdx]['protocol'] = $oldRequest['protocol'];
                            $needsUpdate = true;
                        }
                        if ($oldRequest['remote_address'] && !isset($redirects[$lastIdx]['remote_address'])) {
                            $redirects[$lastIdx]['remote_address'] = $oldRequest['remote_address'];
                            $needsUpdate = true;
                        }
                        if ($needsUpdate) {
                            file_put_contents($redirectsFile, json_encode($redirects));
                        }
                    }
                }
            }
        }

        $raw = loadRawFiles($path);
        $data = computeFromRaw($raw, $row['domain'], $row['timestamp'], true);
        $data['timestamp'] = $row['timestamp'];
        echo json_encode(['success' => true, 'data' => $data]);
        exit;
    }
    
    if ($action === 'bulk_upgrade') {
        if (php_sapi_name() !== 'cli') {
            echo json_encode(['error' => 'CLI only']);
            exit;
        }
        
        $stmt = $pdo->query("SELECT id, domain, timestamp, data FROM history ORDER BY timestamp DESC");
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
        $total = count($rows);
        $upgraded = 0;
        $skipped = 0;
        $failed = 0;
        
        echo "Periscope Bulk Upgrade - Target version: " . PERISCOPE_VERSION . "\n";
        echo "Found $total scans to process\n\n";
        
        foreach ($rows as $i => $row) {
            $num = $i + 1;
            $domain = $row['domain'];
            $timestamp = $row['timestamp'];
            $path = getScanPath($domain, $timestamp);
            
            if (!is_dir($path)) {
                echo "[$num/$total] $domain - skipped (legacy, no raw files)\n";
                $skipped++;
                continue;
            }
            
            $cache = loadResponseCache($path);
            if (isCacheValid($cache)) {
                echo "[$num/$total] $domain - skipped (already v" . PERISCOPE_VERSION . ")\n";
                $skipped++;
                continue;
            }
            
            $oldVersion = $cache['plugin_version'] ?? 'none';
            echo "[$num/$total] Upgrading $domain ($oldVersion -> " . PERISCOPE_VERSION . ")...";

            try {
                // Backfill redirects.json from old cache BEFORE regenerating
                if ($cache && isset($cache['data']['request'])) {
                    $oldRequest = $cache['data']['request'];
                    if ($oldRequest['timing'] || $oldRequest['protocol'] || $oldRequest['remote_address']) {
                        $redirectsFile = "$path/redirects.json";
                        if (file_exists($redirectsFile)) {
                            $redirects = @json_decode(file_get_contents($redirectsFile), true);
                            if ($redirects && count($redirects) > 0) {
                                $lastIdx = count($redirects) - 1;
                                $needsUpdate = false;
                                if ($oldRequest['timing'] && !isset($redirects[$lastIdx]['timing'])) {
                                    $redirects[$lastIdx]['timing'] = $oldRequest['timing'];
                                    $needsUpdate = true;
                                }
                                if ($oldRequest['protocol'] && !isset($redirects[$lastIdx]['protocol'])) {
                                    $redirects[$lastIdx]['protocol'] = $oldRequest['protocol'];
                                    $needsUpdate = true;
                                }
                                if ($oldRequest['remote_address'] && !isset($redirects[$lastIdx]['remote_address'])) {
                                    $redirects[$lastIdx]['remote_address'] = $oldRequest['remote_address'];
                                    $needsUpdate = true;
                                }
                                if ($needsUpdate) {
                                    file_put_contents($redirectsFile, json_encode($redirects));
                                }
                            }
                        }
                    }
                }

                $raw = loadRawFiles($path);
                $data = computeFromRaw($raw, $domain, $timestamp, true);
                echo " done\n";
                $upgraded++;
            } catch (Exception $e) {
                echo " FAILED: " . $e->getMessage() . "\n";
                $failed++;
            }
        }
        
        echo "\n=== Complete ===\n";
        echo "Upgraded: $upgraded\n";
        echo "Skipped:  $skipped\n";
        echo "Failed:   $failed\n";
        exit;
    }
    
    if ($action === 'export_report') {
        $domain = $_GET['domain'] ?? '';
        $timestamp = $_GET['timestamp'] ?? '';
        if (!$domain || !$timestamp) {
            echo json_encode(['error' => 'Missing domain or timestamp']);
            exit;
        }
        
        // 1. Check Database for Legacy Data
        $stmt = $pdo->prepare("SELECT data FROM history WHERE domain = ? AND timestamp = ?");
        $stmt->execute([$domain, $timestamp]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        $data = null;
        $path = getScanPath($domain, $timestamp);
        $raw = [];

        if ($row && !empty($row['data'])) {
            // LEGACY: Data is stored in DB column
            $d = json_decode($row['data'], true);
            $data = is_string($d) ? json_decode($d, true) : $d;
            // Legacy scans won't have raw files on disk, so $raw remains empty
        } else {
            // MODERN: Data is stored in files
            $cache = loadResponseCache($path);
            $raw = loadRawFiles($path);
            if (!$cache) {
                $data = computeFromRaw($raw, $domain, $timestamp, false);
            } else {
                $data = $cache['data'] ?? $cache;
            }
        }

        if (!$data) {
            echo "Error: No data found for this scan.";
            exit;
        }

        $data['timestamp'] = (int)$timestamp;
        
        // The export is the regular frontend booted in report mode: the same index.html that the
        // bridge serves, with the scan data, the raw text files and the stored images inlined as
        // window.PERISCOPE_EMBED. One UI, one design, no second template to keep in sync.
        $rawKeys = ['robots_txt', 'sitemap_xml', 'security_txt', 'ads_txt', 'app_ads_txt', 'app_site_association', 'assetlinks', 'manifest', 'humans_txt', 'browserconfig', 'keybase_txt', 'whois_domain', 'rdap'];
        $rawFiles = [];
        foreach ($rawKeys as $k) {
            if (!empty($raw[$k]) && is_string($raw[$k])) $rawFiles[$k] = $k === 'sitemap_xml' ? substr($raw[$k], 0, 50000) : $raw[$k];
        }

        $mimes = ['png' => 'image/png', 'jpg' => 'image/jpeg', 'jpeg' => 'image/jpeg', 'gif' => 'image/gif', 'webp' => 'image/webp', 'ico' => 'image/x-icon', 'svg' => 'image/svg+xml', 'avif' => 'image/avif'];
        $dataUri = function ($file, $ext) use ($mimes) {
            if (!$file || !file_exists($file) || filesize($file) > 3 * 1024 * 1024) return '';
            return 'data:' . ($mimes[strtolower($ext)] ?? 'application/octet-stream') . ';base64,' . base64_encode(file_get_contents($file));
        };
        $images = [];
        if (!empty($data['metadata']['favicon']['hash'])) {
            $fav = $data['metadata']['favicon'];
            $images['favicon'] = $dataUri(getFilesPath($domain) . '/' . $fav['hash'] . '.' . ($fav['extension'] ?? 'ico'), $fav['extension'] ?? 'ico');
        }
        if (empty($images['favicon']) && file_exists("$path/favicon.ico")) $images['favicon'] = $dataUri("$path/favicon.ico", 'ico');
        if (!empty($data['metadata']['meta_tags']['open_graph']['image_hash'])) {
            $og = $data['metadata']['meta_tags']['open_graph'];
            $images['og'] = $dataUri(getFilesPath($domain) . '/' . $og['image_hash'] . '.' . ($og['image_extension'] ?? 'png'), $og['image_extension'] ?? 'png');
        }
        if (!empty($data['metadata']['meta_tags']['twitter']['image_hash'])) {
            $tw = $data['metadata']['meta_tags']['twitter'];
            $images['twitter'] = $dataUri(getFilesPath($domain) . '/' . $tw['image_hash'] . '.' . ($tw['image_extension'] ?? 'png'), $tw['image_extension'] ?? 'png');
        }
        $images = array_filter($images);

        $template = @file_get_contents(__DIR__ . '/index.html');
        if (!$template) {
            header('Content-Type: text/plain');
            echo "Error: index.html not found next to engine.php; cannot build the report.";
            exit;
        }
        $embed = json_encode([
            'domain' => $domain,
            'timestamp' => (int)$timestamp,
            'data' => $data,
            'rawFiles' => $rawFiles,
            'images' => $images,
        ], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_SLASHES);
        $bootstrap = "<script>window.PERISCOPE_EMBED = $embed;</script>\n";
        // The mark and favicon are inline SVG in index.html, so the file already has no asset dependency.
        // Swap the favicon for the scanned site's own icon when one was stored.
        if (!empty($images['favicon'])) {
            $template = preg_replace('/<link id="favicon"[^>]*>/', '<link id="favicon" rel="icon" href="' . $images['favicon'] . '">', $template, 1);
        }
        $template = str_replace('<title>Periscope</title>', '<title>Periscope report: ' . htmlspecialchars($domain) . '</title>', $template);
        $template = preg_replace('/<script>\s*\/\/ -{10,}\s*\/\/ Periscope frontend/', $bootstrap . '$0', $template, 1, $injected);
        if (!$injected) $template = str_replace('</head>', $bootstrap . '</head>', $template);

        header('Content-Type: text/html; charset=utf-8');
        header('Content-Disposition: attachment; filename="' . $domain . '-report-' . date('Y-m-d', $timestamp) . '.html"');
        echo $template;
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

    set_time_limit(0); // Disable execution time limit for long scans

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

    $dnsServer = isset($_GET['dns_server']) ? trim($_GET['dns_server']) : null;
    if ($dnsServer && !preg_match('/^[a-zA-Z0-9._:-]+$/', $dnsServer)) {
        $dnsServer = null;
    }

    try {
        $result = performLookup($domain, ['sse' => true, 'save_db' => true, 'dns_server' => $dnsServer]);
        sendComplete($result);
    } catch (Exception $e) {
        sendError($e->getMessage());
    }
    exit;
}

if(isset($_GET['domain'])) {
    $dnsServer = isset($_GET['dns_server']) ? trim($_GET['dns_server']) : null;
    if ($dnsServer && !preg_match('/^[a-zA-Z0-9._:-]+$/', $dnsServer)) {
        $dnsServer = null;
    }
    echo json_encode(performLookup($_GET['domain'], ['dns_server' => $dnsServer]));
} else {
    echo json_encode(['error' => 'No domain provided']);
}