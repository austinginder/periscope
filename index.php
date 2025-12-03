<?php

require_once 'vendor/autoload.php';

use Badcow\DNS\Classes;
use Badcow\DNS\Zone;
use Badcow\DNS\Rdata\Factory;
use Badcow\DNS\ResourceRecord;
use Badcow\DNS\AlignedBuilder;

error_reporting(E_ALL & ~E_DEPRECATED);

/**
 * Establishes a connection to the SQLite database and returns the PDO object.
 * Creates the database and table if they don't exist.
 *
 * @return PDO
 */
function getDbConnection(): PDO
{
    try {
        $db = new PDO('sqlite:history.db');
        $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        // Create table if it doesn't exist. NOTE: UNIQUE constraint on 'domain' is removed.
        $db->exec("CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            timestamp INTEGER NOT NULL,
            data TEXT NOT NULL,
            UNIQUE(domain, timestamp)
        )");
        return $db;
    } catch (PDOException $e) {
        header('Content-Type: application/json');
        echo json_encode(['error' => 'Database connection failed: ' . $e->getMessage()]);
        die();
    }
}

/**
 * Performs an RDAP lookup for a domain.
 *
 * @param string $domain The domain to look up.
 * @return array An array of WHOIS data or an empty array on failure.
 */
function rdapLookup(string $domain): array
{
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, "https://rdap.org/domain/" . $domain);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    // Per RFC 7480, RDAP should be served over HTTPS
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
    $json_data = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($http_code !== 200 || !$json_data) {
        return []; // Return empty array on failure
    }

    $data = json_decode($json_data, true);
    $whois = [];

    // Extract key information from the RDAP response
    if (isset($data['ldhName'])) {
        $whois[] = ["name" => "Domain Name", "value" => strtolower($data['ldhName'])];
    }

    if (isset($data['events'])) {
        foreach ($data['events'] as $event) {
            if ($event['eventAction'] == 'registration') {
                $whois[] = ["name" => "Creation Date", "value" => $event['eventDate']];
            }
            if ($event['eventAction'] == 'expiration') {
                $whois[] = ["name" => "Expiration Date", "value" => $event['eventDate']];
            }
            if ($event['eventAction'] == 'last changed') {
                $whois[] = ["name" => "Updated Date", "value" => $event['eventDate']];
            }
        }
    }

    if (isset($data['nameservers'])) {
        foreach ($data['nameservers'] as $ns) {
            $whois[] = ["name" => "Name Server", "value" => strtolower($ns['ldhName'])];
        }
    }
    
    if (isset($data['entities'])) {
        foreach ($data['entities'] as $entity) {
            if (in_array('registrar', $entity['roles'])) {
                 $whois[] = ["name" => "Registrar", "value" => $entity['vcardArray'][1][1][3]];
            }
        }
    }
    
    if (isset($data['status'])) {
        foreach ($data['status'] as $status) {
            $whois[] = ["name" => "Domain Status", "value" => $status];
        }
    }

    return $whois;
}

/**
 * Parses raw WHOIS text into a structured array.
 *
 * @param string $whois_raw The raw text from a WHOIS query.
 * @return array A structured array of WHOIS data.
 */
function parseWhoisText(string $whois_raw): array
{
    $whois_lines = explode("\n", trim($whois_raw));
    $whois = [];
    $fields_to_capture = [
        'Name Server',
        'Registrar:',
        'Domain Name:',
        'Updated Date:',
        'Creation Date:',
        'Registry Expiry Date:',
        'Expiry Date:',
        'Expiration Date:',
        'Registrar IANA ID:',
        'Domain Status:',
        'Reseller:'
    ];

    foreach ($whois_lines as $record) {
        foreach ($fields_to_capture as $field) {
            if (stripos(trim($record), $field) === 0) {
                $split = explode(":", trim($record), 2);
                if (count($split) < 2) continue;

                $name = trim(str_replace(':', '', $split[0]));
                $value = trim($split[1]);

                if ($name == "Name Server" || $name == "Domain Name") {
                    $value = strtolower($value);
                }
                $whois[] = ["name" => $name, "value" => $value];
            }
        }
    }
    return $whois;
}

/**
 * Performs the full domain lookup and returns the results as an array.
 *
 * @param string $domain The domain to look up.
 * @return array The lookup results.
 */
function performDomainLookup(string $domain): array
{
    $errors = [];
    $ip_lookup = [];
    $dns_records = [];
    $required_bins = ["whois", "dig", "host"];
    foreach ($required_bins as $bin) {
        $output = null;
        $return_var = null;
        exec("command -v $bin", $output, $return_var);
        if ($return_var != 0) {
            $errors[] = "Required command \"$bin\" is not installed.";
        }
    }

    if (!filter_var($domain, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
        $errors[] = "Invalid domain.";
    }

    if (strpos($domain, '.') === false) {
        $errors[] = "Invalid domain.";
    }

    if (strlen($domain) < 4) {
        $errors[] = "No domain name is that short.";
    }

    if (strlen($domain) > 80) {
        $errors[] = "Too long.";
    }

    if (count($errors) > 0) {
        return ["errors" => $errors];
    }

    $zone = new Zone($domain . ".");
    $zone->setDefaultTtl(3600);
    // Attempt RDAP lookup first
    $whois = rdapLookup($domain);
    // If RDAP fails, fall back to shell whois
    if (empty($whois)) {
        $whois_raw = shell_exec("whois " . escapeshellarg($domain));
        if (empty($whois_raw)) {
            $errors[] = "Domain not found via RDAP or WHOIS.";
            return ["errors" => $errors];
        }
        $whois = parseWhoisText($whois_raw);
    }
    
    if (empty($whois)) {
        $errors[] = "Domain not found.";
        return ["errors" => $errors];
    }

    $whois = array_map("unserialize", array_unique(array_map("serialize", $whois)));
    array_multisort(array_column($whois, 'name'), SORT_ASC, array_column($whois, 'value'), SORT_ASC, $whois);
    $ips = gethostbynamel($domain);
    if ($ips === false) {
        $ips = [];
    }

    foreach ($ips as $ip) {
        if (empty($ip) || !filter_var($ip, FILTER_VALIDATE_IP)) {
            continue;
        }
        $response = shell_exec("whois " . escapeshellarg($ip) . " | grep -E 'NetName:|Organization:|OrgName:'");
        $ip_lookup["$ip"] = empty($response) ? "" : trim($response);
    }

    $wildcard_cname = "";
    $wildcard_a = []; // Changed to array to handle multiple IPs
    $records_to_check = [
        ["a" => ""], ["a" => "*"], ["a" => "mail"], ["a" => "remote"], ["a" => "www"], ["a" => "blog"],
        ["a" => "shop"], ["a" => "portal"], ["a" => "api"], ["a" => "dev"], ["cname" => "*"], ["cname" => "www"],
        ["cname" => "blog"], ["cname" => "shop"], ["cname" => "portal"], ["cname" => "api"], ["cname" => "dev"],
        ["cname" => "autodiscover"], ["cname" => "sip"], ["cname" => "lyncdiscover"], ["cname" => "enterpriseregistration"],
        ["cname" => "enterpriseenrollment"], ["cname" => "email.mg"], ["cname" => "msoid"], ["cname" => "_acme-challenge"],
        ["cname" => "k1._domainkey"], ["cname" => "k2._domainkey"], ["cname" => "k3._domainkey"], ["cname" => "s1._domainkey"],
        ["cname" => "s2._domainkey"], ["cname" => "selector1._domainkey"], ["cname" => "selector2._domainkey"],
        ["cname" => "ctct1._domainkey"], ["cname" => "ctct2._domainkey"], ["cname" => "mail"], ["cname" => "ftp"],
        ["mx" => ""], ["mx" => "mg"], ["txt" => ""], ["txt" => "_dmarc"], ["txt" => "_amazonses"], ["txt" => "_acme-challenge"],
        ["txt" => "_acme-challenge.www"], ["txt" => " _mailchannels"], ["txt" => "default._domainkey"], ["txt" => "google._domainkey"],
        ["txt" => "mg"], ["txt" => "smtp._domainkey.mg"], ["txt" => "k1._domainkey"], ["txt" => "default._bimi"],
        ["srv" => "_sip._tls"], ["srv" => "_sipfederationtls._tcp"], ["srv" => "_autodiscover._tcp"], ["srv" => "_submissions._tcp"],
        ["srv" => "_imaps._tcp"], ["ns" => ""], ["soa" => ""],
    ];
    foreach ($records_to_check as $record_info) {
        $type = key($record_info);
        $name = $record_info[$type];
        $pre = empty($name) ? "" : "{$name}.";
        $value = shell_exec("(host -t $type $pre$domain | grep -q 'is an alias for') && echo \"\" || dig $pre$domain $type +short | sort -n");
        if ($type == "cname") {
            $value = shell_exec("host -t $type $pre$domain | grep 'alias for' | awk '{print \$NF}'");
        }
        $value = trim($value);
        if (str_starts_with($value, ';')) {
            continue;
        }
        if (empty($value)) continue;
        if ($type == "a" && preg_match("/[a-z]/i", $value)) { // Check if A record is actually a CNAME
            $type = "cname";
            $value = trim(shell_exec("dig $pre$domain $type +short | sort -n"));
            if (str_starts_with($value, ';')) {
                continue;
            }
            if (empty($value)) continue;
        }

        if ($type == 'a') {
            $current_a_values = explode("\n", $value);
            if ($name === '*') {
                $wildcard_a = $current_a_values;
            } elseif (!empty($wildcard_a) && $wildcard_a == $current_a_values) {
                continue; // This is a duplicate of the wildcard A record, so skip it entirely.
            }
        }
        if ($type == 'cname') {
            if ($name === '*') {
                $wildcard_cname = $value;
            } elseif (!empty($wildcard_cname) && $wildcard_cname == $value) {
                continue; // This is a duplicate of the wildcard CNAME record, so skip it entirely.
            }
        }

        $setName = empty($name) ? "@" : $name;
        $record_values = explode("\n", $value);
        foreach ($record_values as $record_value) {
            try {
                $record = new ResourceRecord();
                $record->setName($setName);
                $record->setClass('IN');

                switch ($type) {
                    case 'soa':
                        $parts = explode(" ", $record_value);
                        $record->setRdata(Factory::Soa($parts[0], $parts[1], $parts[2], $parts[3], $parts[4], $parts[5], $parts[6]));
                        break;
                    case 'ns':
                        $record->setRdata(Factory::Ns($record_value));
                        break;
                    case 'a':
                        $record->setRdata(Factory::A($record_value));
                        break;
                    case 'cname':
                        $record->setRdata(Factory::Cname($record_value));
                        break;
                    case 'srv':
                        $parts = explode(" ", $record_value);
                        if (count($parts) != 4) continue 2;
                        $record->setRdata(Factory::Srv($parts[0], $parts[1], $parts[2], $parts[3]));
                        break;
                    case 'mx':
                        $parts = explode(" ", $record_value);
                        if (count($parts) != 2) continue 2;
                        $record->setRdata(Factory::Mx($parts[0], $parts[1]));
                        break;
                    case 'txt':
                        $record->setRdata(Factory::Txt(trim($record_value, '"')));
                        break;
                    default:
                        continue 2;
                }
                $zone->addResourceRecord($record);
            } catch (Exception $e) {
                // Ignore errors from the DNS library for invalid records
            }
        }
        $dns_records[] = ["type" => $type, "name" => $name, "value" => $value];
    }

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $domain);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_HEADER, 1);
    curl_setopt($ch, CURLOPT_NOBODY, 1);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    $response = curl_exec($ch);
    curl_close($ch);

    // Split the response by the double CRLF that separates header blocks
    $header_blocks = explode("\r\n\r\n", trim($response));
    // Get the last header block, which corresponds to the final response after redirects
    $last_header_block = end($header_blocks);
    $lines = explode("\n", trim($last_header_block));

    $http_headers = [];
    foreach ($lines as $line) {
        if (preg_match('/^([^:]+):\s*(.*)$/', trim($line), $matches)) {
            $key = strtolower($matches[1]);
            $value = $matches[2];
            if (isset($http_headers[$key])) {
                $http_headers[$key] = is_array($http_headers[$key]) ?
                    [...$http_headers[$key], $value] : [$http_headers[$key], $value];
            } else {
                $http_headers[$key] = $value;
            }
        }
    }

    $builder = new AlignedBuilder();
    $builder->addRdataFormatter('TXT', 'specialTxtFormatter');

    return [
        "domain" => $whois,
        "http_headers" => $http_headers,
        "dns_records" => $dns_records,
        "ip_lookup" => $ip_lookup,
        "errors" => [],
        "zone" => $builder->build($zone)
    ];
}

// Handle AJAX requests for history management
if (isset($_REQUEST['action'])) {
    $action = $_REQUEST['action'];
    $db = getDbConnection();

    switch ($action) {
        case 'get_history':
            header('Content-Type: application/json');
            // Select all historical entries, not just the most recent per domain.
            $stmt = $db->query("SELECT id, domain, timestamp FROM history ORDER BY timestamp DESC");
            $history = $stmt->fetchAll(PDO::FETCH_ASSOC);
            echo json_encode($history);
            break;

        case 'get_domain_versions':
            header('Content-Type: application/json');
            $domain = $_GET['domain'] ?? '';
            $stmt = $db->prepare("SELECT id, domain, timestamp FROM history WHERE domain = ? ORDER BY timestamp DESC");
            $stmt->execute([$domain]);
            $versions = $stmt->fetchAll(PDO::FETCH_ASSOC);
            echo json_encode($versions);
            break;

        case 'get_history_item':
            header('Content-Type: application/json');
            $id = $_GET['id'] ?? 0;
            $stmt = $db->prepare("SELECT data, timestamp FROM history WHERE id = ?");
            $stmt->execute([$id]);
            $result = $stmt->fetch(PDO::FETCH_ASSOC);
            if ($result) {
                // Return data and timestamp
                $data = json_decode($result['data'], true);
                $data['timestamp'] = $result['timestamp'];
                echo json_encode($data);
            } else {
                echo json_encode(['error' => 'History item not found.']);
            }
            break;

        case 'delete_history':
            header('Content-Type: application/json');
            $id = $_POST['id'] ?? 0;
            $stmt = $db->prepare("DELETE FROM history WHERE id = ?");
            echo json_encode(['success' => $stmt->execute([$id])]);
            break;

        case 'export_history':
            $stmt = $db->query("SELECT domain, timestamp, data FROM history ORDER BY timestamp DESC");
            $history = $stmt->fetchAll(PDO::FETCH_ASSOC);
            header('Content-Type: application/json');
            header('Content-Disposition: attachment; filename="periscope-history-' . date('Y-m-d') . '.json"');
            echo json_encode($history, JSON_PRETTY_PRINT);
            break;

        case 'import_history':
            header('Content-Type: application/json');
            if (isset($_FILES['importFile']) && $_FILES['importFile']['error'] === UPLOAD_ERR_OK) {
                $fileContent = file_get_contents($_FILES['importFile']['tmp_name']);
                $importedHistory = json_decode($fileContent, true);

                if (is_array($importedHistory)) {
                    $db->beginTransaction();
                    try {
                        // Use simple INSERT instead of INSERT OR REPLACE
                        $stmt = $db->prepare("INSERT INTO history (domain, timestamp, data) VALUES (:domain, :timestamp, :data)");
                        foreach ($importedHistory as $item) {
                            if (isset($item['domain'], $item['timestamp'], $item['data'])) {
                                $stmt->execute([
                                    ':domain' => $item['domain'],
                                    ':timestamp' => $item['timestamp'],
                                    ':data' => is_string($item['data']) ? $item['data'] : json_encode($item['data'])
                                ]);
                            }
                        }
                        $db->commit();
                        echo json_encode(['success' => true, 'count' => count($importedHistory)]);
                    } catch (Exception $e) {
                        $db->rollBack();
                        echo json_encode(['success' => false, 'message' => 'Database error: ' . $e->getMessage()]);
                    }
                } else {
                    echo json_encode(['success' => false, 'message' => 'Invalid JSON file.']);
                }
            } else {
                echo json_encode(['success' => false, 'message' => 'File upload error.']);
            }
            break;
    }
    die();
}

/**
 * Formats TXT records for DNS zone file output, splitting long strings.
 *
 * @param Badcow\DNS\Rdata\TXT $rdata The RDATA object.
 * @param int $padding The padding for alignment.
 * @return string The formatted string.
 */
function specialTxtFormatter(Badcow\DNS\Rdata\TXT $rdata, int $padding): string
{
    $text = $rdata->getText();
    if (strlen($text) <= 500) {
        return sprintf('"%s"', addcslashes($text, '"\\'));
    }

    $returnVal = "(\n";
    $chunks = str_split($text, 255); // Split into 255-char chunks as per RFC
    foreach ($chunks as $chunk) {
        $returnVal .= str_repeat(' ', $padding) . sprintf('"%s"', addcslashes($chunk, '"\\')) . "\n";
    }
    $returnVal .= str_repeat(' ', $padding) . ")";

    return $returnVal;
}

/**
 * Handles all web-based requests (UI, context menus, etc.).
 */
function runWebApp()
{
    // Handle context menu lookups
    if (isset($_REQUEST['dig'])) {
        header('Content-Type: text/plain');
        $domain_to_dig = trim($_REQUEST['dig'], ".'\""); // Sanitize a bit
        if (filter_var($domain_to_dig, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
            $escaped_domain = escapeshellarg($domain_to_dig);

            // Try the default (A record) lookup first
            $result = shell_exec("dig $escaped_domain +short");

            // If that's empty, fall back to a TXT lookup
            if (empty(trim($result))) {
                $result = shell_exec("dig $escaped_domain TXT +short");
            }

            echo $result;
        } else {
            echo "Invalid domain provided.";
        }
        die();
    }

    if (isset($_REQUEST['whois'])) {
        header('Content-Type: text/plain');
        $ip_to_check = trim($_REQUEST['whois']);
        if (filter_var($ip_to_check, FILTER_VALIDATE_IP)) {
            echo shell_exec("whois " . escapeshellarg($ip_to_check));
        } else {
            echo "Invalid IP address provided.";
        }
        die();
    }

    if (isset($_REQUEST['raw_domain'])) {
        $domain_to_check = trim($_REQUEST['raw_domain']);
        if (filter_var($domain_to_check, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
            // Attempt RDAP lookup first
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, "https://rdap.org/domain/" . $domain_to_check);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
            curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
            $rdap_data = curl_exec($ch);
            $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);

            if ($http_code === 200 && !empty($rdap_data)) {
                header('Content-Type: application/json');
                // Decode and re-encode with pretty print
                $decoded_json = json_decode($rdap_data);
                echo json_encode($decoded_json, JSON_PRETTY_PRINT);
            } else {
                // Fallback to shell whois
                header('Content-Type: text/plain');
                echo shell_exec("whois " . escapeshellarg($domain_to_check));
            }
        } else {
            header('Content-Type: text/plain');
            echo "Invalid domain provided.";
        }
        die();
    }

    if (!isset($_REQUEST['domain'])) {
        return; // This allows the HTML to be rendered on first load
    }

    header('Content-Type: application/json');
    $domain = $_REQUEST['domain'];
    $final_response = performDomainLookup($domain);

    if (!empty($final_response['errors'])) {
        echo json_encode($final_response);
        die();
    }

    // Save result to the database
    $db = getDbConnection();
    $stmt = $db->prepare("INSERT INTO history (domain, timestamp, data) VALUES (?, ?, ?)");
    $timestamp = time();
    $stmt->execute([$domain, $timestamp, json_encode($final_response)]);

    // Add timestamp to the response for the frontend
    $final_response['timestamp'] = $timestamp;

    echo json_encode($final_response);
    die();
}

/**
 * Handles CLI requests.
 *
 * @param array $argv Command-line arguments.
 * @param int $argc Command-line argument count.
 */
function runCliApp(array $argv, int $argc)
{
    if ($argc < 2) {
        echo "Usage: php index.php <domain>\n";
        exit(1);
    }

    $domain = $argv[1];
    echo "Looking up domain: $domain...\n\n";

    $final_response = performDomainLookup($domain);

    if (!empty($final_response['errors'])) {
        echo "Errors encountered:\n";
        foreach ($final_response['errors'] as $error) {
            echo "- $error\n";
        }
        exit(1);
    }

    // Save result to the database
    $db = getDbConnection();
    $stmt = $db->prepare("INSERT INTO history (domain, timestamp, data) VALUES (?, ?, ?)");
    $timestamp = time();
    $stmt->execute([$domain, $timestamp, json_encode($final_response)]);

    // --- Generate CLI Summary ---
    $registrar = 'N/A';
    foreach ($final_response['domain'] as $item) {
        if (stripos($item['name'], 'Registrar') !== false) {
            $registrar = $item['value'];
            break;
        }
    }

    $ips = array_keys($final_response['ip_lookup']);
    $nameservers = [];
    foreach ($final_response['dns_records'] as $record) {
        if (strtolower($record['type']) === 'ns') {
            $nameservers = array_merge($nameservers, explode("\n", $record['value']));
        }
    }
    $nameservers = array_unique($nameservers);

    echo "--- Summary for $domain ---\n";
    echo "Registrar:     " . $registrar . "\n";
    echo "IP Addresses:  " . (empty($ips) ? 'N/A' : implode(', ', $ips)) . "\n";
    echo "Name Servers:  " . (empty($nameservers) ? 'N/A' : implode(', ', $nameservers)) . "\n";
    echo "---------------------------\n";
    echo "\nFull report saved to database.\n";
    exit(0);
}

// --- Main Application Dispatcher ---
if (php_sapi_name() === 'cli') {
    runCliApp($argv, $argc);
} else {
    runWebApp();
    // The web app continues to render the HTML below
}

?>  <!DOCTYPE html>
<html lang="en" class="h-full">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Periscope</title>
    <link rel="icon" href="Periscope.webp" />
    
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    
    <link href="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/themes/prism-tomorrow.min.css" rel="stylesheet" />
    
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    fontFamily: {
                        sans: ['Inter', 'sans-serif'],
                        mono: ['JetBrains Mono', 'monospace'],
                    },
                    colors: {
                        // "Submarine" Palette overrides
                        slate: {
                            850: '#1e293b', 
                            900: '#0f172a', 
                            950: '#020617', // Deepest ocean
                        },
                        cyan: {
                            400: '#22d3ee', // Radar blip
                            500: '#06b6d4',
                            900: '#164e63',
                        }
                    },
                    animation: {
                        'radar': 'radar 2s cubic-bezier(0, 0, 0.2, 1) infinite',
                    },
                    keyframes: {
                        radar: {
                            '75%, 100%': { transform: 'scale(2)', opacity: '0' },
                        }
                    }
                }
            }
        }
    </script>

    <link href="https://cdn.jsdelivr.net/npm/@mdi/font@7.4.47/css/materialdesignicons.min.css" rel="stylesheet">

    <style>
        [v-cloak] { display: none; }
        .custom-scroll::-webkit-scrollbar { width: 8px; height: 8px; }
        .custom-scroll::-webkit-scrollbar-track { background: transparent; }
        .custom-scroll::-webkit-scrollbar-thumb { background-color: rgba(6, 182, 212, 0.2); border-radius: 4px; }
        .custom-scroll::-webkit-scrollbar-thumb:hover { background-color: rgba(6, 182, 212, 0.5); }
    </style>
</head>
<body class="h-full bg-slate-50 text-slate-800 dark:bg-slate-950 dark:text-slate-200 transition-colors duration-200 selection:bg-cyan-500/30">

<div id="app" v-cloak class="min-h-full flex flex-col">

    <nav class="sticky top-0 z-40 w-full backdrop-blur-lg bg-white/70 dark:bg-slate-950/70 border-b border-slate-200 dark:border-slate-800/50">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div class="flex items-center justify-between h-16">
                <div @click="resetView()" class="flex items-center gap-3 cursor-pointer group select-none">
                    <div class="relative">
                        <img src="Periscope.webp" alt="Logo" class="h-8 w-8 object-contain relative z-10 transition-transform group-hover:rotate-12">
                        <div class="absolute inset-0 rounded-full bg-cyan-400 opacity-0 group-hover:animate-radar z-0"></div>
                    </div>
                    <span class="font-bold text-lg tracking-tight text-slate-900 dark:text-cyan-50 group-hover:text-cyan-600 dark:group-hover:text-cyan-400 transition-colors">Periscope</span>
                </div>
                <div class="flex items-center gap-2">
                    
                    <a href="https://github.com/austinginder/periscope" target="_blank" class="relative group p-2 rounded-full hover:bg-slate-200 dark:hover:bg-slate-800 text-slate-500 dark:text-slate-400 hover:text-cyan-600 dark:hover:text-cyan-400 transition-colors">
                        <span class="mdi mdi-github text-xl"></span>
                        <span class="absolute top-full mt-2 left-1/2 -translate-x-1/2 px-2 py-1 bg-slate-800 dark:bg-slate-700 text-white text-xs rounded opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none whitespace-nowrap z-50 shadow-lg">
                            GitHub Source
                        </span>
                    </a>

                    <button @click="openHistory()" class="relative group p-2 rounded-full hover:bg-slate-200 dark:hover:bg-slate-800 text-slate-500 dark:text-slate-400 hover:text-cyan-600 dark:hover:text-cyan-400 transition-colors">
                        <span class="mdi mdi-history text-xl"></span>
                        <span class="absolute top-full mt-2 left-1/2 -translate-x-1/2 px-2 py-1 bg-slate-800 dark:bg-slate-700 text-white text-xs rounded opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none whitespace-nowrap z-50 shadow-lg">
                            Scan History
                        </span>
                    </button>

                    <button @click="toggleTheme()" class="relative group p-2 rounded-full hover:bg-slate-200 dark:hover:bg-slate-800 text-slate-500 dark:text-slate-400 hover:text-cyan-600 dark:hover:text-cyan-400 transition-colors">
                        <span class="mdi text-xl" :class="currentTheme === 'dark' ? 'mdi-white-balance-sunny' : 'mdi-moon-waning-crescent'"></span>
                        <span class="absolute top-full mt-2 left-1/2 -translate-x-1/2 px-2 py-1 bg-slate-800 dark:bg-slate-700 text-white text-xs rounded opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none whitespace-nowrap z-50 shadow-lg">
                            {{ currentTheme === 'dark' ? 'Light Mode' : 'Dark Mode' }}
                        </span>
                    </button>

                </div>
            </div>
        </div>
    </nav>

    <main class="flex-grow w-full max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        
        <div class="max-w-3xl mx-auto mb-10 transition-all duration-500 relative z-30" :class="{'mt-20 scale-110': !response.domain, 'mt-0': response.domain}">
            <div class="relative group">
                <div class="absolute -inset-1 bg-gradient-to-r from-cyan-500 to-sky-600 rounded-lg blur opacity-25 group-hover:opacity-50 transition duration-1000 group-hover:duration-200"></div>
                
                <div class="relative flex items-center bg-white dark:bg-slate-900 rounded-lg ring-1 ring-slate-900/5 dark:ring-white/10 shadow-xl">
                    <div class="pl-4 text-slate-400">
                        <span class="mdi mdi-radar text-2xl"></span>
                    </div>
                    
                    <input 
                        v-model="domain" 
                        @keydown.enter="lookupDomain()"
                        @input="showAutocomplete = true"
                        @focus="showAutocomplete = true"
                        @blur="handleBlur"
                        type="text" 
                        class="w-full bg-transparent border-0 py-4 px-4 text-slate-900 dark:text-white placeholder-slate-400 focus:ring-0 focus:outline-none sm:text-lg" 
                        placeholder="Target domain (e.g., google.com)" 
                        spellcheck="false"
                        autocomplete="off"
                        autofocus
                    >
                    
                    <div class="pr-2">
                        <button 
                            @click="lookupDomain()" 
                            class="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-cyan-600 hover:bg-cyan-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-cyan-500 disabled:opacity-50 disabled:cursor-not-allowed transition-all"
                            :disabled="loading"
                        >
                            <svg v-if="loading" class="animate-spin -ml-1 mr-2 h-4 w-4 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                                <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                                <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                            </svg>
                            Scan
                        </button>
                    </div>
                </div>

                <div v-if="showAutocomplete && filteredHistory.length > 0" 
                     class="absolute top-full left-0 right-0 mt-2 bg-white dark:bg-slate-900 rounded-lg border border-slate-200 dark:border-slate-800 shadow-2xl overflow-hidden max-h-60 overflow-y-auto custom-scroll z-50">
                    <div class="px-3 py-2 text-xs font-semibold text-slate-500 uppercase tracking-wider bg-slate-50 dark:bg-slate-950/50">
                        History Suggestions
                    </div>
                    <ul>
                        <li v-for="item in filteredHistory" :key="item.domain" 
                            @mousedown="selectAutocomplete(item)"
                            class="px-4 py-3 hover:bg-cyan-50 dark:hover:bg-cyan-900/20 cursor-pointer transition-colors border-b border-slate-100 dark:border-slate-800/50 last:border-0 group">
                            <div class="flex items-center justify-between">
                                <span class="text-slate-700 dark:text-slate-200 font-medium group-hover:text-cyan-700 dark:group-hover:text-cyan-400">{{ item.domain }}</span>
                                <span class="text-xs text-slate-400 font-mono">{{ formatDateShort(item.timestamp) }}</span>
                            </div>
                        </li>
                    </ul>
                </div>
            </div>
            
            <div v-if="response.errors.length > 0" class="mt-4 space-y-2">
                <div v-for="error in response.errors" class="bg-red-50 dark:bg-red-900/20 border-l-4 border-red-500 p-4 rounded-md shadow-sm">
                    <div class="flex">
                        <div class="flex-shrink-0">
                            <span class="mdi mdi-alert-circle text-red-500"></span>
                        </div>
                        <div class="ml-3">
                            <p class="text-sm text-red-700 dark:text-red-200" v-html="error"></p>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <div v-if="response.domain" class="animate-fade-in-up">
            
            <div v-if="otherVersions.length > 0" class="mb-6 flex justify-center">
                <button @click="showVersionsModal = true" class="inline-flex items-center px-4 py-2 rounded-full text-sm font-medium bg-cyan-50 text-cyan-700 dark:bg-cyan-900/30 dark:text-cyan-300 hover:bg-cyan-100 dark:hover:bg-cyan-900/50 transition-colors border border-cyan-200 dark:border-cyan-800/50">
                    <span class="mdi mdi-history mr-2"></span>
                    View History ({{ otherVersions.length }} older scans)
                </button>
            </div>

            <div class="grid grid-cols-1 md:grid-cols-12 gap-6">
                
                <div class="md:col-span-5 space-y-6">
                    
                    <div class="bg-white dark:bg-slate-900 rounded-xl shadow-sm border border-slate-200 dark:border-slate-800 overflow-hidden">
                        <div class="px-5 py-4 border-b border-slate-100 dark:border-slate-800 flex justify-between items-center bg-slate-50/50 dark:bg-slate-950/30">
                            <h3 class="text-sm font-semibold text-slate-900 dark:text-cyan-50 uppercase tracking-wider">Target Status</h3>
                            <button @click="showRawWhois()" class="text-xs text-cyan-600 dark:text-cyan-400 hover:underline">View Raw</button>
                        </div>
                        <div class="divide-y divide-slate-100 dark:divide-slate-800">
                            <div v-for="record in response.domain" :key="record.name" class="px-5 py-3 grid grid-cols-3 gap-4 hover:bg-slate-50 dark:hover:bg-slate-800/30 transition-colors group">
                                <dt class="text-sm font-medium text-slate-500 dark:text-slate-400">{{ record.name }}</dt>
                                <dd class="text-sm text-slate-900 dark:text-slate-200 col-span-2 break-words font-mono" @contextmenu="showContextMenu($event, record.value)">
                                    {{ record.value }}
                                </dd>
                            </div>
                        </div>
                    </div>

                    <div class="bg-white dark:bg-slate-900 rounded-xl shadow-sm border border-slate-200 dark:border-slate-800 overflow-hidden">
                        <div class="px-5 py-4 border-b border-slate-100 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-950/30">
                            <h3 class="text-sm font-semibold text-slate-900 dark:text-cyan-50 uppercase tracking-wider">Network Coordinates</h3>
                        </div>
                        <div class="p-5 space-y-6">
                            <template v-for="(rows, ip) in response.ip_lookup">
                                <div class="bg-slate-50 dark:bg-slate-950 rounded-lg p-3 border border-slate-100 dark:border-slate-800">
                                    <div class="flex justify-between items-center mb-3">
                                        <div class="flex items-center gap-2">
                                            <span class="h-2 w-2 rounded-full bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.5)]"></span>
                                            <span class="font-mono text-sm font-bold text-slate-700 dark:text-slate-200">{{ ip }}</span>
                                        </div>
                                        <button @click="runWhois(ip)" class="text-xs px-2 py-1 rounded bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-700">Raw</button>
                                    </div>
                                    <div class="space-y-1">
                                        <div v-for="row in rows.split('\n')" class="grid grid-cols-3 gap-2 text-xs">
                                            <span class="text-slate-500 dark:text-slate-400">{{ row.split(":")[0] }}</span>
                                            <span class="col-span-2 text-slate-800 dark:text-slate-300 font-mono truncate" @contextmenu="showContextMenu($event, row.split(':')[1])">{{ row.split(":")[1] }}</span>
                                        </div>
                                    </div>
                                </div>
                            </template>
                        </div>
                    </div>

                    <div class="bg-white dark:bg-slate-900 rounded-xl shadow-sm border border-slate-200 dark:border-slate-800 overflow-hidden">
                        <div class="px-5 py-4 border-b border-slate-100 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-950/30">
                            <h3 class="text-sm font-semibold text-slate-900 dark:text-cyan-50 uppercase tracking-wider">Signature (Headers)</h3>
                        </div>
                        <div class="overflow-x-auto">
                            <table class="min-w-full divide-y divide-slate-100 dark:divide-slate-800">
                                <tbody class="divide-y divide-slate-100 dark:divide-slate-800">
                                    <tr v-for="(value, key) in response.http_headers" class="hover:bg-slate-50 dark:hover:bg-slate-800/30">
                                        <td class="px-5 py-2 text-xs font-medium text-slate-500 dark:text-slate-400 whitespace-nowrap">{{ key }}</td>
                                        <td class="px-5 py-2 text-xs font-mono text-slate-800 dark:text-slate-300 break-all" @contextmenu="showContextMenu($event, value)">{{ value }}</td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </div>

                </div>

                <div class="md:col-span-7 space-y-6">
                    
                    <div class="bg-white dark:bg-slate-900 rounded-xl shadow-sm border border-slate-200 dark:border-slate-800 overflow-hidden">
                        <div class="px-5 py-4 border-b border-slate-100 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-950/30">
                            <h3 class="text-sm font-semibold text-slate-900 dark:text-cyan-50 uppercase tracking-wider">DNS Records</h3>
                        </div>
                        <div class="overflow-x-auto">
                            <table class="min-w-full divide-y divide-slate-200 dark:divide-slate-800">
                                <thead class="bg-slate-50 dark:bg-slate-950/50">
                                    <tr>
                                        <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider w-20">Type</th>
                                        <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider w-32">Name</th>
                                        <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">Value</th>
                                    </tr>
                                </thead>
                                <tbody class="bg-white dark:bg-slate-900 divide-y divide-slate-200 dark:divide-slate-800">
                                    <tr v-for="record in response.dns_records" class="hover:bg-slate-50 dark:hover:bg-slate-800/30 transition-colors">
                                        <td class="px-6 py-3 whitespace-nowrap text-xs font-bold text-slate-600 dark:text-slate-300 uppercase">{{ record.type }}</td>
                                        <td class="px-6 py-3 whitespace-nowrap text-xs text-slate-500 dark:text-slate-400 font-mono">{{ record.name }}</td>
                                        <td class="px-6 py-3 text-xs text-slate-800 dark:text-slate-300 font-mono break-all">
                                            <template v-if="record.type !== 'mx'">
                                                <span @contextmenu="showContextMenu($event, record.value)">{{ record.value }}</span>
                                            </template>
                                            <template v-else>
                                                <div v-for="line in record.value.split('\n').filter(l => l.trim() !== '')" :key="line" class="py-0.5">
                                                    <span class="text-cyan-600 dark:text-cyan-400 mr-2">{{ line.split(' ')[0] }}</span>
                                                    <span @contextmenu="showContextMenu($event, line.split(' ')[1])">{{ line.split(' ')[1] }}</span>
                                                </div>
                                            </template>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </div>

                    <div class="bg-slate-950 rounded-xl shadow-lg border border-slate-900 overflow-hidden relative group">
                        <div class="absolute top-4 right-4 flex gap-2 opacity-0 group-hover:opacity-100 transition-opacity z-10">
                            <button @click="copyZone()" class="p-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-md shadow-sm border border-slate-700 transition-colors" title="Copy">
                                <span class="mdi mdi-content-copy"></span>
                            </button>
                            <button @click="downloadZone()" class="p-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-md shadow-sm border border-slate-700 transition-colors" title="Download">
                                <span class="mdi mdi-download"></span>
                            </button>
                        </div>
                        <div class="px-5 py-3 bg-black/40 border-b border-slate-900 flex justify-between items-center">
                            <h3 class="text-xs font-semibold text-slate-400 uppercase tracking-wider">BIND Zone File</h3>
                        </div>
                        <div class="p-0 overflow-x-auto custom-scroll bg-[#0b1016]">
                             <pre class="language-dns-zone-file !m-0 !bg-transparent !p-4 !text-sm"><code class="language-dns-zone-file">{{ response.zone }}</code></pre>
                        </div>
                        <a ref="download_zone" href="#" class="hidden"></a>
                    </div>

                </div>
            </div>
        </div>

        <div v-if="!response.domain" class="mt-20 text-center">
             <div class="text-slate-400 dark:text-slate-600 text-sm flex flex-col items-center gap-2">
                 <span class="mdi mdi-submarine text-4xl opacity-50"></span>
                 <p>Waiting for target coordinates...</p>
             </div>
        </div>

    </main>

    <div v-if="contextMenu.show" 
         class="fixed bg-white dark:bg-slate-800 rounded-lg shadow-xl border border-slate-200 dark:border-slate-700 py-1 z-50 w-48 animate-scale-in"
         :style="{ top: contextMenu.y + 'px', left: contextMenu.x + 'px' }"
         @mouseleave="contextMenu.show = false">
         
         <div v-if="isDomain(contextMenu.value)" @click="runDig(contextMenu.value)" class="px-4 py-2 text-sm text-slate-700 dark:text-slate-200 hover:bg-cyan-50 dark:hover:bg-slate-700 cursor-pointer flex items-center gap-2">
            <span class="mdi mdi-dns w-4"></span> Dig {{ contextMenu.value }}
         </div>
         <div v-if="isIp(contextMenu.value)" @click="runWhois(contextMenu.value)" class="px-4 py-2 text-sm text-slate-700 dark:text-slate-200 hover:bg-cyan-50 dark:hover:bg-slate-700 cursor-pointer flex items-center gap-2">
            <span class="mdi mdi-card-account-details w-4"></span> Whois {{ contextMenu.value }}
         </div>
         <div @click="copyToClipboard(contextMenu.value)" class="px-4 py-2 text-sm text-slate-700 dark:text-slate-200 hover:bg-cyan-50 dark:hover:bg-slate-700 cursor-pointer flex items-center gap-2 border-t border-slate-100 dark:border-slate-700 mt-1">
            <span class="mdi mdi-content-copy w-4"></span> Copy Value
         </div>
    </div>

    <div v-if="dialog.show" class="fixed inset-0 z-50 overflow-y-auto" aria-labelledby="modal-title" role="dialog" aria-modal="true">
        <div class="flex items-end justify-center min-h-screen pt-4 px-4 pb-20 text-center sm:block sm:p-0">
            <div class="fixed inset-0 bg-slate-900/75 transition-opacity" @click="dialog.show = false"></div>
            <span class="hidden sm:inline-block sm:align-middle sm:h-screen" aria-hidden="true">&#8203;</span>
            <div class="inline-block align-bottom bg-white dark:bg-slate-900 rounded-xl text-left overflow-hidden shadow-xl transform transition-all sm:my-8 sm:align-middle sm:max-w-4xl sm:w-full border border-slate-200 dark:border-slate-800">
                <div class="px-4 pt-5 pb-4 sm:p-6 sm:pb-4">
                    <div class="flex justify-between items-center mb-4">
                        <h3 class="text-lg leading-6 font-medium text-slate-900 dark:text-white" id="modal-title">{{ dialog.title }}</h3>
                        <button @click="dialog.show = false" class="text-slate-400 hover:text-slate-500 dark:hover:text-slate-300">
                            <span class="mdi mdi-close text-xl"></span>
                        </button>
                    </div>
                    <div class="bg-black/50 rounded-lg p-4 overflow-auto max-h-[70vh] custom-scroll border border-slate-800">
                        <pre class="text-xs sm:text-sm text-cyan-50 font-mono whitespace-pre-wrap">{{ dialog.content }}</pre>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <div v-if="showHistoryModal" class="fixed inset-0 z-50 overflow-y-auto">
        <div class="flex items-center justify-center min-h-screen px-4 pt-4 pb-20 text-center sm:block sm:p-0">
            <div class="fixed inset-0 bg-slate-900/75 transition-opacity" @click="showHistoryModal = false"></div>
            <span class="hidden sm:inline-block sm:align-middle sm:h-screen">&#8203;</span>
            <div class="inline-block align-bottom bg-white dark:bg-slate-900 rounded-xl text-left overflow-hidden shadow-xl transform transition-all sm:my-8 sm:align-middle sm:max-w-xl sm:w-full border border-slate-200 dark:border-slate-700">
                <div class="px-6 py-4 border-b border-slate-200 dark:border-slate-700 flex justify-between items-center bg-slate-50 dark:bg-slate-950">
                    <h3 class="text-lg font-medium text-slate-900 dark:text-white">Scan Log</h3>
                    <div class="flex gap-2">
                        <button @click="exportHistory" :disabled="historyItems.length === 0" class="p-2 text-slate-500 hover:text-cyan-600 dark:hover:text-cyan-400 disabled:opacity-30">
                            <span class="mdi mdi-export-variant"></span>
                        </button>
                        <button @click="triggerImport" class="p-2 text-slate-500 hover:text-cyan-600 dark:hover:text-cyan-400">
                            <span class="mdi mdi-import"></span>
                        </button>
                        <button @click="showHistoryModal = false" class="p-2 text-slate-500 hover:text-slate-700">
                            <span class="mdi mdi-close"></span>
                        </button>
                    </div>
                </div>
                <div class="max-h-[60vh] overflow-y-auto custom-scroll">
                    <input type="file" ref="importFile" @change="importHistory" accept=".json" class="hidden" />
                    <ul v-if="historyItems.length > 0" class="divide-y divide-slate-200 dark:divide-slate-800">
                        <li v-for="item in historyItems" :key="item.id" @click="loadFromHistory(item)" class="px-6 py-4 hover:bg-slate-50 dark:hover:bg-slate-800 cursor-pointer transition-colors group">
                            <div class="flex justify-between items-center">
                                <div>
                                    <p class="text-sm font-medium text-cyan-600 dark:text-cyan-400">{{ item.domain }}</p>
                                    <p class="text-xs text-slate-500 dark:text-slate-400">{{ formatDate(item.timestamp) }}</p>
                                </div>
                                <span class="mdi mdi-chevron-right text-slate-300 group-hover:text-slate-500"></span>
                            </div>
                        </li>
                    </ul>
                    <div v-else class="text-center py-12">
                        <span class="mdi mdi-history text-5xl text-slate-200 dark:text-slate-700"></span>
                        <p class="mt-2 text-slate-500">Log empty</p>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <div v-if="showVersionsModal" class="fixed inset-0 z-50 overflow-y-auto">
        <div class="flex items-center justify-center min-h-screen px-4 pt-4 pb-20 text-center sm:block sm:p-0">
            <div class="fixed inset-0 bg-slate-900/75 transition-opacity" @click="showVersionsModal = false"></div>
            <span class="hidden sm:inline-block sm:align-middle sm:h-screen">&#8203;</span>
            <div class="inline-block align-bottom bg-white dark:bg-slate-900 rounded-xl text-left overflow-hidden shadow-xl transform transition-all sm:my-8 sm:align-middle sm:max-w-xl sm:w-full border border-slate-200 dark:border-slate-700">
                <div class="px-6 py-4 border-b border-slate-200 dark:border-slate-700 flex justify-between items-center bg-slate-50 dark:bg-slate-950">
                    <h3 class="text-lg font-medium text-slate-900 dark:text-white">Snapshots: {{ domain }}</h3>
                    <button @click="showVersionsModal = false" class="text-slate-400 hover:text-slate-500"><span class="mdi mdi-close"></span></button>
                </div>
                <ul class="divide-y divide-slate-200 dark:divide-slate-800 max-h-[60vh] overflow-y-auto custom-scroll">
                    <li v-for="(item, index) in domainVersions" :key="item.id" @click="loadFromHistory(item)" 
                        class="px-6 py-4 hover:bg-slate-50 dark:hover:bg-slate-800 cursor-pointer transition-colors flex justify-between items-center"
                        :class="{'bg-cyan-50 dark:bg-cyan-900/20': item.timestamp === response.timestamp}">
                        <div class="flex items-center gap-3">
                             <span v-if="item.timestamp === response.timestamp" class="mdi mdi-check-circle text-cyan-500"></span>
                             <span v-else class="mdi mdi-clock-outline text-slate-400"></span>
                             <div>
                                 <p class="text-sm font-medium text-slate-900 dark:text-slate-200">{{ formatDate(item.timestamp) }}</p>
                             </div>
                        </div>
                        <button @click.stop="removeHistoryItem(item, index)" class="p-1 text-slate-400 hover:text-red-500 transition-colors">
                            <span class="mdi mdi-trash-can-outline"></span>
                        </button>
                    </li>
                </ul>
            </div>
        </div>
    </div>

    <div v-if="snackbar.show" class="fixed bottom-4 right-4 z-50 animate-slide-in-right">
        <div class="bg-slate-800 dark:bg-cyan-500 text-white dark:text-slate-900 px-6 py-3 rounded-lg shadow-lg flex items-center gap-4 font-medium">
            <span>{{ snackbar.message }}</span>
            <button @click="snackbar.show = false" class="text-sm font-bold opacity-75 hover:opacity-100">DISMISS</button>
        </div>
    </div>

</div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/prism.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-dns-zone-file.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-json.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/vue@v3.5.19/dist/vue.global.js"></script>

<script>
    const { createApp } = Vue;

    createApp({
        data() {
            return {
                domain: "",
                loading: false,
                snackbar: { show: false, message: "" },
                response: { domain: "", errors: [], zone: "", timestamp: null },
                currentTheme: localStorage.getItem('theme') || 'dark',
                contextMenu: { show: false, x: 0, y: 0, value: '' },
                dialog: { show: false, title: '', content: '' },
                showHistoryModal: false,
                historyItems: [],
                showVersionsModal: false,
                domainVersions: [],
                showAutocomplete: false
            }
        },
        computed: {
            otherVersions() {
                if (!this.response.timestamp) return [];
                return this.domainVersions.filter(v => v.timestamp !== this.response.timestamp);
            },
            filteredHistory() {
                if (!this.domain || this.domain.length < 1) return [];
                
                // Create unique list based on domain name
                const unique = [];
                const seen = new Set();
                
                // Sort by timestamp desc first so we get the latest entry for each unique domain
                const sortedHistory = [...this.historyItems].sort((a, b) => b.timestamp - a.timestamp);
                
                for (const item of sortedHistory) {
                    if (item.domain.toLowerCase().includes(this.domain.toLowerCase()) && !seen.has(item.domain)) {
                        unique.push(item);
                        seen.add(item.domain);
                    }
                    if (unique.length >= 8) break; // Limit suggestions
                }
                return unique;
            }
        },
        methods: {
            resetView() {
                this.response = { domain: "", errors: [], zone: "", timestamp: null };
                this.domain = "";
                this.domainVersions = [];
            },
            handleBlur() {
                // Delay hiding to allow click event to register on the list item
                setTimeout(() => {
                    this.showAutocomplete = false;
                }, 200);
            },
            selectAutocomplete(item) {
                this.loadFromHistory(item);
                this.showAutocomplete = false;
            },
            lookupDomain() {
                if(!this.domain) return;
                this.loading = true;
                this.showAutocomplete = false;
                this.response = { domain: "", errors: [], zone: "", timestamp: null };
                
                // Clean input
                let cleanDomain = this.domain;
                if (cleanDomain.indexOf("//") > -1) cleanDomain = cleanDomain.split('/')[2];
                else cleanDomain = cleanDomain.split('/')[0];
                cleanDomain = cleanDomain.split(':')[0].split('?')[0];
                this.domain = cleanDomain;

                fetch("?domain=" + this.domain)
                    .then(response => response.json())
                    .then(data => {
                        this.loading = false
                        this.response = data
                        this.loadHistory()
                        this.getDomainVersions(this.domain);
                        this.$nextTick(() => { Prism.highlightAll() })
                    })
                    .catch(error => {
                        this.loading = false;
                        this.response.errors.push("Connection failed. Check console.");
                        console.error(error);
                    });
            },
            copyZone() {
                navigator.clipboard.writeText(this.response.zone)
                this.showToast("Zone copied to clipboard");
            },
            copyToClipboard(text) {
                navigator.clipboard.writeText(text);
                this.contextMenu.show = false;
                this.showToast("Copied to clipboard");
            },
            showToast(msg) {
                this.snackbar.message = msg;
                this.snackbar.show = true;
                setTimeout(() => { this.snackbar.show = false }, 3000);
            },
            downloadZone() {
                const blob = new Blob([this.response.zone], { type: "text/dns" })
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `${this.domain}.zone`;
                a.click();
                window.URL.revokeObjectURL(url);
            },
            toggleTheme() {
                this.currentTheme = this.currentTheme === 'light' ? 'dark' : 'light';
                localStorage.setItem('theme', this.currentTheme);
                this.applyTheme();
            },
            applyTheme() {
                if (this.currentTheme === 'dark') {
                    document.documentElement.classList.add('dark');
                } else {
                    document.documentElement.classList.remove('dark');
                }
            },
            isDomain(str) {
                if (typeof str !== 'string' || str.trim() === '') return false;
                const cleanedStr = str.trim().split('\n')[0].trim();
                const domainRegex = /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\.?$/;
                return domainRegex.test(cleanedStr) && !this.isIp(cleanedStr);
            },
            isIp(str) {
                if (typeof str !== 'string' || str.trim() === '') return false;
                const cleanedStr = str.trim().split('\n')[0].trim();
                const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
                return ipRegex.test(cleanedStr);
            },
            showContextMenu(event, value) {
                const cleanedValue = typeof value === 'string' ? value.trim() : '';
                event.preventDefault();
                this.contextMenu.show = false;
                this.contextMenu.x = event.clientX;
                this.contextMenu.y = event.clientY;
                this.contextMenu.value = cleanedValue.split('\n')[0].trim();
                
                this.$nextTick(() => {
                    const menuWidth = 192; // approximate width (w-48)
                    if (this.contextMenu.x + menuWidth > window.innerWidth) {
                        this.contextMenu.x = window.innerWidth - menuWidth - 10;
                    }
                    this.contextMenu.show = true;
                });
            },
            runDig(domain) {
                this.dialog.title = `Dig: ${domain}`;
                this.dialog.content = 'Loading...';
                this.dialog.show = true;
                this.contextMenu.show = false;
                fetch(`?dig=${encodeURIComponent(domain)}`)
                    .then(r => r.text())
                    .then(data => this.dialog.content = data || 'No results.');
            },
            runWhois(ip) {
                this.dialog.title = `Whois: ${ip}`;
                this.dialog.content = 'Loading...';
                this.dialog.show = true;
                this.contextMenu.show = false;
                fetch(`?whois=${encodeURIComponent(ip)}`)
                    .then(r => r.text())
                    .then(data => this.dialog.content = data || 'No results.');
            },
            showRawWhois() {
                this.dialog.title = `Raw JSON: ${this.domain}`;
                this.dialog.content = 'Loading...';
                this.dialog.show = true;
                fetch(`?raw_domain=${encodeURIComponent(this.domain)}`)
                    .then(r => r.text())
                    .then(data => this.dialog.content = data || 'No results.');
            },
            openHistory() {
                this.loadHistory();
                this.showHistoryModal = true;
            },
            loadHistory() {
                fetch("?action=get_history").then(r => r.json()).then(data => this.historyItems = data);
            },
            getDomainVersions(domain) {
                fetch(`?action=get_domain_versions&domain=${domain}`).then(r => r.json()).then(data => this.domainVersions = data);
            },
            loadFromHistory(item) {
                fetch(`?action=get_history_item&id=${item.id}`)
                    .then(r => r.json())
                    .then(data => {
                        this.domain = item.domain;
                        this.response = data;
                        this.showHistoryModal = false;
                        this.showVersionsModal = false;
                        this.showToast(`Loaded ${item.domain} (${this.formatDate(data.timestamp)})`);
                        this.getDomainVersions(item.domain);
                        this.$nextTick(() => Prism.highlightAll());
                    });
            },
            removeHistoryItem(item, index) {
                const fd = new FormData();
                fd.append('id', item.id);
                fetch('?action=delete_history', { method: 'POST', body: fd })
                    .then(r => r.json())
                    .then(data => {
                        if (data.success) {
                            this.domainVersions.splice(index, 1);
                            this.loadHistory();
                            if (this.response.timestamp === item.timestamp) this.response = { domain: "", errors: [], zone: "", timestamp: null };
                        }
                    });
            },
            formatDate(ts) {
                return new Date(ts * 1000).toLocaleString();
            },
            formatDateShort(ts) {
                return new Date(ts * 1000).toLocaleDateString();
            },
            exportHistory() {
                window.location.href = '?action=export_history';
            },
            triggerImport() {
                this.$refs.importFile.click();
            },
            importHistory(e) {
                const file = e.target.files[0];
                if (!file) return;
                const fd = new FormData();
                fd.append('importFile', file);
                fd.append('action', 'import_history');
                fetch('', { method: 'POST', body: fd })
                    .then(r => r.json())
                    .then(data => {
                        if (data.success) {
                            this.showToast(`Imported ${data.count} items`);
                            this.loadHistory();
                        } else this.showToast('Import failed');
                    })
                    .catch(e => this.showToast('Error importing file'))
                    .finally(() => e.target.value = '');
            }
        },
        mounted() {
            this.applyTheme();
            this.loadHistory();
        }
    }).mount('#app');
</script>
</body>
</html>