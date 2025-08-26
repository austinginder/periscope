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

?><!DOCTYPE html>
<html>
<head>
    <title>Periscope</title>
    <link href="prism.css" rel="stylesheet" />
    <link href="https://fonts.googleapis.com/css?family=Roboto:100,300,400,500,700,900" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/@mdi/font@7.4.47/css/materialdesignicons.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/vuetify@v3.7.6/dist/vuetify.min.css" rel="stylesheet">
    <link rel="icon" href="Periscope.webp" />
    <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no, minimal-ui">
    <style>
        [v-cloak]>* {
            display: none;
        }

        .multiline {
            white-space: pre-wrap;
        }

        /* Base Toolbar (light mode default) */
        .top-toolbar {
            background: linear-gradient(90deg, #0E7490, #0A3D62);
            border: 1px solid rgba(255, 255, 255, 0.18);
            color: #ffffff;
            box-shadow: 0 2px 12px rgba(10, 61, 98, 0.25);
            border-radius: 2rem;
            padding: 0.75rem 1.5rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin: 1rem auto;
            max-width: 90%;
            position: relative;
            z-index: 1000;
            border: 1px solid #08263d;
        }

        .top-toolbar .v-toolbar-title,
        .top-toolbar a,
        .top-toolbar .v-icon,
        .top-toolbar .v-btn {
        color: #ffffff;
        }

        .top-toolbar a:hover {
        color: #E6F7FF;
        }

        /* 🌙 Dark Mode Styles */
        .v-theme--dark .top-toolbar {
            background: linear-gradient(90deg, #0B1E33, #09263F);
            border: 1px solid rgba(246, 236, 219, 0.25);
            color: #f6ecdb;
            box-shadow: 0 2px 12px rgba(0, 0, 0, 0.5);
        }

        .v-theme--dark .top-toolbar .v-toolbar-title,
        .v-theme--dark .top-toolbar a,
        .v-theme--dark .top-toolbar .v-icon,
        .v-theme--dark .top-toolbar .v-btn {
        color: #f6ecdb;
        }

        .v-theme--dark .top-toolbar a:hover {
        color: #ffffff;
        }

        /* --- Prism JS Theme Overrides for DNS Zone --- */
        pre[class*=language-] {
            margin: 0 !important;
        }
    </style>
</head>
<body>
    <div id="app" v-cloak>
        <v-app :theme="currentTheme">
            <v-main>
                <v-toolbar flat dense color="transparent" class="top-toolbar py-0 px-3">
                    <v-img src="Periscope.webp" max-height="50" max-width="50" contain class="ml-2"></v-img>
                    <v-toolbar-title>Periscope</v-toolbar-title>
                    <v-spacer></v-spacer>
                    <v-tooltip location="bottom" :text="historyItems.length > 0 ? `${historyItems.length} items in history` : 'No lookup history'">
                        <template v-slot:activator="{ props }">
                            <v-btn v-bind="props" icon @click="openHistory()" class="mr-2 position-relative">
                                <v-icon>mdi-history</v-icon>
                            </v-btn>
                        </template>
                    </v-tooltip>
                    <v-btn icon @click="toggleTheme()">
                        <v-icon>{{ currentTheme === 'dark' ? 'mdi-white-balance-sunny' : 'mdi-moon-waning-crescent' }}</v-icon>
                    </v-btn>
                </v-toolbar>
                <v-container class="mb-16 pb-16">
                    <v-text-field autofocus variant="outlined" color="primary" label="Domain" v-model="domain" spellcheck="false" @keydown.enter="lookupDomain()" class="mt-5 mx-auto">
                        <template v-slot:append-inner>
                            <v-btn variant="flat" color="primary" @click="lookupDomain()" :loading="loading">
                                Lookup
                                <template v-slot:loader><v-progress-circular :size="22" :width="2" :color="currentTheme === 'dark' ? 'black' : 'white'" indeterminate></v-progress-circular></template>
                            </v-btn>
                        </template>
                    </v-text-field>
                    <v-alert type="warning" v-for="error in response.errors" class="mb-3" v-html="error"></v-alert>

                    <v-row v-if="response.domain && response.domain != ''">
                        <v-col cols="12">
                            <v-btn v-if="otherVersions.length > 0" @click="showVersionsModal = true" color="primary" variant="tonal" class="mb-4">
                                <v-icon start>mdi-history</v-icon>
                                View History ({{ otherVersions.length }} older)
                            </v-btn>
                        </v-col>
                        <v-col md="5" cols="12">
                            <v-card variant="outlined" color="primary">
                                <v-btn size="small" @click="showRawWhois()" class="position-absolute right-0 mt-2 mr-4" variant="tonal">
                                    View raw
                                </v-btn>
                                <v-card-title>Domain</v-card-title>
                                <v-card-text>
                                    <v-table density="compact">
                                        <template v-slot:default>
                                            <thead>
                                                <tr>
                                                    <th class="text-left">Name</th>
                                                    <th class="text-left">Value</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                <tr v-for='record in response.domain'>
                                                    <td>{{ record.name }}</td>
                                                    <td @contextmenu="showContextMenu($event, record.value)">{{ record.value }}</td>
                                                </tr>
                                            </tbody>
                                        </template>
                                    </v-table>
                                </v-card-text>
                            </v-card>
                            <v-card class="mt-5" variant="outlined" color="primary">
                                <v-card-title>IP information</v-card-title>
                                <v-card-text>
                                    <template v-for='(rows, ip) in response.ip_lookup'>
                                        <div class="d-flex justify-space-between align-center mt-3 mb-2">
                                            <span>Details for {{ ip }}</span>
                                            <v-btn size="small" @click="runWhois(ip)" variant="tonal">
                                                View raw
                                            </v-btn>
                                        </div>
                                        <v-table density="compact">
                                            <template v-slot:default>
                                                <thead>
                                                    <tr>
                                                        <th class="text-left">Name</th>
                                                        <th class="text-left">Value</th>
                                                    </tr>
                                                </thead>
                                                <tbody>
                                                    <tr v-for='row in rows.split("\n")'>
                                                        <td>{{ row.split( ":" )[0] }}</td>
                                                        <td @contextmenu="showContextMenu($event, row.split( ':' )[1])">{{ row.split( ":" )[1] }}</td>
                                                    </tr>
                                                </tbody>
                                            </template>
                                        </v-table>
                                    </template>
                                </v-card-text>
                            </v-card>
                            <v-card class="mt-5" variant="outlined" color="primary">
                                <v-card-title>HTTP headers</v-card-title>
                                <v-card-text>
                                    <v-table density="compact">
                                        <template v-slot:default>
                                            <thead>
                                                <tr>
                                                    <th class="text-left" style="min-width: 200px;">Name</th>
                                                    <th class="text-left">Value</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                <tr v-for='(key, value) in response.http_headers'>
                                                    <td>{{ value }}</td>
                                                    <td @contextmenu="showContextMenu($event, key)">{{ key }}</td>
                                                </tr>
                                            </tbody>
                                        </template>
                                    </v-table>
                                </v-card-text>
                            </v-card>
                        </v-col>

                        <v-col md="7" cols="12">
                            <v-card variant="outlined" color="primary">
                                <v-card-title>Common DNS records</v-card-title>
                                <v-card-text>
                                    <v-table density="compact">
                                        <template v-slot:default>
                                            <thead>
                                                <tr>
                                                    <th class="text-left">Type</th>
                                                    <th class="text-left">Name</th>
                                                    <th class="text-left">Value</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                <tr v-for="record in response.dns_records">
                                                    <td>{{ record.type }}</td>
                                                    <td>{{ record.name }}</td>
                                                    <td class="multiline">
                                                        <template v-if="record.type !== 'mx'">
                                                            <span @contextmenu="showContextMenu($event, record.value)">{{ record.value }}</span>
                                                        </template>
                                                        <template v-else>
                                                            <div v-for="line in record.value.split('\n').filter(l => l.trim() !== '')" :key="line">
                                                                {{ line.split(' ')[0] }}&nbsp;<span @contextmenu="showContextMenu($event, line.split(' ')[1])" style="cursor: pointer;">{{ line.split(' ')[1] }}</span>
                                                            </div>
                                                        </template>
                                                    </td>
                                                </tr>
                                            </tbody>
                                        </template>
                                    </v-table>
                                </v-card-text>
                            </v-card>
                            <v-card class="mt-5" variant="flat">
                                <v-btn size="small" @click="copyZone()" class="position-absolute right-0 mt-6" style="margin-right: 140px;">
                                    <v-icon left>mdi-content-copy</v-icon>
                                </v-btn>
                                <v-btn size="small" @click="downloadZone()" class="position-absolute right-0 mt-6 mr-4">
                                    <v-icon left>mdi-download</v-icon>
                                    Download
                                </v-btn>
                                <pre class="language-dns-zone-file text-body-2" style="border-radius:4px;border:0px"><code class="language-dns-zone-file">{{ response.zone }}</code></pre>
                                <a ref="download_zone" href="#"></a>
                            </v-card>
                        </v-col>
                    </v-row>
                </v-container>
                <v-snackbar v-model="snackbar.show" timeout="2000">
                    {{ snackbar.message }}
                    <template v-slot:actions>
                        <v-btn variant="text" @click="snackbar.show = false">
                            Close
                        </v-btn>
                    </template>
                </v-snackbar>

                <v-menu v-model="contextMenu.show" :style="{ top: contextMenu.y + 'px', left: contextMenu.x + 'px', position: 'fixed', zIndex: 9999 }">
                    <v-list dense>
                        <v-list-item v-if="isDomain(contextMenu.value)" @click="runDig(contextMenu.value)">
                            <v-list-item-title>Dig {{ contextMenu.value }}</v-list-item-title>
                        </v-list-item>
                        <v-list-item v-if="isIp(contextMenu.value)" @click="runWhois(contextMenu.value)">
                            <v-list-item-title>Whois {{ contextMenu.value }}</v-list-item-title>
                        </v-list-item>
                    </v-list>
                </v-menu>

                <v-dialog v-model="dialog.show" max-width="1100">
                    <v-card>
                        <v-card-title class="d-flex align-center">
                            <span class="text-h5">{{ dialog.title }}</span>
                            <v-spacer></v-spacer>
                            <v-btn icon="mdi-close" variant="text" @click="dialog.show = false"></v-btn>
                        </v-card-title>
                        <v-card-text class="pt-4">
                            <pre class="language-json text-body-2" style="border-radius:4px;border:0px"><code>{{ dialog.content }}</code></pre>
                        </v-card-text>
                    </v-card>
                </v-dialog>

                <v-dialog v-model="showHistoryModal" max-width="600">
                    <v-card>
                        <v-card-title class="d-flex align-center">
                            <span class="text-h5">Recent Lookups</span>
                            <v-spacer></v-spacer>
                            <v-tooltip location="bottom" text="Export history to a JSON file">
                                <template v-slot:activator="{ props }">
                                    <v-btn v-bind="props" icon="mdi-export-variant" variant="text" @click="exportHistory" :disabled="historyItems.length === 0"></v-btn>
                                </template>
                            </v-tooltip>
                            <v-tooltip location="bottom" text="Import history from a JSON file">
                                <template v-slot:activator="{ props }">
                                    <v-btn v-bind="props" icon="mdi-import" variant="text" @click="triggerImport"></v-btn>
                                </template>
                            </v-tooltip>
                            <v-btn icon="mdi-close" variant="text" @click="showHistoryModal = false"></v-btn>
                        </v-card-title>
                        <v-card-text>
                            <input type="file" ref="importFile" @change="importHistory" accept=".json" style="display:none" />
                            <v-list v-if="historyItems.length > 0">
                                <v-list-item v-for="(item, index) in historyItems" :key="item.id" @click="loadFromHistory(item)">
                                    <v-list-item-title>{{ item.domain }}</v-list-item-title>
                                    <v-list-item-subtitle>{{ formatDate(item.timestamp) }}</v-list-item-subtitle>
                                </v-list-item>
                            </v-list>
                            <div v-else class="text-center py-8">
                                <v-icon size="64" class="mb-4">mdi-history</v-icon>
                                <p>No previous lookups found</p>
                            </div>
                        </v-card-text>
                    </v-card>
                </v-dialog>
                
                <v-dialog v-model="showVersionsModal" max-width="600">
                    <v-card>
                        <v-card-title class="d-flex align-center">
                            <span class="text-h5">History for {{ domain }}</span>
                            <v-spacer></v-spacer>
                            <v-btn icon="mdi-close" variant="text" @click="showVersionsModal = false"></v-btn>
                        </v-card-title>
                        <v-card-text>
                            <v-list>
                                <v-list-item v-for="(item, index) in domainVersions" :key="item.id" @click="loadFromHistory(item)" :active="item.timestamp === response.timestamp">
                                    <v-list-item-title>
                                        <v-icon v-if="item.timestamp === response.timestamp" class="mr-2">mdi-check-circle</v-icon>
                                        Lookup from {{ formatDate(item.timestamp) }}
                                        </v-list-item-title>
                                    <template v-slot:append>
                                        <v-btn icon variant="text" @click.stop="removeHistoryItem(item, index)">
                                            <v-icon>mdi-close</v-icon>
                                        </v-btn>
                                    </template>
                                </v-list-item>
                            </v-list>
                        </v-card-text>
                    </v-card>
                </v-dialog>

            </v-main>
        </v-app>
    </div>
    <script src="prism.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/vue@v3.5.19/dist/vue.global.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/vuetify@v3.9.5/dist/vuetify.min.js"></script>
    <script>
        const {
            createApp,
            computed
        } = Vue;
        const {
            createVuetify
        } = Vuetify;
        const vuetify = createVuetify({
            theme: {
                themes: {
                    light: {
                        dark: false,
                        colors: {
                            background: '#F8F9F9', // Sail White
                            primary: '#09263f', // New Primary Color
                            secondary: '#001F3F', // Deep Navy
                            error: '#FF4136', // Signal Red
                            info: '#F5DEB3' // Rope Beige
                        }
                    },
                    dark: {
                        dark: true,
                        colors: {
                            background: '#000000ff', // Deep Navy
                            primary: '#f6ecdb', // New
                            secondary: '#F5DEB3', // Rope Beige
                            error: '#FF4136', // Signal Red
                            info: '#F8F9F9' // Sail White
                        }
                    }
                }
            }
        });
        createApp({
            data() {
                return {
                    domain: "",
                    loading: false,
                    snackbar: {
                        show: false,
                        message: ""
                    },
                    response: {
                        domain: "",
                        errors: [],
                        zone: "",
                        timestamp: null
                    },
                    currentTheme: localStorage.getItem('theme') || 'light',
                    contextMenu: {
                        show: false,
                        x: 0,
                        y: 0,
                        value: ''
                    },
                    dialog: {
                        show: false,
                        title: '',
                        content: ''
                    },
                    showHistoryModal: false,
                    historyItems: [],
                    showVersionsModal: false,
                    domainVersions: []
                }
            },
            computed: {
                otherVersions() {
                    if (!this.response.timestamp) return [];
                    return this.domainVersions.filter(v => v.timestamp !== this.response.timestamp);
                }
            },
            methods: {
                lookupDomain() {
                    this.loading = true;
                    // Reset the response object to clear the old data
                    this.response = {
                        domain: "",
                        errors: [],
                        zone: "",
                        timestamp: null
                    };
                    this.domain = this.extractHostname(this.domain)
                    fetch("?domain=" + this.domain)
                        .then(response => response.json())
                        .then(data => {
                            this.loading = false
                            this.response = data
                            this.loadHistory() // Refresh main history list
                            this.getDomainVersions(this.domain); // Get all versions for this domain
                        })
                        .then(done => {
                            Prism.highlightAll()
                        })
                        .catch(error => {
                            this.loading = false;
                            this.response.errors.push("An error occurred while fetching data. Please try again.");
                            console.error("Fetch Error:", error);
                        });
                },
                extractHostname(url) {
                    var hostname;
                    if (url.indexOf("//") > -1) {
                        hostname = url.split('/')[2];
                    } else {
                        hostname = url.split('/')[0];
                    }
                    hostname = hostname.split(':')[0];
                    hostname = hostname.split('?')[0];
                    return hostname;
                },
                downloadZone() {
                    newBlob = new Blob([this.response.zone], {
                        type: "text/dns"
                    })
                    this.$refs.download_zone.download = `${this.domain}.zone`;
                    this.$refs.download_zone.href = window.URL.createObjectURL(newBlob);
                    this.$refs.download_zone.click();
                },
                copyZone() {
                    navigator.clipboard.writeText(this.response.zone)
                    this.snackbar.message = "Zone copied to clipboard"
                    this.snackbar.show = true
                },
                toggleTheme() {
                    this.currentTheme = this.currentTheme === 'light' ?
                        'dark' : 'light';
                    localStorage.setItem('theme', this.currentTheme);
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
                    const cleanedValue = typeof value === 'string' ?
                        value.trim() : '';
                    if (!this.isDomain(cleanedValue) && !this.isIp(cleanedValue)) {
                        return;
                    }
                    event.preventDefault();
                    this.contextMenu.show = false;
                    this.contextMenu.x = event.clientX;
                    this.contextMenu.y = event.clientY;
                    this.contextMenu.value = cleanedValue.split('\n')[0].trim();
                    this.$nextTick(() => {
                        this.contextMenu.show = true;
                    });
                },
                runDig(domain) {
                    this.dialog.title = `Dig results for: ${domain}`;
                    this.dialog.content = 'Loading...';
                    this.dialog.show = true;
                    fetch(`?dig=${encodeURIComponent(domain)}`)
                        .then(response => response.text())
                        .then(data => {
                            this.dialog.content = data.trim() === '' ? 'No results found.' : data;
                        });
                },
                runWhois(ip) {
                    this.dialog.title = `whois ${ip}`;
                    this.dialog.content = 'Loading...';
                    this.dialog.show = true;
                    fetch(`?whois=${encodeURIComponent(ip)}`)
                        .then(response => response.text())
                        .then(data => {
                            this.dialog.content = data.trim() === '' ? 'No results found.' : data;
                            Prism.highlightAll();
                        });
                },
                showRawWhois() {
                    this.dialog.title = `Raw response for: ${this.domain}`;
                    this.dialog.content = 'Loading...';
                    this.dialog.show = true;
                    fetch(`?raw_domain=${encodeURIComponent(this.domain)}`)
                        .then(response => response.text())
                        .then(data => {
                            this.dialog.content = data.trim() === '' ? 'No results found.' : data;
                        });
                },
                openHistory() {
                    this.loadHistory();
                    this.showHistoryModal = true;
                },
                loadHistory() {
                    fetch("?action=get_history")
                        .then(response => response.json())
                        .then(data => {
                            this.historyItems = data;
                        });
                },
                getDomainVersions(domain) {
                    fetch(`?action=get_domain_versions&domain=${domain}`)
                        .then(response => response.json())
                        .then(data => {
                            this.domainVersions = data;
                        });
                },
                loadFromHistory(item) {
                    fetch(`?action=get_history_item&id=${item.id}`)
                        .then(response => response.json())
                        .then(data => {
                            this.domain = item.domain;
                            this.response = data;
                            this.showHistoryModal = false;
                            this.showVersionsModal = false;
                            this.snackbar.message = `Loaded results for ${item.domain} from ${this.formatDate(data.timestamp)}`;
                            this.snackbar.show = true;
                            this.getDomainVersions(item.domain); // Refresh the versions list for the new context
                            this.$nextTick(() => {
                                Prism.highlightAll();
                            });
                        });
                },
                removeHistoryItem(item, index) {
                    const formData = new FormData();
                    formData.append('id', item.id);

                    fetch('?action=delete_history', {
                            method: 'POST',
                            body: formData
                        })
                        .then(response => response.json())
                        .then(data => {
                            if (data.success) {
                                this.domainVersions.splice(index, 1);
                                this.loadHistory(); // Reload main history in case the deleted item was the most recent
                                // If the currently viewed item is the one deleted, clear the view
                                if (this.response.timestamp === item.timestamp) {
                                    this.response.domain = ""; // Clear the main view
                                }
                            }
                        });
                },
                formatDate(timestamp) {
                    return new Date(timestamp * 1000).toLocaleString();
                },
                exportHistory() {
                    window.location.href = '?action=export_history';
                },
                triggerImport() {
                    this.$refs.importFile.click();
                },
                importHistory(event) {
                    const file = event.target.files[0];
                    if (!file) return;

                    const formData = new FormData();
                    formData.append('importFile', file);
                    formData.append('action', 'import_history');

                    fetch('', {
                            method: 'POST',
                            body: formData
                        })
                        .then(response => response.json())
                        .then(data => {
                            if (data.success) {
                                this.snackbar.message = `Successfully imported ${data.count} items.`;
                                this.loadHistory();
                            } else {
                                throw new Error(data.message || "Unknown error");
                            }
                            this.snackbar.show = true;
                        })
                        .catch(error => {
                            this.snackbar.message = "Failed to import history: " + error.message;
                            this.snackbar.show = true;
                        })
                        .finally(() => {
                            event.target.value = '';
                        });
                }
            },
            mounted() {
                document.documentElement.setAttribute('data-theme', this.currentTheme);
                this.loadHistory();
            }
        }).use(vuetify).mount('#app');
    </script>
</body>
</html>