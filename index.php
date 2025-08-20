<?php

require_once 'vendor/autoload.php';
use Badcow\DNS\Classes;
use Badcow\DNS\Zone;
use Badcow\DNS\Rdata\Factory;
use Badcow\DNS\ResourceRecord;
use Badcow\DNS\AlignedBuilder;
error_reporting(E_ALL & ~E_DEPRECATED);

function specialTxtFormatter(Badcow\DNS\Rdata\TXT $rdata, int $padding): string {
    //If the text length is less than or equal to 50 characters, just return it unaltered.
    if (strlen($rdata->getText()) <= 500) {
        return sprintf('"%s"', addcslashes($rdata->getText(), '"\\'));
    }

    $returnVal = "(\n";
    $chunks = str_split($rdata->getText(), 500);
    foreach ($chunks as $chunk) {
        $returnVal .= str_repeat(' ', $padding).
            sprintf('"%s"', addcslashes($chunk, '"\\')).
            "\n";
    }
    $returnVal .= str_repeat(' ', $padding) . ")";

    return $returnVal;
}

function run() {

    // Handle context menu lookups
    if ( isset( $_REQUEST['dig'] ) ) {
        header('Content-Type: text/plain');
        $domain_to_dig = trim( $_REQUEST['dig'], ".'\"" ); // Sanitize a bit
        if (filter_var($domain_to_dig, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
            $escaped_domain = escapeshellarg($domain_to_dig);
            echo shell_exec("dig $escaped_domain +short");
        } else {
            echo "Invalid domain provided.";
        }
        die();
    }

    if ( isset( $_REQUEST['whois'] ) ) {
        header('Content-Type: text/plain');
        $ip_to_check = trim( $_REQUEST['whois'] );
        if (filter_var($ip_to_check, FILTER_VALIDATE_IP)) {
            $escaped_ip = escapeshellarg($ip_to_check);
            echo shell_exec("whois $escaped_ip");
        } else {
            echo "Invalid IP address provided.";
        }
        die();
    }


    if ( ! isset( $_REQUEST['domain'] ) ) {
        return;
    }

    $domain        = $_REQUEST['domain'];
    $errors        = [];
    $ip_lookup     = [];
    $dns_records   = [];
    $required_bins = [ "whois", "dig", "host" ];

    foreach ($required_bins as $bin) {
        $output     = null;
        $return_var = null;
        exec( "command -v $bin", $output, $return_var );
        if ($return_var != 0) {
            $errors[] = "Required command \"$bin\" is not installed.";
        }
    }

    if ( ! filter_var( $domain, FILTER_VALIDATE_DOMAIN ) ) {
        $errors[] = "Invalid domain.";
    }
    
    if ( filter_var( $domain, FILTER_VALIDATE_DOMAIN ) && strpos( $domain, '.') === false ) {
        $errors[] = "Invalid domain.";
    }

    if (strlen($domain) < 4) {
        $errors[] = "No domain name is that short.";
    }

    if (strlen($domain) > 80) {
        $errors[] = "Too long.";
    }

    if ( count( $errors ) > 0 ) {
        echo json_encode( [
            "errors" => $errors,
        ] );
        die();
    }

    $zone = new Zone( $domain ."." );
    $zone->setDefaultTtl(3600);

    $bash_ip_lookup = <<<EOT
for ip in $( dig $domain +short ); do
    echo "Details on \$ip"
    whois \$ip | grep -E 'NetName:|Organization:|OrgName:'
done
EOT;

    $whois = shell_exec( "whois $domain | grep -E 'Name Server|Registrar:|Domain Name:|Updated Date:|Creation Date:|Registrar IANA ID:Domain Status:|Reseller:'" );
    $whois = empty( $whois ) ? "" : trim( $whois );

    if ( empty( $whois ) ) {
        $errors[] = "Domain not found.";
        echo json_encode( [
            "errors" => $errors,
        ] );
        die();
    }

    $whois = explode( "\n", $whois );
    foreach( $whois as $key => $record ) {
        $split  = explode( ":", trim( $record ) );
        $name   = trim( $split[0] );
        $value  = trim( $split[1] );
        if ( $name == "Name Server" || $name == "Domain Name"  ) {
            $value = strtolower( $value );
        }
        $whois[ $key ] = [ "name" => $name, "value" => $value ];
    }
    $whois     = array_map("unserialize", array_unique(array_map("serialize", $whois)));
    $col_name  = array_column($whois, 'name');
    $col_value = array_column($whois, 'value');
    array_multisort($col_name, SORT_ASC, $col_value, SORT_ASC, $whois);
    $ips      = explode( "\n", trim( shell_exec( "dig $domain +short" ) ) );
    foreach ( $ips as $ip ) {
        if ( empty( $ip ) ) {
            continue;
        }
        $response           = shell_exec( "whois $ip | grep -E 'NetName:|Organization:|OrgName:'" );
        $response           = empty( $response ) ? "" : trim( $response );
        $ip_lookup[ "$ip" ] = $response;
    }

    $wildcard_cname   = "";
    $wildcard_a       = "";
    $records_to_check = [
        [ "a"     => "" ],
        [ "a"     => "*" ],
        [ "a"     => "mail" ],
        [ "a"     => "remote" ],
        [ "a"     => "www" ],
        [ "a"     => "blog" ],
        [ "a"     => "shop" ],
        [ "a"     => "portal" ],
        [ "a"     => "api" ],
        [ "a"     => "dev" ],
        [ "cname" => "*" ],
        [ "cname" => "www" ],
        [ "cname" => "blog" ],
        [ "cname" => "shop" ],
        [ "cname" => "portal" ],
        [ "cname" => "api" ],
        [ "cname" => "dev" ],
        [ "cname" => "autodiscover" ],
        [ "cname" => "sip" ],
        [ "cname" => "lyncdiscover" ],
        [ "cname" => "enterpriseregistration" ],
        [ "cname" => "enterpriseenrollment" ],
        [ "cname" => "email.mg" ],
        [ "cname" => "msoid" ],
        [ "cname" => "_acme-challenge" ],
        [ "cname" => "k1._domainkey" ],
        [ "cname" => "k2._domainkey" ],
        [ "cname" => "k3._domainkey" ],
        [ "cname" => "s1._domainkey" ],
        [ "cname" => "s2._domainkey" ],
        [ "cname" => "selector1._domainkey" ],
        [ "cname" => "selector2._domainkey" ],
        [ "cname" => "ctct1._domainkey" ],
        [ "cname" => "ctct2._domainkey" ],
        [ "cname" => "mail" ],
        [ "cname" => "ftp" ],
        [ "mx"    => "" ],
        [ "mx"    => "mg" ],
        [ "txt"   => "" ],
        [ "txt"   => "_dmarc" ],
        [ "txt"   => "_amazonses" ],
        [ "txt"   => "_acme-challenge" ],
        [ "txt"   => "_acme-challenge.www" ],
        [ "txt"   => " _mailchannels" ],
        [ "txt"   => "default._domainkey" ],
        [ "txt"   => "google._domainkey" ],
        [ "txt"   => "mg" ],
        [ "txt"   => "smtp._domainkey.mg" ],
        [ "txt"   => "k1._domainkey" ],
        [ "txt"   => "default._bimi" ],
        [ "srv"   => "_sip._tls" ],
        [ "srv"   => "_sipfederationtls._tcp" ],
        [ "srv"   => "_autodiscover._tcp" ],
        [ "srv"   => "_submissions._tcp" ],
        [ "srv"   => "_imaps._tcp" ],
        [ "ns"    => "" ],
        [ "soa"   => "" ],
    ];

    foreach( $records_to_check as $record ) {
        $pre  = "";
        $type = key( $record );
        $name = $record[ $type ];
        if ( ! empty( $name ) ) {
            $pre = "{$name}.";
        }
        $value = shell_exec( "(host -t $type $pre$domain | grep -q 'is an alias for') && echo \"\" || dig $pre$domain $type +short | sort -n" );
        if ( $type == "cname" ) {
            $value = shell_exec( "host -t $type $pre$domain | grep 'alias for' | awk '{print \$NF}'" );
        }
        $value = empty( $value ) ? "" : trim( $value );
        if ( empty( $value ) ) {
            continue;
        }
        if ( $type == "soa" ) {
            $record_value = explode( " ", $value );
            $setName = empty( $name ) ? "@" : $name;
            $record  = new ResourceRecord;
            $record->setName( $setName );
            $record->setRdata(Factory::Soa($record_value[0],$record_value[1],$record_value[2],$record_value[3],$record_value[4],$record_value[5],$record_value[6]));
            $zone->addResourceRecord($record);
            continue;
        }
        if ( $type == "ns" ) {
            $record_values = explode( "\n", $value );
            foreach( $record_values as  $record_value ) {
                $setName = empty( $name ) ? "@" : $name;
                $record  = new ResourceRecord;
                $record->setName( $setName );
                $record->setRdata(Factory::Ns($record_value));
                $zone->addResourceRecord($record);
            }
        }
        // Verify A record is not a CNAME record
        if(  $type == "a" && preg_match("/[a-z]/i", $value)){
            $type  = "cname";
            $value = shell_exec( "dig $pre$domain $type +short | sort -n" );
            $value = empty( $value ) ? "" : trim( $value );
            if ( empty( $value ) ) {
                continue;
            }
        }
        if ( $type == "a" ) {
            if ( ! empty( $wildcard_a ) && $wildcard_a == $record_values ) {
                continue;
            }
            if ( $name == "*" ) {
                $wildcard_a = $record_values;
            }
            $record_values = explode( "\n", $value );
            $setName       = empty( $name ) ? "@" : $name;
            foreach( $record_values as $record_value ) {
                $record    = new ResourceRecord;
                $record->setName( $setName );
                $record->setRdata(Factory::A( $record_value ));
                $zone->addResourceRecord($record);
            }
        }
        if ( $type == "cname" ) {
            if ( $name == "*" ) {
                $wildcard_cname = $value;
                continue;
            }
            if ( ! empty( $wildcard_cname ) && $wildcard_cname == $value ) {
                continue;
            }
            $setName = empty( $name ) ? $domain : $name;
            $record  = new ResourceRecord;
            $record->setName( $setName );
            $record->setRdata(Factory::Cname($value));
            $zone->addResourceRecord($record);
        }
        if ( $type == "srv" ) {
            $record_values = explode( " ", $value );
            if ( count ( $record_values ) != "4" ) {
                continue;
            }
            $setName = empty( $name ) ? "@" : $name;
            $record  = new ResourceRecord;
            $record->setName( $setName );
            $record->setRdata(Factory::Srv($record_values[0], $record_values[1], $record_values[2], $record_values[3]));
            $zone->addResourceRecord($record);
        }
        if ( $type == "mx" ) {
            $setName       = empty( $name ) ? "@" : $name;
            $record_values = explode( "\n", $value );
            usort($record_values, function ($a, $b) {
                $a_value = explode( " ", $a );
                $b_value = explode( " ", $b );
                return (int) $a_value[0] - (int) $b_value[0];
            });
            foreach( $record_values as $record_value ) {
                $record_value = explode( " ", $record_value );
                if ( count( $record_value ) != "2" ) {
                    continue;
                }
                $mx_priority  = $record_value[0];
                $mx_value     = $record_value[1];
                $record       = new ResourceRecord;
                $record->setName( $setName );
                $record->setRdata(Factory::Mx($mx_priority, $mx_value));
                $zone->addResourceRecord($record);
            }
        }
        if ( $type == "txt" ) {
            $record_values = explode( "\n", $value );
            $setName       = empty( $name ) ? "@" : "$name";
            foreach( $record_values as $record_value ) {
                $record = new ResourceRecord;
                $record->setName( $setName );
                $record->setClass('IN');
                $record->setRdata(Factory::Txt(trim($record_value,'"'), 0, 200));
                $zone->addResourceRecord($record);
            }
        }
        $dns_records[] = [ "type" => $type, "name" => $name, "value" => $value ];
    }

    $response = shell_exec( "curl -sLI $domain | awk 'BEGIN{RS=\"\\r\\n\\r\\n\"}; END{print}'" );
    $lines    = explode("\n", trim( $response ) );
    $http_headers = [];
    foreach ($lines as $line) {
        // Trim whitespace from each line
        $line = trim($line);
        // Match key-value pairs (lines with a colon)
        if (preg_match('/^([^:]+):\s*(.*)$/', $line, $matches)) {
            $key = strtolower($matches[1]); // Use lowercase keys for consistency
            $value = $matches[2];
            // Handle duplicate keys (e.g., "vary" appears twice)
            if (isset($http_headers[$key])) {
                if (is_array($http_headers[$key])) {
                    $http_headers[$key][] = $value;
                } else {
                    $http_headers[$key] = [$http_headers[$key], $value];
                }
            } else {
                $http_headers[$key] = $value;
            }
        }
    }

  $builder = new AlignedBuilder();
  $builder->addRdataFormatter('TXT', 'specialTxtFormatter');

  echo json_encode( [
    "whois"        => $whois,
    "http_headers" => $http_headers,
    "dns_records"  => $dns_records,
    "ip_lookup"    => $ip_lookup,
    "errors"       => [],
    "zone"         => $builder->build($zone)
  ] );
  die();
}

run();

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
    [v-cloak] > * {
        display:none;
    }
    .multiline {
        white-space: pre-wrap;
    }
    /* Base Toolbar (light mode default) */
    .top-toolbar {
        background: linear-gradient(to bottom right, #fff, #fff);
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

    .top-toolbar a {
        color: #004d73;
        text-decoration: none;
        margin: 0 0.75rem;
        font-weight: 600;
        transition: color 0.2s;
    }

    .top-toolbar a:hover {
        color: #0077be;
    }

    /* 🌙 Dark Mode Styles */
    .v-theme--dark .top-toolbar {
        background: linear-gradient(to bottom right, #000, #000);
        border: 1px solid #f6ecdb;
    }

    .v-theme--dark .top-toolbar a {
        color: #b3e5fc; /* Lighter, soft blue text */
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
            <v-btn icon @click="toggleTheme()">
                <v-icon>{{ currentTheme === 'dark' ? 'mdi-white-balance-sunny' : 'mdi-moon-waning-crescent' }}</v-icon>
            </v-btn>
        </v-toolbar>
        <v-container class="mb-16 pb-16">
            <v-text-field autofocus variant="outlined" color="primary" label="Domain" v-model="domain" spellcheck="false" @keydown.enter="lookupDomain()" class="mt-5 mx-auto">
            <template v-slot:append-inner>
                <v-btn variant="flat" color="primary" @click="lookupDomain()" :loading="loading">
                    Lookup
                    <template v-slot:loader><v-progress-circular :size="22" :width="2" color="white" indeterminate></v-progress-circular></template>
                </v-btn>
            </template>
            </v-text-field>
            <v-alert type="warning" v-for="error in response.errors" class="mb-3" v-html="error"></v-alert>
            <v-row v-if="response.whois && response.whois != ''">
            <v-col md="5" cols="12">
                <v-card variant="outlined" color="primary">
                    <v-card-title>Whois</v-card-title>
                    <v-card-text>
                    <v-table density="compact">
                    <template v-slot:default>
                    <thead>
                        <tr>
                        <th class="text-left">
                            Name
                        </th>
                        <th class="text-left">
                            Value
                        </th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr v-for='record in response.whois'>
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
                        <div class="mt-3">Details for {{ ip }}</div>
                        <v-table density="compact">
                        <template v-slot:default>
                        <thead>
                            <tr>
                            <th class="text-left">
                                Name
                            </th>
                            <th class="text-left">
                                Value
                            </th>
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
                            <th class="text-left" style="min-width: 200px;">
                                Name
                            </th>
                            <th class="text-left">
                                Value
                            </th>
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
                        <th class="text-left">
                            Type
                        </th>
                        <th class="text-left">
                            Name
                        </th>
                        <th class="text-left">
                            Value
                        </th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr v-for="record in response.dns_records">
                            <td>{{ record.type }}</td>
                            <td>{{ record.name }}</td>
                            <td class="multiline" @contextmenu="showContextMenu($event, record.value)">{{ record.value }}</td>
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

        <v-dialog v-model="dialog.show" max-width="800">
            <v-card>
                <v-card-title>{{ dialog.title }}</v-card-title>
                <v-card-text>
                    <pre>{{ dialog.content }}</pre>
                </v-card-text>
                <v-card-actions>
                    <v-spacer></v-spacer>
                    <v-btn color="primary" text @click="dialog.show = false">Close</v-btn>
                </v-card-actions>
            </v-card>
        </v-dialog>
      </v-main>
    </v-app>
  </div>
  <script src="prism.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/vue@3.4.30/dist/vue.global.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/vuetify@v3.6.10/dist/vuetify.min.js"></script>
  <script>
    const { createApp } = Vue;
    const { createVuetify } = Vuetify;
    const vuetify = createVuetify({
        theme: {
            themes: {
                light: {
                    dark: false,
                    colors: {
                        background: '#F8F9F9', // Sail White
                        primary: '#09263f',    // New Primary Color
                        secondary: '#001F3F', // Deep Navy
                        error: '#FF4136',      // Signal Red
                        info: '#F5DEB3'        // Rope Beige
                    }
                },
                dark: {
                    dark: true,
                    colors: {
                        background: '#000000ff', // Deep Navy
                        primary: '#f6ecdb',    // New Primary Color
                        secondary: '#F5DEB3', // Rope Beige
                        error: '#FF4136',      // Signal Red
                        info: '#F8F9F9'        // Sail White
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
                snackbar: { show: false, message: "" },
                response: { whois: "", errors: [], zone: "" },
                currentTheme: localStorage.getItem('theme') || 'light',
                contextMenu: { show: false, x: 0, y: 0, value: '' },
                dialog: { show: false, title: '', content: '' }
            }
        },
        methods: {
            lookupDomain() {
                this.loading = true
                this.domain = this.extractHostname( this.domain )
                fetch( "?domain=" + this.domain )
                    .then( response => response.json() )
                    .then( data => {
                        this.loading = false
                        this.response = data
                    })
                    .then( done => {
                        Prism.highlightAll()
                    })
            },
            extractHostname( url ) {
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
                newBlob = new Blob([this.response.zone], {type: "text/dns"})
                this.$refs.download_zone.download = `${this.domain}.zone`;
                this.$refs.download_zone.href = window.URL.createObjectURL(newBlob);
                this.$refs.download_zone.click();
            },
            copyZone() {
                navigator.clipboard.writeText( this.response.zone )
                this.snackbar.message = "Zone copied to clipboard"
                this.snackbar.show = true
            },
            toggleTheme() {
                this.currentTheme = this.currentTheme === 'light' ? 'dark' : 'light';
                localStorage.setItem('theme', this.currentTheme);
            },
            isDomain(str) {
                if (typeof str !== 'string' || str.trim() === '') return false;
                // A simple check: contains a dot, no spaces, and is not an IP address. Allows for an optional trailing dot.
                const cleanedStr = str.trim().split('\n')[0].trim(); // Check the first line
                const domainRegex = /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\.?$/;
                return domainRegex.test(cleanedStr) && !this.isIp(cleanedStr);
            },
            isIp(str) {
                if (typeof str !== 'string' || str.trim() === '') return false;
                const cleanedStr = str.trim().split('\n')[0].trim(); // Check the first line
                const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
                return ipRegex.test(cleanedStr);
            },
            showContextMenu(event, value) {
                const cleanedValue = typeof value === 'string' ? value.trim() : '';
                if (!this.isDomain(cleanedValue) && !this.isIp(cleanedValue)) {
                    return; // Don't show menu if not a valid domain or IP
                }
                event.preventDefault();
                this.contextMenu.show = false;
                this.contextMenu.x = event.clientX;
                this.contextMenu.y = event.clientY;
                this.contextMenu.value = cleanedValue.split('\n')[0].trim(); // Use the first line for the action
                this.$nextTick(() => {
                    this.contextMenu.show = true;
                });
            },
            runDig(domain) {
                this.dialog.title = `dig ${domain} +short`;
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
                    });
            }
        },
        mounted() {
            // Apply saved theme on page load
            document.documentElement.setAttribute('data-theme', this.currentTheme);
        }
    }).use(vuetify).mount('#app');
  </script>
</body>
</html>