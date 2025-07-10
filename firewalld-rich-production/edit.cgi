#!/usr/bin/perl
# Edit or create a firewalld rich rule

require './firewalld-rich-lib.pl';

# Check if firewalld is installed and running
if (!check_firewalld_installed() || !is_firewalld_running() || !rich_rules_supported()) {
    &error($text{'edit_einstall'});
}

&ReadParse();

# Determine if this is a new rule or editing existing
my $new = $in{'new'};
my $zone = $in{'zone'} || get_default_zone();
my $idx = $in{'idx'};

my $rule_text = '';
my $parsed = {};

if (!$new && defined($idx)) {
    # Editing existing rule
    my @rules = list_rich_rules($zone);
    if ($idx >= 0 && $idx < @rules) {
        $rule_text = $rules[$idx]->{'text'};
        $parsed = $rules[$idx]->{'parsed'};
    } else {
        &error($text{'edit_erule'});
    }
}

# Set default values
$parsed->{'family'} ||= 'ipv4';
$parsed->{'action'} ||= 'accept';
$parsed->{'log_level'} ||= 'info';
$parsed->{'protocol'} ||= 'tcp';

# Page header
&ui_print_header(undef, $new ? $text{'edit_title1'} : $text{'edit_title2'}, "", undef, 1, 1);

# Start main form
print &ui_form_start("save.cgi", "post");
print &ui_hidden("new", $new);
print &ui_hidden("zone", $zone);
print &ui_hidden("idx", $idx) if (!$new);

# Main configuration table
print &ui_table_start($text{'edit_header'}, "width=100%", 2);

# Zone selection
my @zones = list_firewalld_zones();
my @zone_opts = map { [$_, $_] } @zones;
print &ui_table_row($text{'edit_zone'}, 
    &ui_select("zone", $zone, \@zone_opts, 1, 0, 0, 0, "onchange='updateZone()'"));

# IP Family
my @family_opts = (
    ['ipv4', $text{'edit_family_ipv4'}],
    ['ipv6', $text{'edit_family_ipv6'}],
    ['both', $text{'edit_family_both'}]
);
print &ui_table_row($text{'edit_family'}, 
    &ui_radio_table("family", $parsed->{'family'}, \@family_opts));

print &ui_table_end();

# Rule Type Selection
print "<h3>" . $text{'edit_rule_type'} . "</h3>\n";

my $rule_type = 'source';
if ($parsed->{'service_name'}) {
    $rule_type = 'service';
} elsif ($parsed->{'port'}) {
    $rule_type = 'port';
} elsif ($parsed->{'protocol_value'}) {
    $rule_type = 'protocol';
}

my @type_opts = (
    ['source', $text{'edit_rule_source'}],
    ['service', $text{'edit_rule_service'}],
    ['port', $text{'edit_rule_port'}],
    ['protocol', $text{'edit_rule_protocol'}]
);
print &ui_radio_table("rule_type", $rule_type, \@type_opts, 1, 0, "onchange='updateRuleType()'");

# Source Configuration
print "<div id='source_config'>\n";
print "<h3>" . $text{'edit_source'} . "</h3>\n";
print &ui_table_start("", "width=100%", 2);

my $source_type = 'address';
if ($parsed->{'source_mac'}) {
    $source_type = 'mac';
} elsif ($parsed->{'source_interface'}) {
    $source_type = 'interface';
} elsif ($parsed->{'source_ipset'}) {
    $source_type = 'ipset';
}

my @source_opts = (
    ['address', $text{'edit_source_address'}],
    ['mac', $text{'edit_source_mac'}],
    ['interface', $text{'edit_source_interface'}],
    ['ipset', $text{'edit_source_ipset'}]
);
print &ui_table_row($text{'edit_source_type'}, 
    &ui_radio_table("source_type", $source_type, \@source_opts, 1, 0, "onchange='updateSourceType()'"));

print &ui_table_row($text{'edit_source_address'}, 
    &ui_textbox("source_address", $parsed->{'source_address'} || '', 30) . 
    " <small>e.g. 192.168.1.0/24, 10.0.0.1</small>", 
    undef, "id='source_address_row'");

print &ui_table_row($text{'edit_source_mac'}, 
    &ui_textbox("source_mac", $parsed->{'source_mac'} || '', 20) . 
    " <small>e.g. 00:11:22:33:44:55</small>", 
    undef, "id='source_mac_row'");

print &ui_table_row($text{'edit_source_interface'}, 
    &ui_textbox("source_interface", $parsed->{'source_interface'} || '', 20) . 
    " <small>e.g. eth0, wlan0</small>", 
    undef, "id='source_interface_row'");

print &ui_table_row($text{'edit_source_ipset'}, 
    &ui_textbox("source_ipset", $parsed->{'source_ipset'} || '', 20) . 
    " <small>IP set name</small>", 
    undef, "id='source_ipset_row'");

print &ui_table_end();
print "</div>\n";

# Destination Configuration
print "<div id='destination_config'>\n";
print "<h3>" . $text{'edit_destination'} . "</h3>\n";
print &ui_table_start("", "width=100%", 2);

print &ui_table_row($text{'edit_destination_address'}, 
    &ui_textbox("destination_address", $parsed->{'destination_address'} || '', 30) . 
    " <small>e.g. 192.168.1.100, 10.0.0.0/8</small>");

print &ui_table_row($text{'edit_destination_interface'}, 
    &ui_textbox("destination_interface", $parsed->{'destination_interface'} || '', 20) . 
    " <small>e.g. eth1, tun0</small>");

print &ui_table_end();
print "</div>\n";

# Service Configuration
print "<div id='service_config'>\n";
print "<h3>" . $text{'edit_service'} . "</h3>\n";
print &ui_table_start("", "width=100%", 2);

# Get available services for autocomplete
my @services = get_firewalld_services();
my @service_opts = map { [$_, $_] } @services;
print &ui_table_row($text{'edit_service_name'}, 
    &ui_select("service_name", $parsed->{'service_name'} || '', \@service_opts, 1, 1) . 
    " <small>Select or type service name</small>");

print &ui_table_end();
print "</div>\n";

# Port Configuration
print "<div id='port_config'>\n";
print "<h3>" . $text{'edit_port'} . "</h3>\n";
print &ui_table_start("", "width=100%", 2);

my $port_mode = 'single';
if ($parsed->{'port'} && $parsed->{'port'} =~ /-/) {
    $port_mode = 'range';
}

my ($port_single, $port_from, $port_to) = ('', '', '');
if ($parsed->{'port'}) {
    if ($port_mode eq 'range') {
        ($port_from, $port_to) = split(/-/, $parsed->{'port'}, 2);
    } else {
        $port_single = $parsed->{'port'};
    }
}

my @port_opts = (
    ['single', $text{'edit_port_single'}, &ui_textbox("port_single", $port_single, 8)],
    ['range', $text{'edit_port_range'}, 
     $text{'edit_port_from'} . " " . &ui_textbox("port_from", $port_from, 8) . " " . 
     $text{'edit_port_to'} . " " . &ui_textbox("port_to", $port_to, 8)]
);
print &ui_table_row($text{'edit_port'}, 
    &ui_radio_table("port_mode", $port_mode, \@port_opts));

my @protocol_opts = (
    ['tcp', $text{'edit_protocol_tcp'}],
    ['udp', $text{'edit_protocol_udp'}],
    ['sctp', $text{'edit_protocol_sctp'}],
    ['dccp', $text{'edit_protocol_dccp'}]
);
print &ui_table_row($text{'edit_protocol'}, 
    &ui_radio_table("protocol", $parsed->{'protocol'}, \@protocol_opts));

print &ui_table_end();
print "</div>\n";

# Protocol Configuration
print "<div id='protocol_config'>\n";
print "<h3>" . $text{'edit_protocol'} . "</h3>\n";
print &ui_table_start("", "width=100%", 2);

print &ui_table_row($text{'edit_protocol'}, 
    &ui_textbox("protocol_value", $parsed->{'protocol_value'} || '', 10) . 
    " <small>Protocol number (e.g. 47 for GRE)</small>");

print &ui_table_end();
print "</div>\n";

# Action Configuration
print "<h3>" . $text{'edit_action'} . "</h3>\n";
print &ui_table_start("", "width=100%", 2);

my @action_opts = (
    ['accept', $text{'edit_action_accept'}],
    ['reject', $text{'edit_action_reject'}],
    ['drop', $text{'edit_action_drop'}]
);
print &ui_table_row($text{'edit_action'}, 
    &ui_radio_table("action", $parsed->{'action'}, \@action_opts, 1, 0, "onchange='updateAction()'"));

# Reject type (only shown for reject action)
my @reject_opts = (
    ['', $text{'edit_reject_icmp'}],
    ['icmp6-adm-prohibited', $text{'edit_reject_icmp6'}],
    ['tcp-reset', $text{'edit_reject_tcp'}]
);
print &ui_table_row($text{'edit_reject_type'}, 
    &ui_select("reject_type", $parsed->{'reject_type'} || '', \@reject_opts, 1, 0, 0, 0, ""),
    undef, "id='reject_type_row'");

print &ui_table_end();

# Logging Configuration
print "<h3>" . $text{'edit_logging'} . "</h3>\n";
print &ui_table_start("", "width=100%", 2);

print &ui_table_row($text{'edit_log_enable'}, 
    &ui_checkbox("log_enable", 1, "", $parsed->{'log'} || 0, "onchange='updateLogging()'"));

print &ui_table_row($text{'edit_log_prefix'}, 
    &ui_textbox("log_prefix", $parsed->{'log_prefix'} || '', 30), 
    undef, "id='log_prefix_row'");

my @log_levels = qw(emerg alert crit err warn notice info debug);
my @log_level_opts = map { [$_, $text{'edit_log_level_' . $_}] } @log_levels;
print &ui_table_row($text{'edit_log_level'}, 
    &ui_select("log_level", $parsed->{'log_level'} || 'info', \@log_level_opts, 1, 0), 
    undef, "id='log_level_row'");

print &ui_table_row($text{'edit_log_limit'}, 
    &ui_textbox("log_limit_rate", $parsed->{'log_limit'} ? (split(/\//, $parsed->{'log_limit'}))[0] : '', 8) . 
    " " . $text{'edit_log_limit_per'} . " " . 
    &ui_select("log_limit_unit", $parsed->{'log_limit'} ? (split(/\//, $parsed->{'log_limit'}))[1] : 'minute', 
               [['second', $text{'edit_log_limit_second'}], ['minute', $text{'edit_log_limit_minute'}], 
                ['hour', $text{'edit_log_limit_hour'}], ['day', $text{'edit_log_limit_day'}]], 1, 0), 
    undef, "id='log_limit_row'");

print &ui_table_end();

# Advanced Options
print "<h3>" . $text{'edit_advanced'} . "</h3>\n";
print &ui_table_start("", "width=100%", 2);

print &ui_table_row($text{'edit_audit'}, 
    &ui_checkbox("audit", 1, "", $parsed->{'audit'} || 0));

print &ui_table_row($text{'edit_masquerade'}, 
    &ui_checkbox("masquerade", 1, "", $parsed->{'masquerade'} || 0));

print &ui_table_end();

# Port Forwarding
print "<h3>" . $text{'edit_forward'} . "</h3>\n";
print &ui_table_start("", "width=100%", 2);

print &ui_table_row($text{'edit_forward_enable'}, 
    &ui_checkbox("forward_enable", 1, "", ($parsed->{'forward_port'} ? 1 : 0), "onchange='updateForwarding()'"));

print &ui_table_row($text{'edit_forward_to_port'}, 
    &ui_textbox("forward_to_port", $parsed->{'forward_to_port'} || '', 8), 
    undef, "id='forward_to_port_row'");

print &ui_table_row($text{'edit_forward_to_addr'}, 
    &ui_textbox("forward_to_addr", $parsed->{'forward_to_addr'} || '', 20), 
    undef, "id='forward_to_addr_row'");

print &ui_table_end();

# Rule Preview
print "<h3>" . $text{'edit_preview'} . "</h3>\n";
print "<div id='rule_preview' style='border: 1px solid #ccc; padding: 10px; background-color: #f9f9f9; font-family: monospace;'>\n";
print $text{'edit_preview_text'} . " <span id='preview_text'>" . &html_escape($rule_text) . "</span>\n";
print "</div>\n";

# Form buttons
print &ui_form_end([
    [ "save", $text{'save'} ],
    [ "cancel", $text{'cancel'} ]
]);

# JavaScript for dynamic form behavior
print <<'EOF';
<script type="text/javascript">
function updateRuleType() {
    var type = getRadioValue('rule_type');
    var configs = ['source_config', 'service_config', 'port_config', 'protocol_config'];
    
    for (var i = 0; i < configs.length; i++) {
        var elem = document.getElementById(configs[i]);
        if (elem) elem.style.display = 'none';
    }
    
    if (type == 'source') {
        showElement('source_config');
        showElement('destination_config');
    } else if (type == 'service') {
        showElement('service_config');
        showElement('source_config');
        showElement('destination_config');
    } else if (type == 'port') {
        showElement('port_config');
        showElement('source_config');
        showElement('destination_config');
    } else if (type == 'protocol') {
        showElement('protocol_config');
        showElement('source_config');
        showElement('destination_config');
    }
    
    updateSourceType();
    updateAction();
    updateLogging();
    updateForwarding();
    updatePreview();
}

function updateSourceType() {
    var type = getRadioValue('source_type');
    var rows = ['source_address_row', 'source_mac_row', 'source_interface_row', 'source_ipset_row'];
    
    for (var i = 0; i < rows.length; i++) {
        var elem = document.getElementById(rows[i]);
        if (elem) elem.style.display = 'none';
    }
    
    if (type && document.getElementById('source_' + type + '_row')) {
        document.getElementById('source_' + type + '_row').style.display = '';
    }
    
    updatePreview();
}

function updateAction() {
    var action = getRadioValue('action');
    var rejectRow = document.getElementById('reject_type_row');
    if (rejectRow) {
        rejectRow.style.display = (action == 'reject') ? '' : 'none';
    }
    updatePreview();
}

function updateLogging() {
    var enabled = document.getElementsByName('log_enable')[0].checked;
    var rows = ['log_prefix_row', 'log_level_row', 'log_limit_row'];
    
    for (var i = 0; i < rows.length; i++) {
        var elem = document.getElementById(rows[i]);
        if (elem) elem.style.display = enabled ? '' : 'none';
    }
    
    updatePreview();
}

function updateForwarding() {
    var enabled = document.getElementsByName('forward_enable')[0].checked;
    var rows = ['forward_to_port_row', 'forward_to_addr_row'];
    
    for (var i = 0; i < rows.length; i++) {
        var elem = document.getElementById(rows[i]);
        if (elem) elem.style.display = enabled ? '' : 'none';
    }
    
    updatePreview();
}

function updatePreview() {
    // Build preview of the rule
    var preview = "rule";
    
    var family = getRadioValue('family');
    if (family && family != 'both') {
        preview += ' family="' + family + '"';
    }
    
    var ruleType = getRadioValue('rule_type');
    var sourceType = getRadioValue('source_type');
    
    // Add source
    if (sourceType && document.getElementsByName('source_' + sourceType)[0]) {
        var sourceVal = document.getElementsByName('source_' + sourceType)[0].value;
        if (sourceVal) {
            preview += ' source ' + sourceType + '="' + sourceVal + '"';
        }
    }
    
    // Add destination
    var destAddr = document.getElementsByName('destination_address')[0].value;
    if (destAddr) {
        preview += ' destination address="' + destAddr + '"';
    }
    
    // Add service/port based on rule type
    if (ruleType == 'service') {
        var service = document.getElementsByName('service_name')[0].value;
        if (service) {
            preview += ' service name="' + service + '"';
        }
    } else if (ruleType == 'port') {
        var portMode = getRadioValue('port_mode');
        var protocol = getRadioValue('protocol');
        var port = '';
        
        if (portMode == 'single') {
            port = document.getElementsByName('port_single')[0].value;
        } else {
            var from = document.getElementsByName('port_from')[0].value;
            var to = document.getElementsByName('port_to')[0].value;
            if (from && to) {
                port = from + '-' + to;
            }
        }
        
        if (port && protocol) {
            preview += ' port port="' + port + '" protocol="' + protocol + '"';
        }
    }
    
    // Add logging
    if (document.getElementsByName('log_enable')[0].checked) {
        preview += ' log';
        var logPrefix = document.getElementsByName('log_prefix')[0].value;
        if (logPrefix) {
            preview += ' prefix="' + logPrefix + '"';
        }
        var logLevel = document.getElementsByName('log_level')[0].value;
        if (logLevel) {
            preview += ' level="' + logLevel + '"';
        }
    }
    
    // Add action
    var action = getRadioValue('action');
    if (action) {
        preview += ' ' + action;
        if (action == 'reject') {
            var rejectType = document.getElementsByName('reject_type')[0].value;
            if (rejectType) {
                preview += ' type="' + rejectType + '"';
            }
        }
    }
    
    document.getElementById('preview_text').innerHTML = preview;
}

function getRadioValue(name) {
    var radios = document.getElementsByName(name);
    for (var i = 0; i < radios.length; i++) {
        if (radios[i].checked) {
            return radios[i].value;
        }
    }
    return null;
}

function showElement(id) {
    var elem = document.getElementById(id);
    if (elem) elem.style.display = '';
}

// Initialize form on load
document.addEventListener('DOMContentLoaded', function() {
    updateRuleType();
    
    // Add event listeners for preview updates
    var inputs = document.querySelectorAll('input, select');
    for (var i = 0; i < inputs.length; i++) {
        inputs[i].addEventListener('change', updatePreview);
        inputs[i].addEventListener('keyup', updatePreview);
    }
});
</script>
EOF

&ui_print_footer("index.cgi", $text{'index_return'});