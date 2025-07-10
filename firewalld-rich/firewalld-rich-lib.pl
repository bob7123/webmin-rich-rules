#!/usr/bin/perl
# Functions for managing firewalld rich rules

BEGIN { push(@INC, ".."); };
use strict;
use warnings;
no warnings 'redefine';
no warnings 'uninitialized';
use WebminCore;
&init_config();

# Try to load the existing firewalld module if available
if (&foreign_exists("firewalld")) {
    &foreign_require("firewalld", "firewalld-lib.pl");
}

our ($module_root_directory, %text, %config, %gconfig);
our %access = &get_module_acl();

=head1 firewalld-rich-lib.pl

Library functions for managing firewalld rich rules.

=cut

# Check if firewalld is installed and running
sub check_firewalld_installed
{
#    return &has_command($config{'firewall_cmd'});
    return system("which $config{'firewall_cmd'} >/dev/null 2>&1") == 0;
}

sub is_firewalld_running
{
    my $ex = system("$config{'firewall_cmd'} --state >/dev/null 2>&1 </dev/null");
    return $ex ? 0 : 1;
}

# Execute firewall-cmd with proper error handling
sub execute_firewall_cmd
{
    my ($args, $permanent) = @_;
    my $cmd = $config{'firewall_cmd'} . " " . $args;
    $cmd .= " --permanent" if $permanent;
    
    my $output = &backquote_logged("$cmd 2>&1");
    my $exit_code = $?;
    
    return wantarray ? ($output, $exit_code) : ($exit_code ? $output : undef);
}

# Get list of all firewalld zones
sub list_firewalld_zones
{
    my ($output, $err) = execute_firewall_cmd("--get-zones");
    return () if $err;
    
    my @zones = split(/\s+/, $output);
    return grep { /\S/ } @zones;
}

# Get default zone
sub get_default_zone
{
    my ($output, $err) = execute_firewall_cmd("--get-default-zone");
    return undef if $err;
    
    chomp($output);
    return $output;
}

# Validate zone name
sub validate_zone
{
    my ($zone) = @_;
    return 0 if (!$zone || $zone =~ /[^a-zA-Z0-9_-]/);
    
    my @zones = list_firewalld_zones();
    return grep { $_ eq $zone } @zones;
}

# Get all rich rules for a zone
sub list_rich_rules
{
    my ($zone) = @_;
    
    my ($output, $err) = execute_firewall_cmd("--zone=" . quotemeta($zone) . " --list-rich-rules", 1);
    return () if $err;
    
    my @rules = split(/\n/, $output);
    my @result;
    
    for my $i (0..$#rules) {
        my $rule = $rules[$i];
        next if (!$rule || $rule !~ /\S/);
        
        push @result, {
            'index' => $i,
            'zone' => $zone,
            'text' => $rule,
            'parsed' => parse_rich_rule($rule)
        };
    }
    
    return @result;
}

# Get all rich rules from all zones
sub list_all_rich_rules
{
    my @all_rules;
    
    for my $zone (list_firewalld_zones()) {
        push @all_rules, list_rich_rules($zone);
    }
    
    return @all_rules;
}

# Parse a rich rule text into components
sub parse_rich_rule
{
    my ($rule_text) = @_;
    return undef if (!$rule_text);
    
    my %parsed;
    
    # Extract family
    if ($rule_text =~ /family="([^"]+)"/) {
        $parsed{'family'} = $1;
    }
    
    # Extract source
    if ($rule_text =~ /source\s+address="([^"]+)"/) {
        $parsed{'source_address'} = $1;
    }
    if ($rule_text =~ /source\s+mac="([^"]+)"/) {
        $parsed{'source_mac'} = $1;
    }
    if ($rule_text =~ /source\s+interface="([^"]+)"/) {
        $parsed{'source_interface'} = $1;
    }
    if ($rule_text =~ /source\s+ipset="([^"]+)"/) {
        $parsed{'source_ipset'} = $1;
    }
    
    # Extract destination
    if ($rule_text =~ /destination\s+address="([^"]+)"/) {
        $parsed{'destination_address'} = $1;
    }
    if ($rule_text =~ /destination\s+interface="([^"]+)"/) {
        $parsed{'destination_interface'} = $1;
    }
    
    # Extract service
    if ($rule_text =~ /service\s+name="([^"]+)"/) {
        $parsed{'service_name'} = $1;
    }
    
    # Extract port
    if ($rule_text =~ /port\s+port="([^"]+)"\s+protocol="([^"]+)"/) {
        $parsed{'port'} = $1;
        $parsed{'protocol'} = $2;
    }
    
    # Extract protocol value
    if ($rule_text =~ /protocol\s+value="([^"]+)"/) {
        $parsed{'protocol_value'} = $1;
    }
    
    # Extract ICMP block
    if ($rule_text =~ /icmp-block\s+name="([^"]+)"/) {
        $parsed{'icmp_block'} = $1;
    }
    
    # Extract masquerade
    if ($rule_text =~ /masquerade/) {
        $parsed{'masquerade'} = 1;
    }
    
    # Extract forward port
    if ($rule_text =~ /forward-port\s+port="([^"]+)"\s+protocol="([^"]+)"(?:\s+to-port="([^"]+)")?(?:\s+to-addr="([^"]+)")?/) {
        $parsed{'forward_port'} = $1;
        $parsed{'forward_protocol'} = $2;
        $parsed{'forward_to_port'} = $3 if $3;
        $parsed{'forward_to_addr'} = $4 if $4;
    }
    
    # Extract logging
    if ($rule_text =~ /log(?:\s+prefix="([^"]*)")?(?:\s+level="([^"]+)")?(?:\s+limit\s+value="([^"]+)")?/) {
        $parsed{'log'} = 1;
        $parsed{'log_prefix'} = $1 if defined $1;
        $parsed{'log_level'} = $2 if $2;
        $parsed{'log_limit'} = $3 if $3;
    }
    
    # Extract audit
    if ($rule_text =~ /audit/) {
        $parsed{'audit'} = 1;
    }
    
    # Extract action
    if ($rule_text =~ /accept/) {
        $parsed{'action'} = 'accept';
    } elsif ($rule_text =~ /reject(?:\s+type="([^"]+)")?/) {
        $parsed{'action'} = 'reject';
        $parsed{'reject_type'} = $1 if $1;
    } elsif ($rule_text =~ /drop/) {
        $parsed{'action'} = 'drop';
    }
    
    return \%parsed;
}

# Construct rich rule text from components
sub construct_rich_rule
{
    my (%opts) = @_;
    
    my $rule = "rule";
    
    # Add family
    if ($opts{'family'} && $opts{'family'} ne 'both') {
        $rule .= " family=\"" . $opts{'family'} . "\"";
    }
    
    # Add source
    if ($opts{'source_address'}) {
        $rule .= " source address=\"" . $opts{'source_address'} . "\"";
    } elsif ($opts{'source_mac'}) {
        $rule .= " source mac=\"" . $opts{'source_mac'} . "\"";
    } elsif ($opts{'source_interface'}) {
        $rule .= " source interface=\"" . $opts{'source_interface'} . "\"";
    } elsif ($opts{'source_ipset'}) {
        $rule .= " source ipset=\"" . $opts{'source_ipset'} . "\"";
    }
    
    # Add destination
    if ($opts{'destination_address'}) {
        $rule .= " destination address=\"" . $opts{'destination_address'} . "\"";
    } elsif ($opts{'destination_interface'}) {
        $rule .= " destination interface=\"" . $opts{'destination_interface'} . "\"";
    }
    
    # Add service or port
    if ($opts{'service_name'}) {
        $rule .= " service name=\"" . $opts{'service_name'} . "\"";
    } elsif ($opts{'port'} && $opts{'protocol'}) {
        $rule .= " port port=\"" . $opts{'port'} . "\" protocol=\"" . $opts{'protocol'} . "\"";
    }
    
    # Add protocol value
    if ($opts{'protocol_value'}) {
        $rule .= " protocol value=\"" . $opts{'protocol_value'} . "\"";
    }
    
    # Add ICMP block
    if ($opts{'icmp_block'}) {
        $rule .= " icmp-block name=\"" . $opts{'icmp_block'} . "\"";
    }
    
    # Add masquerade
    if ($opts{'masquerade'}) {
        $rule .= " masquerade";
    }
    
    # Add forward port
    if ($opts{'forward_port'} && $opts{'forward_protocol'}) {
        $rule .= " forward-port port=\"" . $opts{'forward_port'} . "\" protocol=\"" . $opts{'forward_protocol'} . "\"";
        if ($opts{'forward_to_port'}) {
            $rule .= " to-port=\"" . $opts{'forward_to_port'} . "\"";
        }
        if ($opts{'forward_to_addr'}) {
            $rule .= " to-addr=\"" . $opts{'forward_to_addr'} . "\"";
        }
    }
    
    # Add logging
    if ($opts{'log'}) {
        $rule .= " log";
        if ($opts{'log_prefix'}) {
            $rule .= " prefix=\"" . $opts{'log_prefix'} . "\"";
        }
        if ($opts{'log_level'}) {
            $rule .= " level=\"" . $opts{'log_level'} . "\"";
        }
        if ($opts{'log_limit'}) {
            $rule .= " limit value=\"" . $opts{'log_limit'} . "\"";
        }
    }
    
    # Add audit
    if ($opts{'audit'}) {
        $rule .= " audit";
    }
    
    # Add action
    if ($opts{'action'} eq 'accept') {
        $rule .= " accept";
    } elsif ($opts{'action'} eq 'reject') {
        $rule .= " reject";
        if ($opts{'reject_type'}) {
            $rule .= " type=\"" . $opts{'reject_type'} . "\"";
        }
    } elsif ($opts{'action'} eq 'drop') {
        $rule .= " drop";
    }
    
    return $rule;
}

# Validate rich rule syntax and components
sub validate_rich_rule
{
    my ($rule_text) = @_;
    
    return "No rule text provided" if (!$rule_text || $rule_text !~ /\S/);
    
    # Basic syntax check
    return "Rule must start with 'rule'" if ($rule_text !~ /^rule\s/);
    
    # Parse the rule to validate components
    my $parsed = parse_rich_rule($rule_text);
    return "Failed to parse rule" if (!$parsed);
    
    # Validate family
    if ($parsed->{'family'} && $parsed->{'family'} !~ /^(ipv4|ipv6)$/) {
        return "Invalid family: must be ipv4 or ipv6";
    }
    
    # Validate source address
    if ($parsed->{'source_address'}) {
        my $addr = $parsed->{'source_address'};
        if ($addr !~ /^[\d\.\/]+$/ && $addr !~ /^[a-fA-F0-9:\/]+$/) {
            return "Invalid source address format";
        }
    }
    
    # Validate MAC address
    if ($parsed->{'source_mac'}) {
        my $mac = $parsed->{'source_mac'};
        if ($mac !~ /^([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$/) {
            return "Invalid MAC address format";
        }
    }
    
    # Validate port
    if ($parsed->{'port'}) {
        my $port = $parsed->{'port'};
        if ($port =~ /^(\d+)-(\d+)$/) {
            my ($start, $end) = ($1, $2);
            return "Invalid port range" if ($start < 1 || $end > 65535 || $start > $end);
        } elsif ($port =~ /^\d+$/) {
            return "Invalid port number" if ($port < 1 || $port > 65535);
        } else {
            return "Invalid port format";
        }
    }
    
    # Validate protocol
    if ($parsed->{'protocol'} && $parsed->{'protocol'} !~ /^(tcp|udp|sctp|dccp)$/) {
        return "Invalid protocol: must be tcp, udp, sctp, or dccp";
    }
    
    # Validate action
    if ($parsed->{'action'} && $parsed->{'action'} !~ /^(accept|reject|drop)$/) {
        return "Invalid action: must be accept, reject, or drop";
    }
    
    # Validate log level
    if ($parsed->{'log_level'} && $parsed->{'log_level'} !~ /^(emerg|alert|crit|err|warn|notice|info|debug)$/) {
        return "Invalid log level";
    }
    
    return undef; # No errors
}

# Add rich rule to zone
sub add_rich_rule
{
    my ($rule_text, $zone) = @_;
    
    # Validate inputs
    return "Invalid zone" if (!validate_zone($zone));
    my $validate_err = validate_rich_rule($rule_text);
    return $validate_err if ($validate_err);
    
    # Check for conflicts
    my @existing = list_rich_rules($zone);
    for my $existing_rule (@existing) {
        if ($existing_rule->{'text'} eq $rule_text) {
            return "Rule already exists in zone";
        }
    }
    
    # Add the rule
    my $err = execute_firewall_cmd("--zone=" . quotemeta($zone) . " --add-rich-rule='" . quotemeta($rule_text) . "'", 1);
    return $err if ($err);
    
    # Reload to apply changes
    my $reload_err = execute_firewall_cmd("--reload");
    return $reload_err if ($reload_err);
    
    return undef;
}

# Remove rich rule from zone
sub remove_rich_rule
{
    my ($rule_text, $zone) = @_;
    
    # Validate inputs
    return "Invalid zone" if (!validate_zone($zone));
    
    # Remove the rule
    my $err = execute_firewall_cmd("--zone=" . quotemeta($zone) . " --remove-rich-rule='" . quotemeta($rule_text) . "'", 1);
    return $err if ($err);
    
    # Reload to apply changes
    my $reload_err = execute_firewall_cmd("--reload");
    return $reload_err if ($reload_err);
    
    return undef;
}

# Modify rich rule (atomic replace)
sub modify_rich_rule
{
    my ($old_rule, $new_rule, $zone) = @_;
    
    # Validate inputs
    return "Invalid zone" if (!validate_zone($zone));
    my $validate_err = validate_rich_rule($new_rule);
    return $validate_err if ($validate_err);
    
    # Check if new rule conflicts with existing (except the one being replaced)
    my @existing = list_rich_rules($zone);
    for my $existing_rule (@existing) {
        if ($existing_rule->{'text'} eq $new_rule && $existing_rule->{'text'} ne $old_rule) {
            return "New rule conflicts with existing rule";
        }
    }
    
    # Remove old rule
    my $remove_err = execute_firewall_cmd("--zone=" . quotemeta($zone) . " --remove-rich-rule='" . quotemeta($old_rule) . "'", 1);
    return $remove_err if ($remove_err);
    
    # Add new rule
    my $add_err = execute_firewall_cmd("--zone=" . quotemeta($zone) . " --add-rich-rule='" . quotemeta($new_rule) . "'", 1);
    if ($add_err) {
        # Try to restore old rule on failure
        execute_firewall_cmd("--zone=" . quotemeta($zone) . " --add-rich-rule='" . quotemeta($old_rule) . "'", 1);
        return $add_err;
    }
    
    # Reload to apply changes
    my $reload_err = execute_firewall_cmd("--reload");
    return $reload_err if ($reload_err);
    
    return undef;
}

# Get list of available services
sub get_firewalld_services
{
    my ($output, $err) = execute_firewall_cmd("--get-services");
    return () if $err;
    
    my @services = split(/\s+/, $output);
    return grep { /\S/ } @services;
}

# Get list of available ICMP types
sub get_firewalld_icmp_types
{
    my ($output, $err) = execute_firewall_cmd("--get-icmptypes");
    return () if $err;
    
    my @types = split(/\s+/, $output);
    return grep { /\S/ } @types;
}

# Reload firewalld configuration
sub reload_firewalld
{
    return execute_firewall_cmd("--reload");
}

# Get firewalld version
sub get_firewalld_version
{
    my ($output, $err) = execute_firewall_cmd("--version");
    return undef if $err;
    
    chomp($output);
    return $output;
}

# Check if rich rules are supported
sub rich_rules_supported
{
    my $version = get_firewalld_version();
    return 0 if (!$version);
    
    # Rich rules supported in firewalld >= 0.3.0
    if ($version =~ /^(\d+)\.(\d+)\.(\d+)/) {
        my ($major, $minor, $patch) = ($1, $2, $3);
        return 1 if ($major > 0 || ($major == 0 && $minor >= 3));
    }
    
    return 0;
}

# Backup firewalld configuration
sub backup_firewalld_config
{
    my $backup_dir = "/tmp/firewalld-backup-" . time();
    system("mkdir -p $backup_dir");
    system("cp -r $config{'config_dir'}/* $backup_dir/ 2>/dev/null");
    return $backup_dir;
}

1;
