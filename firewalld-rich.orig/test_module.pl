#!/usr/bin/perl
# Simple test script to verify module functionality

# Test library loading
eval {
    require './firewalld-rich-lib.pl';
    print "✓ Library loaded successfully\n";
};
if ($@) {
    print "✗ Library load failed: $@\n";
    exit 1;
}

# Test config loading
eval {
    my $cmd = $config{'firewall_cmd'};
    print "✓ Config loaded: firewall_cmd = $cmd\n";
};
if ($@) {
    print "✗ Config load failed: $@\n";
}

# Test language file loading
eval {
    my $title = $text{'index_title'};
    print "✓ Language file loaded: title = $title\n";
};
if ($@) {
    print "✗ Language file load failed: $@\n";
}

# Test firewalld detection
eval {
    my $installed = check_firewalld_installed();
    print "✓ FirewallD installed: " . ($installed ? "YES" : "NO") . "\n";
    
    if ($installed) {
        my $running = is_firewalld_running();
        print "✓ FirewallD running: " . ($running ? "YES" : "NO") . "\n";
        
        if ($running) {
            my $supported = rich_rules_supported();
            print "✓ Rich rules supported: " . ($supported ? "YES" : "NO") . "\n";
            
            if ($supported) {
                my @zones = list_firewalld_zones();
                print "✓ Available zones: " . join(", ", @zones) . "\n";
                
                my $default = get_default_zone();
                print "✓ Default zone: $default\n";
            }
        }
    }
};
if ($@) {
    print "✗ FirewallD detection failed: $@\n";
}

# Test rule parsing
eval {
    my $test_rule = 'rule family="ipv4" source address="192.168.1.0/24" service name="ssh" accept';
    my $parsed = parse_rich_rule($test_rule);
    if ($parsed) {
        print "✓ Rule parsing works\n";
        print "  - Family: " . ($parsed->{'family'} || 'none') . "\n";
        print "  - Source: " . ($parsed->{'source_address'} || 'none') . "\n";
        print "  - Service: " . ($parsed->{'service_name'} || 'none') . "\n";
        print "  - Action: " . ($parsed->{'action'} || 'none') . "\n";
    } else {
        print "✗ Rule parsing failed\n";
    }
};
if ($@) {
    print "✗ Rule parsing test failed: $@\n";
}

# Test rule construction
eval {
    my $constructed = construct_rich_rule(
        'family' => 'ipv4',
        'source_address' => '10.0.0.0/8',
        'service_name' => 'http',
        'action' => 'accept'
    );
    print "✓ Rule construction works: $constructed\n";
};
if ($@) {
    print "✗ Rule construction failed: $@\n";
}

# Test rule validation
eval {
    my $valid_rule = 'rule family="ipv4" source address="192.168.1.0/24" service name="ssh" accept';
    my $invalid_rule = 'invalid rule syntax';
    
    my $err1 = validate_rich_rule($valid_rule);
    my $err2 = validate_rich_rule($invalid_rule);
    
    print "✓ Rule validation works:\n";
    print "  - Valid rule: " . ($err1 ? "FAILED ($err1)" : "PASSED") . "\n";
    print "  - Invalid rule: " . ($err2 ? "FAILED ($err2)" : "PASSED") . "\n";
};
if ($@) {
    print "✗ Rule validation test failed: $@\n";
}

print "\nModule test completed!\n";