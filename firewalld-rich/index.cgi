#!/usr/bin/perl
# Main page for firewalld rich rules management

require './firewalld-rich-lib.pl';

# Check if firewalld is installed and running
if (!check_firewalld_installed()) {
    &ui_print_header(undef, $text{'index_title'}, "", undef, 1, 1);
    print &ui_hr();
    print &text('index_ecommand', "<tt>$config{'firewall_cmd'}</tt>"), "<p>\n";
    &ui_print_footer("/", $text{'index'});
    exit;
}

if (!is_firewalld_running()) {
    &ui_print_header(undef, $text{'index_title'}, "", undef, 1, 1);
    print &ui_hr();
    print &text('index_estopped'), "<p>\n";
    &ui_print_footer("/", $text{'index'});
    exit;
}

if (!rich_rules_supported()) {
    &ui_print_header(undef, $text{'index_title'}, "", undef, 1, 1);
    print &ui_hr();
    print &text('index_eversion'), "<p>\n";
    &ui_print_footer("/", $text{'index'});
    exit;
}

# Parse form inputs
&ReadParse();

# Get zone filter
my $zone_filter = $in{'zone'} || '';
my $search_filter = $in{'search'} || '';

# Build page header
&ui_print_header(undef, $text{'index_title'}, "", undef, 1, 1);

# Add zone filter and search form
print &ui_form_start("index.cgi", "get");
print &ui_hidden("refresh", 1);

print "<table width='100%'><tr>\n";

# Zone filter dropdown
print "<td width='50%'>";
print $text{'index_filter'} . " ";
my @zones = &list_firewalld_zones();
my @zone_opts = (["", $text{'index_all'}]);
foreach my $zone (@zones) {
    push @zone_opts, [$zone, $zone];
}
print &ui_select("zone", $zone_filter, \@zone_opts, 1, 0, 0, 0, "onchange='this.form.submit()'");
print "</td>\n";

# Search box
print "<td width='50%' align='right'>";
print $text{'index_search'} . " ";
print &ui_textbox("search", $search_filter, 20);
print " " . &ui_submit($text{'search'});
print "</td>\n";

print "</tr></table>\n";
print &ui_form_end();

print &ui_hr();

# Get all rich rules
my @all_rules;
if ($zone_filter) {
    @all_rules = &list_rich_rules($zone_filter);
} else {
    @all_rules = &list_all_rich_rules();
}

# Apply search filter if specified
if ($search_filter) {
    @all_rules = grep { $_->{'text'} =~ /\Q$search_filter\E/i } @all_rules;
}

# Count statistics
my $total_rules = scalar(@all_rules);
my $active_rules = scalar(grep { $_->{'text'} =~ /accept|reject|drop/ } @all_rules);
my $error_rules = 0; # TODO: Implement error detection

# Display statistics
print "<div style='margin-bottom: 10px;'>";
print &text('index_stats', $total_rules, $active_rules, $error_rules);
print "</div>\n";

# Add Rule button
print &ui_link("edit.cgi?new=1" . ($zone_filter ? "&zone=" . &urlize($zone_filter) : ""), 
               $text{'index_add'});
print "<br><br>\n";

if (@all_rules) {
    # Display rules table
    print &ui_columns_start([
        $text{'index_zone'},
        $text{'index_rule'},
        $text{'index_action'}
    ], 100);
    
    foreach my $rule (@all_rules) {
        my $parsed = $rule->{'parsed'};
        my $rule_summary = &format_rule_summary($rule);
        
        # Create action links
        my $edit_link = &ui_link("edit.cgi?zone=" . &urlize($rule->{'zone'}) . 
                                 "&idx=" . $rule->{'index'}, 
                                 $text{'edit'});
        my $delete_link = &ui_link("delete.cgi?zone=" . &urlize($rule->{'zone'}) . 
                                   "&idx=" . $rule->{'index'}, 
                                   $text{'delete'});
        
        print &ui_columns_row([
            $rule->{'zone'},
            $rule_summary,
            $edit_link . " | " . $delete_link
        ]);
    }
    
    print &ui_columns_end();
} else {
    print "<p><i>" . $text{'index_none'} . "</i></p>\n";
}

# Format rule summary for display
sub format_rule_summary
{
    my ($rule) = @_;
    my $parsed = $rule->{'parsed'};
    my $text = $rule->{'text'};
    
    # Create a shorter, more readable summary
    my @parts;
    
    # Source info
    if ($parsed->{'source_address'}) {
        push @parts, "from " . $parsed->{'source_address'};
    } elsif ($parsed->{'source_interface'}) {
        push @parts, "from " . $parsed->{'source_interface'};
    } elsif ($parsed->{'source_mac'}) {
        push @parts, "from MAC " . $parsed->{'source_mac'};
    }
    
    # Service/port info
    if ($parsed->{'service_name'}) {
        push @parts, "service " . $parsed->{'service_name'};
    } elsif ($parsed->{'port'} && $parsed->{'protocol'}) {
        push @parts, $parsed->{'protocol'} . "/" . $parsed->{'port'};
    }
    
    # Action
    if ($parsed->{'action'}) {
        push @parts, uc($parsed->{'action'});
    }
    
    # Logging
    if ($parsed->{'log'}) {
        push @parts, "LOG";
    }
    
    # Forwarding
    if ($parsed->{'forward_port'}) {
        push @parts, "forward to " . ($parsed->{'forward_to_port'} || $parsed->{'forward_port'});
    }
    
    # Masquerade
    if ($parsed->{'masquerade'}) {
        push @parts, "MASQUERADE";
    }
    
    my $summary = join(", ", @parts);
    
    # If summary is too long or empty, show truncated original rule
    if (!$summary || length($summary) > 80) {
        $summary = $text;
        if (length($summary) > 80) {
            $summary = substr($summary, 0, 77) . "...";
        }
    }
    
    # Make it a link to edit page
    return &ui_link("edit.cgi?zone=" . &urlize($rule->{'zone'}) . 
                    "&idx=" . $rule->{'index'}, 
                    &html_escape($summary));
}

&ui_print_footer("/", $text{'index'});