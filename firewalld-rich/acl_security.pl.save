#!/usr/bin/perl
# ACL security definitions for firewalld-rich module

sub acl_security_form
{
    my ($u) = @_;
    
    print &ui_table_start($text{'acl_header'}, "width=100%", 2);
    
    # Zone restrictions
    print &ui_table_row($text{'acl_zones'},
        &ui_radio("zones_mode", $u->{'zones_mode'} || 0, [
            [0, $text{'acl_zoneall'}],
            [1, $text{'acl_zonesel'}]
        ]) . "<br>" .
        &ui_select("zones", [ split(/\s+/, $u->{'zones'}) ], 
                   [ map { [$_, $_] } &list_firewalld_zones() ], 
                   5, 1, 0, 0, "style='margin-left: 20px;'"));
    
    # Edit permissions
    print &ui_table_row($text{'acl_edit'},
        &ui_yesno_radio("edit", $u->{'edit'} ne '0' ? 1 : 0));
    
    # Delete permissions
    print &ui_table_row($text{'acl_delete'},
        &ui_yesno_radio("delete", $u->{'delete'} ne '0' ? 1 : 0));
    
    print &ui_table_end();
}

sub acl_security_save
{
    my ($u, $in) = @_;
    
    $u->{'zones_mode'} = $in->{'zones_mode'};
    if ($in->{'zones_mode'} == 1) {
        $u->{'zones'} = join(" ", @{$in->{'zones'}});
    } else {
        delete($u->{'zones'});
    }
    
    $u->{'edit'} = $in->{'edit'};
    $u->{'delete'} = $in->{'delete'};
}

# Check if user can access a specific zone
sub can_access_zone
{
    my ($zone) = @_;
    
    return 1 if (!$access{'zones_mode'} || $access{'zones_mode'} == 0);
    return 1 if (!$access{'zones'});
    
    my @allowed = split(/\s+/, $access{'zones'});
    return grep { $_ eq $zone } @allowed;
}

# Check if user can edit rules
sub can_edit_rules
{
    return $access{'edit'} ne '0';
}

# Check if user can delete rules
sub can_delete_rules
{
    return $access{'delete'} ne '0';
}

1;