#!/usr/bin/perl
# Check if firewalld is installed and can be managed

sub is_installed
{
    my ($mode) = @_;
    
    # Check if firewalld is installed
    my $firewalld_check = system("which firewall-cmd >/dev/null 2>&1") == 0;
    return 0 if (!$firewalld_check);
    
    # Check if firewalld supports rich rules (version >= 0.3.0)
    my $version_output = `firewall-cmd --version 2>/dev/null`;
    if ($version_output =~ /^(\d+)\.(\d+)\.(\d+)/) {
        my ($major, $minor, $patch) = ($1, $2, $3);
        return 0 if ($major == 0 && $minor < 3);
    }
    
    if ($mode) {
        # Check if firewalld is running
        my $running = system("firewall-cmd --state >/dev/null 2>&1") == 0;
        return $running ? 2 : 1;
    }
    
    return 1;
}

1;