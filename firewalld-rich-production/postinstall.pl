#!/usr/bin/perl
# postinstall.pl - Installation script for firewalld-rich module

require 'web-lib.pl';

# Called after module installation
sub module_install
{
    # Get the module's config directory
    my $module_name = "firewalld-rich";
    my $config_dir = "$config_directory/$module_name";
    
    # Create the config directory if it doesn't exist
    if (!-d $config_dir) {
        mkdir($config_dir, 0755) || die "Failed to create config directory $config_dir: $!";
    }
    
    # Copy config files from module directory to system config directory
    # Only copy if the files don't already exist (don't overwrite user configs)
    
    # Copy main config file
    my $src_config = "$module_root_directory/config";
    my $dst_config = "$config_dir/config";
    if (-f $src_config && !-f $dst_config) {
        copy_source_dest($src_config, $dst_config);
        chmod(0644, $dst_config);
    }
    
    # Copy config.info file
    my $src_config_info = "$module_root_directory/config.info";
    my $dst_config_info = "$config_dir/config.info";
    if (-f $src_config_info && !-f $dst_config_info) {
        copy_source_dest($src_config_info, $dst_config_info);
        chmod(0644, $dst_config_info);
    }
    
    # Create language directory if it doesn't exist
    my $lang_dir = "$config_dir/lang";
    if (!-d $lang_dir) {
        mkdir($lang_dir, 0755);
    }
    
    # Copy language files
    my $src_lang = "$module_root_directory/lang/en";
    my $dst_lang = "$lang_dir/en";
    if (-f $src_lang && !-f $dst_lang) {
        copy_source_dest($src_lang, $dst_lang);
        chmod(0644, $dst_lang);
    }
    
    # Set proper ownership for config files
    if ($< == 0) {  # Only if running as root
        my $webmin_user = $ENV{'WEBMIN_USER'} || 'root';
        my $webmin_group = $ENV{'WEBMIN_GROUP'} || 'root';
        
        system("chown -R $webmin_user:$webmin_group $config_dir");
    }
    
    # Verify firewall-cmd is available
    my $firewall_cmd = "/usr/bin/firewall-cmd";
    if (!-x $firewall_cmd) {
        # Try alternative locations
        foreach my $alt_path ("/bin/firewall-cmd", "/sbin/firewall-cmd", "/usr/sbin/firewall-cmd") {
            if (-x $alt_path) {
                $firewall_cmd = $alt_path;
                last;
            }
        }
    }
    
    # Update config with correct firewall-cmd path if found
    if (-x $firewall_cmd && -f $dst_config) {
        my $config_content = read_file_contents($dst_config);
        $config_content =~ s/firewall_cmd=.*/firewall_cmd=$firewall_cmd/;
        write_file_contents($dst_config, $config_content);
    }
    
    print "Firewalld Rich Rules module installed successfully.\n";
    print "Config files copied to: $config_dir\n";
    
    return undef;  # Success
}

# Helper function to read file contents
sub read_file_contents
{
    my ($file) = @_;
    local $/;
    open(my $fh, '<', $file) || die "Cannot read $file: $!";
    my $content = <$fh>;
    close($fh);
    return $content;
}

# Helper function to write file contents
sub write_file_contents
{
    my ($file, $content) = @_;
    open(my $fh, '>', $file) || die "Cannot write $file: $!";
    print $fh $content;
    close($fh);
}

1;