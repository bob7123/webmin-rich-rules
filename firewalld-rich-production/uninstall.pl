#!/usr/bin/perl
# uninstall.pl - Uninstallation script for firewalld-rich module

require 'web-lib.pl';

# Called before module removal
sub module_uninstall
{
    # Get the module's config directory
    my $module_name = "firewalld-rich";
    my $config_dir = "$config_directory/$module_name";
    
    # Remove the module's config directory and all contents
    if (-d $config_dir) {
        print "Removing firewalld-rich configuration directory: $config_dir\n";
        
        # Remove all files in the config directory
        if (opendir(my $dh, $config_dir)) {
            my @files = readdir($dh);
            closedir($dh);
            
            foreach my $file (@files) {
                next if ($file eq '.' || $file eq '..');
                my $full_path = "$config_dir/$file";
                
                if (-d $full_path) {
                    # Remove subdirectory (like lang/)
                    system("rm -rf '$full_path'");
                } else {
                    # Remove file
                    unlink($full_path);
                }
            }
        }
        
        # Remove the config directory itself
        rmdir($config_dir) || print "Warning: Could not remove $config_dir: $!\n";
    }
    
    # Clean up any temporary files that might have been created
    my @temp_files = (
        "/tmp/firewalld-rich-*",
        "/var/tmp/firewalld-rich-*"
    );
    
    foreach my $pattern (@temp_files) {
        my @files = glob($pattern);
        foreach my $file (@files) {
            unlink($file) if (-f $file);
        }
    }
    
    print "Firewalld Rich Rules module uninstalled successfully.\n";
    print "Configuration files removed from: $config_dir\n";
    
    return undef;  # Success
}

1;