#!/usr/bin/perl

require 'firewalld-rich-lib.pl';

print "Content-type: text/html\n\n";
print "<html><body><h2>Debug Info</h2>";

print "<p><b>Config firewall_cmd:</b> [" . $config{'firewall_cmd'} . "]</p>";

# Test has_command function
my $has_cmd_result = eval { &has_command($config{'firewall_cmd'}) };
print "<p><b>has_command result:</b> " . ($has_cmd_result || "undef/error") . "</p>";

# Test which command
my $which_result = system("which $config{'firewall_cmd'} >/dev/null 2>&1");
print "<p><b>which result:</b> " . $which_result . "</p>";

# Test our function
my $check_result = eval { check_firewalld_installed() };
print "<p><b>check_firewalld_installed result:</b> " . ($check_result || "undef/error") . "</p>";

# Test direct command
my $direct_test = `$config{'firewall_cmd'} --version 2>&1`;
print "<p><b>Direct command test:</b> " . $direct_test . "</p>";

print "</body></html>";
