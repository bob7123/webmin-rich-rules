# Firewalld Rich Rules Module - Installation Guide

## Overview
This guide provides instructions for installing and verifying the Firewalld Rich Rules management module for Webmin.

## Prerequisites

### System Requirements
- **Webmin**: Version 1.900 or later
- **Operating System**: Linux with firewalld support
- **Firewalld**: Must be installed and available
- **Perl**: Version 5.8 or later (usually included with Webmin)

### Pre-Installation Checks
1. Verify Webmin is running:
   ```bash
   systemctl status webmin
   ```

2. Verify firewalld is installed:
   ```bash
   which firewall-cmd
   firewall-cmd --version
   ```

3. Verify firewalld service status:
   ```bash
   systemctl status firewalld
   ```

## Installation Methods

### Method 1: Via Webmin Web Interface (Recommended)

1. **Login to Webmin** as root or administrative user

2. **Navigate to Module Installation**:
   - Go to **Webmin Configuration** → **Webmin Modules**
   - Click **Install Module**

3. **Upload Module**:
   - Select **From uploaded file**
   - Choose the `firewalld-rich.wbm.gz` file
   - Click **Install Module**

4. **Verify Installation**:
   - The module should appear in the **Networking** section
   - Look for **"Firewalld Rich Rules"** in the module list

### Method 2: Command Line Installation

1. **Copy the module package** to your server:
   ```bash
   scp firewalld-rich.wbm.gz root@yourserver:/tmp/
   ```

2. **Install via Webmin command**:
   ```bash
   /usr/share/webmin/install-module.pl /tmp/firewalld-rich.wbm.gz
   ```

3. **Restart Webmin** (if required):
   ```bash
   systemctl restart webmin
   ```

## Post-Installation Verification

### 1. Module Visibility Check
- Login to Webmin web interface
- Navigate to **Networking** section
- Verify **"Firewalld Rich Rules"** appears in the module list

### 2. Module Access Check
- Click on **"Firewalld Rich Rules"** module
- Verify the module loads without errors
- Check that firewalld zones are detected and displayed

### 3. Configuration Files Check
Verify that config files were properly installed:
```bash
ls -la /etc/webmin/firewalld-rich/
```

Expected files:
- `config` - Main configuration file
- `config.info` - Configuration parameter definitions
- `lang/en` - English language strings

### 4. Firewall Command Detection
The module should automatically detect the firewall-cmd location. Common locations:
- `/usr/bin/firewall-cmd`
- `/bin/firewall-cmd`
- `/sbin/firewall-cmd`
- `/usr/sbin/firewall-cmd`

### 5. Functional Testing
1. **Zone List Test**:
   - Module should display available firewalld zones
   - Default zones (public, internal, external, etc.) should be visible

2. **Rich Rule Display**:
   - Existing rich rules should be displayed
   - If no rules exist, should show "No rich rules defined"

3. **Add Rule Test**:
   - Click "Add Rich Rule"
   - Verify the edit form loads properly
   - Cancel without saving

## Troubleshooting

### Common Issues

#### 1. Module Not Appearing in Networking Section
**Cause**: Module installation failed or permissions issue
**Solution**:
- Check `/var/log/webmin/miniserv.log` for errors
- Verify file permissions: `chmod 755 /usr/share/webmin/firewalld-rich/*.cgi`
- Restart Webmin: `systemctl restart webmin`

#### 2. "Command not found" Error
**Cause**: firewall-cmd not detected
**Solution**:
- Install firewalld: `yum install firewalld` or `apt install firewalld`
- Check config file: `/etc/webmin/firewalld-rich/config`
- Verify firewall_cmd path is correct

#### 3. "Permission denied" Error
**Cause**: Insufficient permissions to access firewalld
**Solution**:
- Ensure Webmin runs with appropriate privileges
- Check firewalld service is running: `systemctl start firewalld`
- Verify user has sudo/root access

#### 4. Configuration Not Saving
**Cause**: Config directory not writable
**Solution**:
- Check permissions: `ls -la /etc/webmin/firewalld-rich/`
- Fix ownership: `chown -R root:root /etc/webmin/firewalld-rich/`
- Fix permissions: `chmod 755 /etc/webmin/firewalld-rich/`

### Log Files
Check these log files for troubleshooting:
- `/var/log/webmin/miniserv.log` - Webmin server logs
- `/var/log/webmin/miniserv.error` - Webmin error logs
- `/var/log/firewalld` - Firewalld logs

## Uninstallation

### Via Webmin Web Interface
1. Go to **Webmin Configuration** → **Webmin Modules**
2. Find **"Firewalld Rich Rules"** in the module list
3. Click **Delete** next to the module
4. Confirm deletion

### Via Command Line
```bash
rm -rf /usr/share/webmin/firewalld-rich
rm -rf /etc/webmin/firewalld-rich
systemctl restart webmin
```

## Support

### Module Information
- **Module Name**: firewalld-rich
- **Version**: 1.0
- **Category**: Networking
- **Author**: Claude Code Generated

### Getting Help
For issues with this module:
1. Check the troubleshooting section above
2. Review Webmin logs for error messages
3. Verify firewalld installation and configuration
4. Check file permissions and ownership

### File Locations
- **Module Directory**: `/usr/share/webmin/firewalld-rich/`
- **Config Directory**: `/etc/webmin/firewalld-rich/`
- **Log Files**: `/var/log/webmin/`

## Security Considerations

1. **Access Control**: This module requires root privileges to modify firewall rules
2. **Backup**: Always backup your current firewall configuration before making changes
3. **Testing**: Test rule changes in a non-production environment first
4. **Monitoring**: Monitor firewall logs after implementing new rules

## Package Contents

The `firewalld-rich.wbm.gz` package includes:
- Core module files (*.cgi, *.pl)
- Configuration files (config, config.info)
- Language files (lang/en)
- Installation scripts (postinstall.pl, uninstall.pl)
- Documentation (README.md)

Total package size: ~17KB