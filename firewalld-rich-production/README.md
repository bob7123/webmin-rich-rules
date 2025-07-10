# FirewallD Rich Rules Webmin Module

This is a comprehensive Webmin module for managing firewalld rich rules with full syntax support. It provides an advanced graphical interface for creating, editing, and managing complex firewall rules that go beyond basic port and service management.

## Features

- **Complete Rich Rule Support**: Handles all firewalld rich rule syntax variations
- **Intuitive Web Interface**: Complex conditional forms that adapt based on rule type
- **Real-time Validation**: Syntax checking and conflict detection
- **Rule Preview**: Live preview of generated rules as you type
- **Zone Management**: Full integration with firewalld zones
- **Advanced Options**: Support for logging, audit, masquerading, and port forwarding
- **Comprehensive Validation**: IP address, port range, and protocol validation
- **Webmin Integration**: Follows all Webmin conventions and security practices

## Installation

1. **Copy module to Webmin directory**:
   ```bash
   cp -r firewalld-rich /usr/libexec/webmin/
   ```

2. **Install through Webmin interface**:
   - Go to Webmin Configuration → Webmin Modules
   - Use "Install Module" and select the module directory

3. **Alternative installation**:
   ```bash
   cd /usr/libexec/webmin
   tar czf firewalld-rich.wbm.gz firewalld-rich/
   /usr/share/webmin/install-module.pl firewalld-rich.wbm.gz
   ```

## Requirements

- **FirewallD**: Version 0.3.0 or later (for rich rule support)
- **Webmin**: Version 1.970 or later
- **Operating System**: Linux with firewalld installed
- **Perl**: Version 5.10 or later
- **Root Access**: Required for firewall management

## Module Structure

```
firewalld-rich/
├── module.info              # Module metadata
├── config                   # Default configuration
├── config.info             # Configuration definitions
├── firewalld-rich-lib.pl   # Core library functions
├── index.cgi               # Main page (rules listing)
├── edit.cgi                # Add/edit rule form
├── save.cgi                # Form processing
├── delete.cgi              # Rule deletion
├── install_check.pl        # Installation verification
└── lang/
    └── en                  # English language strings
```

## Usage

### Main Interface

The main page displays all rich rules across zones with:
- **Zone filtering**: View rules for specific zones
- **Search functionality**: Find rules by content
- **Rule summaries**: Easy-to-read rule descriptions
- **Quick actions**: Edit and delete links

### Adding Rules

1. Click "Add Rich Rule" on the main page
2. Select target zone
3. Choose rule type (source-based, service-based, port-based, or protocol-based)
4. Configure source/destination as needed
5. Set action (accept, reject, drop)
6. Configure optional features (logging, audit, masquerading, forwarding)
7. Preview the generated rule
8. Save the rule

### Rich Rule Types

#### Source-based Rules
- **IP Address/Network**: `192.168.1.0/24`, `10.0.0.1`
- **MAC Address**: `00:11:22:33:44:55`
- **Interface**: `eth0`, `wlan0`
- **IP Set**: Named IP sets

#### Service-based Rules
- Uses predefined firewalld services
- Automatically includes correct ports/protocols
- Examples: `ssh`, `http`, `https`

#### Port-based Rules
- **Single Port**: `22`, `80`, `443`
- **Port Range**: `8000-8010`
- **Protocols**: TCP, UDP, SCTP, DCCP

#### Protocol-based Rules
- Raw IP protocol numbers
- Example: `47` for GRE

### Advanced Features

#### Logging
- **Enable/Disable**: Toggle rule logging
- **Log Prefix**: Custom prefix for log entries
- **Log Level**: Emergency, Alert, Critical, Error, Warning, Notice, Info, Debug
- **Rate Limiting**: Prevent log flooding

#### Actions
- **Accept**: Allow traffic
- **Reject**: Block with rejection message
- **Drop**: Silently drop traffic

#### Port Forwarding
- **Forward Port**: Source port to forward
- **Target Port**: Destination port
- **Target Address**: Destination IP

#### Other Options
- **Audit**: Enable audit logging
- **Masquerade**: Enable NAT masquerading
- **Priority**: Rule priority (if supported)

## Rich Rule Examples

### Basic Examples
```bash
# Allow SSH from specific network
rule family="ipv4" source address="192.168.1.0/24" service name="ssh" accept

# Block HTTP from specific IP
rule family="ipv4" source address="10.0.0.100" service name="http" drop

# Allow port range with logging
rule family="ipv4" port port="8000-8010" protocol="tcp" log prefix="APP-PORTS" accept
```

### Advanced Examples
```bash
# Port forwarding with logging
rule family="ipv4" source address="0.0.0.0/0" forward-port port="80" protocol="tcp" to-port="8080" to-addr="192.168.1.100" log prefix="WEB-FORWARD" accept

# Reject with custom message and rate limiting
rule family="ipv4" source address="192.168.100.0/24" service name="ssh" log prefix="SSH-REJECT" level="warn" limit value="3/minute" reject type="tcp-reset"

# Masquerading rule
rule family="ipv4" source address="192.168.1.0/24" masquerade
```

## Security Considerations

- All user input is validated and sanitized
- Commands use proper shell escaping
- Access control integration with Webmin
- No secrets or sensitive data in logs
- Atomic rule operations (rollback on failure)

## Troubleshooting

### Common Issues

1. **"Command not found"**: Install firewalld package
2. **"Service not running"**: Start firewalld service
3. **"Rich rules not supported"**: Upgrade firewalld to >= 0.3.0
4. **"Permission denied"**: Ensure Webmin runs as root

### Debug Information

Check `/var/log/webmin/miniserv.log` for detailed error messages.

### Testing FirewallD

```bash
# Check firewalld status
systemctl status firewalld

# Check rich rules support
firewall-cmd --version

# List current rich rules
firewall-cmd --list-rich-rules

# Test rule syntax
firewall-cmd --check-config
```

## Contributing

This module follows Webmin development standards:
- Pure Perl CGI architecture
- Consistent error handling
- Internationalization support
- Proper logging and audit trails

## License

This module is provided as-is for educational and operational purposes. Use in production environments should be thoroughly tested.

## Version History

- **v1.0**: Initial release with full rich rule support
- Comprehensive form interface
- Real-time validation and preview
- Complete firewalld integration