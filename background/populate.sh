#!/bin/bash

set -e

# Create and populate background folder with project materials for Claude

mkdir -p relianoid
mkdir -p nftables-gui
mkdir -p webmin-docs
mkdir -p firewalld-docs
mkdir -p webmin-plugins
mkdir -p cockpit-extensions

# Clone relevant GitHub repositories

echo "Cloning Relianoid (Zevenet) ADC..."
git clone https://github.com/relianoid/adc-loadbalancer.git relianoid

echo "Cloning nftables-gui..."
git clone https://github.com/alegarsan11/nftables-gui.git nftables-gui

# Download Webmin developer docs

echo "Downloading Webmin developer documentation..."
curl -L -o webmin-docs/webmin-dev.html https://doxfer.webmin.com/Webmin/Webmin_Module_Development

# Download Firewalld rich rules documentation

echo "Downloading Firewalld rich rules documentation..."
curl -L -o firewalld-docs/rich-rules.html https://firewalld.org/documentation/howto/rich-language.html

# Optional: grab Webmin plugin examples

echo "Cloning example Webmin plugins..."
git clone https://github.com/webmin/webmin.git webmin-plugins

# Optional: grab Cockpit extensions for inspiration

echo "Cloning Cockpit packages (for extension reference)..."
git clone https://github.com/cockpit-project/cockpit.git cockpit-extensions

echo "✅ All background materials downloaded."
echo "You can now feed this folder into Claude or your preferred model to begin coding."

