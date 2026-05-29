#!/usr/bin/env bash
set -e

echo "Installing arduino-cli..."
curl -fsSL https://raw.githubusercontent.com/arduino/arduino-cli/master/install.sh | sh

# The install script usually puts it in bin/
export PATH=$PATH:$(pwd)/bin

echo "Updating index..."
arduino-cli core update-index

echo "Adding ESP32 board index..."
arduino-cli config init
arduino-cli config set board_manager.additional_urls https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json

echo "Updating index again..."
arduino-cli core update-index

echo "Installing ESP32 core..."
arduino-cli core install esp32:esp32

echo "Installing required libraries..."
arduino-cli lib install ArduinoWebsockets
arduino-cli lib install ArduinoJson

echo "Setup complete! Make sure arduino-cli is in your PATH."
