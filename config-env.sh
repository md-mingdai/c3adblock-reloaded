#!/bin/sh
# Linux only: keep ModemManager from grabbing the ESP32's USB serial port (Espressif USB VID 303a),
# which otherwise causes "port busy" errors and random disconnects while flashing / monitoring.
sudo systemctl stop ModemManager
echo 'ATTRS{idVendor}=="303a", ENV{ID_MM_DEVICE_IGNORE}="1"' | sudo tee /etc/udev/rules.d/99-esp-no-modemmanager.rules
sudo udevadm control --reload-rules && sudo udevadm trigger
