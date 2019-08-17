#! /bin/bash

# turn green led to blink
echo 'heartbeat' | sudo tee --append /sys/class/leds/led0/trigger

echo "-starting-" > /home/pi/ToxBlinkenwall/toxblinkenwall/share/online_status.txt

