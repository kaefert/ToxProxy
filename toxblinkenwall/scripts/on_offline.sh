#! /bin/bash

# turn green led to blink, when offline
echo 'heartbeat' | sudo tee --append /sys/class/leds/led0/trigger

echo "*offline*" > /home/pi/ToxBlinkenwall/toxblinkenwall/share/online_status.txt

