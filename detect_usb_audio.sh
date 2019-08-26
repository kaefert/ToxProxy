#! /bin/bash

#*********************************
#
# ToxBlinkenwall - udev script to detect audio and video devices
# (C)Zoff in 2017 - 2019
#
# https://github.com/zoff99/ToxBlinkenwall
#
#*********************************


export usb_device="$1"
export dst_dir=$(dirname "$0")
export logfile="$dst_dir""/tox_usbmount.log"

