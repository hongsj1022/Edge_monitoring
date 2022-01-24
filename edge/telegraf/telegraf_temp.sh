#!/bin/sh
# permission denied? chmod +x telegraf_temp.sh

mkdir /home/pi/temperature
mv /home/pi/edge_cloud/telegraf/rpi-temp.sh /home/pi/temperature

mkdir /home/pi/telegraf
mv /home/pi/edge_cloud/telegraf/telegraf.conf /home/pi/telegraf

docker run --restart=always -d -p 9595:9595 --name=telegraf \
            -v /home/pi/telegraf/telegraf.conf:/etc/telegraf/telegraf.conf:ro \
            -v /home/pi/temperature/rpi-temp.sh:/etc/telegraf/rpi-temp.sh telegraf