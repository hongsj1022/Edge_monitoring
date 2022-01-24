#!/bin/sh
# permission denied? chmod +x influxdb_grafana.sh

# install docker

apt-get update

curl -sSL https://get.docker.com | sh

# Run influxdb container

docker run -d -p 8086:8086 \
	-v /var/lib/influxdb:/var/lib/influxdb \
	--name influxdb \
	-h influxdb influxdb

# Run grafana container

docker run -d -p 3000:3000 \
	--link influxdb:influxdb \
	--name grafana \
	-h grafana grafana/grafana:latest