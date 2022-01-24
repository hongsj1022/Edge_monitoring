docker run -d --name cadvisor \
	--restart=always \
	-v /:/rootfs:ro -v /var/run:/var/run:rw \
	-v /sys:/sys:ro -v /var/lib/docker/:/var/lib/docker:ro \
	-p 1022:1022 cadvisor:raspbian \
	-storage_driver=influxdb \
	-storage_driver_db=edge_cluster_6 \
	-storage_driver_user=icns \
	-storage_driver_password=iloveicns \
	-storage_driver_host=influxdb.icnslab-aws.net:8086