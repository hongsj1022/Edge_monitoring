**1. Root permission**

- `sudo su`

**2. If script file permission denied**

- `chmod +x influxdb_grafana.sh`

**3. Execute script**

- `./influxdb_grafana.sh`

**4. Execute influxdb container**

- `docker exec -it influxdb influx`

**5. Create user id and password**

- `create user <username> with password '<password>' with all privileges`
- `grant all privileges to <username>`

**6. Create databases for cluster1 ~ cluster10**


- `create database edge_cluster_1`

- `create database edge_cluster_2`

- `create database edge_cluster_3`

- `create database edge_cluster_4`

- `create database edge_cluster_5`

- `create database edge_cluster_6`

- `create database edge_cluster_7`

- `create database edge_cluster_8`

- `create database edge_cluster_9`

- `create database edge_cluster_10`

**6. Database list**

- `show databases`
