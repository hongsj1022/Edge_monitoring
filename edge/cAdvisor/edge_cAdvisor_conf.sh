#!/bin/sh
# permission denied? chmod +x edge_cadvisor.sh

apt-get update

curl -sSL https://get.docker.com | sh

echo "console=serial0,115200 console=tty1 root=PARTUUID=5e3da3da-02 rootfstype=ext4 elevator=deadline fsck.repair=yes rootwait quiet splash plymouth.ignore-serial-consoles cgroup_enable=memory cgroup_memory=1" > /boot/cmdline.txt

mkdir /home/pi/cadvisor

echo "# idea from github.com/Budry/cadvisor-arm

# Builder
FROM arm32v7/golang as builder

RUN apt update && apt install -y git dmsetup && apt clean
RUN git clone --branch branch-v0.28.3-influx-memory-rss https://github.com/alicek106/cadvisor.git /go/src/github.com/alicek106/cadvisor

RUN mv /go/src/github.com/alicek106 /go/src/github.com/google

WORKDIR /go/src/github.com/google/cadvisor

RUN make build

# Image for usage
FROM arm32v7/debian

COPY --from=builder /go/src/github.com/google/cadvisor/cadvisor /usr/bin/cadvisor

EXPOSE 8080

ENTRYPOINT [\"/usr/bin/cadvisor\", \"-logtostderr\"]" >> /home/pi/cadvisor/Dockerfile

docker image build -t cadvisor:raspbian /home/pi/cadvisor