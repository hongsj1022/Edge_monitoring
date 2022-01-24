#!/bin/sh
PWD=`pwd -P`

git clone http://gitlab-oauth-token:Nq7sgVKSZiEd7bSxxCot@gitlab.icnslab.net/gom_2020/edge_service.git
export PYTHONPATH=$PYTHONPATH:$PWD/edge_service/src
sudo pip3 install paho-mqtt
python3 $PWD/edge_service/src/main/__init__.py &

#sudo pip3 install --upgrade python-iptables
#sudo update-alternatives --list iptables
#sudo update-alternatives --config iptables
#sudo whereis iptables
#sudo mv /usr/sbin/iptables /root/scripts
#sudo ln -s /usr/sbin/iptables-legacy /usr/sbin/iptables

#git clone http://gitlab-oauth-token:Nq7sgVKSZiEd7bSxxCot@gitlab.icnslab.net/gom_2020/ServiceAwareModule.git 
#sudo python Service-Aware-Module.py cms.aws-icnslab.net localhost
