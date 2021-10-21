#!/bin/bash
echo "Requirements"
apt-get update && apt-get upgrade -y
sudo apt install curl apt-transport-https unzip wget libcap2-bin software-properties-common lsb-release -y
sudo apt install gpgv gpgsm gnupg-l10n gnupg dirmngr -y
export JAVA_HOME=/usr/ && apt install openjdk-11-jdk -y
sudo apt update -y
# Wazuh Prep
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add -
echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list
sudo apt-get update -y
sleep 10

echo "Wazuh Manager"
sudo apt-get install wazuh-manager -y
systemctl daemon-reload
systemctl enable wazuh-manager
sleep 3
systemctl start wazuh-manager
sleep 10
systemctl status wazuh-manager
sleep 3

echo "Elasticsearch"
sudo apt install elasticsearch-oss opendistroforelasticsearch -y
curl -so /etc/elasticsearch/elasticsearch.yml https://raw.githubusercontent.com/wazuh/wazuh-documentation/4.2/resources/open-distro/elasticsearch/7.x/elasticsearch_all_in_one.yml
curl -so /usr/share/elasticsearch/plugins/opendistro_security/securityconfig/roles.yml https://raw.githubusercontent.com/wazuh/wazuh-documentation/4.2/resources/open-distro/elasticsearch/roles/roles.yml
curl -so /usr/share/elasticsearch/plugins/opendistro_security/securityconfig/roles_mapping.yml https://raw.githubusercontent.com/wazuh/wazuh-documentation/4.2/resources/open-distro/elasticsearch/roles/roles_mapping.yml
curl -so /usr/share/elasticsearch/plugins/opendistro_security/securityconfig/internal_users.yml https://raw.githubusercontent.com/wazuh/wazuh-documentation/4.2/resources/open-distro/elasticsearch/roles/internal_users.yml
rm /etc/elasticsearch/esnode-key.pem /etc/elasticsearch/esnode.pem /etc/elasticsearch/kirk-key.pem /etc/elasticsearch/kirk.pem /etc/elasticsearch/root-ca.pem -f
cd ~
curl -so ~/wazuh-cert-tool.sh https://packages.wazuh.com/resources/4.2/open-distro/tools/certificate-utility/wazuh-cert-tool.sh
curl -so ~/instances.yml https://packages.wazuh.com/resources/4.2/open-distro/tools/certificate-utility/instances_aio.yml
bash ~/wazuh-cert-tool.sh
mkdir /etc/elasticsearch/certs/
mv ~/certs/admin* /etc/elasticsearch/certs/
mv ~/certs/elasticsearch-key.pem /etc/elasticsearch/certs/
mv ~/certs/elasticsearch.pem /etc/elasticsearch/certs/
cp ~/certs/root-ca* /etc/elasticsearch/certs/
chown -R root:elasticsearch /etc/elasticsearch/certs/*
chmod 644 /etc/elasticsearch/certs/*
systemctl daemon-reload
systemctl enable elasticsearch
systemctl start elasticsearch
systemctl status elasticsearch -q
export JAVA_HOME=/usr/share/elasticsearch/jdk/ && /usr/share/elasticsearch/plugins/opendistro_security/tools/securityadmin.sh -cd /usr/share/elasticsearch/plugins/opendistro_security/securityconfig/ -nhnv -cacert /etc/elasticsearch/certs/root-ca.pem -cert /etc/elasticsearch/certs/admin.pem -key /etc/elasticsearch/certs/admin-key.pem
curl -XGET https://localhost:9200 -u admin:admin -k

echo "Filebeat"
apt-get install filebeat -y
sleep 10
curl -so /etc/filebeat/filebeat.yml https://raw.githubusercontent.com/wazuh/wazuh-documentation/4.2/resources/open-distro/filebeat/7.x/filebeat_all_in_one.yml
curl -so /etc/filebeat/wazuh-template.json https://raw.githubusercontent.com/wazuh/wazuh/4.2/extensions/elasticsearch/7.x/wazuh-template.json
chmod go+r /etc/filebeat/wazuh-template.json
curl -s https://packages.wazuh.com/4.x/filebeat/wazuh-filebeat-0.1.tar.gz | tar -xvz -C /usr/share/filebeat/module
mkdir /etc/filebeat/certs
cp /etc/elasticsearch/certs/root-ca.pem /etc/filebeat/certs/
mv ~/certs/filebeat* /etc/filebeat/certs/
systemctl daemon-reload
systemctl enable filebeat
systemctl start filebeat
systemctl status filebeat -q

echo "Kibana"
apt-get install opendistroforelasticsearch-kibana -y
sleep 10
curl -so /etc/kibana/kibana.yml https://raw.githubusercontent.com/wazuh/wazuh-documentation/4.1/resources/open-distro/kibana/7.x/kibana_all_in_one.yml
mkdir /usr/share/kibana/data
chown -R kibana:kibana /usr/share/kibana/data
cd /usr/share/kibana
sudo -u kibana /usr/share/kibana/bin/kibana-plugin install https://packages.wazuh.com/4.x/ui/kibana/wazuh_kibana-4.1.2_7.10.0-1.zip
###########################
cd ~
mkdir /etc/kibana/certs
cp ~/certs/root-ca.pem /etc/kibana/certs/
mv ~/certs/kibana* /etc/kibana/certs/
chmod 644 /etc/kibana/certs/*

setcap 'cap_net_bind_service=+ep' /usr/share/kibana/node/bin/node
systemctl daemon-reload
systemctl enable kibana
systemctl start kibana
systemctl status kibana -q
echo "DONE INSTALL"
