# wazuh_install

clone wazuh_install and run as is root

chmod +x wazuhinstall.sh

./wazuhinstall.sh

changes elasticsearch.yml

```
network.host: 0.0.0.0  
node.name: node-1
cluster.initial_master_nodes: node-1

opendistro_security.ssl.transport.pemcert_filepath: /etc/elasticsearch/certs/elasticsearch.pem
opendistro_security.ssl.transport.pemkey_filepath: /etc/elasticsearch/certs/elasticsearch-key.pem
opendistro_security.ssl.transport.pemtrustedcas_filepath: /etc/elasticsearch/certs/root-ca.pem
opendistro_security.ssl.transport.enforce_hostname_verification: false
opendistro_security.ssl.transport.resolve_hostname: false
opendistro_security.ssl.http.enabled: true
opendistro_security.ssl.http.pemcert_filepath: /etc/elasticsearch/certs/elasticsearch.pem
opendistro_security.ssl.http.pemkey_filepath: /etc/elasticsearch/certs/elasticsearch-key.pem
opendistro_security.ssl.http.pemtrustedcas_filepath: /etc/elasticsearch/certs/root-ca.pem
opendistro_security.nodes_dn:
- CN=node-1,OU=Docu,O=Wazuh,L=California,C=US
opendistro_security.authcz.admin_dn:
- CN=admin,OU=Docu,O=Wazuh,L=California,C=US

opendistro_security.audit.type: internal_elasticsearch
opendistro_security.enable_snapshot_restore_privilege: true
opendistro_security.check_snapshot_restore_write_privileges: true
opendistro_security.restapi.roles_enabled: ["all_access", "security_rest_api_access"]
cluster.routing.allocation.disk.threshold_enabled: false
node.max_local_storage_nodes: 3

path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch
```
fix error elasticsearch to status kibana
![image](https://user-images.githubusercontent.com/85473544/138298168-6042d159-64f3-4a26-9cff-a3b0d51ae0be.png)

run code down here
```
export JAVA_HOME=/usr/share/elasticsearch/jdk/ && /usr/share/elasticsearch/plugins/opendistro_security/tools/securityadmin.sh opendistro_security/securityconfig/ -nhnv -cacert /etc/elasticsearch/certs/root-ca.pem -cert /etc/elasticsearch/certs/admin.pem -key /etc/elasticsearch/certs/admin-key.pem
```
fix application not found
![image](https://user-images.githubusercontent.com/85473544/138301180-aacc01e7-bcda-4451-8da2-f8713405be5d.png)

run code down here
```
sudo -u kibana /usr/share/kibana/bin/kibana-plugin install https://packages.wazuh.com/4.x/ui/kibana/wazuh_kibana-4.2.4_7.10.2-1.zip
```

```
testing 
URL: https://<wazuh_server_ip>
user: admin
password: admin
```
setting configure ossec.conf to /var/ossec/etc/ossec.conf

```
  <vulnerability-detector>
    <enabled>yes</enabled>
    <interval>1m</interval>
    <ignore_time>5m</ignore_time>
    <run_on_start>yes</run_on_start>

    <!-- Ubuntu OS vulnerabilities --> 
    <provider name="canonical">
      <enabled>yes</enabled>
      <os>trusty</os>
      <os>xenial</os>
      <os>bionic</os>
      <os>focal</os>
      <update_interval>1m</update_interval>
    </provider>

    <!-- Debian OS vulnerabilities -->  
    <provider name="debian">
      <enabled>yes</enabled>
      <os>stretch</os>
      <os>buster</os>
      <update_interval>1m</update_interval>
    </provider>

    <!-- RedHat OS vulnerabilities -->  
    <provider name="redhat">
      <enabled>yes</enabled>
      <os>5</os>
      <os>6</os>
      <os>7</os>
      <os>8</os>
      <update_interval>1m</update_interval>
    </provider>

    <!-- Windows OS vulnerabilities -->
    <provider name="msu">
      <enabled>yes</enabled>
      <update_interval>1m</update_interval>
    </provider>

    <!-- Aggregate vulnerabilities -->
    <provider name="nvd">
      <enabled>yes</enabled>
      <update_from_year>2021</update_from_year>
      <update_interval>1m</update_interval>
    </provider>

  </vulnerability-detector>

```
and restart wazuh-manager (systemctl restart wazuh-manager)
