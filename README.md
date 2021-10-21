# wazuh_install

clone wazuh_install and mv as is root

chmod +x wazuhinstall.sh

run ./wazuhinstall.sh

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

```
testing 
URL: https://<wazuh_server_ip>
user: admin
password: admin
```
