#!/bin/bash
echo "starting restart"
systemctl restart wazuh-manager &&
systemctl restart elasticsearch &&
systemctl restart kibana &&
systemctl restart filebeat &&
systemctl status wazuh-manager &&
systemctl status elasticsearch &&
systemctl status kibana &&
systemctl status filebeat
echo "DONE Restart"
