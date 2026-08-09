# Wazuh Active Response Setup

SentinelHQ reikia Wazuh active-response konfigūracijos host izoliacjai.

## Diegimas (vieną kartą)

Nukopijuok `sentinelhq_active_response.conf` į Wazuh konfigūracijos direktoriją:

```bash
docker cp sentinelhq_active_response.conf single-node-wazuh.manager-1:/var/ossec/etc/ossec.conf.d/
# arba pridėk turinį prie /var/ossec/etc/ossec.conf
docker exec single-node-wazuh.manager-1 sh -c "cat /path/to/sentinelhq_active_response.conf >> /var/ossec/etc/ossec.conf"
docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control restart
```

## Patikrinimas

```bash
docker exec single-node-wazuh.manager-1 grep -q sentinelhq-isolation /var/ossec/etc/ossec.conf && echo "OK"
```
