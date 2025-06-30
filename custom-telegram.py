#!/usr/bin/env python

import sys
import json
import requests

from requests.auth import HTTPBasicAuth

#CHAT_ID="xxxx"
CHAT_ID="o da gacf"

# Read configuration parameters
alert_file = open(sys.argv[1])
hook_url = sys.argv[3]


# Read the alert file
alert_json = json.loads(alert_file.read())
alert_file.close()

# Extract data fields
alert_level = alert_json['rule']['level'] if 'level' in alert_json['rule'] else "N/A"
description = alert_json['rule']['description'] if 'description' in alert_json['rule'] else "N/A"
agent = alert_json['agent']['name'] if 'name' in alert_json['agent'] else "N/A"
#alert_data = alert_json['data']
alert_data = alert_json['full_log'] if 'full_log' in alert_json else ''

## Generate request - antigo
#msg_data = {}
#msg_data['chat_id'] = CHAT_ID
#msg_data['text'] = {}
#msg_data['text']['alert'] = "Wazuh-Alert"
#msg_data['text']['description'] =  description
#msg_data['text']['alert_level'] = str(alert_level)
#msg_data['text']['agent'] =  agent
#msg_data['text']['alert_data'] =  alert_data
#headers = {'content-type': 'application/json', 'Accept-Charset': 'UTF-8'}

# Generate request - novo
msg_data = {}
msg_data['chat_id'] = CHAT_ID
msg_data['text'] = ""
msg_data['text'] += "** \u26A1\u26A1\u26A1\u26A1\u26A1\u26A1\u26A1\u26A1 **\n\n"
msg_data['text'] += "\u203C️ GCF - Wazuh-Alert \u203C️\n\n"
msg_data['text'] += "\u2197 Description: {}\n".format(description)
msg_data['text'] += "\u2197 Alert Level: {}\n".format(str(alert_level))
msg_data['text'] += "\u2197 Agent: {}\n".format(agent)
msg_data['text'] += "\u2197 Alert Data: {}\n".format(alert_data)

# Debugging information
with open('/var/ossec/logs/integrations.log', 'a') as f:
     f.write(f'MSG: {msg_data}\n')

# Send the request
headers = {'content-type': 'application/json', 'Accept-Charset': 'UTF-8'}
response = requests.post(hook_url, headers=headers, data=json.dumps(msg_data))

# Debugging information
with open('/var/ossec/logs/integrations.log', 'a') as f:
    f.write(f'ANSWER.: {response}\n')

sys.exit(0)
