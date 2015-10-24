#!/bin/bash

#set -x
set -e

function curl_() {
  local ret
  ret=$(curl -Lks -HContent-Type:application/json -HAccept:application/json \
    --write-out "%{http_code}" -o /tmp/rest_result "$@")
  if [[ $ret -ge 400 ]]; then
    cat 1>&2 /tmp/rest_result
    exit 1
  fi
  cat /tmp/rest_result
  rm -f /tmp/rest_result
  return 0
}

types=($(curl_ localhost:5000/module_types/ | jq -r .data[].name))
tn1=$(curl_ localhost:5000/modules/ -d '{
  "module_type": "Tunnel", "display_name": "tn1",
  "config": {"peer_ip": "192.168.1.20"}
}' | jq .data.uuid)
br1=$(curl_ localhost:5000/modules/ -d '{
  "module_type": "Bridge", "display_name": "br1",
  "config": {"ipaddr": "10.10.1.1/24"}
}' | jq .data.uuid)
br2=$(curl_ localhost:5000/modules/ -d '{
  "module_type": "Bridge", "display_name": "br2",
  "config": {"ipaddr": "10.10.1.2/24"}
}' | jq .data.uuid)
pt1=$(curl_ localhost:5000/modules/ -d '{"module_type": "Passthrough", "display_name": "pt1"}' | jq .data.uuid)
pt2=$(curl_ localhost:5000/modules/ -d '{"module_type": "Passthrough", "display_name": "pt2"}' | jq .data.uuid)
c1=$(curl_ localhost:5000/connections/ -d '{
  "iomodules": [
    {"uuid": '${br1}', "interface": null},
    {"uuid": '${pt1}', "interface": null}
  ]
}' | jq .data.uuid)
c2=$(curl_ localhost:5000/connections/ -d '{
  "iomodules": [
    {"uuid": '${pt1}', "interface": null},
    {"uuid": '${pt2}', "interface": null}
  ]
}' | jq .data.uuid)
c3=$(curl_ localhost:5000/connections/ -d '{
  "iomodules": [
    {"uuid": '${pt2}', "interface": null},
    {"uuid": '${br2}', "interface": null}
  ]
}' | jq .data.uuid)
c4=$(curl_ localhost:5000/connections/ -d '{
  "iomodules": [
    {"uuid": '${tn1}', "interface": null},
    {"uuid": '${br1}', "interface": null}
  ]
}' | jq .data.uuid)

# br1 <-> pt1 <-> pt2 <-> br2
#  |
# tn1
