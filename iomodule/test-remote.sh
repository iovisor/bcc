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

tn1=$(curl_ localhost:5000/modules/ -d '{
  "module_type": "Tunnel", "display_name": "tn1",
  "config": {"peer_ip": "192.168.1.10"}
}' | jq .data.uuid)
br1=$(curl_ localhost:5000/modules/ -d '{
  "module_type": "Bridge", "display_name": "br1",
  "config": {"ipaddr": "10.10.1.3/24"}
}' | jq .data.uuid)
c1=$(curl_ localhost:5000/connections/ -d '{"iomodules": ['${tn1}', '${br1}']}' | jq .data.uuid)

# br1
#  |
# tn1
