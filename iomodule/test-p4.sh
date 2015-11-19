#!/bin/bash

set -x
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

#p4src=/home/bblanco/work/bcc/src/cc/frontends/p4/test/testprograms/basic_routing.p4
p4src=/home/bblanco/work/bcc/src/cc/frontends/p4/test/testprograms/simple.p4
function load_p4() {
  python -c 'import json; f = open("'$p4src'"); print(json.dumps(
{
  "module_type": "P4Switch",
  "display_name": "sw1",
  "config": {
    "p4": {
      "is_router": True,
      "text": f.read()
    }
  }
}))'
}

types=($(curl_ localhost:5000/module_types/ | jq -r .data[].name))
sw1=$(curl_ localhost:5000/modules/ -d @<(load_p4) | jq .data.uuid)
br1=$(curl_ localhost:5000/modules/ -d '{
  "module_type": "Bridge", "display_name": "br1",
  "config": {"ipaddr": "10.10.1.1/24", "mac": "a6:09:f0:00:01:01", "arp": "10.10.1.2 a6:09:f0:00:01:02"}
}' | jq .data.uuid)
br2=$(curl_ localhost:5000/modules/ -d '{
  "module_type": "Bridge", "display_name": "br2",
  "config": {"ipaddr": "10.10.1.2/24", "mac": "a6:09:f0:00:01:02", "arp": "10.10.1.1 a6:09:f0:00:01:01"}
}' | jq .data.uuid)
c1=$(curl_ localhost:5000/connections/ -d '{
  "iomodules": [
    {"uuid": '${br1}', "interface": null, "config": {}},
    {"uuid": '${sw1}', "interface": null, "config": {"nexthop": ["10.10.1.1"]}}
  ]
}' | jq .data.uuid)
c2=$(curl_ localhost:5000/connections/ -d '{
  "iomodules": [
    {"uuid": '${sw1}', "interface": null, "config": {"nexthop": ["10.10.1.2"]}},
    {"uuid": '${br2}', "interface": null, "config": {}}
  ]
}' | jq .data.uuid)

# br1 <-> sw1 <-> br2
