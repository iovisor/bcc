import requests


server_address = "192.168.1.42"
api_address = "https://api.ipify.org"

# https://api.ipify.org should be allowed on default
print(requests.get(f"http://{server_address}/public_ip", params={"api": api_address}).content.decode())

# Now let's use an address which isn't on the allow list. This is an MAC address to Vendor API.
# If tcp_mon_block is running and filtering the Flask's server PID, this request should fail! otherwise we should receive a response
api_address = "https://api.macvendors.com/00:0c:29:de:b1:fd"

print(requests.get(f"http://{server_address}/public_ip", params={"api": api_address}).content.decode())
