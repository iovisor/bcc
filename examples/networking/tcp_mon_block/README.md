# eBPF tcp_mon_block

This eBPF program uses netlink TC, kernel tracepoints and kprobes to monitor outgoing connections from given PIDs (usually HTTP web servers) and block connections to all addresses initiated from them, unless they are listed in allow_list.json 

To run the example:

    1. Run python3 web_server.py . Note the server's PID (will be printed to stdout)
    2. Add the server's PID to allow_list.json . You can replace the first entry on the JSON file and put your PID instead
    3. Run tcp_mon_block.py -i network_interface_name (-v for verbose output). For example: python3 tcp_mon_block.py -i eth0
    4. Put your web_server's listening IP in 'server_address' variable in http_client.py and run python3 http_client.py 

**Explanation**:

web_server.py is a simple HTTP web server built with flask. It has a SSRF vulnerability in the route to /public_ip  (you can read more about this vulnerability here https://portswigger.net/web-security/ssrf).

This route demonstrates a web server which connects to some remote API server (which is pretty common behavior) and receives some data. The attached POC simply connects to https://api.ipify.org and fetches the server's public IP, then sends it back to the client.  
However, this specific route receives the API address to connect to from the user (http_client.py is used as the client in this POC, but in real life scenarios it will probably be a web browser). 

This creates a SSRF vulnerability as an attacker can put any address he/she wishes to force the web server to connect to it instead of the intended API address (https://api.ipify.org)

**Run the POC twice:** 

**First**, run only web_server.py and http_client.py . http_client.py will send 2 requests to the web server:

    - The first one send HTTP GET request to the web server with 'https://api.ipify.org' address as the 'api' parameter, as intended to be used by the web server.
    - The second one sends HTTP GET request to the web server with 'https://api.macvendors.com' address as the 'api' parameter. This exploits the vulnerability, as it forces the web server to connect to a different address than intended at /public_ip route.


**Now run the POC again**

First run web_server.py but this time add the web server's PID to allow_list.json and then run tcp_mon_block.py as mentioned earlier. 

This will make sure the web server will only connect to the predefined allow_list of addresses (this can be either an IPv4, URL or domain name), essentially blocking any connection to any address not listed in the allow_list.

Lastly, run http_client.py again:

    - The first reqeusts sends HTTP GET request to the web server with 'https://api.ipify.org' address as the 'api' parameter, as intended to be used by the web server.
    - The second reqeusts sends HTTP GET request to the web server with 'https://api.macvendors.com' address as the 'api' parameter. This time the exploitation attempt will be blocked by tcp_mon_block.py and the client should receive an error.


Monitoring started:

![alt text](https://github.com/agentzex/ebpf_tcp_mon_block/blob/main/screenshots/1.JPG)


After web_server.py initiated a connection to a non-allowed address:

![alt text](https://github.com/agentzex/ebpf_tcp_mon_block/blob/main/screenshots/2.JPG)



**Prerequisites**: 

    1. BCC and pyroute2 for tcp_mon_block
    2. Python3 flask and requests in order to run the web_server.py and http_client.py POC
    3. Tested on Ubuntu with kernel version 5.15.0-57

