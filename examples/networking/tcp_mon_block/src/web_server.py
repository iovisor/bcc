from flask import Flask, request
import requests
import os

# Forcing requests to use IPV4 addresses only currently
requests.packages.urllib3.util.connection.HAS_IPV6 = False

app = Flask(__name__)


@app.route('/', methods=['GET'])
def index():
    return "Hello World!"


# A simple route which is vulnerable to SSRF attack.
# On normal usage, it uses an API service to get the server's public IP, this demonstrates outgoing connections from a web server
# Extra read: https://portswigger.net/web-security/ssrf
@app.route('/public_ip', methods=['GET'])
def public_ip():
    try:
        api = request.args["api"]
    except Exception as e:
        return "Missing api argument"

    # On expected connection to http://api.ipify.org the output here should be the server's public IP
    server_ip = requests.get(api).content.decode()
    return f"Server public IP is: {server_ip}"


if __name__ == '__main__':
    print(f"Web server running on PID: {str(os.getpid())}")
    app.run(host="0.0.0.0", port=80)

