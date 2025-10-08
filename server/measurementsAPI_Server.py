import subprocess
from flask import Flask, request, Response

app = Flask(__name__)

def execute_command(command_list):
    try:
        result = subprocess.run(
            command_list,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30
        )
        output = result.stdout.decode() + result.stderr.decode()
    except Exception as e:
        output = f"Error executing command '{' '.join(command_list)}': {e}"
    return output

@app.route("/")
def root():
    help_text = """
📡 Network Diagnostic API — Usage Guide (CLI Style)

Available Endpoints:

1. /trace         => TCP Traceroute
   Parameters:    ?target=<host>&port=<port>
   Default:       target=ifconfig.me, port=80
   Example:       curl "http://localhost:8080/trace?target=example.com&port=443"

2. /ping          => ICMP Ping
   Parameters:    ?target=<host>&count=<number_of_pings>
   Default:       target=ifconfig.me, count=4
   Example:       curl "http://localhost:8080/ping?target=example.com&count=5"

3. /nslookup      => DNS Lookup
   Parameters:    ?target=<host>
   Default:       target=ifconfig.me
   Example:       curl "http://localhost:8080/nslookup?target=example.com"

4. /mtr           => My Traceroute (summary mode)
   Parameters:    ?target=<host>&count=<packets>
   Default:       target=ifconfig.me, count=10
   Example:       curl "http://localhost:8080/mtr?target=example.com&count=10"

Note: Replace <host> and <port> with your desired values.
"""
    return Response(help_text, mimetype="text/plain")

@app.route("/trace", methods=["GET"])
def trace():
    target = request.args.get("target", "ifconfig.me")
    port = request.args.get("port", "80")
    cmd = ["tcptraceroute", target, port]
    output = execute_command(cmd)
    return Response(output, mimetype="text/plain")

@app.route("/ping", methods=["GET"])
def ping():
    target = request.args.get("target", "ifconfig.me")
    count = request.args.get("count", "4")
    cmd = ["ping", "-c", count, target]
    output = execute_command(cmd)
    return Response(output, mimetype="text/plain")

@app.route("/nslookup", methods=["GET"])
def nslookup():
    target = request.args.get("target", "ifconfig.me")
    cmd = ["nslookup", target]
    output = execute_command(cmd)
    return Response(output, mimetype="text/plain")

@app.route("/mtr", methods=["GET"])
def mtr():
    target = request.args.get("target", "ifconfig.me")
    count = request.args.get("count", "10")
    cmd = ["mtr", "-r", "-c", count, target]
    output = execute_command(cmd)
    return Response(output, mimetype="text/plain")

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8080)

