# Tunnel-Based Reverse Proxy (Expose) Tools Benchmarking Framework



[![DOI](https://zenodo.org/badge/1071978576.svg)](https://doi.org/10.5281/zenodo.17291653)



## Overview

This is a comprehensive framework for quantifying and assessing the performance and reliability aspects of Expose tools, such as ngrok, zrok, and Cloudflared, among others.

## Purpose and Methodology

The framework automates tunneling setup and performance measurements. The performance tests include the following:

- **Performance Metrics**:
  - **Web Metrics**: First Contentful Paint (FCP), Largest Contentful Paint (LCP), and Speed Index in milliseconds (ms); time splits (DNS lookup, TCP connection, TLS handshake, time to first byte, total time) in milliseconds (ms).
  - **File Transfer**: Sizes in bytes (B) or megabytes (MB); hash integrity (SHA-256); percent downloaded (%).
  - **Latency**: Round-trip time (RTT) in microseconds (μs); one-way latency in μs (estimated or NTP-style).

Results are JSON-formatted.

## Repository Structure

```
/
|
|- /client
|    |- /testbed (Contains all client-side scripts)
|
|- /server (Contains all server-side scripts)
|
|- /Graphing (Contains all graphing scripts)
|
|- README.md (This file)
```

## Dependencies and Setup

- **Python**: 3.12.3; `pip install fastapi uvicorn psutil colorlog cryptography stem`.
- **Node.js/TypeScript**: 18+; `npm install` for client deps (e.g., `axios`, `playwright`).
- **System**: Linux (uses `dig`, `ping`, Tor). Install Tor for .onion tools.
- **Configuration**: Edit hosts/ports; auth files for tools like Ngrok.

## Usage Instructions

1. **Setup**: Clone repo; install deps. Start servers on remote hosts.
2. **Run Servers**: `python <server_script>.py`.
3. **Run Clients**: `pnpm dlx tsx <client_script>.ts`.
4. **Analyze**: JSON in `results/` or `rtt_results/`. Use tools like Pandas for stats.

## Script Details

### Client-Side Scripts (TypeScript/Node.js)

1. `measureWebMetrics_Client.ts`
   - **Description**: Measures web page loading over tunnels using curl, Playwright, and Lighthouse. Supports 15 measurements; focuses on user-perceived performance.
   - **Key Metrics and Units**: Download/upload speeds (B/s); time splits (ms); FCP, LCP, Speed Index (ms); total times (ms).
   - **Dependencies**: `axios`, `playwright`, `speedline`, `cli-progress`, etc.
   - **Usage**: `ts-node measureWebMetrics_Client.ts`. Config: `NUM_MEASUREMENTS`, `SERVER_URL`.

2. `measureNonLimitTools_Client.ts`
   - **Description**: Evaluates non-rate-limited tools via file transfers and web tests. Verifies integrity with hashes; 15 measurements.
   - **Key Metrics and Units**: File sizes (B); speeds (B/s); time splits (ms); percent downloaded (%); durations (ms).
   - **Dependencies**: Similar to above, plus `crypto`.
   - **Usage**: `ts-node measureNonLimitTools_Client.ts`.

3. `measureLimitTools_Client.ts`
   - **Description**: Similar to non-limited variant but for rate-limited tools (5 measurements). Handles auth files (e.g., `ngrok-auth.txt`).
   - **Key Metrics and Units**: Identical to `measureNonLimitTools_Client.ts`.
   - **Usage**: `ts-node measureLimitTools_Client.ts --tool <name>`.

4. `measureRTT_Overhead_Client.ts`
   - **Description**: Focuses on latency overhead: RTT (μs), one-way latency (μs), ICMP/TCP pings (ms). Uses high-res timing; supports baselines.
   - **Key Metrics and Units**: RTT/one-way (μs); pings (ms); timestamps (μs since epoch).
   - **Dependencies**: `axios`, `net`, `child_process`.
   - **Usage**: `ts-node measureRTT_Overhead_Client.ts --tool <name> --num <requests>`.

5. `measureTrancoMetricsForProxy_Client.ts`
   - **Description**: Measures web metrics for top Tranco domains over proxies. Uses CSV for domain list; focuses on proxy performance.
   - **Key Metrics and Units**: Similar to web metrics scripts; includes FCP, LCP, Speed Index (ms).
   - **Dependencies**: `axios`, `playwright`, `csv-parse`, etc.
   - **Usage**: `ts-node measureTrancoMetricsForProxy_Client.ts`. Requires `tranco1k.csv`.

6. `tools.ts`
   - **Description**: Defines `TunnelTool` interface and implementations (e.g., Ngrok, Cloudflare, Tor-based like Onionpipe). Modular for extension.
   - **Usage**: Imported by clients; standalone testing via `main()`.

### Server-Side Scripts (Python)

1. `measureWebMetric_Server.py`, `measureLimitTools_Server.py`, `measureNonLimitTools_Server.py`
   - **Description**: FastAPI servers for web/file benchmarks. Handle file metadata/downloads, diagnostics, health checks, and heavy HTML for stress testing. Identical across variants for consistency in different scenarios (web-only, limited/non-limited throughput).
   - **Endpoints**:
     - `/files`: Lists file metadata.
     - `/download/{filename}`: Serves files with HTTP/1.1 headers.
     - `/diagnostics`: System info (CPU %, memory MB).
     - `/webtest`: Heavy HTML with images/videos/JS.
   - **Dependencies**: `fastapi`, `uvicorn`, `psutil`, `colorlog`.
   - **Usage**: `python <script>.py`. Port: 3000; logs with colors.

2. `measureRTT_Overhead_Server.py`
   - **Description**: FastAPI server for latency measurements. Supports tunnel starts/stops, socket-based one-way latency (μs), and ping measurements.
   - **Endpoints**:
     - `/start-tunnel`: Starts tool, returns URL.
     - `/stop-tunnel`: Stops active tunnel.
     - `/bc-latency`: Measures TCP pings (ms) to targets.
     - `/socket-timing`: Calculates one-way latency (μs) via keep-alive.
   - **Key Metrics and Units**: One-way latency (μs); pings (ms).
   - **Dependencies**: Similar to other servers.
   - **Usage**: `python measureRTT_Overhead_Server.py`.

3. `measurementsAPI_Server.py`
   - **Description**: Flask server for network diagnostics. Executes commands like tcptraceroute, ping, nslookup, and mtr to measure network performance through tunnels.
   - **Endpoints**:
      - `/`: Usage guide for diagnostic endpoints.
      - `/trace`: TCP traceroute (parameters: target, port).
      - `/ping`: ICMP ping (parameters: target, count).
      - `/nslookup`: DNS lookup (parameter: target).
      - `/mtr`: MTR in summary mode (parameters: target, count).
   - **Key Metrics and Units**: Latency (ms); hop counts; DNS resolution times (ms).
   - **Dependencies**: flask, system tools (tcptraceroute, ping, nslookup, mtr).
   - **Usage**: python measurementsAPI_Server.py. Runs on 127.0.0.1:8080.

3. `tunnel_tools.py`
   - **Description**: Python counterpart to `tools.ts`. Defines tunnel classes with start/stop methods; CLI for testing.
   - **Features**: Pattern matching for URLs; safe process handling.
   - **Usage**: `python tunnel_tools.py --tool <name>` or `--all`.

4. `performance.py`
   - **Description**: Monitors system resources over duration (default: 10,800 s).
   - **Key Metrics and Units**: CPU (%); RAM, disk read, network sent (MB).
   - **Dependencies**: `psutil`.
   - **Usage**: `python performance.py`.

5. `eph.py`
   - **Description**: Creates tunnel for ephemeralHiddenService. Generates X25519 keys for auth; exposes local ports as .onion.
   - **Usage**: `./eph.py --local-port 3000 [--public]`.

### Configuration Files

1. `tunnel.conf`
   - **Description**: WireGuard config for tunneling (e.g., to pyjam.as). Includes private/public keys, endpoints.

## Crowdsourced Measurements Setup

To enable network diagnostic measurements using the `measurementsAPI_Server.py` script, follow these streamlined steps:

- **Start the Server**: Launch measurementsAPI_Server.py on the server machine to run the Flask-based diagnostic API on port 8080.
- **Expose the Server**: Use a tunneling tool (e.g., Ngrok, Cloudflare) to expose port 8080 to the internet. This can be done manually or by adapting an existing server script from the framework (e.g., tunnel_tools.py).
- **Send Requests**: From the client side, access the tunnel URL and send diagnostic requests using tools like cURL or Postman. Example: curl `"http://<tunnel-url>/ping?target=example.com&count=5"`.

## Using Expose Services as SOCKS Proxies
To configure an Expose service as a SOCKS proxy for tunneling network traffic, follow these steps:
- **Set Up SOCKS Proxy on Server**: Start an SSH-based SOCKS proxy on the server machine by running:
```bash
ssh -D 1080 user@localhost
```
This binds a SOCKS proxy to port 1080 on the server.
- **Configure Expose Service**: Modify the Expose service (e.g., using a tunneling tool like Ngrok or a script like tunnel_tools.py) to forward all TCP traffic to the local port 1080 on the server.
- **Use Proxy URL on Client**: On the client machine, configure the tunnel URL provided by the Expose service as the SOCKS proxy endpoint.
- **Test the Proxy**: Verify the setup by sending a request from the client machine using the SOCKS proxy. For example:
```bash
curl --socks5 <tunnelURL>:1080 ifconfig.me
```
- This should return the public IP address of the server machine, confirming that the traffic is routed through the server rather than the client.
<hr>

> **NOTE: Tool-Specific Setup Requirements**
>
> Many tunneling tools require preliminary setup — creating accounts, obtaining auth tokens, installing binaries, or configuring system services. The implementations in `tunnel_tools.py` (Python) and `tools.ts` (TypeScript/Node.js) assume those steps are already done. Failure to complete them may cause timeouts or auth failures. Always check each tool’s official docs for the latest instructions.
>
> ### Tools Requiring Accounts & Authentication
>
> * **Ngrok:** Requires a free account and an authtoken. Sign up at ngrok.com, generate a token.
> * **Zrok:** Create an account at zrok.io
> * **Loophole:** Download the binary from loophole.cloud and create an account for authenticated tunnels. Ensure `./loophole` is executable and in your `PATH`.
> * **Beeceptor:** Create a free account at beeceptor.com. Scripts reference `./autobeeceptor.sh` or `beeceptor-cli`; create an endpoint and configure auth if required.
>
> ### Tools Requiring Binary / CLI Installation
>
> * **Cloudflared:** Install from the Cloudflare docs.
> * **Bore:** Install via `cargo install bore-cli` or download the binary from GitHub.
> * **Telebit:** Uses `pnpm dlx telebit`; install PNPM globally if absent.
> * **Loophole** Download the binary and `chmod +x` them (or put them in `PATH`).
> * **Ngtor:** Requires the JAR (e.g., `ngtor-0.1.0-boot.jar`) and a Java runtime.
> * **Onionpipe / EphemeralHiddenService:** Install via package managers or source; Ephemeral uses `eph.py`.
> * **Custom Tools (TunnelPyjamas):** Provide custom scripts like `./tunnel.pyjamas.sh`; follow that tool’s docs.
