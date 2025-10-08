from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
import uvicorn
import os
import asyncio
import json
import datetime
import logging
import signal
import sys
import time
import re
import subprocess
import socket
from pydantic import BaseModel, Field
from tunnel_tools import tunnel_tools
from contextlib import asynccontextmanager

# ---------------- Global Constants and Variables ---------------- #
PORT = 3000
BC_LATENCY_RESULTS_DIR = os.path.join(os.path.dirname(__file__), "bc_latency_results")
os.makedirs(BC_LATENCY_RESULTS_DIR, exist_ok=True)
active_tunnel = None

# ---------------- Logging Setup ---------------- #
try:
    import colorlog
    handler = colorlog.StreamHandler()
    formatter = colorlog.ColoredFormatter(
        "%(log_color)s%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        log_colors={
            'DEBUG':    'cyan',
            'INFO':     'green',
            'WARNING':  'yellow',
            'ERROR':    'red',
            'CRITICAL': 'bold_red',
        }
    )
    handler.setFormatter(formatter)
    logger = colorlog.getLogger("epic_server")
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
except ImportError:
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    logger = logging.getLogger("epic_server")

# ---------------- FastAPI Lifespan ---------------- #
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("🚀 Server startup")
    yield
    if active_tunnel:
        logger.info("🛑 Shutting down active tunnel")
        try:
            await asyncio.get_event_loop().run_in_executor(None, active_tunnel.stop)
        except Exception as e:
            logger.error(f"Error stopping active tunnel during shutdown: {str(e)}")
    logger.info("🛑 Server shutdown")

app = FastAPI(
    title="HTTP Keep-Alive Latency Server",
    description="HTTP-wrapped socket latency measurement with post-handshake timing via keep-alive",
    version="2.0",
    lifespan=lifespan
)

# ---------------- Signal Handling ---------------- #
def signal_handler(sig, frame):
    logger.info("Ctrl+C detected. Shutting down gracefully.")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

# ---------------- BC Latency Helper Functions ---------------- #
def resolve_ip_with_dig(host: str) -> str:
    """Resolve hostname to IP using dig +short with IPv4 validation."""
    logger.info(f"Resolving hostname {host} with dig +short...")
    try:
        result = subprocess.run(['dig', '+short', host], capture_output=True, text=True, check=True)
        output = result.stdout.strip()
        if not output:
            raise ValueError("No IP address returned")
        # Regex for valid IPv4
        ipv4_regex = r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        # Split output into lines and find first valid IPv4
        lines = [line.strip() for line in output.split('\n') if line.strip()]
        for line in lines:
            if re.match(ipv4_regex, line):
                logger.info(f"Resolved {host} to IP {line}")
                return line
        raise ValueError("No valid IPv4 address found")
    except Exception as e:
        logger.error(f"Failed to resolve {host} with dig: {str(e)}")
        return ""

def measure_tcp_ping_py(host: str, port: int, count: int = 33, timeout: int = 60) -> dict:
    """
    Measures TCP latency by pinging the host 33 times.
    The first 3 pings are ignored in the average calculation.
    Results include both RTT and one-way (RTT/2) estimates.
    """
    ip = resolve_ip_with_dig(host)
    if not ip:
        return {
            "type": "tcp",
            "times_ms": [],
            "average_ms": 0,
            "one_way_average_ms": 0,
            "error": f"Failed to resolve {host}",
            "resolved_ip": ""
        }

    logger.info(f"Pinging {ip}:{port} {count} times (TCP)...")
    times_ms = []
    for _ in range(count):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        start_time = time.perf_counter()
        try:
            s.connect((ip, port))
            end_time = time.perf_counter()
            times_ms.append((end_time - start_time) * 1000)
        except Exception:
            pass
        finally:
            s.close()
    
    # Ignore the first 3 pings for a more stable average
    valid_times = times_ms[3:] if len(times_ms) > 3 else []
    average = sum(valid_times) / len(valid_times) if valid_times else 0
    one_way_average = average / 2  # Divide by 2 for one-way estimate
    
    logger.info(f"TCP Ping to {ip}:{port} successful. RTT Average (excluding first 3): {average:.2f} ms, One-way: {one_way_average:.2f} ms")
    return {
        "type": "tcp",
        "times_ms": valid_times,
        "average_ms": average,
        "one_way_average_ms": one_way_average,
        "resolved_ip": ip
    }

# ---------------- Pydantic Models ---------------- #
class LatencyMeasurePayload(BaseModel):
    target_host: str = Field(..., description="The hostname or IP of the rendezvous point (B).")
    target_port: int = Field(..., description="The port of the rendezvous point (B).")
    tool_name: str = Field(..., description="The name of the tool being tested (e.g., 'ngrok').")

# ---------------- API Endpoints ---------------- #
@app.post("/start-tunnel")
async def start_tunnel(payload: dict):
    global active_tunnel
    tool_name = payload.get("toolName")
    if not tool_name:
        raise HTTPException(status_code=400, detail="toolName is required.")
    tool = next((t for t in tunnel_tools if t.name.lower() == tool_name.lower()), None)
    if not tool:
        raise HTTPException(status_code=400, detail=f"Invalid tool name: {tool_name}")
    try:
        if active_tunnel:
            await asyncio.get_event_loop().run_in_executor(None, active_tunnel.stop)
        loop = asyncio.get_event_loop()
        url = await loop.run_in_executor(None, tool.start, {"port": PORT})
        active_tunnel = tool
        return JSONResponse({"url": url})
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to start tunnel: {str(e)}")

@app.post("/stop-tunnel")
async def stop_tunnel():
    global active_tunnel
    if active_tunnel:
        try:
            await asyncio.get_event_loop().run_in_executor(None, active_tunnel.stop)
            active_tunnel = None
            return JSONResponse({"message": "Tunnel stopped"})
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to stop tunnel: {str(e)}")
    return JSONResponse({"message": "No active tunnel"})

@app.post("/measure-latency")
async def measure_bc_latency(payload: LatencyMeasurePayload):
    """
    Measures latency from this server (C) to a specified target host (B).
    Results are saved in a single timestamped directory under bc_latency_results,
    with each tool's results saved as <toolname>.json.
    Returns the file content in the response.
    """
    logger.info(f"Received request to measure latency for tool '{payload.tool_name}' to {payload.target_host}:{payload.target_port}")
    try:
        time.sleep(10)
        tcp_results = measure_tcp_ping_py(payload.target_host, payload.target_port)

        results_data = {
            "tool_name": payload.tool_name,
            "target_host": payload.target_host,
            "target_port": payload.target_port,
            "measurement_timestamp_utc": datetime.datetime.utcnow().isoformat(),
            "measurements": {"tcp": tcp_results},
            "resolved_target_ip": tcp_results.get("resolved_ip", "")
        }

        global timestamp_dir
        if 'timestamp_dir' not in globals():
            timestamp_dir = datetime.datetime.utcnow().strftime('%Y-%m-%d_%H%M%S')
            os.makedirs(os.path.join(BC_LATENCY_RESULTS_DIR, timestamp_dir), exist_ok=True)

        sanitized_tool_name = re.sub(r'[^\w-]', '', payload.tool_name)
        filename = f"{sanitized_tool_name}.json"
        filepath = os.path.join(BC_LATENCY_RESULTS_DIR, timestamp_dir, filename)

        with open(filepath, 'w') as f:
            json.dump(results_data, f, indent=2)

        with open(filepath, 'r') as f:
            file_content = json.load(f)

        logger.info(f"✅ Successfully saved BC latency results to {filepath}")
        return JSONResponse(
            status_code=200,
            content={
                "message": "BC latency measurement completed successfully.",
                "results_file": filepath,
                "results_data": file_content
            }
        )

    except Exception as e:
        logger.error(f"❌ Failed to measure BC latency: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to measure BC latency: {str(e)}")

@app.post("/socket-timing")
async def socket_timing(request: Request):
    """
    Receives client timestamp (post-handshake via HTTP keep-alive) and calculates one-way latency.
    The connection is already established, so handshake time is not included.
    
    Protocol:
    1. Client establishes HTTP connection (handshake)
    2. Client sends POST with plain text body containing t1 (client timestamp in microseconds)
    3. Server receives t1, records t2 immediately
    4. Server calculates one_way_latency = t2 - t1
    5. Server sends back JSON with one_way_latency_us
    """
    try:
        # Get server receive time with microsecond precision
        t2_us = int(time.time() * 1_000_000)
        
        # Read client timestamp from request body (plain text)
        body = await request.body()
        t1_us = int(body.decode('utf-8').strip())
        
        # Calculate one-way latency (server time - client time)
        one_way_latency_us = t2_us - t1_us
        
        logger.info(f"Socket-based measurement: Client t1={t1_us}µs, Server t2={t2_us}µs, Latency={one_way_latency_us}µs")
        
        return JSONResponse({
            "status": "ok",
            "client_timestamp_us": t1_us,
            "server_timestamp_us": t2_us,
            "one_way_latency_us": one_way_latency_us
        })
    except Exception as e:
        logger.error(f"Error in socket timing: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Socket timing failed: {str(e)}")

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    now = datetime.datetime.utcnow()
    timestamp_str = now.strftime("%Y-%m-%dT%H:%M:%S.%f")
    return JSONResponse({"status": "ok", "timestamp": timestamp_str})

if __name__ == '__main__':
    uvicorn.run("measureRTT_Overhead_Server:app", host="0.0.0.0", port=PORT, reload=True)