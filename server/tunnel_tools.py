import subprocess
import logging
import time
import re
import requests
import os
import select
import argparse
import signal
import sys
from abc import ABC, abstractmethod
import textwrap


# ----------------- Global Process List & Safe Popen ----------------- #
child_processes = []

def safe_popen(*args, **kwargs):
    proc = subprocess.Popen(*args, **kwargs)
    child_processes.append(proc)
    return proc

# ----------------- Logging Setup ----------------- #
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
    logger = colorlog.getLogger()
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
except ImportError:
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    logger = logging.getLogger()

# ----------------- Signal Handler ----------------- #
def signal_handler(sig, frame):
    logger.info("Ctrl+C pressed. Exiting gracefully...")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

# ----------------- Helper Functions ----------------- #
def ensure_tor_running():
    """Ensure Tor is running. If not, attempt to start it."""
    try:
        subprocess.run(["pgrep", "tor"], check=True, stdout=subprocess.DEVNULL)
        logger.info("Tor service is already running.")
    except subprocess.CalledProcessError:
        logger.info("Tor is not running; attempting to start Tor service...")
        try:
            subprocess.run(["service", "tor", "start"], check=True)
            logger.info("Tor service started successfully.")
        except subprocess.CalledProcessError as e:
            raise Exception("Failed to start Tor service") from e
        
def wait_for_pattern(process, patterns, timeout):
    """Wait for regex patterns in process output. Returns first match or raises TimeoutError."""
    compiled_patterns = [re.compile(p) for p in (patterns if isinstance(patterns, list) else [patterns])]
    start = time.monotonic()
    buffers = {process.stdout: '', process.stderr: ''}  # Handle stdout/stderr buffers

    while True:
        for stream in (process.stdout, process.stderr):
            if stream is None:
                continue
            
            # Read all available data without blocking
            while True:
                rlist, _, _ = select.select([stream], [], [], 0)
                if not rlist:
                    break
                data = os.read(stream.fileno(), 4096).decode(errors='ignore')
                if not data:
                    break
                buffers[stream] += data
                logger.debug(f"Raw output chunk: {data.strip()}")

        # Check all buffers for patterns
        for stream, buffer in buffers.items():
            for pattern in compiled_patterns:
                match = pattern.search(buffer)
                if match:
                    logger.debug(f"Matched pattern '{pattern.pattern}' in buffer")
                    return match
                
            # Check for line-by-line matches (legacy fallback)
            lines = buffer.split('\n')
            for line in lines[:-1]:  # Process complete lines
                logger.debug(f"Output line: {line.strip()}")
                for pattern in compiled_patterns:
                    match = pattern.search(line)
                    if match:
                        return match

        if time.monotonic() - start > timeout:
            raise TimeoutError(f"Timeout waiting for patterns: {patterns}")

        time.sleep(0.1)
        if match:
            if not match.groups():
                return match.group(0)
            else:
                return match

# Common URL patterns
GENERAL_URL_PATTERNS = [
    r'https?://[^\s>"\'\)]+',  # Most common URL pattern
    r'\b(?:https?://)?(?:[\w-]+\.)+\w+\b'  # For URLs without scheme
]

# ----------------- Base Tunnel Class ----------------- #
class BaseTunnel(ABC):
    def __init__(self):
        self.process = None
        self.pre_setup_commands = []  # Each command is a list of strings.
        self.pre_start_commands = []
        self.post_setup_commands = []

    def run_commands(self, commands):
        for cmd in commands:
            logger.info("Running command: " + " ".join(cmd))
            subprocess.run(cmd, check=True)

    def run_pre_setup_commands(self):
        if self.pre_setup_commands:
            self.run_commands(self.pre_setup_commands)

    def run_pre_start_commands(self):
        if self.pre_start_commands:
            self.run_commands(self.pre_start_commands)

    def run_post_setup_commands(self):
        if self.post_setup_commands:
            self.run_commands(self.post_setup_commands)

    def start(self, options=None):
        if options is None:
            options = {"port": 3000, "url_pattern": r"https://[^\s]+"}
        self.run_pre_setup_commands()
        self.run_pre_start_commands()
        port = options.get("port", 3000)
        logger.info(f"Starting {self.name} on port {port}")
        url = self.launch_tunnel(options)
        return url

    @abstractmethod
    def launch_tunnel(self, options) -> str:
        """Launch the tunnel and return the URL string."""
        pass

    def stop(self):
        if self.process:
            logger.info(f"Stopping {self.name}")
            self.process.kill()
            self.process = None



# ----------------- Tunnel Implementations ----------------- #
class CloudflareTunnel(BaseTunnel):
    name = "Cloudflared"

    def launch_tunnel(self, options) -> str:
        port = options.get("port", 8000)
        self.process = subprocess.Popen(
            ["cloudflared", "tunnel", "--url", f"http://localhost:{port}"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1
        )
        try:
            # Specific pattern for Cloudflare tunnel URLs
            match = wait_for_pattern(
                self.process, 
                r"https:\/\/([a-z0-9-]+\.)+trycloudflare\.com",  # More strict pattern
                40
            )
            tunnel_url = match.group(0).strip()
            
            # Additional validation
            if "trycloudflare.com" not in tunnel_url:
                raise ValueError("Invalid tunnel URL format")
                
            logger.info(f"Cloudflare Tunnel URL: {tunnel_url}")
            return tunnel_url
        except TimeoutError as e:
            raise Exception("Timeout: Failed to start Cloudflare Tunnel") from e

class ServeoTunnel(BaseTunnel):
    name = "Serveo"

    def launch_tunnel(self, options) -> str:
        port = options.get("port", 3000)
        # Launch ssh with stderr redirected to stdout for unified output
        self.process = subprocess.Popen(
            ["ssh", "-R", f"80:localhost:{port}", "serveo.net"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,  # Redirect stderr to stdout
            text=True,
            bufsize=1
        )
        try:
            # Define a specific pattern for Serveo's output
            serveo_pattern = re.compile(r"https://[a-zA-Z0-9-]+\.serveo\.net")
            # Wait for the pattern in the combined output
            match = wait_for_pattern(self.process, [serveo_pattern], 20)
            serveo_url = match.group(0)  # Extract the full matched URL
            logger.info(f"Serveo URL: {serveo_url}")
            return serveo_url
        except TimeoutError as e:
            # Log the last few lines of output for debugging
            output = "".join(line for line in self.process.stdout if line)
            logger.error(f"Timeout: Failed to start Serveo Tunnel. Output: {output}")
            raise Exception("Timeout: Failed to start Serveo Tunnel") from e

    def stop(self):
        if self.process:
            self.process.terminate()
            self.process.wait()
            self.process = None
            logger.info("Serveo stopped successfully")

class BoreTunnel(BaseTunnel):
    name = "Bore"

    def launch_tunnel(self, options) -> str:
        port = options.get("port", 3000)
        self.process = subprocess.Popen(
            ["bore", "local", str(port), "--to", "bore.pub"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1
        )
        try:
            match = wait_for_pattern(self.process, [r"bore\.pub:\d+", r"http://bore\.pub/\w+"], 15)
            bore_id = match.group(0).split('/')[-1] if '/' in match.group(0) else match.group(0)
            return f"http://{bore_id}"
        except TimeoutError as e:
            raise Exception("Timeout: Failed to start Bore Tunnel") from e

import subprocess
import re
import requests
import logging
from threading import Thread, Event
from queue import Queue, Empty

logger = logging.getLogger(__name__)

class LocalTunnel(BaseTunnel):
    name = "LocalTunnel"
    pre_setup_commands = []
    pre_start_commands = []

    def launch_tunnel(self, options) -> str:
        port = options.get("port", 3000)
        self.process = subprocess.Popen(
            ["lt", "--port", str(port)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )

        output_queue = Queue()
        error_event = Event()
        url_event = Event()

        def read_stdout():
            for line in iter(self.process.stdout.readline, ''):
                match = re.search(r"your url is: (https://[^\s]+)", line)
                if match:
                    output_queue.put(("url", match.group(1)))
                    url_event.set()
                    break

        def read_stderr():
            for line in iter(self.process.stderr.readline, ''):
                if "error" in line.lower():
                    output_queue.put(("error", line))
                    error_event.set()
                    break

        stdout_thread = Thread(target=read_stdout)
        stderr_thread = Thread(target=read_stderr)
        stdout_thread.daemon = True
        stderr_thread.daemon = True
        stdout_thread.start()
        stderr_thread.start()

        try:
            while True:
                try:
                    event_type, value = output_queue.get(timeout=10)
                    if event_type == "url":
                        logger.info(f"LocalTunnel URL: {value}")
                        try:
                            password = self.get_tunnel_password()
                            logger.info(f"Tunnel Password: {password}")
                        except Exception as e:
                            logger.error(f"Failed to retrieve tunnel password: {e}")
                            raise
                        return value
                    elif event_type == "error":
                        raise Exception(f"Failed to start LocalTunnel: {value}")
                except Empty:
                    if url_event.is_set() or error_event.is_set():
                        continue
                    raise TimeoutError("Timeout: Failed to start LocalTunnel")
        finally:
            if self.process.poll() is None:
                self.process.terminate()
                self.process.wait()

    def get_tunnel_password(self) -> str:
        try:
            response = requests.get("https://loca.lt/mytunnelpassword")
            response.raise_for_status()
            return response.text
        except requests.exceptions.RequestException as e:
            raise Exception("Could not retrieve tunnel password") from e
        
        
class NgrokTunnel(BaseTunnel):
    name = "Ngrok"
    pre_setup_commands = [["echo", "Running pre-setup command for ngrok"]]
    pre_start_commands = [["echo", "Running pre-start command for ngrok"]]

    def launch_tunnel(self, options) -> str:
        port = options.get("port", 3000)
        url_pattern = options.get("url_pattern", r"https://[^\s]+")
        self.process = subprocess.Popen(
            ["ngrok", "http", str(port)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1
        )
        time.sleep(10)  # Allow time for ngrok to initialize.
        try:
            resp = requests.get("http://127.0.0.1:4040/api/tunnels")
            data = resp.json()
            ngrok_url = data.get("tunnels", [{}])[0].get("public_url", "")
            if ngrok_url and re.match(url_pattern, ngrok_url):
                logger.info(f"Ngrok tunnel started with URL: {ngrok_url}")
                return ngrok_url
            else:
                raise Exception("Could not retrieve ngrok URL.")
        except Exception as e:
            raise Exception("Error fetching ngrok URL") from e


class TelebitTunnel(BaseTunnel):
    name = "Telebit"
    def launch_tunnel(self, options: dict) -> str:
        port = options.get("port", 3000)
        # Use the "mode" option to select between HTTP (default) and a file-transfer–friendly mode.
        mode = options.get("mode", "http")
        logger.info(f"Starting Telebit in mode: {mode}")
        self.process = subprocess.Popen(
            ["stdbuf", "-oL", "pnpm", "dlx", "telebit", mode, str(port)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        # The expected log line now remains the same
        telebit_pattern = r"Forwarding (https://[^\s]+) =>"
        match = wait_for_pattern(self.process, telebit_pattern, 30)
        if not match:
            raise Exception("Timeout waiting for Telebit forwarding URL")
        return match.group(1)

class LocalxposeTunnel(BaseTunnel):
    name = "Localxpose"

    def launch_tunnel(self, options) -> str:
        port = options.get("port", 3000)
        # Merge stderr into stdout and remove shell=True for better reliability
        self.process = subprocess.Popen(
            ["loclx", "tunnel", "http", "--to", f"localhost:{port}"],
            stdout=subprocess.PIPE, 
            stderr=subprocess.STDOUT,  # Merge stderr with stdout
            text=True, 
            bufsize=1
        )

        try:
            match = wait_for_pattern(
                self.process,
                patterns=[
                    r"([a-z0-9]+\.loclx\.io)",  # Match just the domain part
                    *GENERAL_URL_PATTERNS
                ],
                timeout=10  # Match TypeScript's 10s timeout
            )
            # Return HTTP URL to match TypeScript behavior
            return f"http://{match.group(1)}"
        except TimeoutError as e:
            raise Exception("Timeout: Failed to start Localxpose Tunnel") from e


class ExposeTunnel(BaseTunnel):
    name = "Expose"

    def launch_tunnel(self, options) -> str:
        port = options.get("port", 3000)
        self.process = subprocess.Popen(
            ["expose", "share", f"http://localhost:{port}"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1, shell=True
        )
        try:
            match = wait_for_pattern(self.process, GENERAL_URL_PATTERNS, 20)
            expose_url = match.group(1)
            logger.info(f"Expose URL: {expose_url}")
            return expose_url
        except TimeoutError as e:
            raise Exception("Timeout: Failed to start Expose Tunnel") from e

class LoopholeTunnel(BaseTunnel):
    name = "Loophole"

    def launch_tunnel(self, options) -> str:
        port = options.get("port", 3000)
        self.process = subprocess.Popen(
            ["./loophole", "http", str(port)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True
        )

        try:
            # Updated pattern to match both output formats
            patterns = [
                r"Forwarding (https://[a-f0-9]+\.loophole\.site)\s->",  # Original format
                r"(\b[a-f0-9]{32}\.loophole\.site)\s->",  # New format without protocol
                r"(\b[a-f0-9]+\.loophole\.site)\b"  # Fallback pattern
            ]
            
            start_time = time.time()
            timeout = 20
            buffer = ""

            while time.time() - start_time < timeout:
                line = self.process.stdout.readline()
                if not line:
                    time.sleep(0.1)
                    continue

                logger.debug(f"Loophole output: {line.strip()}")

                # Check patterns in priority order
                for pattern in patterns:
                    match = re.search(pattern, line)
                    if match:
                        url_part = match.group(1)
                        # Add https:// if missing
                        full_url = f"https://{url_part}" if "://" not in url_part else url_part
                        logger.info(f"Loophole URL found: {full_url}")
                        return full_url

            raise TimeoutError("Failed to find URL within 20 seconds")

        except Exception as e:
            self.process.kill()
            output, _ = self.process.communicate()
            logger.error(f"Final output:\n{output}")
            raise Exception(f"Failed to start Loophole Tunnel: {str(e)}") from e

class PinggyTunnel(BaseTunnel):
    name = "Pinggy"

    def launch_tunnel(self, options) -> str:
        port = options.get("port", 3000)
        # Single command string with shell=True
        self.process = subprocess.Popen(
            f"ssh -p 443 -o LogLevel=ERROR -T -R0:localhost:{port} a.pinggy.io",
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            shell=True  # Required for single string command
        )

        try:
            # Pattern to match both HTTP and HTTPS URLs
            pinggy_pattern = r'https?://\S+?\.free\.pinggy\.link'
            start_time = time.time()
            timeout = 15

            while time.time() - start_time < timeout:
                line = self.process.stdout.readline()
                if not line:
                    time.sleep(0.1)
                    continue

                logger.debug(f"Pinggy output: {line.strip()}")
                match = re.search(pinggy_pattern, line)
                if match:
                    url = match.group(0).strip()
                    logger.info(f"Pinggy URL: {url}")
                    return url

            raise TimeoutError("No URL found within 15 seconds")

        except TimeoutError as e:
            self.process.kill()
            output, _ = self.process.communicate()
            logger.error(f"Pinggy output before timeout:\n{output}")
            raise Exception("Timeout: Failed to start Pinggy Tunnel") from e
        except Exception as e:
            self.process.kill()
            raise

class TailscaleTunnel(BaseTunnel):
    name = "Tailscale"

    def launch_tunnel(self, options) -> str:
        port = options.get("port", 3000)
        self.process = subprocess.Popen(
            ["tailscale", "funnel", f"{port}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        try:
            ts_pattern = r'https://\S+\.ts\.net'
            start_time = time.time()
            timeout = 45

            while time.time() - start_time < timeout:
                line = self.process.stdout.readline()
                if not line:
                    time.sleep(0.1)
                    continue

                if match := re.search(ts_pattern, line):
                    url = match.group(0).strip().rstrip('/')
                    logger.info(f"✓ Tailscale Funnel URL: {url}")
                    return url  # Do NOT terminate the process here

            raise TimeoutError("No Funnel URL detected")

        except TimeoutError as e:
            output, _ = self.process.communicate()
            logger.error(f"Tailscale output before timeout:\n{output}")
            raise Exception("Timeout: Failed to start Tailscale Tunnel") from e
        except Exception as e:
            if self.process.poll() is None:
                self.process.kill()
            raise

    def stop(self):
        if self.process and self.process.poll() is None:
            logger.info(f"Stopping {self.name}")
            self.process.terminate()
            try:
                self.process.wait(2)
            except subprocess.TimeoutExpired:
                self.process.kill()
            self.process = None
        logger.info(f"Stopped {self.name} tunnel.")


class TunnelPyjamas(BaseTunnel):
    name = "TunnelPyjamas"

    def launch_tunnel(self, options):
        """Launch the TunnelPyjamas tunnel and return the URL."""
        port = options.get("port", 3000)

        # Step 1: Download tunnel configuration
        try:
            subprocess.run(
                ["curl", f"https://tunnel.pyjam.as/{port}", "-o", "tunnel.conf"],
                check=True,
                text=True,
                capture_output=True
            )
            os.chmod("tunnel.conf", 0o600)
        except subprocess.CalledProcessError as e:
            raise Exception(f"Failed to download tunnel configuration: {e.stderr}") from e

        # Step 2: Launch the tunnel
        self.process = subprocess.Popen(
            ["sudo", "wg-quick", "up", "./tunnel.conf"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            shell=False
        )

        # Step 3: Wait for the URL in the output
        url_pattern = r"on (https://[^\s]+) ✨"
        try:
            match = self.wait_for_pattern(self.process, url_pattern, 30)
            pyjamas_url = match.group(1).rstrip("/")
            logger.info(f"TunnelPyjamas URL: {pyjamas_url}")
            return pyjamas_url
        except TimeoutError as e:
            output = ""
            while True:
                line = self.process.stdout.readline()
                if not line:
                    break
                output += line
            logger.error(f"Timeout: Failed to start tunnel. Output: {output}")
            raise Exception("Timeout: Failed to start TunnelPyjamas Tunnel") from e

    def wait_for_pattern(self, process, pattern, timeout):
        """Wait for a regex pattern in the process output with a timeout."""
        start_time = time.monotonic()
        compiled_pattern = re.compile(pattern)
        while True:
            line = process.stdout.readline()
            if line:
                logger.debug(f"Output: {line.strip()}")
                match = compiled_pattern.search(line)
                if match:
                    return match
            if time.monotonic() - start_time > timeout:
                raise TimeoutError(f"Timeout waiting for pattern: {pattern}")
            time.sleep(0.1)

    def stop(self):
        """Stop the tunnel and clean up."""
        if self.process:
            logger.info("Bringing down TunnelPyjamas tunnel.")
            try:
                subprocess.run(
                    ["sudo", "wg-quick", "down", "./tunnel.conf"],
                    check=True,
                    text=True,
                    capture_output=True
                )
                os.unlink("tunnel.conf")
                logger.info("Stopped TunnelPyjamas tunnel.")
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to bring down tunnel: {e.stderr}")
                raise Exception(f"Failed to bring down tunnel: {e.stderr}") from e
            finally:
                self.process = None


class ZrokTunnel(BaseTunnel):
    name = "Zrok"

    def launch_tunnel(self, options) -> str:
        port = options.get("port", 3000)
        # Launch Zrok with merged stdout/stderr and proper regex matching
        self.process = subprocess.Popen(
            ["zrok", "share", "public", str(port), "--headless"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,  # Combine output streams
            text=True,
            bufsize=1
        )
        try:
            # Regex to match Zrok's specific URL format (e.g., https://[id].share.zrok.io)
            zrok_pattern = r'https://\S+\.share\.zrok\.io'
            match = wait_for_pattern(self.process, zrok_pattern, 20)
            url = match.group(0).strip()
            logger.info(f"Zrok URL: {url}")
            return url
        except TimeoutError as e:
            # Include error logs for debugging
            output = self.process.stdout.read()
            logger.error(f"Zrok output before timeout: {output}")
            raise Exception("Timeout: Failed to start Zrok Tunnel") from e

class TunwgTunnel(BaseTunnel):
    name = "Tunwg"

    def launch_tunnel(self, options) -> str:
        port = options.get("port", 3000)
        self.process = subprocess.Popen(
            ["./tunwg", "-p", str(port)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1, shell=True
        )
        try:
            match = wait_for_pattern(self.process, GENERAL_URL_PATTERNS, 20)
            tunwg_url = match.group(1)
            logger.info(f"Tunwg URL: {tunwg_url}")
            return tunwg_url
        except TimeoutError as e:
            raise Exception("Timeout: Failed to start Tunwg Tunnel") from e

class PacketriotTunnel(BaseTunnel):
    name = "Packetriot"

    def launch_tunnel(self, options) -> str:
        port = options.get("port", 3000)
        self.process = subprocess.Popen(
            ["sudo", "pktriot", "http", str(port)],
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            text=True, 
            bufsize=1
        )
        
        try:
            # Match the domain from the service table
            match = wait_for_pattern(
                self.process,
                r"\| (\S+\.pktriot\.net)\s+\|",  # Capture domain from table
                timeout=20
            )
            full_url = f"http://{match.group(1)}"
            #logger.info(f"Packetriot URL: {full_url}")
            
            # # Verify basic connectivity
            # response = requests.get(full_url, timeout=10)
            # if response.status_code != 200:
            #     raise Exception(f"Connectivity check failed. Status: {response.status_code}")
                
            return full_url
            
        except TimeoutError as e:
            output = self.process.communicate()[0]
            logger.error(f"Packetriot output:\n{output}")
            raise Exception("Timeout: Failed to establish Packetriot tunnel") from e
            
        except Exception as e:
            self.process.kill()
            raise Exception(f"Packetriot tunnel verification failed: {str(e)}") from e

class BoreDigitalTunnel(BaseTunnel):
    name = "BoreDigital"

    def launch_tunnel(self, options) -> str:
        port = options.get("port", 8000)
        self.server = subprocess.Popen(
            ["./bore-server_linux_amd64"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1
        )
        time.sleep(2)
        self.process = subprocess.Popen(
            ["./bore_linux_amd64", "-s", "bore.digital", "-p", "2200", "-ls", "localhost", "-lp", str(port)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1
        )
        try:
            match = wait_for_pattern(self.process, GENERAL_URL_PATTERNS, 20)
            url = match.group(0).strip()
            logger.info(f"BoreDigital URL: {url}")
            return url
        except TimeoutError as e:
            raise Exception("Timeout: Failed to start BoreDigital Tunnel") from e

    def stop(self):
        if hasattr(self, "client") and self.client:
            self.client.kill()
        if hasattr(self, "server") and self.server:
            self.server.kill()
        logger.info(f"Stopped {self.name} tunnel.")

class LocalhostRunTunnel(BaseTunnel):
    name = "LocalhostRun"

    def launch_tunnel(self, options) -> str:
        port = options.get("port", 3000)
        self.process = subprocess.Popen(
            ["ssh", "-R", f"80:localhost:{port}", "nokey@localhost.run"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1
        )
        try:
            match = wait_for_pattern(self.process, r"(https://[^\s]+\.lhr\.life[^\s]*)", 10)
            url = match.group(0).strip()
            logger.info(f"Localhost.run URL: {url}")
            return url
        except TimeoutError as e:
            raise Exception("Timeout: Failed to start Localhost.run Tunnel") from e

    def stop(self):
        super().stop()
        logger.info(f"Stopped {self.name} tunnel.")

class DevTunnel(BaseTunnel):
    name = "DevTunnel"

    def launch_tunnel(self, options) -> str:
        port = options.get("port", 3000)
        self.process = subprocess.Popen(
            ["devtunnel", "host", "-p", str(port), "--allow-anonymous"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1
        )
        # Use a regex that excludes inspect URLs and captures the main tunnel URLs
        regex = re.compile(r'https://(?!.*-inspect)[^\s]+\.devtunnels\.ms(?::\d+)?')
        start_time = time.monotonic()
        timeout = 30  # seconds

        while True:
            # Check both stdout and stderr for the URL
            for stream in (self.process.stdout, self.process.stderr):
                if stream is None:
                    continue
                # Read all available data
                while True:
                    line = stream.readline()
                    if not line:
                        break
                    # Search for the first matching URL
                    match = regex.search(line)
                    if match:
                        url = match.group(0)
                        logger.info(f"DevTunnel URL: {url}")
                        return url
            # Check timeout
            if time.monotonic() - start_time > timeout:
                raise Exception("Timeout: Failed to get devtunnel URL")
            time.sleep(0.1)

    def stop(self):
        super().stop()
        logger.info(f"Stopped {self.name} tunnel.")


class Btunnel(BaseTunnel):
    name = "Btunnel"

    def launch_tunnel(self, options) -> str:
        port = options.get("port", 3000)
        self.process = subprocess.Popen(
            ["./btunnel", "http", "--port", str(port), "-k", "JDJhJDEyJEYwLnRIUEVRMHEvbGlvczNmMTFSVnVaTEtoOGFObmhScHZNSHN6U3VYTHFGdmxyMWdteUUu"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1, shell=True
        )
        try:
            match = wait_for_pattern(self.process, GENERAL_URL_PATTERNS, 20)
            url = match.group(1).strip()
            logger.info(f"Btunnel URL: {url}")
            return url
        except TimeoutError as e:
            raise Exception("Timeout: Failed to start Btunnel") from e

class BeeceptorTunnel(BaseTunnel):
    name = "Beeceptor"
    
    def launch_tunnel(self, options) -> str:
        port = options.get("port", 3000)
        self.process = subprocess.Popen(
            ["./autobeeceptor.sh"],
            stdin=subprocess.PIPE, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            text=True, 
            bufsize=1
        )
        
        try:
            # Match the tunnel URL from the "Now tunneling" message
            match = wait_for_pattern(
                self.process,
                r"from (https://\S+\.free\.beeceptor\.com) to",  # Capture tunnel URL
                timeout=15
            )
            base_url = match.group(1).strip()
            return base_url
            
        except TimeoutError as e:
            output = self.process.communicate()[0]
            logger.error(f"Startup output:\n{output}")
            raise Exception("Timeout: Failed to establish Beeceptor tunnel") from e
            
        except Exception as e:
            self.process.kill()
            raise Exception(f"Beeceptor tunnel verification failed: {str(e)}") from e

    def stop(self):
        if self.process:
            logger.info("Terminating Beeceptor tunnel...")
            self.process.terminate()
            try:
                self.process.wait(5)
            except subprocess.TimeoutExpired:
                self.process.kill()

class OpenportTunnel(BaseTunnel):
    name = "Openport"

    def launch_tunnel(self, options) -> str:
        port = options.get("port", 3000)
        logger.info("Starting Openport tunnel...")
        self.process = subprocess.Popen(
            ["openport", str(port)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1
        )
        main_port = None
        start_time = time.monotonic()
        timeout = 60
        while time.monotonic() - start_time < timeout:
            for stream in (self.process.stdout, self.process.stderr):
                if stream is None:
                    continue
                rlist, _, _ = select.select([stream], [], [], 0.1)
                if rlist:
                    line = stream.readline()
                    if line:
                        port_match = re.search(r"forwarding remote port (spr\.openport\.io:\d+)", line)
                        if port_match and not main_port:
                            main_port = port_match.group(1)
                            logger.info(f"✓ Port allocated: {main_port}")
                        auth_match = re.search(r"first visit (https://spr\.openport\.io/l/\d+/\w+)", line)
                        if auth_match and main_port:
                            auth_url = auth_match.group(1)
                            logger.info(f"✓ Auth URL found: {auth_url}")
                            try:
                                response = requests.get(auth_url)
                                if response.status_code == 200:
                                    final_url = f"http://{main_port}"
                                    logger.info("✓ Authentication successful!")
                                    logger.info(f"✓ Final URL: {final_url}")
                                    return final_url
                            except Exception as err:
                                raise Exception(f"Failed to authenticate: {err}") from err
        raise Exception("Timeout: Failed to start Openport Tunnel")

    def stop(self):
        if self.process:
            logger.info("Stopping Openport tunnel...")
            self.process.kill()
            logger.info(f"✓ Stopped {self.name} tunnel")

import subprocess
import logging

# Assuming logger is already configured in tunnel_tools.py
logger = logging.getLogger("epic_server")

class NgtorTunnel(BaseTunnel):
    name = "Ngtor"

    def launch_tunnel(self, options) -> str:
        """Launch the ngtor tunnel and return the onion URL."""
        port = options.get("port", 3000)
        ensure_tor_running()
        self.process = subprocess.Popen(
            ["./ngtor-0.1.0-boot.jar", "http", f"--port={port}"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1
        )
        try:
            match = wait_for_pattern(self.process, r'http://[a-z2-7]{56}\.onion', 40)
            onion_url = match.group(0)
            logger.info(f"Ngtor Onion URL: {onion_url}")
            return onion_url
        except TimeoutError as e:
            raise Exception("Timeout: Failed to start Ngtor Tunnel") from e

    def stop(self):
        """Stop the ngtor tunnel and terminate the Tor processes."""
        # First, stop the ngtor process using the parent method
        super().stop()
        # Then, attempt to kill all Tor processes
        try:
            subprocess.run(["sudo", "pkill", "tor"], check=True)
            logger.info("Successfully executed sudo pkill tor")
        except subprocess.CalledProcessError as e:
            if e.returncode == 1:
                logger.info("No tor process found to kill")
            else:
                logger.error(f"Failed to execute sudo pkill tor: {e}")

import re
import time
import subprocess

class EphemeralHiddenServiceTunnel(BaseTunnel):
    name = "EphemeralHiddenService"

    def launch_tunnel(self, options) -> str:
        port = options.get("port", 3000)
        ensure_tor_running()

        self.process = subprocess.Popen(
            ["python3", "-u", "eph.py", "-lp", str(port), "--public"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, bufsize=1
        )

        onion_pattern = re.compile(r"localhost:3000 is exposed at ([a-zA-Z0-9]{16,56}\.onion)(:\d+)?")
        start_time = time.time()
        timeout = 60  # Increase timeout to 60 seconds

        while True:
            line = self.process.stdout.readline()
            if not line:
                break  # If no more output, exit loop

            logger.info(f"[eph.py] {line.strip()}")  # Log each output line

            # Try to extract the .onion URL
            match = onion_pattern.search(line)
            if match:
                onion_url = f"http://{match.group(1)}"  # Ensure it includes "http://"
                logger.info(f"✅ Ephemeral Hidden Service URL: {onion_url}")
                return onion_url

            # Timeout handling
            if time.time() - start_time > timeout:
                logger.error("❌ Timeout: Failed to start Ephemeral Hidden Service")
                self.process.kill()
                raise Exception("Timeout: Failed to start Ephemeral Hidden Service")

        logger.error("❌ No .onion URL found in eph.py output")
        self.process.kill()
        raise Exception("Failed to retrieve .onion URL")



class OnionpipeTunnel(BaseTunnel):
    name = "Onionpipe"

    def launch_tunnel(self, options) -> str:
        port = options.get("port", 3000)
        ensure_tor_running()
        self.process = subprocess.Popen(
            ["onionpipe", str(port)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1
        )
        start = time.monotonic()
        while True:
            for stream in (self.process.stdout, self.process.stderr):
                if stream is None:
                    continue
                rlist, _, _ = select.select([stream], [], [], 0.1)
                if rlist:
                    line = stream.readline()
                    if line:
                        match = re.search(r"([a-z2-7]{16,56}\.onion):80", line)
                        if match:
                            onion_url = match.group(1)
                            logger.info(f"Onionpipe URL: {onion_url}")
                            return onion_url
            if time.monotonic() - start > 30:
                raise Exception("Timeout: Failed to start Onionpipe Tunnel")

    def stop(self):
        super().stop()

# ----------------- List of Tunnel Tools ----------------- #
tunnel_tools = [
    NgrokTunnel(),
    CloudflareTunnel(),
    ZrokTunnel(),
    ServeoTunnel(),
    TelebitTunnel(),
    BoreTunnel(),
    LoopholeTunnel(),
    PinggyTunnel(),
    OnionpipeTunnel(),
    NgtorTunnel(),
    BeeceptorTunnel(),
    TunnelPyjamas(),
    EphemeralHiddenServiceTunnel(),
]

# ----------------- CLI & Execution Functions ----------------- #
def print_header():
    header = textwrap.dedent("""\
    ===========================================
         Tunnel Tools Tester - CLI Utility
    ===========================================
    """)
    print(header)

def list_tools():
    print("Available Tunnel Tools:")
    for idx, tool in enumerate(tunnel_tools, start=1):
        print(f"  {idx}. {tool.name}")
    print()

def execute_tool(tool, options=None) -> bool:
    try:
        logger.info(f"Testing {tool.name} ...")
        url = tool.start(options)
        logger.info(f"✓ {tool.name} - URL: {url}")
        tool.stop()
        return True
    except Exception as e:
        logger.error(f"✗ {tool.name} - Error: {e}")
        return False

def run_all_tools(options=None):
    success_count = 0
    fail_count = 0
    for tool in tunnel_tools:
        if execute_tool(tool, options):
            success_count += 1
        else:
            fail_count += 1
    print("\nResults:")
    print(f"  ✓ Successful: {success_count}")
    print(f"  ✗ Failed: {fail_count}")
    print(f"  Total tools: {len(tunnel_tools)}")

def main():
    print_header()
    parser = argparse.ArgumentParser(
        description="Test tunnel tools by launching and stopping each tunnel."
    )
    parser.add_argument(
        "-t", "--tool", type=str, help="Tool number or name to test (e.g., '1' or 'LocalTunnel')"
    )
    parser.add_argument(
        "--all", action="store_true", help="Test all available tools."
    )
    parser.add_argument(
        "--port", type=int, default=3000, help="Port to use for testing tunnels."
    )
    args = parser.parse_args()

    options = {"port": args.port, "url_pattern": r"https://[^\s]+"}

    try:
        if args.all:
            logger.info("Running all tunnel tool tests...")
            run_all_tools(options)
        elif args.tool:
            list_tools()
            tool = None
            if args.tool.isdigit():
                index = int(args.tool) - 1
                if 0 <= index < len(tunnel_tools):
                    tool = tunnel_tools[index]
            else:
                for t in tunnel_tools:
                    if t.name.lower() == args.tool.lower():
                        tool = t
                        break
            if tool:
                logger.info(f"Testing tool: {tool.name}")
                if execute_tool(tool, options):
                    logger.info("Test completed successfully.")
                else:
                    logger.error("Test failed.")
            else:
                logger.error("Invalid tool selection. Please check the available tools below:")
                list_tools()
        else:
            list_tools()
            selection = input('Enter the number or name of the tool to test (or "all" to test all): ').strip()
            if selection.lower() == "all":
                run_all_tools(options)
            else:
                tool = None
                if selection.isdigit():
                    index = int(selection) - 1
                    if 0 <= index < len(tunnel_tools):
                        tool = tunnel_tools[index]
                else:
                    for t in tunnel_tools:
                        if t.name.lower() == selection.lower():
                            tool = t
                            break
                if tool:
                    logger.info(f"Testing tool: {tool.name}")
                    if execute_tool(tool, options):
                        logger.info("Test completed successfully.")
                    else:
                        logger.error("Test failed.")
                else:
                    logger.error("Invalid selection. Exiting.")
    except KeyboardInterrupt:
        logger.info("KeyboardInterrupt received. Exiting.")
    except Exception as ex:
        logger.error(f"Error: {ex}")

if __name__ == '__main__':
    main()

# ----------------- End of tools.py ----------------- #
