import axios from 'axios';
import { performance } from 'perf_hooks';
import fs from 'fs/promises';
import path from 'path';
import chalk from 'chalk';
import cliProgress from 'cli-progress';
import { SocksProxyAgent } from 'socks-proxy-agent';
import { TunnelTool, tunnelTools } from './tools';
import { hrtime } from 'process';
import net from 'net';
import { spawnSync } from 'child_process';

/**
 * Configuration Constants
 */
const SERVER_HOST = '';
const SERVER_PORT = 3000;
const SERVER_URL = `http://${SERVER_HOST}:${SERVER_PORT}`;
const DEFAULT_NUM_REQUESTS = 10;
const ENABLE_LOGGING = false;
const RESULTS_DIR = 'rtt_results';

/**
 * Interfaces for Data Structures
 */
interface RTTMeasurement {
  requestNumber: number;
  timestamp: number; // Microseconds since Unix epoch
  rtt: number; // Microseconds
  statusCode: number;
  error?: string;
}

interface NtpOneWayMeasurement {
  requestNumber: number;
  timestamp: number; // Microseconds since Unix epoch
  oneWayLatency: number; // Microseconds
  statusCode: number;
  error?: string;
}

interface PingMeasurement {
  type: 'icmp' | 'tcp';
  times: number[]; // ms
  average: number; // ms
}

interface RunResult {
  tool: string;
  tunnelUrl: string;
  rttMeasurements: RTTMeasurement[];
  averageRtt: number; // Microseconds
  estimatedOneWayFromRtt: number; // Microseconds
  ntpOneWayMeasurements: NtpOneWayMeasurement[];
  averageNtpOneWay: number; // Microseconds
  duration: number; // Milliseconds
  errors: { stage: string; error: string }[];
  abPings?: { icmp: PingMeasurement; tcp: PingMeasurement };
}

/**
 * Helper to get absolute time in microseconds
 */
let baseDateUs: bigint;
let baseHr: bigint;
function initializeHighResTime() {
  baseDateUs = BigInt(Date.now()) * 1000n;
  baseHr = hrtime.bigint() / 1000n; // to microseconds
}

function getAbsoluteUs(): bigint {
  const currentHr = hrtime.bigint() / 1000n;
  return baseDateUs + (currentHr - baseHr);
}

/**
 * Parse ISO timestamp with microseconds to microseconds since Unix epoch
 * @param iso ISO string like "2025-08-25T12:34:56.789012"
 * @returns BigInt microseconds
 */
function parseIsoToUs(iso: string): bigint {
  const match = iso.match(/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})\.(\d{6})$/);
  if (!match) throw new Error('Invalid ISO format');
  const [, year, month, day, hour, min, sec, usStr] = match;
  const dt = new Date(Date.UTC(parseInt(year), parseInt(month) - 1, parseInt(day), parseInt(hour), parseInt(min), parseInt(sec)));
  const ms = BigInt(dt.getTime());
  const us = BigInt(usStr);
  return ms * 1000n + us;
}
function sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
}
/**
 * Resolve hostname to IP using dig +short
 * @param host The hostname to resolve
 * @returns The resolved IP address or empty string if resolution fails
 */
function resolveIpWithDig(host: string): string {
  console.log(chalk.cyan(`Resolving ${host} with dig +short...`));
  try {
    const res = spawnSync('dig', ['+short', host]);
    if (res.error || res.status !== 0) {
      throw new Error(res.error?.message || res.stderr.toString());
    }
    const output = res.stdout.toString().trim();
    if (!output) {
      throw new Error('No IP address returned');
    }
    // Take the first IP address
    const ip = output.split('\n')[0];
    console.log(chalk.cyan(`Resolved ${host} to IP ${ip}`));
    return ip;
  } catch (error) {
    console.error(chalk.red(`Failed to resolve ${host} with dig: ${(error as Error).message}`));
    return '';
  }
}

/**
 * Measures ICMP ping using system 'ping' command to the resolved IP
 * @param host The host to resolve and ping
 * @param count Number of pings to send
 * @returns Ping measurement with times and average in ms
 */
function measureIcmpPing(host: string, count: number = 13): PingMeasurement {
  const ip = resolveIpWithDig(host);
  if (!ip) {
    return { type: 'icmp', times: [], average: 0 };
  }

  console.log(chalk.cyan(`Pinging ${ip} ${count} times (ICMP)...`));
  const res = spawnSync('ping', ['-c', count.toString(), ip]);
  if (res.error || res.status !== 0) {
    console.error(chalk.red(`ICMP ping to ${ip} failed: ${res.error?.message || res.stderr.toString()}`));
    return { type: 'icmp', times: [], average: 0 };
  }
  const output = res.stdout.toString();
  const times: number[] = [];
  const lines = output.split('\n');
  for (const line of lines) {
    const match = line.match(/time=([\d.]+) ms/);
    if (match) {
      times.push(parseFloat(match[1]));
    }
  }
  // Ignore the first 3 pings
  const validTimes = times.slice(3);
  const average = validTimes.length ? validTimes.reduce((a, b) => a + b, 0) / validTimes.length : 0;
  return { type: 'icmp', times: validTimes, average };
}

/**
 * Measures TCP ping using socket connection to the resolved IP
 * @param host The host to resolve and ping
 * @param port The port to connect to
 * @param count Number of pings to send
 * @returns Ping measurement with times and average in ms
 */
async function measureTcpPing(host: string, port: number, count: number = 13): Promise<PingMeasurement> {
  const ip = resolveIpWithDig(host);
  if (!ip) {
    return { type: 'tcp', times: [], average: 0 };
  }

  console.log(chalk.cyan(`Pinging ${ip}:${port} ${count} times (TCP)...`));
  const times: number[] = [];
  for (let i = 0; i < count; i++) {
    const start = performance.now();
    await new Promise<void>((resolve) => {
      const socket = net.connect(port, ip, () => {
        const end = performance.now();
        times.push(end - start);
        socket.destroy();
        resolve();
      });
      socket.setTimeout(2000);
      socket.on('error', () => {
        socket.destroy();
        resolve();
      });
      socket.on('timeout', () => {
        socket.destroy();
        resolve();
      });
    });
  }
  // Ignore the first 3 pings
  const validTimes = times.slice(3);
  const average = validTimes.length ? validTimes.reduce((a, b) => a + b, 0) / validTimes.length : 0;
  return { type: 'tcp', times: validTimes, average };
}

/**
 * Measures RTT using high-precision timing
 * @param targetUrl The URL to test
 * @param numRequests Number of requests to send
 * @returns Array of RTT measurements
 */
async function measureRTT(targetUrl: string, numRequests: number): Promise<RTTMeasurement[]> {
  const measurements: RTTMeasurement[] = [];
  const healthUrl = `${targetUrl.replace(/\/$/, '')}/health`;
  const isOnion = targetUrl.includes('.onion');
  const agent = isOnion ? new SocksProxyAgent('socks5h://127.0.0.1:9050') : undefined;
  const progressBar = new cliProgress.SingleBar({
    format: chalk.green('RTT Measurement | {bar} | {percentage}% | {value}/{total} Requests'),
    barCompleteChar: '\u2588',
    barIncompleteChar: '\u2591',
    hideCursor: true,
  }, cliProgress.Presets.shades_classic);
  progressBar.start(numRequests, 0);

  for (let i = 0; i < numRequests; i++) {
    const measurement: RTTMeasurement = {
      requestNumber: i + 1,
      timestamp: Number(getAbsoluteUs()),
      rtt: 0,
      statusCode: 0,
    };

    try {
      const start = hrtime.bigint();
      const response = await axios.get(healthUrl, {
        timeout: 10000,
        httpAgent: agent,
        httpsAgent: agent,
      });
      const end = hrtime.bigint();
      const diff = end - start;
      measurement.rtt = Number(diff / 1000n); // Nanoseconds to microseconds
      measurement.statusCode = response.status;
      if (ENABLE_LOGGING) console.log(chalk.blue(`Request ${i + 1}: RTT = ${measurement.rtt} μs, Status = ${response.status}`));
    } catch (error) {
      measurement.error = (error as Error).message;
      if (ENABLE_LOGGING) console.error(chalk.red(`Request ${i + 1} failed: ${measurement.error}`));
    }

    measurements.push(measurement);
    progressBar.update(i + 1);
  }

  progressBar.stop();
  return measurements;
}

/**
 * Measures one-way latency assuming NTP-synchronized clocks
 * @param targetUrl The URL to test
 * @param numRequests Number of requests to send
 * @returns Array of one-way measurements
 */
async function measureOneWay(targetUrl: string, numRequests: number): Promise<NtpOneWayMeasurement[]> {
  const measurements: NtpOneWayMeasurement[] = [];
  const healthUrl = `${targetUrl.replace(/\/$/, '')}/health`;
  const isOnion = targetUrl.includes('.onion');
  const agent = isOnion ? new SocksProxyAgent('socks5h://127.0.0.1:9050') : undefined;
  const progressBar = new cliProgress.SingleBar({
    format: chalk.green('One-Way (NTP) Measurement | {bar} | {percentage}% | {value}/{total} Requests'),
    barCompleteChar: '\u2588',
    barIncompleteChar: '\u2591',
    hideCursor: true,
  }, cliProgress.Presets.shades_classic);
  progressBar.start(numRequests, 0);

  for (let i = 0; i < numRequests; i++) {
    const measurement: NtpOneWayMeasurement = {
      requestNumber: i + 1,
      timestamp: Number(getAbsoluteUs()),
      oneWayLatency: 0,
      statusCode: 0,
    };

    try {
      const t1 = getAbsoluteUs();
      const response = await axios.get(healthUrl, {
        timeout: 10000,
        httpAgent: agent,
        httpsAgent: agent,
      });
      const t2 = parseIsoToUs(response.data.timestamp);
      measurement.oneWayLatency = Number(t2 - t1);
      measurement.statusCode = response.status;
      if (ENABLE_LOGGING) console.log(chalk.blue(`Request ${i + 1}: One-way (NTP) = ${measurement.oneWayLatency} μs, Status = ${response.status}`));
    } catch (error) {
      measurement.error = (error as Error).message;
      if (ENABLE_LOGGING) console.error(chalk.red(`Request ${i + 1} failed: ${measurement.error}`));
    }

    measurements.push(measurement);
    progressBar.update(i + 1);
  }

  progressBar.stop();
  return measurements;
}

/**
 * Performs a baseline measurement run without any tunnel
 * @param numRequests Number of measurement requests
 * @returns Run result with measurements and statistics
 */
async function performBaselineRun(numRequests: number): Promise<RunResult> {
    initializeHighResTime();
    const totalStopwatch = { start: performance.now(), end: 0 };
    const errors: { stage: string; error: string }[] = [];
    const directUrl = SERVER_URL;

    console.log(chalk.cyan(`Performing baseline measurement direct to ${directUrl}`));

    let rttMeasurements: RTTMeasurement[] = [];
    try {
        rttMeasurements = await measureRTT(directUrl, numRequests);
    } catch (error) {
        errors.push({ stage: 'RTT Measurement', error: (error as Error).message });
    }

    let oneWayMeasurements: NtpOneWayMeasurement[] = [];
    try {
        oneWayMeasurements = await measureOneWay(directUrl, numRequests);
    } catch (error) {
        errors.push({ stage: 'One-Way Measurement', error: (error as Error).message });
    }

    const successfulRtts = rttMeasurements.filter(m => m.statusCode === 200).map(m => m.rtt);
    const averageRtt = successfulRtts.length > 0 ? successfulRtts.reduce((sum, rtt) => sum + rtt, 0) / successfulRtts.length : 0;
    const estimatedOneWayFromRtt = averageRtt / 2;

    const successfulOneWays = oneWayMeasurements.filter(m => m.statusCode === 200).map(m => m.oneWayLatency);
    const averageNtpOneWay = successfulOneWays.length > 0 ? successfulOneWays.reduce((sum, lat) => sum + lat, 0) / successfulOneWays.length : 0;

    totalStopwatch.end = performance.now();
    const duration = totalStopwatch.end - totalStopwatch.start;

    return {
        tool: 'Direct (Baseline)',
        tunnelUrl: directUrl,
        rttMeasurements,
        averageRtt,
        estimatedOneWayFromRtt,
        ntpOneWayMeasurements: oneWayMeasurements,
        averageNtpOneWay,
        duration,
        errors,
    };
}

/**
 * Performs a full measurement run for a tunneling tool
 * @param tunnelTool The tunnel tool to test
 * @param numRequests Number of measurement requests
 * @returns Run result with measurements and statistics
 */
async function performMeasurementRun(tunnelTool: TunnelTool, numRequests: number): Promise<RunResult> {
  initializeHighResTime();
  const totalStopwatch = { start: performance.now(), end: 0 };
  let tunnelUrl = '';
  const errors: { stage: string; error: string }[] = [];

  try {
    const response = await axios.post(`${SERVER_URL}/start-tunnel`, { toolName: tunnelTool.name });
    tunnelUrl = response.data.url.replace(/\/$/, '');
    if (ENABLE_LOGGING) console.log(chalk.green(`Tunnel established: ${tunnelUrl}`));
  } catch (error) {
    errors.push({ stage: 'Tunnel Setup', error: (error as Error).message });
    if (ENABLE_LOGGING) console.error(chalk.red(`Tunnel setup failed: ${(error as Error).message}`));
    return {
      tool: tunnelTool.name,
      tunnelUrl: '',
      rttMeasurements: [],
      averageRtt: 0,
      estimatedOneWayFromRtt: 0,
      ntpOneWayMeasurements: [],
      averageNtpOneWay: 0,
      duration: 0,
      errors,
    };
  }

  let abPings;
  try {
    const normalizedUrl = tunnelUrl.startsWith('http') ? tunnelUrl : `http://${tunnelUrl}`;
    const urlObj = new URL(normalizedUrl);
    const host = urlObj.hostname;
    const port = parseInt(urlObj.port) || (urlObj.protocol === 'https:' ? 443 : 80);

    console.log(chalk.cyan(`Triggering BC measurement on server for ${host}:${port}`));
    try {
      await axios.post(`${SERVER_URL}/measure-latency`, {
        target_host: host,
        target_port: port,
        tool_name: tunnelTool.name,
      });
      if (ENABLE_LOGGING) console.log(chalk.green(`BC measurement successfully triggered.`));
    } catch (error) {
      const errorMessage = (error as Error).message;
      errors.push({ stage: 'BC Measurement Trigger', error: errorMessage });
      console.error(chalk.red(`Failed to trigger BC measurement on server: ${errorMessage}`));
    }

    if (!tunnelTool.isOnion) {
      console.log(chalk.cyan(`Measuring AB pings (client to ${host}:${port})`));
      try {
        await sleep(3000);
        const icmpAb = measureIcmpPing(host, 13);
        const tcpAb = await measureTcpPing(host, port, 13);
        abPings = { icmp: icmpAb, tcp: tcpAb };
      } catch (error) {
        errors.push({ stage: 'AB Ping', error: (error as Error).message });
      }
    } else {
      console.log(chalk.yellow(`Skipping AB pings for Onion tool: ${tunnelTool.name}`));
    }
  } catch (error) {
    errors.push({ stage: 'URL Parsing for AB/BC', error: `Invalid tunnel URL: ${tunnelUrl}` });
  }

  let rttMeasurements: RTTMeasurement[] = [];
  try {
    rttMeasurements = await measureRTT(tunnelUrl, numRequests);
  } catch (error) {
    errors.push({ stage: 'RTT Measurement', error: (error as Error).message });
  }

  let ntpOneWayMeasurements: NtpOneWayMeasurement[] = [];
  try {
    ntpOneWayMeasurements = await measureOneWay(tunnelUrl, numRequests);
  } catch (error) {
    errors.push({ stage: 'One-Way Measurement', error: (error as Error).message });
  }

  const successfulRtts = rttMeasurements.filter(m => m.statusCode === 200).map(m => m.rtt);
  const averageRtt = successfulRtts.length > 0 ? successfulRtts.reduce((sum, rtt) => sum + rtt, 0) / successfulRtts.length : 0;
  const estimatedOneWayFromRtt = averageRtt / 2;

  const successfulOneWays = ntpOneWayMeasurements.filter(m => m.statusCode === 200).map(m => m.oneWayLatency);
  const averageNtpOneWay = successfulOneWays.length > 0 ? successfulOneWays.reduce((sum, lat) => sum + lat, 0) / successfulOneWays.length : 0;

  try {
    await axios.post(`${SERVER_URL}/stop-tunnel`);
    if (ENABLE_LOGGING) console.log(chalk.green('Tunnel stopped'));
  } catch (error) {
    errors.push({ stage: 'Tunnel Cleanup', error: (error as Error).message });
    if (ENABLE_LOGGING) console.error(chalk.red(`Tunnel cleanup failed: ${(error as Error).message}`));
  }

  totalStopwatch.end = performance.now();
  const duration = totalStopwatch.end - totalStopwatch.start;

  return {
    tool: tunnelTool.name,
    tunnelUrl,
    rttMeasurements,
    averageRtt,
    estimatedOneWayFromRtt,
    ntpOneWayMeasurements,
    averageNtpOneWay,
    duration,
    errors,
    abPings,
  };
}

/**
 * Saves measurement results to a JSON file
 * @param directory Output directory
 * @param toolName Tool name for filename
 * @param result Run result to save
 */
async function saveResults(directory: string, toolName: string, result: RunResult): Promise<void> {
  await fs.mkdir(directory, { recursive: true });
  const sanitizedToolName = toolName.replace(/\s+/g, '-').replace(/[^a-zA-Z0-9-]/g, '');
  const filePath = path.join(directory, `${sanitizedToolName}_latency.json`);
  await fs.writeFile(filePath, JSON.stringify(result, (key, value) => typeof value === 'bigint' ? value.toString() : value, 2));
  console.log(chalk.magenta(`Results saved: ${filePath}`));
}

/**
 * Main execution function
 */
async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const toolName = args.includes('--tool') ? args[args.indexOf('--tool') + 1] : null;
  const numRequests = args.includes('--num') ? parseInt(args[args.indexOf('--num') + 1], 10) : DEFAULT_NUM_REQUESTS;
  const listTools = args.includes('--list');
  const skipBaseline = args.includes('--no-baseline');

  const timestamp = new Date().toISOString().replace(/[-:T]/g, '').slice(2, 14);

  if (listTools) {
    console.log(chalk.cyan('Available tools:'));
    tunnelTools.forEach((tool, index) => console.log(`${index + 1}. ${tool.name}`));
    process.exit(0);
  }

  const resultsDirForRun = toolName ? `${RESULTS_DIR}/${toolName}-${timestamp}` : `${RESULTS_DIR}/all-${timestamp}`;

  if (!skipBaseline) {
    console.log(chalk.bold.magenta('\n--- Running Baseline Measurement ---'));
    try {
      const baselineResult = await performBaselineRun(numRequests);
      await saveResults(resultsDirForRun, 'Direct-Baseline', baselineResult);
      console.log(chalk.yellow(`\n--- Baseline Results ---`));
      console.log(chalk.yellow(`Average RTT: ${baselineResult.averageRtt.toFixed(2)} μs`));
      console.log(chalk.yellow(`Estimated one-way from RTT: ${baselineResult.estimatedOneWayFromRtt.toFixed(2)} μs`));
      console.log(chalk.yellow(`Average one-way (NTP): ${baselineResult.averageNtpOneWay.toFixed(2)} μs`));
      console.log(chalk.bold.magenta('------------------------------------\n'));
    } catch (error) {
      console.error(chalk.red(`Error running baseline: ${(error as Error).message}`));
    }
  }

  if (toolName) {
    const tool = tunnelTools.find(t => t.name.toLowerCase() === toolName.toLowerCase());
    if (!tool) {
      console.error(chalk.red(`Tool ${toolName} not found.`));
      process.exit(1);
    }

    console.log(chalk.cyan(`Running latency measurements for: ${tool.name}`));
    try {
      const result = await performMeasurementRun(tool, numRequests);
      await saveResults(resultsDirForRun, tool.name, result);
      console.log(chalk.green(`\nCompleted measurements for ${tool.name}`));
      console.log(chalk.green(`Average RTT: ${result.averageRtt.toFixed(2)} μs`));
      console.log(chalk.green(`Estimated one-way from RTT: ${result.estimatedOneWayFromRtt.toFixed(2)} μs`));
      console.log(chalk.green(`Average one-way (NTP): ${result.averageNtpOneWay.toFixed(2)} μs`));
      if (result.abPings) {
        console.log(chalk.green(`AB ICMP Ping Average: ${result.abPings.icmp.average.toFixed(2)} ms`));
        console.log(chalk.green(`AB TCP Ping Average: ${result.abPings.tcp.average.toFixed(2)} ms`));
      }
    } catch (error) {
      console.error(chalk.red(`Error running ${tool.name}: ${(error as Error).message}`));
    } finally {
      try {
        await axios.post(`${SERVER_URL}/stop-tunnel`);
      } catch (e) { /* ignore */ }
    }
    process.exit(0);
  }

  const progressBar = new cliProgress.SingleBar({
    format: chalk.magenta('Overall Progress | {bar} | {percentage}% | {value}/{total} Tools | Fastest: {fastest}s | Slowest: {slowest}s'),
    barCompleteChar: '\u2588',
    barIncompleteChar: '\u2591',
    hideCursor: true,
  }, cliProgress.Presets.shades_classic);
  progressBar.start(tunnelTools.length, 0, { fastest: 0, slowest: 0 });

  let fastestTime = Infinity;
  let slowestTime = 0;

  for (let i = 0; i < tunnelTools.length; i++) {
    const tool = tunnelTools[i];
    const start = Date.now();
    try {
      console.log(chalk.cyan(`\nRunning latency measurements for: ${tool.name}`));
      const result = await performMeasurementRun(tool, numRequests);
      await saveResults(resultsDirForRun, tool.name, result);
      console.log(chalk.green(`Average RTT: ${result.averageRtt.toFixed(2)} μs`));
      console.log(chalk.green(`Estimated one-way from RTT: ${result.estimatedOneWayFromRtt.toFixed(2)} μs`));
      console.log(chalk.green(`Average one-way (NTP): ${result.averageNtpOneWay.toFixed(2)} μs`));
      if (result.abPings) {
        console.log(chalk.green(`AB ICMP Ping Average: ${result.abPings.icmp.average.toFixed(2)} ms`));
        console.log(chalk.green(`AB TCP Ping Average: ${result.abPings.tcp.average.toFixed(2)} ms`));
      }
    } catch (error) {
      console.error(chalk.red(`Error running ${tool.name}: ${(error as Error).message}`));
    } finally {
      try {
        await axios.post(`${SERVER_URL}/stop-tunnel`);
      } catch (e) { /* ignore */ }
    }
    const duration = (Date.now() - start) / 1000;
    fastestTime = Math.min(fastestTime, duration);
    slowestTime = Math.max(slowestTime, duration);
    progressBar.update(i + 1, { fastest: fastestTime.toFixed(2), slowest: slowestTime.toFixed(2) });
  }

  progressBar.stop();
  console.log(chalk.bold.green(`\nFastest Run: ${fastestTime.toFixed(2)}s, Slowest Run: ${slowestTime.toFixed(2)}s`));
  process.exit(0);
}

// Run the entry point
main().catch(error => {
  console.error(chalk.red('Fatal error:', error));
  process.exit(1);
});