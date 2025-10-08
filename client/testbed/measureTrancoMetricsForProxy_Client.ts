import axios from 'axios';
import { spawn } from 'child_process';
import { performance } from 'perf_hooks';
import path from 'path';
import { chromium } from 'playwright';
import cliProgress from 'cli-progress';
import chalk from 'chalk';
import { tunnelTools, TunnelTool } from './tools';
import os from 'os';
import fs from 'fs/promises';
import pcap from 'pcap';
import readline from 'readline';
import crypto from 'crypto';
import SocksProxyAgent from 'socks-proxy-agent';
import { parse } from 'csv-parse/sync';

const SERVER_HOST = '';
const SERVER_PORT = 3000;
const SERVER_URL = `http://${SERVER_HOST}:${SERVER_PORT}`;
const NUM_MEASUREMENTS = 5;
const ENABLE_LOGGING = true;
const TRANCO_CSV_FILE = 'tranco1k.csv';
const RESULTS_DIR = path.join(__dirname, 'results');

interface Timing {
  duration: number;
}

interface DiagnosticResult {
  tool: string;
  rawOutput: string;
  parsedOutput: any;
  timing: Timing;
  error?: string;
}

interface CurlResult {
  statusCode: number;
  timeSplit: TimeSplit;
  ttfb: number;
  latency: number;
  sizeDownload: number;
  speedDownload: number;
  speedUpload: number;
  error?: string;
}

interface TimeSplit {
  dnsLookup: number;
  tcpConnection: number;
  tlsHandshake: number;
  firstByte: number;
  total: number;
}

interface WebTestResult {
    url: string;
    statusCode: number;
    speedDownload: number;
    speedUpload: number;
    timeSplit: TimeSplit;
    fcp: number;
    lcp: number;
    speedIndex: number;
    curlTotalTime: number;       // Total time taken by curl in milliseconds
    playwrightTotalTime: number; // Total time taken by Playwright in milliseconds
    error?: string;
}

interface Measurement {
  measurementNumber: number;
  timestamp: number;
  webTests: WebTestResult[];
}

interface RunResult {
  tool: string;
  diagnostics: DiagnosticResult[];
  measurements: Measurement[];
  durations: {
    total: Timing;
    toolSetup: Timing;
    diagnostics: Timing;
    measurements: { total: Timing; average: Timing };
  };
  errors: { stage: string; error: string }[];
}

interface FlattenedMeasurement {
    toolName: string;
    measurementNumber: number;
    timestamp: number;
    webTests: Array<{
      url: string;
      statusCode: number;
      downloadSpeed: number;
      uploadSpeed: number;
      dnsLookup: number; // Milliseconds
      tcpConnection: number; // Milliseconds
      tlsHandshake: number; // Milliseconds
      timeToFirstByte: number; // Milliseconds
      totalTime: number; // Milliseconds
      fcp: number;
      lcp: number;
      speedIndex: number;
      curlTotalTime: number; // Milliseconds
      playwrightTotalTime: number; // Milliseconds
      error?: string;
    }>;
    totalDuration: number;
    setupDuration: number;
    diagnosticsDuration: number;
    measurementDuration: number;
    hasErrors: boolean;
    errorCount: number;
    errors: string[];
}

class Stopwatch {
  private startTime: number = 0;
  private endTime: number = 0;

  start(): void {
    this.startTime = performance.now();
  }

  stop(): void {
    this.endTime = performance.now();
  }

  getTiming(): Timing {
    return { duration: this.endTime - this.startTime };
  }
}

abstract class CliTool<T> {
  abstract parse(output: string): T;

  async run(command: string, args: string[]): Promise<T> {
    const output = await runCommand(command, args);
    return this.parse(output);
  }
}

class Curl extends CliTool<CurlResult> {
  parse(output: string): CurlResult {
    const result: CurlResult = {
      statusCode: 0,
      timeSplit: { dnsLookup: 0, tcpConnection: 0, tlsHandshake: 0, firstByte: 0, total: 0 },
      ttfb: 0,
      latency: 0,
      sizeDownload: 0,
      speedDownload: 0,
      speedUpload: 0,
    };

    if (!output || output.includes('curl: (5)')) {
      result.error = output || 'curl: (5) Could not resolve proxy';
      return result;
    }

    const lines = output.split('\n').filter(line => line.trim());
    for (const line of lines) {
      const [key, value] = line.split(': ').map(s => s.trim());
      if (!key || !value) continue;
      const timeValue = parseFloat(value);
      switch (key) {
        case 'DNS Lookup':
          result.timeSplit.dnsLookup = timeValue;
          break;
        case 'TCP Connection':
          result.timeSplit.tcpConnection = timeValue;
          break;
        case 'TLS Handshake':
          result.timeSplit.tlsHandshake = timeValue;
          break;
        case 'Start Transfer':
          result.timeSplit.firstByte = timeValue;
          break;
        case 'Total Time':
          result.timeSplit.total = timeValue;
          break;
        case 'Download Speed':
          result.speedDownload = parseFloat(value);
          break;
        case 'Upload Speed':
          result.speedUpload = parseFloat(value);
          break;
        case 'Size of Download':
          result.sizeDownload = parseInt(value, 10);
          break;
        case 'HTTP Code':
          result.statusCode = parseInt(value, 10);
          break;
      }
    }

    result.ttfb = result.timeSplit.dnsLookup + result.timeSplit.tcpConnection + result.timeSplit.tlsHandshake + result.timeSplit.firstByte;
    result.latency = result.timeSplit.tcpConnection;
    return result;
  }
}

async function runCommand(
  command: string,
  args: string[],
  progressCallback?: (data: string) => void
): Promise<string> {
  return new Promise((resolve, reject) => {
    if (ENABLE_LOGGING) console.log(chalk.cyan(`Executing: ${command} ${args.join(' ')}`));
    const process = spawn(command, args, { stdio: ['inherit', 'pipe', 'pipe'] });
    let output = '';
    let errorOutput = '';

    process.stdout?.on('data', (data) => {
      const strData = data.toString();
      output += strData;
      if (progressCallback) progressCallback(strData);
      if (ENABLE_LOGGING) console.log(chalk.gray(`[stdout] ${strData.trim()}`));
    });

    process.stderr?.on('data', (data) => {
      const strData = data.toString();
      errorOutput += strData;
      if (progressCallback) progressCallback(strData);
      if (ENABLE_LOGGING) console.log(chalk.red(`[stderr] ${strData.trim()}`));
    });

    process.on('close', (code) => {
      if (code === 0) {
        if (ENABLE_LOGGING) console.log(chalk.green(`${command} completed successfully`));
        resolve(output);
      } else {
        const errorMsg = `Command failed with code ${code}: ${errorOutput || 'No error output'}\nOutput: ${output}`;
        console.error(chalk.red(`Error in ${command}: ${errorMsg}`));
        reject(new Error(errorMsg));
      }
    });

    process.on('error', (err) => {
      console.error(chalk.red(`Process error in ${command}: ${err.message}`));
      reject(err);
    });
  });
}

async function clearDnsCache(): Promise<void> {
  const commands = [
    ['sudo', ['resolvectl', 'flush-caches']],
    ['sudo', ['systemd-resolve', '--flush-caches']],
    ['sudo', ['dscacheutil', '-flushcache']],
  ];

  for (const [command, args] of commands) {
    try {
      await runCommand(command, args);
      if (ENABLE_LOGGING) console.log(chalk.green('DNS cache cleared successfully'));
      return;
    } catch (error) {
      console.error(chalk.yellow(`Failed to clear DNS cache with ${command}: ${error.message}`));
    }
  }
  console.error(chalk.red('All DNS cache clear attempts failed. Proceeding without clearing.'));
}

async function testDnsResolution(host: string): Promise<boolean> {
  const dnsServers = ['', '8.8.8.8', '1.1.1.1'];
  for (const dns of dnsServers) {
    const args = dns ? ['nslookup', host, dns] : ['nslookup', host];
    try {
      if (ENABLE_LOGGING) console.log(chalk.cyan(`Testing DNS resolution for ${host}${dns ? ` using ${dns}` : ''}`));
      await runCommand('nslookup', args);
      if (ENABLE_LOGGING) console.log(chalk.green(`DNS resolution succeeded for ${host}${dns ? ` using ${dns}` : ''}`));
      return true;
    } catch (error) {
      console.error(chalk.yellow(`DNS resolution failed for ${host}${dns ? ` using ${dns}` : ''}: ${error.message}`));
    }
  }
  return false;
}

async function testProxyReachability(toolName: string, url: string, maxRetries: number = 3): Promise<boolean> {
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      if (ENABLE_LOGGING) console.log(chalk.cyan(`Testing proxy reachability (attempt ${attempt}/${maxRetries}): ${url}`));
      await runCommand('curl', [
        '--socks5-hostname',
        url,
        '--connect-timeout',
        '15',
        '--max-time',
        '30',
        'http://localhost:3000/health',
      ]);
      if (ENABLE_LOGGING) console.log(chalk.green(`Proxy reachable: ${url}`));
      return true;
    } catch (error) {
      console.error(chalk.red(`Proxy reachability test failed (attempt ${attempt}/${maxRetries}): ${error.message}`));
      if (attempt < maxRetries) {
        await new Promise(resolve => setTimeout(resolve, 5000));
      }
    }
  }
  return false;
}

async function readTokens(filePath: string): Promise<string[]> {
  try {
    const content = await fs.readFile(filePath, 'utf-8');
    return content.split('\n').filter(line => line.trim()).slice(0, 10);
  } catch (error: unknown) {
    console.error(chalk.red(`Error reading ${filePath}: ${(error as Error).message}`));
    return [];
  }
}

async function readTrancoDomains(): Promise<string[]> {
  try {
    const csvPath = path.join(__dirname, TRANCO_CSV_FILE);
    const content = await fs.readFile(csvPath, 'utf-8');
    const records = parse(content, { columns: true, skip_empty_lines: true });
    const domains = records.map((record: { Rank: string; Domain: string }) => `https://${record.Domain}`);

    // Randomly select 100 unique URLs
    const shuffled = domains.slice();
    for (let i = shuffled.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
    }
    const selectedDomains = shuffled.slice(0, 100);

    if (ENABLE_LOGGING) console.log(chalk.green(`Loaded ${selectedDomains.length} random domains from ${TRANCO_CSV_FILE}`));
    return selectedDomains;
  } catch (error: unknown) {
    console.error(chalk.red(`Error reading ${TRANCO_CSV_FILE}: ${(error as Error).message}`));
    return ['http://example.com', 'https://google.com', 'http://ifconfig.me'];
  }
}

async function startTunnel(toolName: string): Promise<string> {
  let tokens: string[] = [];
  if (toolName === 'Ngrok') {
    tokens = await readTokens('ngrok-auth.txt');
    if (ENABLE_LOGGING) console.log(chalk.gray(`Loaded ${tokens.length} ngrok tokens`));
  }

  for (let attempt = 0; attempt < 3; attempt++) {
    let tokenIndex = 0;
    while (tokenIndex < tokens.length + 1) {
      try {
        if (ENABLE_LOGGING) console.log(chalk.cyan(`Attempt ${attempt + 1}/3 to start tunnel for ${toolName}`));
        await axios.post(`${SERVER_URL}/stop-tunnel`, { toolName }).catch(() => {});
        const response = await axios.post(`${SERVER_URL}/start-tunnel`, { toolName });
        const newUrl = response.data.url.replace(/\/$/, '');
        if (ENABLE_LOGGING) console.log(chalk.green(`Tunnel started: ${newUrl}`));
        return newUrl;
      } catch (error: unknown) {
        console.error(chalk.red(`Failed to start tunnel for ${toolName} (attempt ${attempt + 1}/3): ${error}`));
        break;
      }
    }
    if (attempt < 2) {
      if (ENABLE_LOGGING) console.log(chalk.yellow(`Waiting 5 seconds before retrying tunnel start for ${toolName}`));
      await new Promise(resolve => setTimeout(resolve, 5000));
    }
  }

  console.error(chalk.red(`Failed to start tunnel for ${toolName} after 3 attempts`));
  return '';
}

async function performWebTest(tunnelUrl: string, externalUrl: string, tunnelTool: TunnelTool): Promise<WebTestResult> {
  if (!tunnelUrl) {
    return {
      url: externalUrl,
      statusCode: 0,
      speedDownload: 0,
      speedUpload: 0,
      timeSplit: { dnsLookup: 0, tcpConnection: 0, tlsHandshake: 0, firstByte: 0, total: 0 },
      curlTotalTime: 0,
      fcp:0,
      lcp:0,
      speedIndex:0,
      playwrightTotalTime: 0,
      error: 'Invalid tunnel URL: empty or undefined',
    };
  }

  let currentUrl = tunnelUrl;
  const maxRetries = tunnelTool.name === 'Pinggy' ? 3 : 1;
  let lastError: string | undefined;

  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    const curlStopwatch = new Stopwatch();
    curlStopwatch.start();

    let curlResult: CurlResult;
    try {
      await clearDnsCache();
      let curlOutput: string;

      const curlArgs = [
        '-L',
        '-w',
        'DNS Lookup: %{time_namelookup}s\nTCP Connection: %{time_connect}s\nTLS Handshake: %{time_appconnect}s\nStart Transfer: %{time_starttransfer}s\nTotal Time: %{time_total}s\nDownload Speed: %{speed_download} bytes/sec\nUpload Speed: %{speed_upload} bytes/sec\nHTTP Code: %{http_code}\nSize of Download: %{size_download} bytes\n',
        '-D',
        '-',
        '-o',
        '/dev/null',
        '-s',
        '--socks5-hostname',
        currentUrl,
        externalUrl,
      ];

      curlOutput = await runCommand('curl', curlArgs);
      curlResult = new Curl().parse(curlOutput);
    } catch (error: unknown) {
      lastError = (error as Error).message;
      console.error(chalk.red(`Web test attempt ${attempt}/${maxRetries} failed for ${externalUrl}: ${lastError}`));
      curlResult = {
        statusCode: 0,
        timeSplit: { dnsLookup: 0, tcpConnection: 0, tlsHandshake: 0, firstByte: 0, total: 0 },
        ttfb: 0,
        latency: 0,
        sizeDownload: 0,
        speedDownload: 0,
        speedUpload: 0,
        error: lastError,
      };
      if (attempt < maxRetries) {
        console.log(chalk.yellow(`Retrying web test for ${externalUrl} in 5 seconds`));
        await new Promise(resolve => setTimeout(resolve, 5000));
      }
      continue;
    }
    curlStopwatch.stop();

    const curlTotalTime = curlStopwatch.getTiming().duration;
    let fcp = 0;
    let lcp = 0;
    let speedIndex = 0;
    let error: string | undefined = curlResult.error;

    try {
          const tempFile = path.join(os.tmpdir(), `lighthouse-${crypto.randomUUID()}.json`);
          const lighthouseArgs = [
            externalUrl,
            '--only-audits=first-contentful-paint,largest-contentful-paint,speed-index',
            `--chrome-flags=--proxy-server=socks5://${currentUrl} --headless --no-sandbox`,
            '--output=json',
            `--output-path=${tempFile}`,
            '--verbose'
          ];
    
          await runCommand('lighthouse', lighthouseArgs, (data) => {
            if (ENABLE_LOGGING) console.log(chalk.gray(`[Lighthouse] ${data}`));
          });
    
          const lighthouseOutput = await fs.readFile(tempFile, 'utf-8');
          await fs.unlink(tempFile); // Clean up temporary file
    
          const lighthouseResult = JSON.parse(lighthouseOutput);
          fcp = lighthouseResult.audits['first-contentful-paint']?.numericValue || 0;
          lcp = lighthouseResult.audits['largest-contentful-paint']?.numericValue || 0;
          speedIndex = lighthouseResult.audits['speed-index']?.numericValue || 0;
    
          if (ENABLE_LOGGING) {
            console.log(chalk.green('Onion site metrics from Lighthouse:'));
            console.log(chalk.green(`- FCP: ${fcp} ms`));
            console.log(chalk.green(`- LCP: ${lcp} ms`));
            console.log(chalk.green(`- Speed Index: ${speedIndex} ms`));
          }
        } catch (err) {
          error = `Lighthouse error for onion URL: ${(err as Error).message}`;
          if (ENABLE_LOGGING) console.error(chalk.red(error));
        }

    let playwrightTotalTime = 0;

    try {
      const playwrightStopwatch = new Stopwatch();
      playwrightStopwatch.start();
      const browser = await chromium.launch({
        headless: true,
        proxy: { server: `socks5://${currentUrl}` },
      });
      const page = await browser.newPage();
      await page.goto(externalUrl, { waitUntil: 'load', timeout: 60000 });
      await browser.close();
      playwrightStopwatch.stop();
      playwrightTotalTime = playwrightStopwatch.getTiming().duration;
    } catch (err: unknown) {
      error = error || `Playwright error: ${(err as Error).message}`;
      if (ENABLE_LOGGING) console.error(chalk.red(error));
    }

    return {
        url:externalUrl,
        statusCode: curlResult.statusCode,
        speedDownload: curlResult.speedDownload,
        speedUpload: curlResult.speedUpload,
        timeSplit: curlResult.timeSplit,
        fcp,
        lcp,
        speedIndex,
        curlTotalTime,
        playwrightTotalTime,
        error: error || curlResult.error
      };
  }

  return {
    url: externalUrl,
    statusCode: 0,
    speedDownload: 0,
    speedUpload: 0,
    timeSplit: { dnsLookup: 0, tcpConnection: 0, tlsHandshake: 0, firstByte: 0, total: 0 },
    fcp:0,
    lcp:0,
    speedIndex:0,
    curlTotalTime: 0,
    playwrightTotalTime: 0,
    error: lastError || 'Web test failed after all retries',
  };
}

async function ensureResultsDir(): Promise<string> {
  try {
    await fs.mkdir(RESULTS_DIR, { recursive: true });
    await fs.access(RESULTS_DIR, fs.constants.W_OK);
    if (ENABLE_LOGGING) console.log(chalk.green(`Results directory ensured: ${RESULTS_DIR}`));
    return RESULTS_DIR;
  } catch (error) {
    console.error(chalk.red(`Failed to create or access results directory ${RESULTS_DIR}: ${error.message}`));
    throw new Error(`Cannot create results directory: ${error.message}`);
  }
}

async function performDiagnostics(tunnelTool: TunnelTool): Promise<DiagnosticResult[]> {
  const diagnostics: DiagnosticResult[] = [];
  const commands = tunnelTool.diagnosticCommands || [];

  for (const cmd of commands) {
    const stopwatch = new Stopwatch();
    stopwatch.start();
    try {
      const output = await runCommand(cmd.command, cmd.args);
      stopwatch.stop();
      diagnostics.push({
        tool: tunnelTool.name,
        rawOutput: output,
        parsedOutput: output,
        timing: stopwatch.getTiming(),
      });
    } catch (error: unknown) {
      stopwatch.stop();
      diagnostics.push({
        tool: tunnelTool.name,
        rawOutput: '',
        parsedOutput: null,
        timing: stopwatch.getTiming(),
        error: (error as Error).message,
      });
      console.error(chalk.red(`Diagnostic failed for ${tunnelTool.name}: ${(error as Error).message}`));
    }
  }

  return diagnostics;
}

async function performMeasurementsRun(tunnelTool: TunnelTool, numMeasurements: number): Promise<RunResult> {
  const totalStopwatch = new Stopwatch();
  totalStopwatch.start();
  const errors: { stage: string; error: string }[] = [];

  const setupStopwatch = new Stopwatch();
  setupStopwatch.start();
  let tunnelUrl = '';
  try {
    tunnelUrl = await startTunnel(tunnelTool.name);
    if (!tunnelUrl) {
      throw new Error(`Failed to start tunnel for ${tunnelTool.name}`);
    }
  } catch (error: unknown) {
    setupStopwatch.stop();
    totalStopwatch.stop();
    errors.push({ stage: 'Setup', error: (error as Error).message });
    console.error(chalk.red(`Setup failed for ${tunnelTool.name}: ${(error as Error).message}`));
    return {
      tool: tunnelTool.name,
      diagnostics: [],
      measurements: [],
      durations: {
        total: totalStopwatch.getTiming(),
        toolSetup: setupStopwatch.getTiming(),
        diagnostics: { duration: 0 },
        measurements: { total: { duration: 0 }, average: { duration: 0 } },
      },
      errors,
    };
  }
  setupStopwatch.stop();

  const diagnosticsStopwatch = new Stopwatch();
  diagnosticsStopwatch.start();
  const diagnostics = await performDiagnostics(tunnelTool);
  diagnosticsStopwatch.stop();

  const measurements: Measurement[] = [];
  let totalMeasurementDuration = 0;

  const progressBar = new cliProgress.SingleBar({
    format: `Measuring {tool} | {bar} | {value}/{total} Measurements`,
    barCompleteChar: '#',
    barIncompleteChar: '-',
    hideCursor: true,
  });

  if (ENABLE_LOGGING) console.log(chalk.cyan(`Starting measurements for ${tunnelTool.name}`));
  progressBar.start(numMeasurements, 0, { tool: tunnelTool.name });

  for (let i = 0; i < numMeasurements; i++) {
    if (ENABLE_LOGGING) console.log(chalk.cyan(`Starting measurement ${i + 1} of ${numMeasurements} for ${tunnelTool.name}`));
    const stopwatch = new Stopwatch();
    stopwatch.start();
    const webTests: WebTestResult[] = [];

    await clearDnsCache();

    const trancoUrls = await readTrancoDomains();
    for (let j = 0; j < trancoUrls.length; j++) {
      const url = trancoUrls[j];
      if (j > 0) {
        if (ENABLE_LOGGING) console.log(chalk.yellow(`Waiting 10 seconds before testing ${url}`));
        await new Promise(resolve => setTimeout(resolve, 10000));
      }
      const result = await performWebTest(tunnelUrl, url, tunnelTool);
      webTests.push(result);
      if (result.error) {
        errors.push({ stage: `Measurement ${i + 1}`, error: `Web test failed for ${url}: ${result.error}` });
      }
    }

    stopwatch.stop();
    totalMeasurementDuration += stopwatch.getTiming().duration;
    measurements.push({ measurementNumber: i + 1, timestamp: performance.now(), webTests });
    progressBar.update(i + 1);

    if (i < numMeasurements - 1) {
      await new Promise(resolve => setTimeout(resolve, 2000));
    }
  }

  progressBar.stop();

  try {
    await axios.post(`${SERVER_URL}/stop-tunnel`, { toolName: tunnelTool.name });
    if (ENABLE_LOGGING) console.log(chalk.green(`Tunnel stopped for ${tunnelTool.name}`));
  } catch (error: unknown) {
    errors.push({ stage: 'Cleanup', error: `Failed to stop tunnel: ${(error as Error).message}` });
    console.error(chalk.red(`Failed to stop tunnel for ${tunnelTool.name}: ${(error as Error).message}`));
  }

  totalStopwatch.stop();

  return {
    tool: tunnelTool.name,
    diagnostics,
    measurements,
    durations: {
      total: totalStopwatch.getTiming(),
      toolSetup: setupStopwatch.getTiming(),
      diagnostics: diagnosticsStopwatch.getTiming(),
      measurements: {
        total: { duration: totalMeasurementDuration },
        average: { duration: totalMeasurementDuration / numMeasurements },
      },
    },
    errors,
  };
}

function flattenResults(results: RunResult[]): FlattenedMeasurement[] {
  return results.flatMap((result) =>
    result.measurements.map((measurement) => ({
      toolName: result.tool,
      measurementNumber: measurement.measurementNumber,
      timestamp: measurement.timestamp,
      webTests: measurement.webTests.map((wt) => ({
        url: wt.url,
        statusCode: wt.statusCode,
        downloadSpeed: wt.speedDownload,
        uploadSpeed: wt.speedUpload,
        dnsLookup: wt.timeSplit.dnsLookup,
        tcpConnection: wt.timeSplit.tcpConnection,
        tlsHandshake: wt.timeSplit.tlsHandshake,
        timeToFirstByte: wt.timeSplit.firstByte,
        totalTime: wt.timeSplit.total,
        fcp: wt.fcp,
        lcp: wt.lcp,
        speedIndex: wt.speedIndex,
        curlTotalTime: wt.curlTotalTime,
        playwrightTotalTime: wt.playwrightTotalTime,
        error: wt.error,
      })),
      totalDuration: result.durations.total.duration,
      setupDuration: result.durations.toolSetup.duration,
      diagnosticsDuration: result.durations.diagnostics.duration,
      measurementDuration: result.durations.measurements.total.duration,
      hasErrors: result.errors.length > 0,
      errorCount: result.errors.length,
      errors: result.errors.map((e) => `${e.stage}: ${e.error}`),
    }))
  );
}

async function main(): Promise<void> {
  console.log(chalk.bold('Starting Proxy Client Measurements'));
  let resultsDir: string;
  try {
    resultsDir = await ensureResultsDir();
  } catch (error) {
    console.error(chalk.red(`Failed to ensure results directory: ${error.message}`));
    process.exit(1);
  }

  const results: RunResult[] = [];
  for (const tool of tunnelTools) {
    console.log(chalk.bold(`\nTesting ${tool.name}`));
    const result = await performMeasurementsRun(tool, NUM_MEASUREMENTS);
    results.push(result);

    const success = result.errors.length === 0;
    console.log(chalk[success ? 'green' : 'red'](`Completed testing ${tool.name}. Success: ${success}`));
    if (result.errors.length > 0) {
      console.log(chalk.red('Errors encountered:'));
      result.errors.forEach((err) => console.log(chalk.red(`- ${err.stage}: ${err.error}`)));
    }
  }

  const flattenedResults = flattenResults(results);
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const outputFile = path.join(resultsDir, `results-${timestamp}.json`);
  try {
    await fs.writeFile(outputFile, JSON.stringify(flattenedResults, null, 2));
    console.log(chalk.green(`Results saved to ${outputFile}`));
  } catch (error) {
    console.error(chalk.red(`Failed to save results to ${outputFile}: ${error.message}`));
    console.log(chalk.yellow('Dumping results to console:'));
    console.log(JSON.stringify(flattenedResults, null, 2));
  }
}

main().catch((error) => {
  console.error(chalk.red(`Main process error: ${error.message}`));
  process.exit(1);
});