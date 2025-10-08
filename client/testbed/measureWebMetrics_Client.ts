import speedline from 'speedline';
import axios from 'axios';
import { spawn } from 'child_process';
import fs from 'fs/promises';
import pcap from 'pcap';
import readline from 'readline';
import { performance } from 'perf_hooks';
import crypto from 'crypto';
import path from 'path';
import os from 'os';
import { chromium } from 'playwright';
import SocksProxyAgent from 'socks-proxy-agent';
import cliProgress from 'cli-progress';
import chalk from 'chalk';
import { TunnelTool, tunnelTools } from './tools'; // Assuming tools.ts defines TunnelTool and tunnelTools

/**
 * Web Test Measurement Script
 *
 * This script conducts web performance tests using various tunneling tools.
 * It measures web page load performance, capturing detailed metrics such as
 * download/upload speeds, latency, and Lighthouse performance indicators.
 * Results are saved in JSON format for analysis.
 */

/** Configuration Constants */
const TOR_SOCKS_PORT = 9050;
const TOR_SOCKS_HOST = '127.0.0.1';
const SERVER_HOST = '174.138.65.79'; // NYC
const SERVER_PORT = 3000;
const SERVER_URL = `http://${SERVER_HOST}:${SERVER_PORT}`;
const NUM_MEASUREMENTS = 15;
const ENABLE_LOGGING = true;
const ENABLE_PCAP = false;

/** Interfaces for Data Structures */
interface Timing {
  duration: number; // Milliseconds
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
  ttfb: number; // Milliseconds
  latency: number; // Milliseconds
  sizeDownload: number; // Bytes
  speedDownload: number; // Bytes per second
  speedUpload: number; // Bytes per second
  error?: string;
}

interface TimeSplit {
  dnsLookup: number; // Seconds
  tcpConnection: number; // Seconds
  tlsHandshake: number; // Seconds
  firstByte: number; // Seconds
  total: number; // Seconds
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
  pcapFilePath?: string;
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

/** Utility Classes */
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
    const lines = output.split('\n');
    const result: CurlResult = {
      statusCode: 0,
      timeSplit: { dnsLookup: 0, tcpConnection: 0, tlsHandshake: 0, firstByte: 0, total: 0 },
      ttfb: 0,
      latency: 0,
      sizeDownload: 0,
      speedDownload: 0,
      speedUpload: 0,
    };

    lines.forEach((line) => {
      const [key, value] = line.split(': ');
      if (!key || !value) return;
      const timeValue = parseFloat(value);
      switch (key.trim()) {
        case 'DNS Lookup': result.timeSplit.dnsLookup = timeValue; break;
        case 'TCP Connection': result.timeSplit.tcpConnection = timeValue; break;
        case 'TLS Handshake': result.timeSplit.tlsHandshake = timeValue; break;
        case 'Start Transfer': result.timeSplit.firstByte = timeValue; break;
        case 'Total Time': result.timeSplit.total = timeValue; break;
        case 'Download Speed': result.speedDownload = parseFloat(value); break;
        case 'Upload Speed': result.speedUpload = parseFloat(value); break;
        case 'Size of Download': result.sizeDownload = parseInt(value, 10); break;
        case 'HTTP Code': result.statusCode = parseInt(value, 10); break;
      }
    });

    result.ttfb = result.timeSplit.dnsLookup + result.timeSplit.tcpConnection + result.timeSplit.tlsHandshake + result.timeSplit.firstByte;
    result.latency = result.timeSplit.tcpConnection;
    return result;
  }
}

/** Core Functions */

/**
 * Executes a shell command with optional progress tracking.
 * @param command The command to execute.
 * @param args Command arguments.
 * @param progressCallback Callback for handling progress output from stderr.
 * @returns Promise resolving to the command's stdout.
 */
async function runCommand(
  command: string,
  args: string[],
  progressCallback?: (data: string) => void
): Promise<string> {
  return new Promise((resolve, reject) => {
    if (ENABLE_LOGGING) console.log(chalk.cyan(`Executing: ${command} ${args.join(' ')}`));
    const process = spawn(command, args);
    let output = '';
    let errorOutput = '';

    process.stdout?.on('data', (data) => (output += data.toString()));
    process.stderr?.on('data', (data) => {
      const strData = data.toString();
      if (progressCallback) progressCallback(strData);
      errorOutput += strData;
    });

    process.on('close', (code) => {
      if (code === 0) {
        if (ENABLE_LOGGING) console.log(chalk.green(`${command} completed successfully`));
        resolve(output);
      } else {
        console.error(chalk.red(`Error in ${command}: ${errorOutput}`));
        reject(new Error(`Command failed with code ${code}: ${errorOutput}`));
      }
    });
  });
}

/**
 * Clears the local DNS cache on Linux using resolvectl.
 * Continues execution even if clearing fails to avoid interrupting the script.
 */
async function clearDnsCache(): Promise<void> {
  const command = 'sudo';
  const args = ['resolvectl', 'flush-caches'];
  return new Promise((resolve) => {
    const proc = spawn(command, args, { stdio: 'inherit' });
    proc.on('close', (code) => {
      if (code === 0) {
        if (ENABLE_LOGGING) console.log(chalk.green('DNS cache cleared successfully'));
      } else {
        console.error(chalk.red(`Failed to clear DNS cache with code ${code}. Proceeding without clearing.`));
      }
      resolve();
    });
    proc.on('error', (err) => {
      console.error(chalk.red(`Error executing DNS cache clear command: ${err.message}`));
      resolve();
    });
  });
}

/**
 * Performs a web test, capturing performance metrics using curl, Playwright, and Lighthouse.
 * For .onion URLs, uses Lighthouse command to measure FCP, LCP, and Speed Index.
 * @param url URL to test.
 * @returns Promise resolving to the web test result.
 */
async function performWebTest(url: string): Promise<WebTestResult> {
  let curlStopwatch = new Stopwatch();
  let playwrightStopwatch = new Stopwatch();

  curlStopwatch.start();
  const isOnionUrl = url.includes('.onion');
  const curlArgs = [
    '-w', '\
    DNS Lookup: %{time_namelookup}s\n\
    TCP Connection: %{time_connect}s\n\
    TLS Handshake: %{time_appconnect}s\n\
    Start Transfer: %{time_starttransfer}s\n\
    Total Time: %{time_total}s\n\
    Download Speed: %{speed_download} bytes/sec\n\
    Upload Speed: %{speed_upload} bytes/sec\n\
    HTTP Code: %{http_code}\n\
    Size of Download: %{size_download} bytes\n',
    '-H', 'ngrok-skip-browser-warning: true', // Add header to bypass ngrok warning
    '-D', '-',  
    '-o', '/dev/null',  // Discard content
    '-s',  // Silent mode
  ];

  if (isOnionUrl) {
    curlArgs.push(
      '--socks5-hostname', `${TOR_SOCKS_HOST}:${TOR_SOCKS_PORT}`,
      '--insecure'
    );
  }

  curlArgs.push(url);

  await clearDnsCache();
  const curlOutput = await runCommand('curl', curlArgs);
  curlStopwatch.stop();

  const curlResult = new Curl().parse(curlOutput);
  const curlTotalTime = curlStopwatch.getTiming().duration;

  let fcp = 0;
  let lcp = 0;
  let speedIndex = 0;
  let error: string | undefined;
  let playwrightTotalTime = 0;

  if (!/^https?:\/\//i.test(url)) {
    url = `http://${url}`;
  }

  if (isOnionUrl) {
    // Use Lighthouse for onion URLs
    try {
      const tempFile = path.join(os.tmpdir(), `lighthouse-${crypto.randomUUID()}.json`);
      const lighthouseArgs = [
        url,
        '--only-audits=first-contentful-paint,largest-contentful-paint,speed-index',
        `--chrome-flags=--proxy-server="socks5://${TOR_SOCKS_HOST}:${TOR_SOCKS_PORT}" --headless --no-sandbox`,
        '--output=json',
        `--output-path=${tempFile}`
      ];

      await runCommand('/root/.local/share/pnpm/lighthouse', lighthouseArgs, (data) => {
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
  } else {
    // Non-onion URLs: Use Playwright and Lighthouse as before
    try {
      playwrightStopwatch.start();
      const browser = await chromium.launch({
        headless: true,
        args: ['--no-sandbox', '--disable-setuid-sandbox']
      });
      
      const context = await browser.newContext();
      // Add header to bypass ngrok warning
      await context.setExtraHTTPHeaders({
        'ngrok-skip-browser-warning': 'true'
      });
      const page = await context.newPage();
      await page.goto(url, { waitUntil: 'load', timeout: 60000 });
      
      await browser.close();
      playwrightStopwatch.stop();
      playwrightTotalTime = playwrightStopwatch.getTiming().duration;
    } catch (err) {
      error = `Playwright error: ${(err as Error).message}`;
      if (ENABLE_LOGGING) console.error(chalk.red(error));
      if (playwrightStopwatch.getTiming().duration === 0) {
        playwrightStopwatch.stop();
        playwrightTotalTime = playwrightStopwatch.getTiming().duration;
      }
    }

    if (!error) {
      try {
        const puppeteer = await import('puppeteer');
        const lighthouse = await import('lighthouse');
      
        const launchOptions = {
          headless: 'new',
          args: [
            '--no-sandbox', 
            '--disable-setuid-sandbox'
          ],
          executablePath: process.env.PUPPETEER_EXECUTABLE_PATH || undefined
        };
        
        const browser = await puppeteer.launch(launchOptions);
        const page = await browser.newPage();
        // Add header to bypass ngrok warning
        await page.setExtraHTTPHeaders({
          'ngrok-skip-browser-warning': 'true'
        });
        
        const lighthouseConfig = {
          extends: 'lighthouse:default',
          settings: {
            onlyAudits: [
              'first-contentful-paint',
              'largest-contentful-paint',
              'speed-index'
            ],
            throttlingMethod: 'provided',
            maxWaitForFcp: 30000,
            maxWaitForLoad: 45000,
            formFactor: 'desktop',
            screenEmulation: {
              mobile: false,
              width: 1350,
              height: 940,
              deviceScaleFactor: 1,
              disabled: false
            }
          }
        };
      
        const { lhr } = await lighthouse.default(
          url,
          {
            port: parseInt(new URL(browser.wsEndpoint()).port),
            output: 'json',
            logLevel: ENABLE_LOGGING ? 'info' : 'error'
          },
          lighthouseConfig,
          page
        );
      
        fcp = lhr.audits['first-contentful-paint']?.numericValue || 0;
        lcp = lhr.audits['largest-contentful-paint']?.numericValue || 0;
        speedIndex = lhr.audits['speed-index']?.numericValue || 0;
      
        await browser.close();
      } catch (err) {
        error = `Lighthouse error: ${(err as Error).message}`;
        if (ENABLE_LOGGING) console.error(chalk.red(error));
      }
    }
  }

  return {
    url,
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

/**
 * Executes a full measurement run for a tunneling tool, focusing on web tests.
 * @param tunnelTool Tool to test.
 * @param enablePcap Whether to capture PCAP data.
 * @param numMeasurements Number of measurement iterations.
 * @returns Promise resolving to the run result.
 */
async function performMeasurementsRun(tunnelTool: TunnelTool, enablePcap: boolean, numMeasurements: number): Promise<RunResult> {
  const totalStopwatch = new Stopwatch();
  const setupStopwatch = new Stopwatch();
  const diagnosticsStopwatch = new Stopwatch();
  totalStopwatch.start();
  setupStopwatch.start();

  let tunnelUrl = '';
  let errors: { stage: string; error: string }[] = [];

  try {
    const response = await axios.post(`${SERVER_URL}/start-tunnel`, { toolName: tunnelTool.name });
    tunnelUrl = response.data.url.replace(/\/$/, '');
    if (ENABLE_LOGGING) console.log(chalk.green(`Tunnel established: ${tunnelUrl}`));
  } catch (error) {
    errors.push({ stage: 'Tunnel Setup', error: (error as Error).message });
  }

  setupStopwatch.stop();
  await new Promise(resolve => setTimeout(resolve, 10000)); // Stabilize tunnel

  diagnosticsStopwatch.start();
  const diagnostics: DiagnosticResult[] = [];
  diagnosticsStopwatch.stop();

  const measurements: Measurement[] = [];
  const progressBar = new cliProgress.SingleBar({
    format: chalk.green('Measuring {toolName} | {bar} | {percentage}% | {value}/{total} | ETA: {eta}s'),
    barCompleteChar: '\u2588',
    barIncompleteChar: '\u2591',
    hideCursor: true,
  }, cliProgress.Presets.shades_classic);
  progressBar.start(numMeasurements, 0, { toolName: tunnelTool.name });

  let totalMeasurementDuration = 0;
  for (let i = 0; i < numMeasurements; i++) {
    const stopwatch = new Stopwatch();
    stopwatch.start();
    const webTests: WebTestResult[] = [];
    try {
      const webResult = await performWebTest(`${tunnelUrl}/webtest`);
      webTests.push(webResult);
    } catch (error) {
      webTests.push({
        url: `${tunnelUrl}/webtest`,
        statusCode: 0,
        speedDownload: 0,
        speedUpload: 0,
        timeSplit: { dnsLookup: 0, tcpConnection: 0, tlsHandshake: 0, firstByte: 0, total: 0 },
        fcp: 0,
        lcp: 0,
        speedIndex: 0,
        curlTotalTime: 0,
        playwrightTotalTime: 0,
        error: (error as Error).message
      });
    }
    
    stopwatch.stop();
    totalMeasurementDuration += stopwatch.getTiming().duration;
    measurements.push({ measurementNumber: i + 1, timestamp: performance.now(), webTests });
    progressBar.update(i + 1);
  }
  progressBar.stop();

  totalStopwatch.stop();
  try {
    await axios.post(`${SERVER_URL}/stop-tunnel`, { toolName: tunnelTool.name });
    if (ENABLE_LOGGING) console.log(chalk.green('Tunnel stopped'));
  } catch (error) {
    errors.push({ stage: 'Tunnel Cleanup', error: (error as Error).message });
  }

  return {
    tool: tunnelTool.name,
    diagnostics,
    measurements,
    durations: {
      total: totalStopwatch.getTiming(),
      toolSetup: setupStopwatch.getTiming(),
      diagnostics: diagnosticsStopwatch.getTiming(),
      measurements: { total: { duration: totalMeasurementDuration }, average: { duration: totalMeasurementDuration / numMeasurements } },
    },
    pcapFilePath: enablePcap ? 'placeholder.pcap' : undefined,
    errors,
  };
}

/**
 * Flattens results for JSON serialization, focusing on web tests.
 * @param result Run result to flatten.
 * @returns Array of flattened measurements.
 */
function flattenResults(result: RunResult): FlattenedMeasurement[] {
  return result.measurements.map(measurement => ({
    toolName: result.tool,
    measurementNumber: measurement.measurementNumber,
    timestamp: measurement.timestamp,
    webTests: measurement.webTests.map(test => ({
      url: test.url,
      statusCode: test.statusCode,
      downloadSpeed: test.speedDownload,
      uploadSpeed: test.speedUpload,
      dnsLookup: test.timeSplit.dnsLookup * 1000,
      tcpConnection: test.timeSplit.tcpConnection * 1000,
      tlsHandshake: test.timeSplit.tlsHandshake * 1000,
      timeToFirstByte: test.timeSplit.firstByte * 1000,
      totalTime: test.timeSplit.total * 1000,
      fcp: test.fcp,
      lcp: test.lcp,
      speedIndex: test.speedIndex,
      curlTotalTime: test.curlTotalTime,
      playwrightTotalTime: test.playwrightTotalTime,
      error: test.error,
    })),
    totalDuration: result.durations.total.duration,
    setupDuration: result.durations.toolSetup.duration,
    diagnosticsDuration: result.durations.diagnostics.duration,
    measurementDuration: result.durations.measurements.total.duration,
    hasErrors: result.errors.length > 0,
    errorCount: result.errors.length,
    errors: result.errors.map(e => `${e.stage}: ${e.error}`),
  }));
}

/**
 * Saves measurement results to a JSON file.
 * @param directory Output directory.
 * @param toolName Tool name for filename.
 * @param result Run result to save.
 */
async function saveResults(directory: string, toolName: string, result: RunResult): Promise<void> {
  const filePath = path.join(directory, `${toolName}.json`);
  const flattened = flattenResults(result);
  await fs.writeFile(filePath, JSON.stringify(flattened, null, 2));
  console.log(chalk.green(`Results saved: ${filePath}`));
}

/** Main Execution */
async function main(): Promise<void> {
  const timestamp = new Date().toISOString().replace(/[-:T]/g, '').slice(2, 14);
  const resultsDir = `results/all-${timestamp}`;
  await fs.mkdir(resultsDir, { recursive: true });

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
    const result = await performMeasurementsRun(tool, ENABLE_PCAP, NUM_MEASUREMENTS);
    await saveResults(resultsDir, tool.name, result);
    const duration = (Date.now() - start) / 1000;
    fastestTime = Math.min(fastestTime, duration);
    slowestTime = Math.max(slowestTime, duration);
    progressBar.update(i + 1, { fastest: fastestTime.toFixed(2), slowest: slowestTime.toFixed(2) });
  }
  progressBar.stop();

  console.log(chalk.green(`Fastest: ${fastestTime.toFixed(2)}s, Slowest: ${slowestTime.toFixed(2)}s`));
}

main().catch(error => {
  console.error(chalk.red('Fatal error:', error));
  process.exit(1);
});