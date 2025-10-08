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
import { TunnelTool, tunnelTools } from './tools';

/** Configuration Constants */
const TOR_SOCKS_PORT = 9050;
const TOR_SOCKS_HOST = '127.0.0.1';
const SERVER_HOST = '';
const SERVER_PORT = 3000;
const SERVER_URL = `http://${SERVER_HOST}:${SERVER_PORT}`;
const NUM_MEASUREMENTS = 5;
const ENABLE_LOGGING = true; // Enabled for debugging
const ENABLE_PCAP = false;
const NGROK_AUTH_FILE = 'ngrok-auth.txt';
const ZROK_AUTH_FILE = 'zrok-auth.txt';

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

interface FileMetadata {
  filename: string;
  size: number; // Bytes
  hash: string;
  contentType: string;
  timestamp: string;
}

interface FileTransferResult {
  filename: string;
  timestamp: number;
  originalMetadata: FileMetadata;
  receivedMetadata: FileMetadata;
  transferSuccess: boolean;
  hashMatch: boolean;
  metadataMatch: boolean;
  serverHash: string;
  clientHash: string;
  hashMatchDetails: {
    matched: boolean;
    serverHash: string;
    clientHash: string;
    timeTaken: number;
  };
  sizeMatch: boolean;
  transferStats: CurlResult;
  percentDownloaded: number;
  error?: string;
}

interface WebTestResult {
  url: string;
  statusCode: number;
  speedDownload: number;
  speedUpload: number;
  timeSplit: TimeSplit;
  curlTotalTime: number;
  playwrightTotalTime: number;
  error?: string;
}

interface Measurement {
  measurementNumber: number;
  timestamp: number;
  fileTransfers: { [key: string]: FileTransferResult };
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
  allDownloadsComplete: boolean;
  errors: { stage: string; error: string }[];
}

interface FlattenedMeasurement {
  toolName: string;
  measurementNumber: number;
  timestamp: number;
  fileTransfers: Array<{
    filename: string;
    timestamp: number;
    fileSize: number;
    contentType: string;
    transferSuccess: boolean;
    statusCode: number;
    downloadSpeed: number;
    uploadSpeed: number;
    dnsLookup: number; // Milliseconds
    tcpConnection: number; // Milliseconds
    tlsHandshake: number; // Milliseconds
    timeToFirstByte: number; // Milliseconds
    totalTransferTime: number; // Milliseconds
    hashMatch: boolean;
    sizeMatch: boolean;
    percentDownloaded: number;
    error?: string;
  }>;
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
 * Reads authentication tokens from a file.
 * @param filePath Path to the token file.
 * @returns Promise resolving to an array of tokens.
 */
async function readTokens(filePath: string): Promise<string[]> {
  try {
    const content = await fs.readFile(filePath, 'utf-8');
    return content.split('\n').filter(line => line.trim() !== '').slice(0, 10); // Limit to 10 tokens
  } catch (error) {
    console.error(chalk.red('Error reading ${filePath}: ${error}'));
    return [];
  }
}

/**
 * Performs a single file transfer attempt.
 * @param toolName Name of the tunneling tool.
 * @param url URL to download from.
 * @param filename Name of the file.
 * @param originalMetadata Server-provided metadata.
 * @returns Promise resolving to the transfer result.
 */
async function performFileTransferAttempt(
  toolName: string,
  url: string,
  filename: string,
  originalMetadata: FileMetadata
): Promise<FileTransferResult> {
  const startTime = performance.now();
  const tempFilePath = path.join(TEMP_DIR, `${Date.now()}-${filename}`);
  const progressUpdates: number[] = [];

  if (ENABLE_LOGGING) console.log(chalk.blue(`Initiating transfer: ${url} -> ${tempFilePath}`));
  if (toolName === "Beeceptor" && originalMetadata.size >= 25 * 1024 * 1024) {
    if (ENABLE_LOGGING) console.log(chalk.yellow(`Skipping download for ${filename}: File too large for Beeceptor`));
    return {
      filename,
      timestamp: startTime,
      originalMetadata,
      receivedMetadata: { filename, size: 0, hash: '', contentType: originalMetadata.contentType, timestamp: new Date().toISOString() },
      transferSuccess: false,
      hashMatch: false,
      metadataMatch: false,
      serverHash: originalMetadata.hash,
      clientHash: '',
      hashMatchDetails: { matched: false, serverHash: originalMetadata.hash, clientHash: '', timeTaken: 0 },
      sizeMatch: false,
      transferStats: { statusCode: 0, timeSplit: { dnsLookup: 0, tcpConnection: 0, tlsHandshake: 0, firstByte: 0, total: 0 }, ttfb: 0, latency: 0, sizeDownload: 0, speedDownload: 0, speedUpload: 0 },
      percentDownloaded: 0,
      error: "File too large for Beeceptor",
    };
  }
  try {
    await ensureTempDir();
    const isOnionUrl = url.includes('.onion');
    const curlArgs = [
      '--progress-bar',
      '-L',
      '-w',
      'DNS Lookup: %{time_namelookup}s\nTCP Connection: %{time_connect}s\nTLS Handshake: %{time_appconnect}s\nStart Transfer: %{time_starttransfer}s\nTotal Time: %{time_total}s\nDownload Speed: %{speed_download} bytes/sec\nUpload Speed: %{speed_upload} bytes/sec\nHTTP Code: %{http_code}\nSize of Download: %{size_download} bytes\n',
      '-D', '-',
      '-o', tempFilePath,
      '-s',
    ];

    if (isOnionUrl) curlArgs.push('--socks5-hostname', `${TOR_SOCKS_HOST}:${TOR_SOCKS_PORT}`, '--insecure');
    curlArgs.push(url);

    let progressBuffer = '';
    let lastPercent = -1;
    const progressCallback = (data: string) => {
      if (ENABLE_LOGGING) console.log(chalk.gray(`Progress data: ${data}`));
      progressBuffer += data;
      const parts = progressBuffer.split('\r');
      progressBuffer = parts.pop() || '';
      for (const part of parts) {
        const match = part.match(/(\d+\.\d+)%/);
        if (match) {
          const percent = parseFloat(match[1]);
          progressUpdates.push(percent);
          if (percent !== lastPercent) {
            console.log(chalk.blue(`Progress ${filename}: ${percent}%`));
            lastPercent = percent;
          }
        }
      }
    };

    await clearDnsCache();
    const curlOutput = await runCommand('curl', curlArgs, progressCallback);
    const transferStats = new Curl().parse(curlOutput);
    const fileExists = await fs.access(tempFilePath).then(() => true).catch(() => false);
    if (!fileExists) {
      throw new Error(`Downloaded file not created (HTTP ${transferStats.statusCode})`);
    }
    const percentDownloaded = originalMetadata.size > 0 
      ? Math.min(100, (transferStats.sizeDownload / originalMetadata.size) * 100)
      : 0;
    const serverHash = originalMetadata.hash;
    const serverSize = originalMetadata.size;
    const hashStart = performance.now();
    const clientHash = await calculateFileHash(tempFilePath);
    const hashEnd = performance.now();

    const stats = await fs.stat(tempFilePath);
    const receivedMetadata: FileMetadata = {
      filename,
      size: stats.size,
      hash: clientHash,
      contentType: originalMetadata.contentType,
      timestamp: new Date().toISOString(),
    };

    const hashMatch = serverHash === clientHash;
    const sizeMatch = serverSize === stats.size;

    await fs.unlink(tempFilePath);

    return {
      filename,
      timestamp: startTime,
      originalMetadata,
      receivedMetadata,
      transferSuccess: transferStats.statusCode === 200,
      hashMatch,
      metadataMatch: sizeMatch && hashMatch,
      serverHash,
      clientHash,
      hashMatchDetails: { matched: hashMatch, serverHash, clientHash, timeTaken: hashEnd - hashStart },
      sizeMatch,
      transferStats,
      percentDownloaded
    };
  } catch (error) {
    console.error(chalk.red(`Transfer failed for ${filename}: ${(error as Error).message}`));
    try { await fs.unlink(tempFilePath); } catch {}
    const transferStats = { statusCode: 0, timeSplit: { dnsLookup: 0, tcpConnection: 0, tlsHandshake: 0, firstByte: 0, total: 0 }, ttfb: 0, latency: 0, sizeDownload: 0, speedDownload: 0, speedUpload: 0, error: (error as Error).message };
    return {
      filename,
      timestamp: startTime,
      originalMetadata,
      receivedMetadata: { filename, size: 0, hash: '', contentType: originalMetadata.contentType, timestamp: new Date().toISOString() },
      transferSuccess: false,
      hashMatch: false,
      metadataMatch: false,
      serverHash: originalMetadata.hash,
      clientHash: '',
      hashMatchDetails: { matched: false, serverHash: originalMetadata.hash, clientHash: '', timeTaken: 0 },
      sizeMatch: false,
      transferStats,
      percentDownloaded: 0,
      error: (error as Error).message,
    };
  }
}

/**
 * Attempts to start or restart the tunnel with retries and token switching on failure.
 * @param toolName Name of the tunneling tool.
 * @returns Promise resolving to the new tunnel URL or empty string on failure.
 */
async function startTunnel(toolName: string): Promise<string> {
    let tokens: string[] = [];
    if (toolName === 'Zrok') {
      tokens = await readTokens(ZROK_AUTH_FILE);
      if (ENABLE_LOGGING) console.log(chalk.gray(`Loaded ${tokens.length} zrok tokens`));
    } else if (toolName === 'Ngrok') {
      tokens = await readTokens(NGROK_AUTH_FILE);
      if (ENABLE_LOGGING) console.log(chalk.gray(`Loaded ${tokens.length} ngrok tokens`));
    }
  
    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        if (ENABLE_LOGGING) console.log(chalk.cyan(`Attempt ${attempt + 1}/3 to start tunnel for ${toolName}`));
        
        // First try to stop any existing tunnel
        try {
          await axios.post(`${SERVER_URL}/stop-tunnel`, { toolName });
        } catch (error) {
          console.warn(chalk.yellow(`Could not stop existing tunnel (might not exist): ${error}`));
          // Continue anyway
        }
        
        // If this is a retry attempt and we have tokens available, try switching tokens first
        if (attempt > 0 && tokens.length > 0) {
          const tokenIndex = attempt - 1 < tokens.length ? attempt - 1 : 0;
          const endpoint = toolName === 'Ngrok' ? 'switch-ngrok-token' : 'switch-zrok-token';
          
          try {
            if (ENABLE_LOGGING) console.log(chalk.cyan(`Trying with token ${tokenIndex + 1}/${tokens.length}`));
            const switchResponse = await axios.post(`${SERVER_URL}/${endpoint}`, { token: tokens[tokenIndex] });
            const newUrl = switchResponse.data.url?.replace(/\/$/, '');
            if (newUrl) {
              if (ENABLE_LOGGING) console.log(chalk.green(`Tunnel started after token switch: ${newUrl}`));
              return newUrl;
            }
          } catch (switchError) {
            console.error(chalk.red(`Failed to switch token: ${switchError}`));
            // Continue to normal tunnel start
          }
        }
        
        // Standard tunnel start
        const response = await axios.post(`${SERVER_URL}/start-tunnel`, { toolName });
        const newUrl = response.data.url.replace(/\/$/, '');
        if (ENABLE_LOGGING) console.log(chalk.green(`Tunnel started: ${newUrl}`));
        return newUrl;
      } catch (error: any) {
        console.error(chalk.red(`Failed to start tunnel for ${toolName} (attempt ${attempt + 1}/3): ${error}`));
      }
      
      if (attempt < 2) {
        if (ENABLE_LOGGING) console.log(chalk.yellow(`Waiting 5 seconds before retrying tunnel start for ${toolName}`));
        await new Promise(resolve => setTimeout(resolve, 5000)); // 5-second delay before next attempt
      }
    }
  
    console.error(chalk.red(`Failed to start tunnel for ${toolName} after 3 attempts`));
    return '';
}

/**
 * Performs a file transfer with token switching on failure.
 * @param toolName Name of the tunneling tool.
 * @param url Initial URL to download from.
 * @param filename Name of the file.
 * @param originalMetadata Server-provided metadata.
 * @returns Promise resolving to the transfer result.
 */
// Replace or update the token switching logic in performFileTransfer function in switchfail.ts

async function performFileTransfer(
    toolName: string,
    url: string,
    filename: string,
    originalMetadata: FileMetadata
  ): Promise<FileTransferResult> {
    let currentUrl = url;
    let transferResult = await performFileTransferAttempt(toolName, currentUrl, filename, originalMetadata);
    let tokenSwitchAttempted = false;
  
    if (transferResult.transferSuccess) {
      if (ENABLE_LOGGING) console.log(chalk.green(`Transfer succeeded for ${filename} on attempt 1, counting as legitimate transfer`));
      return transferResult;
    }
  
    // Handle token switching and retries for ngrok and zrok
    if (toolName === 'Ngrok' || toolName === 'Zrok') {
      let tokens: string[] = [];
      let tokenIndex = 0;
  
      if (toolName === 'Ngrok') {
        tokens = await readTokens(NGROK_AUTH_FILE);
        if (ENABLE_LOGGING) console.log(chalk.gray(`Loaded ${tokens.length} ngrok tokens`));
      } else if (toolName === 'Zrok') {
        tokens = await readTokens(ZROK_AUTH_FILE);
        if (ENABLE_LOGGING) console.log(chalk.gray(`Loaded ${tokens.length} zrok tokens`));
      }
  
      if (tokens.length === 0) {
        if (ENABLE_LOGGING) console.log(chalk.yellow(`No tokens available for ${toolName}, returning failed result`));
        return transferResult;
      }
  
      while (tokenIndex < tokens.length) {
        try {
          let shouldSwitchToken = false;
          if (toolName === 'Ngrok' && (transferResult.transferStats.statusCode === 403 || tokenSwitchAttempted)) {
            shouldSwitchToken = true;
            console.log(chalk.yellow(`Ngrok ${transferResult.transferStats.statusCode || 'error'} detected, switching to token ${tokenIndex + 1}/${tokens.length}`));
          } else if (toolName === 'Zrok' && (transferResult.error?.includes('401 shareUnauthorized') || transferResult.error?.includes('Timeout') || tokenSwitchAttempted)) {
            shouldSwitchToken = true;
            console.log(chalk.yellow(`Zrok error detected (${transferResult.error}), switching to token ${tokenIndex + 1}/${tokens.length}`));
          }
  
          if (shouldSwitchToken) {
            const endpoint = toolName === 'Ngrok' ? 'switch-ngrok-token' : 'switch-zrok-token';
            let response;
            try {
              response = await axios.post(`${SERVER_URL}/${endpoint}`, { token: tokens[tokenIndex] });
              tokenSwitchAttempted = true;
              
              // Get the new URL from the response
              currentUrl = response.data.url || await startTunnel(toolName);
              if (!currentUrl) {
                throw new Error(`Failed to start tunnel after token switch`);
              }
              currentUrl = currentUrl + `/download/${filename}`;
              if (ENABLE_LOGGING) console.log(chalk.green(`Tunnel restarted with new URL: ${currentUrl}`));
              tokenIndex++;
            } catch (error: any) {
              if (error.response?.status === 400 && toolName === 'Zrok') {
                // No active zrok tunnel, attempt to start one
                console.log(chalk.yellow(`No active zrok tunnel, attempting to start new tunnel`));
                currentUrl = await startTunnel(toolName);
                if (!currentUrl) {
                  throw new Error(`Failed to start zrok tunnel after 400 error`);
                }
                currentUrl = currentUrl + `/download/${filename}`;
              } else {
                throw error;
              }
            }
          } else {
            if (ENABLE_LOGGING) console.log(chalk.yellow(`No authentication or timeout error detected for ${toolName}, returning failed result`));
            return transferResult;
          }
  
          // Retry transfer with new URL
          transferResult = await performFileTransferAttempt(toolName, currentUrl, filename, originalMetadata);
          if (transferResult.transferSuccess) {
            if (ENABLE_LOGGING) console.log(chalk.green(`Transfer succeeded for ${filename} after token switch (attempt ${tokenIndex}), counting as legitimate transfer`));
            return transferResult;
          }
        } catch (error) {
          console.error(chalk.red(`Token switch failed for ${toolName} (attempt ${tokenIndex + 1}): ${error}`));
          transferResult.error = `Token switch failed: ${error}`;
          break; // Exit loop to avoid further retries
        }
      }
  
      console.error(chalk.red(`File transfer failed for ${filename} after ${tokenIndex} token switch attempts: ${transferResult.error}`));
    }
  
    return transferResult;
    }

async function performWebTest(url: string): Promise<WebTestResult> {
  let curlStopwatch = new Stopwatch();
  let playwrightStopwatch = new Stopwatch();

  curlStopwatch.start();
  const isOnionUrl = url.includes('.onion');
  const curlArgs = [
    '-L',
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
    '-D', '-',  
    '-o', '/dev/null',
    '-s',
  ];

  if (isOnionUrl) {
    curlArgs.push(
      '--socks5-hostname', `${TOR_SOCKS_HOST}:${TOR_SOCKS_PORT}`,
      '--insecure'
    );
  }

  curlArgs.push(url);

  await clearDnsCache();
  let curlResult: CurlResult;
  try {
    const curlOutput = await runCommand('curl', curlArgs);
    curlResult = new Curl().parse(curlOutput);
  } catch (error) {
    curlResult = {
      statusCode: 0,
      timeSplit: { dnsLookup: 0, tcpConnection: 0, tlsHandshake: 0, firstByte: 0, total: 0 },
      ttfb: 0,
      latency: 0,
      sizeDownload: 0,
      speedDownload: 0,
      speedUpload: 0,
      error: (error as Error).message
    };
  }
  curlStopwatch.stop();

  const curlTotalTime = curlStopwatch.getTiming().duration;
  let error: string | undefined = curlResult.error;
  let playwrightTotalTime = 0;
  if (!/^https?:\/\//i.test(url)) {
    url = `http://${url}`;
  }
  try {
    playwrightStopwatch.start();
    const browser = await chromium.launch({
      headless : true,
      args: isOnionUrl
        ? [`--proxy-server=socks5://${TOR_SOCKS_HOST}:${TOR_SOCKS_PORT}`]
        : []
    });
    const page = await browser.newPage();
    await page.goto(url, { waitUntil: 'load' });
    await browser.close();
    playwrightStopwatch.stop();
    playwrightTotalTime = playwrightStopwatch.getTiming().duration;
  } catch (err) {
    error = error || `Playwright error: ${(err as Error).message}`;
    if (ENABLE_LOGGING) console.error(chalk.red(error));
    if (playwrightStopwatch.getTiming().duration === 0) {
      playwrightStopwatch.stop();
      playwrightTotalTime = playwrightStopwatch.getTiming().duration;
    }
  }

  return {
    url,
    statusCode: curlResult.statusCode,
    speedDownload: curlResult.speedDownload,
    speedUpload: curlResult.speedUpload,
    timeSplit: curlResult.timeSplit,
    curlTotalTime,
    playwrightTotalTime,
    error
  };
}

/**
 * Ensures the temporary directory exists for file operations.
 */
async function ensureTempDir(): Promise<void> {
  await fs.mkdir(TEMP_DIR, { recursive: true });
}

/**
 * Calculates the SHA-256 hash of a file.
 * @param filePath Path to the file.
 * @returns Promise resolving to the file's hash.
 */
async function calculateFileHash(filePath: string): Promise<string> {
  const fileBuffer = await fs.readFile(filePath);
  return crypto.createHash('sha256').update(fileBuffer).digest('hex');
}

const TEMP_DIR = path.join(os.tmpdir(), 'tunnel-testbed');

/**
 * Executes a full measurement run for a tunneling tool.
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
  let allDownloadsComplete = true;
  let errors: { stage: string; error: string }[] = [];
  let availableFiles: FileMetadata[] = [];

  try {
    if (ENABLE_LOGGING) console.log(chalk.cyan(`Fetching file metadata from ${SERVER_URL}/files`));
    const response = await axios.get(`${SERVER_URL}/files`);
    availableFiles = response.data;
    if (ENABLE_LOGGING) console.log(chalk.green(`Fetched metadata for ${availableFiles.length} files`));
  } catch (error) {
    console.error(chalk.red(`Metadata fetch failed: ${(error as Error).message}`));
    errors.push({ stage: 'Metadata Fetch', error: (error as Error).message });
  }

  try {
    if (ENABLE_LOGGING) console.log(chalk.cyan(`Starting tunnel for ${tunnelTool.name}`));
    tunnelUrl = await startTunnel(tunnelTool.name);
    if (!tunnelUrl) {
      throw new Error('Failed to obtain a valid tunnel URL after retries');
    }
    if (ENABLE_LOGGING) console.log(chalk.green(`Tunnel established: ${tunnelUrl}`));
  } catch (error) {
    console.error(chalk.red(`Tunnel setup failed: ${(error as Error).message}`));
    errors.push({ stage: 'Tunnel Setup', error: (error as Error).message });
    tunnelUrl = ''; // Ensure tunnelUrl is empty on failure
  }

  setupStopwatch.stop();
  if (tunnelUrl) {
    if (ENABLE_LOGGING) console.log(chalk.gray(`Waiting 10 seconds for tunnel stabilization`));
    await new Promise(resolve => setTimeout(resolve, 10000)); // Stabilize tunnel
  }

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
    if (ENABLE_LOGGING) console.log(chalk.cyan(`Starting measurement ${i + 1} of ${numMeasurements} for ${tunnelTool.name}`));
    const stopwatch = new Stopwatch();
    stopwatch.start();
    const fileTransfers: { [key: string]: FileTransferResult } = {};
    const webTests: WebTestResult[] = [];
    let currentTunnelUrl = tunnelUrl; // Track tunnel URL for this measurement

    if (!currentTunnelUrl) {
      // Skip transfers if no valid tunnel URL
      for (const file of availableFiles) {
        fileTransfers[file.filename] = {
          filename: file.filename,
          timestamp: performance.now(),
          originalMetadata: file,
          receivedMetadata: { filename: file.filename, size: 0, hash: '', contentType: file.contentType, timestamp: new Date().toISOString() },
          transferSuccess: false,
          hashMatch: false,
          metadataMatch: false,
          serverHash: file.hash,
          clientHash: '',
          hashMatchDetails: { matched: false, serverHash: file.hash, clientHash: '', timeTaken: 0 },
          sizeMatch: false,
          transferStats: { statusCode: 0, timeSplit: { dnsLookup: 0, tcpConnection: 0, tlsHandshake: 0, firstByte: 0, total: 0 }, ttfb: 0, latency: 0, sizeDownload: 0, speedDownload: 0, speedUpload: 0 },
          percentDownloaded: 0,
          error: 'No valid tunnel URL'
        };
        allDownloadsComplete = false;
        if (ENABLE_LOGGING) console.log(chalk.red(`Skipped transfer for ${file.filename}: No valid tunnel URL`));
      }
      webTests.push({
        url: `${tunnelTool.name}/webtest`,
        statusCode: 0,
        speedDownload: 0,
        speedUpload: 0,
        timeSplit: { dnsLookup: 0, tcpConnection: 0, tlsHandshake: 0, firstByte: 0, total: 0 },
        curlTotalTime: 0,
        playwrightTotalTime: 0,
        error: 'No valid tunnel URL'
      });
    } else {
      for (const file of availableFiles) {
        if (ENABLE_LOGGING) console.log(chalk.blue(`Transferring file: ${file.filename}`));
        const result = await performFileTransfer(tunnelTool.name, `${currentTunnelUrl}/download/${file.filename}`, file.filename, file);
        fileTransfers[file.filename] = result;
        // Update tunnel URL if it changed during transfer (e.g., after token switch)
        const lastUrl = result.error?.match(/Initiating transfer: (https?:\/\/[^ ]+)/)?.[1] || currentTunnelUrl;
        currentTunnelUrl = lastUrl.replace(/\/download\/[^/]+$/, '');
        if (!result.transferSuccess) {
          allDownloadsComplete = false;
          if (ENABLE_LOGGING) console.log(chalk.red(`File transfer failed for ${file.filename}: ${result.error}`));
        } else {
          if (ENABLE_LOGGING) console.log(chalk.green(`File transfer succeeded for ${file.filename}`));
        }
      }

      try {
        if (ENABLE_LOGGING) console.log(chalk.blue(`Performing web test: ${currentTunnelUrl}/webtest`));
        const webResult = await performWebTest(`${currentTunnelUrl}/webtest`);
        webTests.push(webResult);
        if (ENABLE_LOGGING) console.log(chalk.green(`Web test completed: ${webResult.statusCode}`));
      } catch (error) {
        console.error(chalk.red(`Web test failed: ${(error as Error).message}`));
        webTests.push({
          url: `${currentTunnelUrl}/webtest`,
          statusCode: 0,
          speedDownload: 0,
          speedUpload: 0,
          timeSplit: { dnsLookup: 0, tcpConnection: 0, tlsHandshake: 0, firstByte: 0, total: 0 },
          curlTotalTime: 0,
          playwrightTotalTime: 0,
          error: (error as Error).message
        });
      }
    }
    
    stopwatch.stop();
    totalMeasurementDuration += stopwatch.getTiming().duration;
    measurements.push({ measurementNumber: i + 1, timestamp: performance.now(), fileTransfers, webTests });
    progressBar.update(i + 1);
  }
  progressBar.stop();

  totalStopwatch.stop();
  try {
    if (ENABLE_LOGGING) console.log(chalk.cyan(`Stopping tunnel for ${tunnelTool.name}`));
    await axios.post(`${SERVER_URL}/stop-tunnel`, { toolName: tunnelTool.name });
    if (ENABLE_LOGGING) console.log(chalk.green('Tunnel stopped'));
  } catch (error) {
    console.error(chalk.red(`Tunnel cleanup failed: ${(error as Error).message}`));
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
    allDownloadsComplete,
    errors,
  };
}

/**
 * Flattens results for JSON serialization.
 * @param result Run result to flatten.
 * @returns Array of flattened measurements.
 */
function flattenResults(result: RunResult): FlattenedMeasurement[] {
  return result.measurements.map(measurement => ({
    toolName: result.tool,
    measurementNumber: measurement.measurementNumber,
    timestamp: measurement.timestamp,
    fileTransfers: Object.entries(measurement.fileTransfers).map(([filename, transfer]) => ({
      filename,
      timestamp: transfer.timestamp,
      fileSize: transfer.originalMetadata.size,
      contentType: transfer.originalMetadata.contentType,
      transferSuccess: transfer.transferSuccess,
      statusCode: transfer.transferStats.statusCode,
      downloadSpeed: transfer.transferStats.speedDownload,
      uploadSpeed: transfer.transferStats.speedUpload,
      dnsLookup: transfer.transferStats.timeSplit.dnsLookup * 1000,
      tcpConnection: transfer.transferStats.timeSplit.tcpConnection * 1000,
      tlsHandshake: transfer.transferStats.timeSplit.tlsHandshake * 1000,
      timeToFirstByte: transfer.transferStats.timeSplit.firstByte * 1000,
      totalTransferTime: transfer.transferStats.timeSplit.total * 1000,
      hashMatch: transfer.hashMatch,
      sizeMatch: transfer.sizeMatch,
      percentDownloaded: transfer.percentDownloaded,
      error: transfer.error,
    })),
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
  await ensureTempDir();

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
  await fs.rm(TEMP_DIR, { recursive: true, force: true });
}

async function run(): Promise<void> {
  const args = process.argv.slice(2);
  const toolName = args.includes('--tool') ? args[args.indexOf('--tool') + 1] : null;
  const listTools = args.includes('--list');

  try {
    await fs.rm(TEMP_DIR, { recursive: true, force: true });
    if (ENABLE_LOGGING) console.log(chalk.green('Cleaned up temporary directory'));
  } catch (error) {
    console.error(chalk.red(`Failed to clean up temporary directory: ${(error as Error).message}`));
  }

  if (listTools) {
    console.log(chalk.cyan('Available tools:'));
    tunnelTools.forEach((tool, index) => console.log(`${index + 1}. ${tool.name}`));
    process.exit(0);
  }

  if (toolName) {
    const tool = tunnelTools.find(t => t.name.toLowerCase() === toolName.toLowerCase());
    if (!tool) {
      console.error(chalk.red(`Tool ${toolName} not found.`));
      process.exit(1);
    }

    console.log(chalk.cyan(`Running tool: ${tool.name}`));
    try {
      const timestamp = new Date().toISOString().replace(/[-:T]/g, '').slice(2, 14);
      const resultsDir = `results/${tool.name}-${timestamp}`;
      await fs.mkdir(resultsDir, { recursive: true });
      const result = await performMeasurementsRun(tool, ENABLE_PCAP, NUM_MEASUREMENTS);
      await saveResults(resultsDir, tool.name, result);
      console.log(chalk.green(`Completed measurements for ${tool.name}`));
    } catch (error) {
      console.error(chalk.red(`Error running ${tool.name}: ${(error as Error).message}`));
    } finally {
      try {
        await tool.stop();
        if (ENABLE_LOGGING) console.log(chalk.green(`Stopped ${tool.name}`));
      } catch (error) {
        console.error(chalk.red(`Failed to stop ${tool.name}: ${(error as Error).message}`));
      }
      process.exit(0);
    }
  }

  const timestamp = new Date().toISOString().replace(/[-:T]/g, '').slice(2, 14);
  await ensureTempDir();

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
    try {
      const result = await performMeasurementsRun(tool, ENABLE_PCAP, NUM_MEASUREMENTS);
      await saveResults(resultsDir, tool.name, result);
    } catch (error) {
      console.error(chalk.red(`Error running ${tool.name}: ${(error as Error).message}`));
    } finally {
      try {
        await tool.stop();
        if (ENABLE_LOGGING) console.log(chalk.green(`Stopped ${tool.name}`));
      } catch (error) {
        console.error(chalk.red(`Failed to stop ${tool.name}: ${(error as Error).message}`));
      }
    }
    const duration = (Date.now() - start) / 1000;
    fastestTime = Math.min(fastestTime, duration);
    slowestTime = Math.max(slowestTime, duration);
    progressBar.update(i + 1, { fastest: fastestTime.toFixed(2), slowest: slowestTime.toFixed(2) });
  }
  progressBar.stop();

  console.log(chalk.green(`Fastest: ${fastestTime.toFixed(2)}s, Slowest: ${slowestTime.toFixed(2)}s`));
  try {
    await fs.rm(TEMP_DIR, { recursive: true, force: true });
    if (ENABLE_LOGGING) console.log(chalk.green('Cleaned up temporary directory'));
  } catch (error) {
    console.error(chalk.red(`Failed to clean up temporary directory: ${(error as Error).message}`));
  }

  process.exit(0);
}

run().catch(error => {
  console.error(chalk.red('Fatal error:', error));
  try {
    fs.rmSync(TEMP_DIR, { recursive: true, force: true });
  } catch {}
  process.exit(1);
});