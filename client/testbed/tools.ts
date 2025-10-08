import { spawn, exec, ChildProcess } from 'child_process';
import http from 'http';
import axios from 'axios';
import fs from 'fs';

export interface TunnelTool {
  name: string;
  preSetupCommands?: string[][];
  preStartCommands?: string[][];
  postSetupCommands?: string[][];
  start: (options?: TunnelOptions) => Promise<string>;
  stop: () => Promise<void>;
}

interface TunnelOptions {
  port?: number;
  urlPattern?: string | RegExp;
}

abstract class BaseTunnel implements TunnelTool {
  abstract name: string;
  protected process: any;
  preSetupCommands?: string[][];
  preStartCommands?: string[][];
  postSetupCommands?: string[][];

  async start(options: TunnelOptions = { port: 3000, urlPattern: /https:\/\/[^\s]+/ }): Promise<string> {
    await this.runPreSetupCommands();
    await this.runPreStartCommands();
    console.log(`Starting ${this.name} on port ${options.port}`);
    const url = await this.launchTunnel(options);
    // await this.runPostSetupCommands(); // Run post-setup commands after starting the tunnel
    return url;
  }

  abstract launchTunnel(options: TunnelOptions): Promise<string>;

  async stop(): Promise<void> {
    console.log(`Stopping ${this.name}`);
    this.process.kill();
  }

  protected async runPreSetupCommands() {
    if (this.preSetupCommands) {
      for (const command of this.preSetupCommands) {
        await this.runCommand(command[0], command.slice(1));
      }
    }
  }

  protected async runPreStartCommands() {
    if (this.preStartCommands) {
      for (const command of this.preStartCommands) {
        await this.runCommand(command[0], command.slice(1));
      }
    }
  }

  protected async runPostSetupCommands() {
    if (this.postSetupCommands) {
      for (const command of this.postSetupCommands) {
        await this.runCommand(command[0], command.slice(1));
      }
    }
  }

  protected runCommand(command: string, args: string[]): Promise<void> {
    return new Promise((resolve, reject) => {
      const process = spawn(command, args);
      process.on('close', (code) => {
        if (code === 0) {
          resolve();
        } else {
          reject(new Error(`Command ${command} failed with code ${code}`));
        }
      });
    });
  }
}

export class LocalTunnel extends BaseTunnel {
  name = 'LocalTunnel';
  preSetupCommands = [];
  preStartCommands = [];

  async launchTunnel({ port = 3000 }: TunnelOptions): Promise<string> {
    // Start the LocalTunnel process using the 'lt' command
    this.process = spawn('lt', ['--port', port.toString()]);

    return new Promise((resolve, reject) => {
      this.process.stdout.on('data', (data: Buffer) => {
        const output = data.toString();
        const urlMatch = output.match(/your url is: (https:\/\/[^\s]+)/);

        if (urlMatch) {
          const localTunnelUrl = urlMatch[1];
          console.log(`LocalTunnel URL: i${localTunnelUrl}`); //removed the variable and hardcoded it : ${password}
          
          // Get the tunnel password using the provided command
          this.getTunnelPassword()
            .then(password => {
              console.log(`Tunnel Password: ${password}`);
              resolve(localTunnelUrl);
            })
            .catch(err => {
              console.error('Failed to retrieve tunnel password:', err);
              reject(err);
            });
        }
      });

      this.process.stderr.on('data', (data: Buffer) => {
        const output = data.toString();
        if (output.includes('error')) {
          reject(new Error('Failed to start LocalTunnel'));
        }
      });

      setTimeout(() => {
        reject(new Error('Timeout: Failed to start LocalTunnel'));
      }, 10000);
    });
  }

  // Function to retrieve the tunnel password from the loca.lt service
  async getTunnelPassword(): Promise<string> {
    try {
      const response = await axios.get('https://loca.lt/mytunnelpassword');
      return response.data;
    } catch (error) {
      throw new Error('Could not retrieve tunnel password');
    }
  }
}

export class CloudflareTunnel extends BaseTunnel {
  name = 'Cloudflared';
  preSetupCommands = [];
  preStartCommands = [];

  async launchTunnel({ port = 8000 }: TunnelOptions): Promise<string> {
    // Start the Cloudflare tunnel process
    this.process = spawn('cloudflared', ['tunnel', '--url', `http://localhost:${port}`], { shell: true });

    return new Promise((resolve, reject) => {
      let tunnelUrl: string | null = null;

      const handleOutput = (data: Buffer) => {
        const output = data.toString();
        console.log(`Cloudflared Output: ${output}`);

        // Match the specific URL pattern for Cloudflare Tunnel
        const urlMatch = output.match(/https?:\/\/[a-z0-9-]+\.trycloudflare\.com/);
        if (urlMatch) {
          tunnelUrl = urlMatch[0];
          console.log(`Cloudflare Tunnel URL: ${tunnelUrl}`);
        }
      };

      // Capture both stdout and stderr output
      this.process.stdout.on('data', handleOutput);
      this.process.stderr.on('data', handleOutput);

      // Process exit handling
      this.process.on('exit', (code) => {
        if (code === 0 && tunnelUrl) {
          resolve(tunnelUrl);
        } else {
          reject(new Error('Cloudflare Tunnel failed to launch or URL was not detected.'));
        }
      });

      // Timeout handling
      setTimeout(() => {
        if (tunnelUrl) {
          resolve(tunnelUrl);
        } else {
          reject(new Error('Timeout: Failed to start Cloudflare Tunnel or detect the URL.'));
        }
      }, 15000); // Timeout after 15 seconds
    });
  }
}

export class PagekiteTunnel extends BaseTunnel {
  name = 'Pagekite';
  preSetupCommands = [];
  preStartCommands = [];

  async launchTunnel({ port = 3000 }: TunnelOptions): Promise<string> {
    this.process = spawn('python3', ['pagekite.py', port.toString(), 'sun4.pagekite.me']);

    return new Promise((resolve, reject) => {
      const url = `http://sun4.pagekite.me`;
      console.log(`Tunnel URL: ${url}`);
      resolve(url);

      this.process.stderr.on('data', (data: Buffer) => {
        const output = data.toString();
        if (output.includes('error')) {
          reject(new Error('Failed to start Pagekite Tunnel'));
        }
      });

      setTimeout(() => {
        reject(new Error('Timeout: Failed to start Pagekite Tunnel'));
      }, 10000);
    });
  }
}

  export class NgrokTunnel extends BaseTunnel {
    name = 'Ngrok';
    preSetupCommands = [['echo', 'Running pre-setup command for ngrok']];
    preStartCommands = [['echo', 'Running pre-start command for ngrok']];
  
    async launchTunnel({ port = 3000, urlPattern = /https:\/\/[^\s]+/ }: TunnelOptions): Promise<string> {
      this.process = spawn('ngrok', ['http', port.toString()]);
  
      return new Promise((resolve, reject) => {
        this.process.stderr.on('data', (data: Buffer) => {
          console.error('Ngrok error:', data.toString());
        });
  
        setTimeout(() => {
          const options = {
            hostname: '127.0.0.1',
            port: 4040,
            path: '/api/tunnels',
            method: 'GET'
          };
  
          const req = http.request(options, (res) => {
            let data = '';
  
            res.on('data', (chunk) => {
              data += chunk;
            });
  
            res.on('end', () => {
              try {
                const parsedData = JSON.parse(data);
                const ngrokUrl = parsedData.tunnels[0]?.public_url;
  
                if (ngrokUrl && ngrokUrl.match(urlPattern)) {
                  console.log(`ngrok tunnel started with URL: ${ngrokUrl}`);
                  resolve(ngrokUrl);
                } else {
                  console.error('Could not retrieve ngrok URL.');
                  reject(new Error('Could not retrieve ngrok URL.'));
                }
              } catch (error) {
                console.error('Error parsing ngrok response:', error);
                reject(error);
              }
            });
          });
  
          req.on('error', (error) => {
            console.error('Error fetching ngrok URL:', error);
            reject(error);
          });
  
          req.end();
        }, 10000); // Increased delay to 10 seconds
      });
    }
  }

  export class ServeoTunnel extends BaseTunnel {
    name = 'Serveo';
    preSetupCommands = [];
    preStartCommands = [];
  
    async launchTunnel({ port = 3000 }: TunnelOptions): Promise<string> {
      this.process = spawn('ssh', ['-R', `80:localhost:${port}`, 'serveo.net']);
  
      return new Promise((resolve, reject) => {
        this.process.stdout.on('data', (data: Buffer) => {
          const output = data.toString();
          const urlMatch = output.match(/Forwarding HTTP traffic from (https:\/\/[^\s]+)/);
  
          if (urlMatch) {
            const serveoUrl = urlMatch[1];
            console.log(`Serveo URL: ${serveoUrl}`);
            resolve(serveoUrl);
          }
        });
  
        this.process.stderr.on('data', (data: Buffer) => {
          const output = data.toString();
          if (output.includes('error')) {
            reject(new Error('Failed to start Serveo Tunnel'));
          }
        });
  
        setTimeout(() => {
          reject(new Error('Timeout: Failed to start Serveo Tunnel'));
        }, 10000);
      });
    }
  }

  export class TelebitTunnel extends BaseTunnel {
    name = 'Telebit';
    preSetupCommands = [];
    preStartCommands = [];
  
    async launchTunnel({ port = 3000 }: TunnelOptions): Promise<string> {
      this.process = spawn('pnpm', ['dlx', 'telebit', 'http', port.toString()], { shell: true });
  
      return new Promise((resolve, reject) => {
        this.process.stdout.on('data', (data: Buffer) => {
          const output = data.toString();
          const urlMatch = output.match(/Forwarding (https:\/\/[^\s]+) =>/);
  
          if (urlMatch) {
            const telebitUrl = urlMatch[1];
            console.log(`Telebit URL: ${telebitUrl}`);
            resolve(telebitUrl);
          }
        });
  
        this.process.stderr.on('data', (data: Buffer) => {
          const output = data.toString();
          if (output.includes('error')) {
            reject(new Error('Failed to start Telebit Tunnel'));
          }
        });
  
        setTimeout(() => {
          reject(new Error('Timeout: Failed to start Telebit Tunnel'));
        }, 10000);
      });
    }
  }

  export class BoreTunnel extends BaseTunnel {
    name = 'Bore';
    preSetupCommands = [];
    preStartCommands = [];
  
    async launchTunnel({ port = 3000 }: TunnelOptions): Promise<string> {
      // Start the bore process
      this.process = spawn('bore', ['local', port.toString(), '--to', 'bore.pub'], { shell: true });
  
      return new Promise((resolve, reject) => {
        const handleOutput = (data: Buffer) => {
          const output = data.toString();
          const words = output.split(/\s+/);
          words.forEach(word => {
            if (word.startsWith('bore.pub')) {
              const boreUrl = `http://${word}`
              console.log(`Bore URL: ${boreUrl}`);
              resolve(boreUrl);
            }
          });
        };
        this.process.stdout.on('data', handleOutput);
        this.process.stderr.on('data', handleOutput);
  
        setTimeout(() => {
          reject(new Error('Timeout: Failed to start Bore Tunnel'));
        }, 5000); 
      });
    }
  }

  export class LocalxposeTunnel extends BaseTunnel {
    name = 'Localxpose';
    preSetupCommands = [];
    preStartCommands = [];
  
    async launchTunnel({ port = 3000 }: TunnelOptions): Promise<string> {
      this.process = spawn('pnpm', ['dlx', 'loclx', 'tunnel', 'http', '--to', `localhost:${port}`], { shell: true });
  
      return new Promise((resolve, reject) => {
        const urlRegex = /([a-z0-9]+\.loclx\.io)/;
  
        const handleOutput = (data: Buffer) => {
          const output = data.toString();
          const urlMatch = output.match(urlRegex);
  
          if (urlMatch) {
            const loclxUrl = `http://${urlMatch[0]}`;
            console.log(`Loclx URL: ${loclxUrl}`);
            resolve(loclxUrl);
          }
        };
  
        this.process.stdout.on('data', handleOutput);
        this.process.stderr.on('data', handleOutput);
  
        this.process.on('close', (code) => {
          console.log(`Localxpose process exited with code ${code}`);
          if (code !== 0) {
            reject(new Error('Failed to start Localxpose Tunnel'));
          }
        });
  
        setTimeout(() => {
          reject(new Error('Timeout: Failed to start Localxpose Tunnel'));
        }, 10000);
      });
    }
  }

  
  export class ExposeTunnel extends BaseTunnel {
    name = 'Expose';
    preSetupCommands = [];
    preStartCommands = [];
  
    async launchTunnel({ port = 3000 }: TunnelOptions): Promise<string> {
      this.process = spawn('expose', ['share', `http://localhost:${port}`], { shell: true });
  
      return new Promise((resolve, reject) => {
        const urlRegex = /Public HTTPS:\s+(https:\/\/[^\s]+)/;
  
        const handleOutput = (data: Buffer) => {
          const output = data.toString();
          const urlMatch = output.match(urlRegex);
  
          if (urlMatch) {
            const exposeUrl = urlMatch[1];
            console.log(`Expose URL: ${exposeUrl}`);
            resolve(exposeUrl);
          }
        };
  
        this.process.stdout.on('data', handleOutput);
        this.process.stderr.on('data', handleOutput);
  
        this.process.on('close', (code) => {
          console.log(`Expose process exited with code ${code}`);
          if (code !== 0) {
            reject(new Error('Failed to start Expose Tunnel'));
          }
        });
  
        setTimeout(() => {
          reject(new Error('Timeout: Failed to start Expose Tunnel'));
        }, 10000);
      });
    }
  }

  export class LoopholeTunnel extends BaseTunnel {
    name = 'Loophole';
    preSetupCommands = [];
    preStartCommands = [];
  
    async launchTunnel({ port = 3000 }: TunnelOptions): Promise<string> {
      this.process = spawn('./loophole', ['http', port.toString()]);
  
      return new Promise((resolve, reject) => {
        const urlRegex = /(https:\/\/[^\s]+) ->/;
  
        const handleOutput = (data: Buffer) => {
          const output = data.toString();
          const urlMatch = output.match(urlRegex);
  
          if (urlMatch) {
            const loopholeUrl = urlMatch[1];
            console.log(`Loophole URL: ${loopholeUrl}`);
            resolve(loopholeUrl);
          }
        };
  
        this.process.stdout.on('data', handleOutput);
        this.process.stderr.on('data', handleOutput);
  
        this.process.on('close', (code) => {
          console.log(`Loophole process exited with code ${code}`);
          if (code !== 0) {
            reject(new Error('Failed to start Loophole Tunnel'));
          }
        });
  
        setTimeout(() => {
          reject(new Error('Timeout: Failed to start Loophole Tunnel'));
        }, 10000);
      });
    }
  }


  export class PinggyTunnel extends BaseTunnel {
    name = 'Pinggy';
    preSetupCommands = [];
    preStartCommands = [];
  
    async launchTunnel({ port = 3000 }: TunnelOptions): Promise<string> {
      this.process = spawn('ssh', ['-p', '443', '-R0:localhost:3000', '-L4300:localhost:4300', 'qr@a.pinggy.io'], { shell: true });
  
      return new Promise((resolve, reject) => {
        const urlRegex = /(https:\/\/[^\s]+\.free\.pinggy\.link)/;
  
        const handleOutput = (data: Buffer) => {
          const output = data.toString();
          const urlMatch = output.match(urlRegex);
  
          if (urlMatch) {
            const pinggyUrl = urlMatch[1];
            console.log(`Pinggy URL: ${pinggyUrl}`);
            resolve(pinggyUrl);
          }
        };
  
        this.process.stdout.on('data', handleOutput);
        this.process.stderr.on('data', handleOutput);
  
        this.process.on('close', (code) => {
          console.log(`Pinggy process exited with code ${code}`);
          if (code !== 0) {
            reject(new Error('Failed to start Pinggy Tunnel'));
          }
        });
  
        setTimeout(() => {
          reject(new Error('Timeout: Failed to start Pinggy Tunnel'));
        }, 10000); // Set a reasonable timeout
      });
    }
  }
  
  export class TailscaleTunnel extends BaseTunnel {
    name = 'Tailscale';
    preSetupCommands = [];
    preStartCommands = [];
  
    async launchTunnel({ port = 3000 }: TunnelOptions): Promise<string> {
      this.process = spawn('sudo tailscale', ['funnel', port.toString()], { shell: true });
  
      return new Promise((resolve, reject) => {
        const urlRegex = /(https:\/\/[^\s]+\.ts\.net\/)/;
  
        const handleOutput = (data: Buffer) => {
          const output = data.toString();
          const urlMatch = output.match(urlRegex);
  
          if (urlMatch) {
            const tailscaleUrl = urlMatch[1];
            console.log(`Tailscale URL: ${tailscaleUrl}`);
            resolve(tailscaleUrl);
          }
        };
  
        this.process.stdout.on('data', handleOutput);
        this.process.stderr.on('data', handleOutput);
  
        this.process.on('close', (code) => {
          console.log(`Tailscale process exited with code ${code}`);
          if (code !== 0) {
            reject(new Error('Failed to start Tailscale Tunnel'));
          }
        });
  
        setTimeout(() => {
          reject(new Error('Timeout: Failed to start Tailscale Tunnel'));
        }, 10000); // Set a reasonable timeout
      });
    }
  }

  export class TunnelPyjamas extends BaseTunnel {
    name = 'TunnelPyjamas';
    preSetupCommands = [];
    preStartCommands = [];
    private wgProcess: ChildProcess | null = null;

    async launchTunnel({ port = 3000 }: TunnelOptions): Promise<string> {
      return new Promise((resolve, reject) => {
        // Download new tunnel configuration
        exec(`curl https://tunnel.pyjam.as/${port} > tunnel.conf`, (error, stdout, stderr) => {
          if (error) {
            reject(new Error(`Failed to download tunnel configuration: ${stderr}`));
            return;
          }

          // Secure the tunnel.conf file
          fs.chmodSync('./tunnel.conf', 0o600);

          // Bring up the tunnel
          this.wgProcess = spawn('sudo', ['wg-quick', 'up', './tunnel.conf'], { shell: true });

          const urlRegex = /on (https:\/\/[^\s]+) ✨/;

          const handleOutput = (data: Buffer) => {
            const output = data.toString();
            const urlMatch = output.match(urlRegex);

            if (urlMatch) {
              let pyjamasUrl = urlMatch[1];
              if (pyjamasUrl.endsWith('/')) {
                pyjamasUrl = pyjamasUrl.slice(0, -1);
              }
              console.log(`TunnelPyjamas URL: ${pyjamasUrl}`);
              resolve(pyjamasUrl);
            }
          };

          this.wgProcess.stdout.on('data', handleOutput);
          this.wgProcess.stderr.on('data', (data: Buffer) => {
            console.error(`wg-quick error: ${data.toString()}`);
          });

          this.wgProcess.on('close', (code) => {
            if (code !== 0) {
              reject(new Error('Failed to start TunnelPyjamas Tunnel'));
            }
          });

          setTimeout(() => {
            reject(new Error('Timeout: Failed to start TunnelPyjamas Tunnel'));
          }, 20000); // Consider increasing the timeout
        });
      });
    }

    async stop(): Promise<void> {
      return new Promise((resolve, reject) => {
        console.log(`Bringing down ${this.name} tunnel.`);
        exec('sudo wg-quick down ./tunnel.conf', (error, stdout, stderr) => {
          if (error) {
            console.error(`Failed to bring down tunnel: ${stderr}`);
            reject(new Error(`Failed to bring down tunnel: ${stderr}`));
            return;
          }
          console.log(`Stopped ${this.name} tunnel.`);
          fs.unlinkSync('./tunnel.conf');
          resolve();
        });
      });
    }
  }

  export class ZrokTunnel extends BaseTunnel {
    name = 'Zrok';
    preSetupCommands = [];
    preStartCommands = [];
  
    async launchTunnel({ port = 3000 }: TunnelOptions): Promise<string> {
      this.process = spawn('./zrok', ['share', 'public', `http://localhost:${port}`], { shell: true });
  
      return new Promise((resolve, reject) => {
        this.process.stdout.on('data', (data: Buffer) => {
          const output = data.toString();
          const urlMatch = output.match(/https:\/\/[^\s]+/);
          if (urlMatch) {
            const url = urlMatch[0].split('│')[0].trim(); // Remove trailing ││[PUBLIC]
            console.log(`Zrok URL: ${url}`);
            resolve(url);
          }
        });
  
        this.process.stderr.on('data', (data: Buffer) => {
          // Suppress stderr output
        });
  
        this.process.on('close', (code) => {
          if (code !== 0) {
            reject(new Error('Failed to start Zrok Tunnel'));
          }
        });
  
        setTimeout(() => {
          reject(new Error('Timeout: Failed to start Zrok Tunnel'));
        }, 10000); // Set a reasonable timeout
      });
    }
  }

  export class TunwgTunnel extends BaseTunnel {
    name = 'Tunwg';
    preSetupCommands = [];
    preStartCommands = [];
  
    async launchTunnel({ port = 3000 }: TunnelOptions): Promise<string> {
      this.process = spawn('./tunwg', ['-p', port.toString()], { shell: true });
  
      return new Promise((resolve, reject) => {
        const urlRegex = /https:\/\/[^\s]+\.l\.tunwg\.com/;
  
        const handleOutput = (data: Buffer) => {
          const output = data.toString();
          const urlMatch = output.match(urlRegex);
  
          if (urlMatch) {
            const tunwgUrl = urlMatch[0];
            console.log(`Tunwg URL: ${tunwgUrl}`);
            resolve(tunwgUrl);
          }
        };
  
        this.process.stdout.on('data', handleOutput);
        this.process.stderr.on('data', handleOutput);
  
        this.process.on('close', (code) => {
          console.log(`Tunwg process exited with code ${code}`);
          if (code !== 0) {
            reject(new Error('Failed to start Tunwg Tunnel'));
          }
        });
  
        setTimeout(() => {
          reject(new Error('Timeout: Failed to start Tunwg Tunnel'));
        }, 10000); // Set a reasonable timeout
      });
    }
  }

import { spawn, ChildProcess } from 'child_process';

export class PacketriotTunnel extends BaseTunnel {
  name = 'Packetriot';
  preSetupCommands = [];
  preStartCommands = [];
  process!: ChildProcess;

  async launchTunnel({ port = 3000 }: TunnelOptions): Promise<string> {
    this.process = spawn('sudo', ['pktriot', 'http', port.toString()]);

    return new Promise((resolve, reject) => {
      this.process.stdout.on('data', (data: Buffer) => {
        const output = data.toString();
        const subdomainMatch = output.match(/(\w+-\w+-\d+\.pktriot\.net)/);
        if (subdomainMatch) {
          const fullUrl = `http://${subdomainMatch[1]}`;
          console.log(`Packetriot URL: ${fullUrl}`);
          resolve(fullUrl);
        }
      });

      this.process.stderr.on('data', (data: Buffer) => {
        // Suppress stderr output or handle it as needed
      });

      this.process.on('close', (code) => {
        if (code !== 0) {
          reject(new Error('Failed to start Packetriot Tunnel'));
        }
      });

      setTimeout(() => {
        reject(new Error('Timeout: Failed to start Packetriot Tunnel'));
      }, 10000); // Set a reasonable timeout
    });
  }
}


  export class BoreDigitalTunnel extends BaseTunnel {
    name = 'BoreDigital';
    preSetupCommands = [];
    preStartCommands = [];
    private server: ChildProcess | null = null;
    private client: ChildProcess | null = null;
  
    async launchTunnel({ port = 8000 }: TunnelOptions): Promise<string> {
      return new Promise((resolve, reject) => {
        this.server = spawn('./bore-server_linux_amd64');
  
        this.server.stderr.on('data', (data) => {
          // Suppress server stderr output
        });
  
        this.server.stdout.on('data', (data) => {
          // Suppress server stdout output
        });
  
        this.server.on('close', (code) => {
          // Suppress server close output
        });
  
        // Wait a bit to ensure the server is up before starting the client
        setTimeout(() => {
          this.client = spawn('./bore_linux_amd64', ['-s', 'bore.digital', '-p', '2200', '-ls', 'localhost', '-lp', port.toString()]);
  
          const handleClientData = (data: Buffer) => {
            const output = data.toString();
            const urlMatch = output.match(/https:\/\/[^\s]+bore\.digital[^\s]*/);
            if (urlMatch) {
              const url = urlMatch[0].trim(); // Remove trailing whitespace
              console.log(`BoreDigital URL: ${url}`);
              resolve(url);
            }
          };
  
          this.client.stderr.on('data', handleClientData);
          this.client.stdout.on('data', handleClientData);
  
          this.client.on('close', (code) => {
            // Suppress client close output
          });
        }, 2000); // Adjust the delay as needed
      });
    }
  
    async stop(): Promise<void> {
      if (this.client) {
        this.client.kill();
      }
      if (this.server) {
        this.server.kill();
      }
      console.log(`Stopped ${this.name} tunnel.`);
    }
  }

  export class LocalhostRunTunnel extends BaseTunnel {
    name = 'LocalhostRun';
    preSetupCommands = [];
    preStartCommands = [];
    private server: ChildProcess | null = null;
    private client: ChildProcess | null = null;

    async launchTunnel({ port = 3000 }: TunnelOptions): Promise<string> {
        return new Promise((resolve, reject) => {
            this.client = spawn('ssh', ['-R', '80:localhost:' + port, 'nokey@localhost.run']);

            this.client.stderr.on('data', (data) => {
                // Suppress client stderr output
            });

            this.client.stdout.on('data', (data) => {
                const output = data.toString();
                const urlMatch = output.match(/https:\/\/[^\s]+\.lhr\.life[^\s]*/);
                if (urlMatch) {
                    const url = urlMatch[0].trim(); // Remove trailing whitespace
                    console.log(`Localhost.run URL: ${url}`);
                    resolve(url);
                }
            });

            this.client.on('close', (code) => {
                // Suppress client close output
                console.log(`LocalhostRun client exited with code ${code}`);
            });
        });
    }

    async stop(): Promise<void> {
        if (this.client) {
            this.client.kill();
        }
        console.log(`Stopped ${this.name} tunnel.`);
    }
}


export class DevTunnel extends BaseTunnel {
  name = 'DevTunnel';
  preSetupCommands = [];
  preStartCommands = [];
  private devtunnel: ChildProcess | null = null;

  async launchTunnel({ port = 3000 }: TunnelOptions): Promise<string> {
      return new Promise((resolve, reject) => {
          this.devtunnel = spawn('devtunnel', ['host', '-p', port.toString(), '--allow-anonymous']);

          let urlPrinted = false;
          const urlRegex = /https:\/\/[a-z0-9-]+\.inc1\.devtunnels\.ms(:\d+)?(?!-inspect)/;

          this.devtunnel.stdout.on('data', (data) => {
              const output = data.toString();
              const urlMatch = output.match(urlRegex);
              if (urlMatch && !urlPrinted) {
                  console.log(urlMatch[0]);
                  urlPrinted = true;
                  resolve(urlMatch[0]);
              }
          });

          this.devtunnel.stderr.on('data', (data) => {
              const output = data.toString();
              const urlMatch = output.match(urlRegex);
              if (urlMatch && !urlPrinted) {
                  console.log(urlMatch[0]);
                  urlPrinted = true;
                  resolve(urlMatch[0]);
              }
          });

          this.devtunnel.on('close', (code) => {
              console.log(`devtunnel process exited with code ${code}`);
              if (!urlPrinted) {
                  reject(new Error('Failed to get devtunnel URL'));
              }
          });
      });
  }

  async stop(): Promise<void> {
      if (this.devtunnel) {
          this.devtunnel.kill();
      }
      console.log(`Stopped ${this.name} tunnel.`);
  }
}

export class Btunnel extends BaseTunnel {
  name = 'Btunnel';
  preSetupCommands = [];
  preStartCommands = [];
  private process: ChildProcess | null = null;

  async launchTunnel({ port = 3000 }: TunnelOptions): Promise<string> {
    return new Promise((resolve, reject) => {
      this.process = spawn('./btunnel', ['http', '--port', port.toString(), '-k', 'JDJhJDEyJEYwLnRIUEVRMHEvbGlvczNmMTFSVnVaTEtoOGFObmhScHZNSHN6U3VYTHFGdmxyMWdteUUu'], { shell: true });

      const handleData = (data: Buffer) => {
        const output = data.toString();
        const urlMatch = output.match(/https:\/\/[^\s]+-free\.in\.btunnel\.co\.in/);
        if (urlMatch) {
          const url = urlMatch[0].trim(); // Remove trailing whitespace
          console.log(`Btunnel URL: ${url}`);
          resolve(url);
        }
      };

      this.process.stdout.on('data', handleData);
      this.process.stderr.on('data', handleData);

      this.process.on('close', (code) => {
        console.log(`Btunnel process exited with code ${code}`);
        if (code !== 0) {
          reject(new Error('Failed to start Btunnel'));
        }
      });

      setTimeout(() => {
        reject(new Error('Timeout: Failed to start Btunnel'));
      }, 10000); // Set a reasonable timeout
    });
  }

  async stop(): Promise<void> {
    if (this.process) {
      this.process.kill();
    }
    console.log(`Stopped ${this.name} tunnel.`);
  }
}


export class BeeceptorTunnel extends BaseTunnel {
  name = 'Beeceptor';
  preSetupCommands = [];
  preStartCommands = [];
  private process: ChildProcess | null = null;

  async launchTunnel({ port = 3000 }: TunnelOptions): Promise<string> {
    return new Promise((resolve, reject) => {
      this.process = spawn('beeceptor-cli', ['-p', port.toString()]);

      // Simulate pressing Enter to select the default option
      this.process.stdin.write('\n');

      const handleData = (data: Buffer) => {
        const output = data.toString();
        const urlMatch = output.match(/https:\/\/\S+\.free\.beeceptor\.com/);
        if (urlMatch) {
          const url = urlMatch[0].trim(); // Remove trailing whitespace
          console.log(`Beeceptor URL: ${url}`);
          resolve(url);
        }
      };

      this.process.stderr.on('data', handleData);
      this.process.stdout.on('data', handleData);

      this.process.on('close', (code) => {
        // Suppress process close output
      });
    });
  }

  async stop(): Promise<void> {
    if (this.process) {
      this.process.kill();
    }
    console.log(`Stopped ${this.name} tunnel.`);
  }
}

export class OpenportTunnel extends BaseTunnel {
  name = 'Openport';
  preSetupCommands = [];
  preStartCommands = [];

  async launchTunnel({ port = 3000 }: TunnelOptions): Promise<string> {
    console.log('Starting Openport tunnel...');
    this.process = spawn('openport', [port.toString()]);

    return new Promise((resolve, reject) => {
      let mainPort: string | null = null;
      let timeoutId: NodeJS.Timeout;
      let isResolved = false;

      const handleOutput = async (data: Buffer) => {
        const output = data.toString();
        
        // Match the forwarding port info
        if (!mainPort) {
          const portMatch = output.match(/forwarding remote port (spr\.openport\.io:\d+)/);
          if (portMatch) {
            mainPort = portMatch[1];
            console.log(`✓ Port allocated: ${mainPort}`);
          }
        }

        // Match the auth URL
        const authMatch = output.match(/first visit (https:\/\/spr\.openport\.io\/l\/\d+\/\w+)/);
        if (authMatch && mainPort && !isResolved) {
          const authUrl = authMatch[1];
          console.log(`✓ Auth URL found: ${authUrl}`);
          console.log('Attempting authentication...');
          
          clearTimeout(timeoutId);
          
          try {
            const response = await axios.get(authUrl);
            if (response.status === 200) {
              const finalUrl = `http://${mainPort}`;
              console.log(`✓ Authentication successful!`);
              console.log(`✓ Final URL: ${finalUrl}`);
              isResolved = true;
              resolve(finalUrl);
            }
          } catch (error: any) {
            console.error('✗ Authentication failed:', error.message);
            reject(new Error(`Failed to authenticate: ${error.message}`));
          }
        }
      };

      this.process.stdout.on('data', handleOutput);
      this.process.stderr.on('data', handleOutput);

      this.process.on('error', (error) => {
        if (!isResolved) {
          console.error('✗ Process error:', error);
          reject(new Error(`Process error: ${error.message}`));
        }
      });

      this.process.on('close', (code) => {
        // Only log if it's not a normal shutdown
        if (code !== null && code !== 0 && !isResolved) {
          console.error(`✗ Process closed with code ${code}`);
          reject(new Error(`Process closed with code ${code}`));
        }
      });

      timeoutId = setTimeout(() => {
        if (!isResolved) {
          const state = {
            mainPort,
            processRunning: this.process?.killed === false
          };
          console.error('✗ Timeout reached. Current state:', state);
          reject(new Error('Timeout: Failed to start Openport Tunnel'));
        }
      }, 45000);
    });
  }

  async stop(): Promise<void> {
    if (this.process) {
      console.log('Stopping Openport tunnel...');
      this.process.kill();
      console.log(`✓ Stopped ${this.name} tunnel`);
    }
  }
}

export class NgtorTunnel extends BaseTunnel {
  name = 'Ngtor';
  preSetupCommands = [];
  preStartCommands = [];

  async launchTunnel({ port = 3000 }: TunnelOptions): Promise<string> {
    await this.ensureTorRunning();

    // Start the Ngtor process
    this.process = spawn('java', ['-jar', 'ngtor-0.1.0-boot.jar', 'http', `--port=${port}`]);

    return new Promise((resolve, reject) => {
      const urlRegex = /http:\/\/\S+\.onion/;

      const handleOutput = (data: Buffer) => {
        const output = data.toString();
        const urlMatch = output.match(urlRegex);
        if (urlMatch) {
          const onionUrl = urlMatch[0];
          console.log(`Ngtor Onion URL: ${onionUrl}`);
          resolve(onionUrl);
        }
      };

      this.process.stdout.on('data', handleOutput);
      this.process.stderr.on('data', handleOutput);
      setTimeout(() => {
        reject(new Error('Timeout: Failed to start Ngtor Tunnel'));
      }, 30000);
    });
  }

  private async ensureTorRunning(): Promise<void> {
    return new Promise((resolve, reject) => {
      exec('pgrep tor', async (error) => {
        if (error) {
          console.log('Starting Tor service...');
          exec('service tor start', (startError, stdout, stderr) => {
            if (startError) {
              reject(new Error(`Failed to start Tor: ${startError.message}`));
            } else {
              console.log('Tor service started successfully');
              resolve();
            }
          });
        } else {
          console.log('Tor service is already running');
          resolve();
        }
      });
    });
  }
}

export class EphemeralHiddenServiceTunnel extends BaseTunnel {
  name = 'EphemeralHiddenService';
  preSetupCommands = [];
  preStartCommands = [];

  async launchTunnel({ port = 3000 }: TunnelOptions): Promise<string> {
    await this.ensureTorRunning();

    this.process = spawn('ephemeral-hidden-service', ['-lp', port.toString()]);

    return new Promise((resolve, reject) => {
      const urlRegex = /http:\/\/\S+\.onion/;

      const handleOutput = (data: Buffer) => {
        const output = data.toString();
        const urlMatch = output.match(urlRegex);
        if (urlMatch) {
          const onionUrl = urlMatch[0];
          console.log(`Ephemeral Hidden Service URL: ${onionUrl}`);
          resolve(onionUrl);
        }
      };

      this.process.stdout.on('data', handleOutput);
      this.process.stderr.on('data', handleOutput);

      setTimeout(() => {
        reject(new Error('Timeout: Failed to start Ephemeral Hidden Service'));
      }, 30000);
    });
  }

  private async ensureTorRunning(): Promise<void> {
    return new Promise((resolve, reject) => {
      exec('pgrep tor', async (error) => {
        if (error) {
          console.log('Starting Tor service...');
          exec('service tor start', (startError, stdout, stderr) => {
            if (startError) {
              reject(new Error(`Failed to start Tor: ${startError.message}`));
            } else {
              console.log('Tor service started successfully');
              resolve();
            }
          });
        } else {
          console.log('Tor service is already running');
          resolve();
        }
      });
    });
  }
}

export class OnionpipeTunnel extends BaseTunnel {
  name = 'Onionpipe';
  preSetupCommands = [];
  preStartCommands = [];
  process: any;

  async launchTunnel({ port = 3000 }: TunnelOptions): Promise<string> {
    await this.ensureTorRunning();

    // Start the Onionpipe process
    this.process = spawn('onionpipe', [port.toString()]);

    return new Promise((resolve, reject) => {
      const handleOutput = (data: Buffer) => {
        const output = data.toString();
        const lines = output.split('\n');
        for (const line of lines) {
          if (line.includes('.onion:')) {
            // Extract the .onion URL, removing ':80'
            const match = line.match(/([a-z2-7]{16,56}\.onion):80/);
            if (match) {
              const onionUrl = match[1];
              console.log(`Onionpipe URL: ${onionUrl}`);
              resolve(onionUrl);
              return;
            }
          }
        }
      };

      this.process.stdout.on('data', handleOutput);
      this.process.stderr.on('data', handleOutput);

      this.process.on('close', (code) => {
        if (code !== 0) {
          reject(new Error('Onionpipe process exited with an error'));
        }
      });

      setTimeout(() => {
        reject(new Error('Timeout: Failed to start Onionpipe Tunnel'));
      }, 30000); // 30-second timeout
    });
  }

  // Ensures Tor is running
  private async ensureTorRunning(): Promise<void> {
    return new Promise((resolve, reject) => {
      exec('pgrep tor', (error) => {
        if (error) {
          console.log('Starting Tor service...');
          exec('service tor start', (startError) => {
            if (startError) {
              reject(new Error(`Failed to start Tor: ${startError.message}`));
            } else {
              console.log('Tor service started successfully');
              resolve();
            }
          });
        } else {
          console.log('Tor service is already running');
          resolve();
        }
      });
    });
  }
}

export const tunnelTools: TunnelTool[] = [

  new NgrokTunnel(), 
  new CloudflareTunnel(),
  new ZrokTunnel(),
  new ServeoTunnel(),
  new TelebitTunnel(),
  new BoreTunnel(),
  new LoopholeTunnel(),
  new PinggyTunnel(),
  new OnionpipeTunnel(),
  new NgtorTunnel(),
  new BeeceptorTunnel(), 
  new TunnelPyjamas(),
  new EphemeralHiddenServiceTunnel(),
]

async function main() {
  const args = process.argv.slice(2);
  const autoMode = true;

  if (autoMode) {
    console.log('Available tools:');
    tunnelTools.forEach((tool, index) => console.log(`${index + 1}. ${tool.name}`));

    const readline = require('readline').createInterface({
      input: process.stdin,
      output: process.stdout,
    });

    readline.question('Enter the number of the tool to test (or "all" to test all): ', async (input) => {
      if (input.toLowerCase() === 'all') {
        // Run all tests (similar to auto mode)
        for (const tool of tunnelTools) {
          try {
            console.log(`Testing ${tool.name}...`);
            const url = await tool.start();
            console.log(`${tool.name} launched successfully: ${url}`);
            await tool.stop();
          } catch (error) {
            console.error(`${tool.name} failed:`, error);
          }
        }
      } else {
        const toolIndex = parseInt(input) - 1;
        if (toolIndex >= 0 && toolIndex < tunnelTools.length) {
          const tool = tunnelTools[toolIndex];
          try {
            console.log(`Testing ${tool.name}...`);
            const url = await tool.start();
            console.log(`${tool.name} launched successfully: ${url}`);
            await tool.stop();
          } catch (error) {
            console.error(`${tool.name} failed:`, error);
          }
        } else {
          console.log('Invalid input.');
        }
      }
      readline.close();
    });
  }
}

// main();
// executeTool("BoreDigital");


async function executeTool(tool: TunnelTool, options: TunnelOptions = { port: 3000, urlPattern: /https:\/\/[^\s]+/ }): Promise<boolean> {
  try {
    const url = await tool.start(options);
    console.log(`✓ ${tool.name} - URL: ${url}`);
    await tool.stop();
    return true;
  } catch (error) {
    console.error(`✗ ${tool.name} - Error: ${error.message}`);
    return false;
  }
}

async function runAllTools() {
  let successCount = 0;
  let failCount = 0;

  for (const tool of tunnelTools) {
    const success = await executeTool(tool);
    if (success) {
      successCount++;
    } else {
      failCount++;
    }
  }

  console.log('\nResults:');
  console.log(`✓ Successful: ${successCount}`);
  console.log(`✗ Failed: ${failCount}`);
  console.log(`Total tools: ${tunnelTools.length}`);
}

//runAllTools();

//executeTool(new TelebitTunnel());
// main();
