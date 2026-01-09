/**
 * Server harness for E2E tests.
 * Starts and stops the opencloudmesh-go server as a subprocess with bounded lifecycle.
 */

import { spawn, ChildProcess, execSync } from 'child_process';
import { mkdtempSync, writeFileSync, rmSync, existsSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';
import * as net from 'net';

export interface ServerConfig {
  name: string;
  mode?: 'dev' | 'interop' | 'strict';
  extraConfig?: string;
}

export interface ServerInstance {
  name: string;
  baseURL: string;
  port: number;
  tempDir: string;
  process: ChildProcess;
  logs: string[];
}

/**
 * Finds the project root by looking for go.mod.
 */
function findProjectRoot(): string {
  let dir = __dirname;
  while (dir !== '/') {
    if (existsSync(join(dir, 'go.mod'))) {
      return dir;
    }
    dir = join(dir, '..');
  }
  // Fallback: assume we're in tests/e2e/harness
  return join(__dirname, '..', '..', '..');
}

/**
 * Gets an available port.
 */
async function getAvailablePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address() as net.AddressInfo;
      const port = addr.port;
      server.close(() => resolve(port));
    });
    server.on('error', reject);
  });
}

/**
 * Waits for the server to be ready by polling the health endpoint.
 */
async function waitForServerReady(baseURL: string, timeoutMs: number = 10000): Promise<void> {
  const startTime = Date.now();
  const healthURL = `${baseURL}/api/healthz`;

  while (Date.now() - startTime < timeoutMs) {
    try {
      const response = await fetch(healthURL);
      if (response.ok) {
        return;
      }
    } catch {
      // Server not ready yet
    }
    await new Promise(resolve => setTimeout(resolve, 100));
  }

  throw new Error(`Server not ready after ${timeoutMs}ms`);
}

/**
 * Builds the server binary.
 */
export function buildBinary(): string {
  const projectRoot = findProjectRoot();
  const binaryPath = join(projectRoot, 'bin', 'opencloudmesh-go-test');

  console.log('Building server binary...');
  execSync(`go build -o ${binaryPath} ./cmd/opencloudmesh-go`, {
    cwd: projectRoot,
    env: { ...process.env, CGO_ENABLED: '0' },
    stdio: 'pipe',
  });

  return binaryPath;
}

/**
 * Generates TOML config for a test server.
 * The mode preset (dev/interop/strict) drives SSRF defaults via config.Load().
 * Signature mode is forced off for test simplicity (no key management).
 */
function generateConfig(name: string, port: number, tempDir: string, mode: string, extraConfig?: string): string {
  let config = `mode = "${mode}"
listen_addr = ":${port}"
external_origin = "http://localhost:${port}"
external_base_path = ""

[tls]
mode = "off"

[server]
trusted_proxies = ["127.0.0.0/8", "::1/128"]

[server.bootstrap_admin]
username = "admin"
password = "testpassword123"

[outbound_http]
timeout_ms = 5000
connect_timeout_ms = 2000
max_redirects = 1
max_response_bytes = 1048576
insecure_skip_verify = true

[signature]
mode = "off"
`;

  if (extraConfig) {
    config += '\n' + extraConfig;
  }

  return config;
}

/**
 * Starts a server instance as a subprocess.
 */
export async function startServer(binaryPath: string, config: ServerConfig): Promise<ServerInstance> {
  const tempDir = mkdtempSync(join(tmpdir(), `ocm-e2e-${config.name}-`));
  const port = await getAvailablePort();
  const mode = config.mode || 'dev';

  // Write config file
  const configPath = join(tempDir, 'config.toml');
  const configContent = generateConfig(config.name, port, tempDir, mode, config.extraConfig);
  writeFileSync(configPath, configContent);

  // Start subprocess
  const logs: string[] = [];
  const proc = spawn(binaryPath, ['--config', configPath], {
    cwd: tempDir,
    env: { ...process.env },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  // Capture logs
  proc.stdout?.on('data', (data: Buffer) => {
    logs.push(data.toString());
  });
  proc.stderr?.on('data', (data: Buffer) => {
    logs.push(data.toString());
  });

  const baseURL = `http://localhost:${port}`;

  const instance: ServerInstance = {
    name: config.name,
    baseURL,
    port,
    tempDir,
    process: proc,
    logs,
  };

  // Wait for server to be ready
  try {
    await waitForServerReady(baseURL);
    console.log(`Server ${config.name} started at ${baseURL}`);
  } catch (error) {
    console.error(`Server ${config.name} failed to start. Logs:`);
    console.error(logs.join(''));
    stopServer(instance);
    throw error;
  }

  return instance;
}

/**
 * Stops a server instance and cleans up resources.
 */
export function stopServer(instance: ServerInstance): void {
  if (instance.process && !instance.process.killed) {
    // Try graceful shutdown first
    instance.process.kill('SIGTERM');

    // Force kill after timeout
    setTimeout(() => {
      if (instance.process && !instance.process.killed) {
        instance.process.kill('SIGKILL');
      }
    }, 2000);
  }

  // Clean up temp directory
  try {
    if (existsSync(instance.tempDir)) {
      rmSync(instance.tempDir, { recursive: true, force: true });
    }
  } catch {
    // Ignore cleanup errors
  }

  console.log(`Server ${instance.name} stopped`);
}

/**
 * Dumps server logs for debugging.
 */
export function dumpLogs(instance: ServerInstance): void {
  console.log(`=== Logs for ${instance.name} ===`);
  console.log(instance.logs.join(''));
  console.log(`=== End logs ===`);
}
