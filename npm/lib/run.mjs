import { createHash, randomUUID } from 'node:crypto';
import { chmod, mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { basename, dirname, join } from 'node:path';
import { spawn, spawnSync } from 'node:child_process';

import { assetFor, executableName } from './platform.mjs';

const REPOSITORY = 'https://github.com/HECer/devicelane';

function cacheRoot(version) {
  const base = process.env.DEVICELANE_CACHE_DIR
    ?? (process.platform === 'win32'
      ? join(process.env.LOCALAPPDATA ?? homedir(), 'DeviceLane')
      : join(process.env.XDG_CACHE_HOME ?? join(homedir(), '.cache'), 'devicelane'));
  return join(base, version);
}

async function download(url, destination) {
  const response = await fetch(url, { redirect: 'follow' });
  if (!response.ok) throw new Error(`Download failed (${response.status}): ${url}`);
  await writeFile(destination, Buffer.from(await response.arrayBuffer()));
}

export function checksumFor(checksums, asset) {
  return checksums
    .split(/\r?\n/)
    .map((line) => line.trim().split(/\s+/))
    .find((parts) => parts.at(-1)?.replace(/^\*/, '') === asset)?.[0];
}

async function verifyChecksum(archive, checksums, asset) {
  const expected = checksumFor(checksums, asset);
  if (!expected) throw new Error(`No SHA-256 entry found for ${asset}`);
  const actual = createHash('sha256').update(await readFile(archive)).digest('hex');
  if (actual.toLowerCase() !== expected.toLowerCase()) {
    throw new Error(`SHA-256 mismatch for ${asset}`);
  }
}

function extract(archive, destination) {
  const listing = spawnSync('tar', ['-tf', archive], { encoding: 'utf8' });
  if (listing.status !== 0 || !validateArchiveEntries(listing.stdout, process.platform)) {
    throw new Error(`Unsafe archive layout in ${basename(archive)}`);
  }
  const result = spawnSync('tar', ['-xf', archive, '-C', destination], { stdio: 'inherit' });
  if (result.status !== 0) throw new Error(`Could not extract ${basename(archive)}`);
}

export function validateArchiveEntries(listing, platform) {
  const suffix = platform === 'win32' ? '.exe' : '';
  const allowed = new Set([
    `devicelane${suffix}`,
    `devicelane-service${suffix}`,
    `mesh-cli${suffix}`,
    `mesh-agent${suffix}`,
    `mesh-registry${suffix}`,
    'README.md',
    'LICENSE',
  ]);
  const entries = listing.split(/\r?\n/).filter(Boolean).map((entry) => entry.replace(/^\.\//, ''));
  return entries.length === allowed.size
    && entries.every((entry) => allowed.has(entry))
    && allowed.size === new Set(entries).size;
}

async function sha256(path) {
  return createHash('sha256').update(await readFile(path)).digest('hex');
}

const pause = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));

function processExists(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

export async function acquireLock(path) {
  const token = randomUUID();
  const candidate = `${path}.candidate-${token}`;
  await mkdir(candidate);
  await writeFile(join(candidate, 'owner.json'), JSON.stringify({ token, pid: process.pid, created: Date.now() }));
  for (let attempt = 0; attempt < 300; attempt += 1) {
    try {
      await rename(candidate, path);
      return token;
    } catch (error) {
      if (!['EEXIST', 'EACCES', 'EPERM', 'ENOTEMPTY'].includes(error.code)) {
        await rm(candidate, { recursive: true, force: true });
        throw error;
      }
      try {
        const owner = JSON.parse(await readFile(join(path, 'owner.json'), 'utf8'));
        if (!processExists(owner.pid)) {
          const stale = `${path}.stale-${token}`;
          await rename(path, stale);
          await rm(stale, { recursive: true, force: true });
          continue;
        }
      } catch {
        const stale = `${path}.invalid-${token}`;
        try {
          await rename(path, stale);
          await rm(stale, { recursive: true, force: true });
          continue;
        } catch {}
      }
      await pause(100);
    }
  }
  await rm(candidate, { recursive: true, force: true });
  throw new Error(`Timed out waiting for DeviceLane cache lock: ${path}`);
}

export async function releaseLock(path, token) {
  try {
    const owner = JSON.parse(await readFile(join(path, 'owner.json'), 'utf8'));
    if (owner.token !== token) return;
    const released = `${path}.released-${token}`;
    await rename(path, released);
    await rm(released, { recursive: true, force: true });
  } catch {}
}

export async function verifiedCachedBinary(root, binary, version, platform = process.platform) {
  try {
    const manifest = JSON.parse(await readFile(join(root, '.verified.json'), 'utf8'));
    const name = executableName(binary, platform);
    const executable = join(root, name);
    if (manifest.version !== version || manifest.hashes?.[name] !== await sha256(executable)) return;
    await chmod(executable, 0o755);
    return executable;
  } catch {
    return undefined;
  }
}

async function ensureBinary(binary, version) {
  const root = cacheRoot(version);
  const cached = await verifiedCachedBinary(root, binary, version);
  if (cached) return cached;

  const asset = assetFor(process.platform, process.arch);
  const lock = `${root}.lock`;
  await mkdir(dirname(root), { recursive: true });
  const lockToken = await acquireLock(lock);
  const scratch = `${root}.stage-${process.pid}-${Date.now()}`;
  const staged = join(scratch, 'install');
  try {
    const afterLock = await verifiedCachedBinary(root, binary, version);
    if (afterLock) return afterLock;
    await mkdir(staged, { recursive: true });
    const archive = join(scratch, asset);
    const release = `${REPOSITORY}/releases/download/v${version}`;
    await Promise.all([
      download(`${release}/${asset}`, archive),
      download(`${release}/SHA256SUMS`, join(scratch, 'SHA256SUMS')),
    ]);
    await verifyChecksum(archive, await readFile(join(scratch, 'SHA256SUMS'), 'utf8'), asset);
    extract(archive, staged);
    const hashes = {};
    for (const name of ['devicelane', 'devicelane-service', 'mesh-cli', 'mesh-agent', 'mesh-registry']) {
      const executableNameForPlatform = executableName(name, process.platform);
      hashes[executableNameForPlatform] = await sha256(join(staged, executableNameForPlatform));
    }
    await writeFile(join(staged, '.verified.json'), JSON.stringify({ version, asset, hashes }));
    const backup = `${root}.backup-${lockToken}`;
    let hadPrevious = false;
    try {
      await rename(root, backup);
      hadPrevious = true;
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
    try {
      await rename(staged, root);
    } catch (error) {
      if (hadPrevious) await rename(backup, root);
      throw error;
    }
    if (hadPrevious) await rm(backup, { recursive: true, force: true });
    const executable = await verifiedCachedBinary(root, binary, version);
    if (!executable) throw new Error('Installed DeviceLane binary failed verification');
    return executable;
  } finally {
    await rm(scratch, { recursive: true, force: true });
    await releaseLock(lock, lockToken);
  }
}

export async function run(binary) {
  const packageJson = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8'));
  const executable = await ensureBinary(binary, packageJson.version);
  const child = spawn(executable, process.argv.slice(2), { stdio: 'inherit', windowsHide: true });
  child.once('error', (error) => {
    console.error(`DeviceLane could not start ${binary}: ${error.message}`);
    process.exitCode = 1;
  });
  child.once('exit', (code, signal) => {
    if (signal) process.kill(process.pid, signal);
    else process.exitCode = code ?? 1;
  });
}
