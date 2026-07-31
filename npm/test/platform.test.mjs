import assert from 'node:assert/strict';
import { mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { assetFor, executableName } from '../lib/platform.mjs';
import {
  acquireLock,
  checksumFor,
  releaseLock,
  validateArchiveEntries,
  verifiedCachedBinary,
} from '../lib/run.mjs';

test('maps supported Node platforms to native release assets', () => {
  assert.equal(assetFor('win32', 'x64'), 'devicelane-windows-x64.zip');
  assert.equal(assetFor('linux', 'x64'), 'devicelane-linux-x64.tar.gz');
  assert.equal(assetFor('darwin', 'arm64'), 'devicelane-macos-arm64.tar.gz');
  assert.equal(assetFor('darwin', 'x64'), 'devicelane-macos-x64.tar.gz');
});

test('rejects platforms without a published native build', () => {
  assert.throws(() => assetFor('linux', 'arm64'), /Unsupported platform/);
});

test('uses Windows executable suffix only on Windows', () => {
  assert.equal(executableName('mesh-cli', 'win32'), 'mesh-cli.exe');
  assert.equal(executableName('mesh-cli', 'darwin'), 'mesh-cli');
});

test('selects only an exact checksum asset name', () => {
  const sums = 'abc123  devicelane-linux-x64.tar.gz\ndef456 *devicelane-windows-x64.zip\n';
  assert.equal(checksumFor(sums, 'devicelane-linux-x64.tar.gz'), 'abc123');
  assert.equal(checksumFor(sums, 'devicelane-windows-x64.zip'), 'def456');
  assert.equal(checksumFor(sums, 'linux-x64.tar.gz'), undefined);
});

test('accepts only the exact flat release archive layout', () => {
  const unix = 'mesh-cli\nmesh-agent\nmesh-registry\nREADME.md\nLICENSE\n';
  assert.equal(validateArchiveEntries(unix, 'linux'), true);
  assert.equal(validateArchiveEntries(`${unix}../payload\n`, 'linux'), false);
  assert.equal(validateArchiveEntries(unix.replace('mesh-agent\n', ''), 'linux'), false);
  const windows = 'mesh-cli.exe\nmesh-agent.exe\nmesh-registry.exe\nREADME.md\nLICENSE\n';
  assert.equal(validateArchiveEntries(windows, 'win32'), true);
});

test('detects a tampered cached executable', async () => {
  const root = join(tmpdir(), `devicelane-cache-test-${process.pid}-${Date.now()}`);
  await mkdir(root, { recursive: true });
  try {
    const binary = join(root, 'mesh-cli');
    await writeFile(binary, 'trusted');
    const { createHash } = await import('node:crypto');
    const hash = createHash('sha256').update('trusted').digest('hex');
    await writeFile(join(root, '.verified.json'), JSON.stringify({ version: '0.1.0', hashes: { 'mesh-cli': hash } }));
    assert.equal(await verifiedCachedBinary(root, 'mesh-cli', '0.1.0', 'linux'), binary);
    await writeFile(binary, 'tampered');
    assert.equal(await verifiedCachedBinary(root, 'mesh-cli', '0.1.0', 'linux'), undefined);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('reclaims stale locks and does not release another owner lock', async () => {
  const root = join(tmpdir(), `devicelane-lock-test-${process.pid}-${Date.now()}`);
  const lock = join(root, 'cache.lock');
  await mkdir(lock, { recursive: true });
  await writeFile(join(lock, 'owner.json'), JSON.stringify({ token: 'stale', pid: 999999999, created: 0 }));
  const token = await acquireLock(lock);
  const owner = JSON.parse(await readFile(join(lock, 'owner.json'), 'utf8'));
  assert.equal(owner.token, token);
  await releaseLock(lock, 'not-the-owner');
  assert.equal(JSON.parse(await readFile(join(lock, 'owner.json'), 'utf8')).token, token);
  await releaseLock(lock, token);
  await rm(root, { recursive: true, force: true });
});
