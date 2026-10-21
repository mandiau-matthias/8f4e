// Trusted CI entry point: reads Git objects and parses source, never imports or
// executes the target project's files, package manager scripts or configuration.
import fs from 'node:fs/promises';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import { prepareFixtureCleanup } from './core.mjs';
import { hash } from './shared.mjs';

function git(root, args) {
  return execFileSync('git', ['-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=/dev/null', '-C', root, ...args], {
    env: { PATH: process.env.PATH, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', HOME: '/tmp' },
    maxBuffer: 8 * 1024 * 1024, encoding: 'utf8', timeout: 30_000,
  });
}
export async function prepareCheckout({ root, requestText, requestSha256, now = Date.now() }) {
  if (Buffer.byteLength(requestText) > 65536 || await hash(requestText) !== requestSha256) throw new Error('remote_preparation_input_hash');
  const input = JSON.parse(requestText);
  if (input.inventory !== undefined || !/^[a-f0-9]{40}$/.test(input.source?.baseCommitSha ?? '')) throw new Error('remote_preparation_request');
  if (git(root, ['rev-parse', 'HEAD']).trim() !== input.source.baseCommitSha) throw new Error('remote_preparation_source_commit');
  const treeSha = git(root, ['rev-parse', 'HEAD^{tree}']).trim();
  if (treeSha !== input.source.baseTreeSha) throw new Error('remote_preparation_source_tree');
  const entries = git(root, ['ls-tree', '-r', '-t', '-z', '--full-tree', 'HEAD']).split('\0').filter(Boolean).map(line => {
    const match = /^(\d{6}) (blob|tree|commit) ([a-f0-9]{40})\t([\s\S]+)$/.exec(line);
    if (!match) throw new Error('remote_preparation_tree_format');
    return { mode: match[1], type: match[2], sha: match[3], path: match[4] };
  });
  if (entries.length > 12000) throw new Error('remote_preparation_inventory_limit');
  const files = []; let totalBytes = 0;
  for (const entry of entries.filter(e => e.type === 'blob' && /\.(?:[cm]?[jt]sx?)$/.test(e.path))) {
    const size = Number(git(root, ['cat-file', '-s', entry.sha]).trim());
    totalBytes += size;
    if (!Number.isSafeInteger(size) || size < 0 || totalBytes > 16 * 1024 * 1024) throw new Error('remote_preparation_scan_limit');
    // Read immutable Git blobs, not potentially altered worktree/symlink bytes.
    files.push({ path: entry.path, content: git(root, ['cat-file', 'blob', entry.sha]) });
  }
  input.inventory = { truncated: false, baseCommitSha: input.source.baseCommitSha, treeSha, entries, files };
  const result = await prepareFixtureCleanup(input, now);
  return { schema: 'aura.remote-preparation-envelope.v1', requestSha256, result };
}
export async function encodePreparationLog(envelope) {
  const raw = JSON.stringify(envelope);
  if (Buffer.byteLength(raw) > 1048576) throw new Error('remote_preparation_result_size');
  const encoded = Buffer.from(raw).toString('base64'), chunks = encoded.match(/.{1,2048}/g);
  return [`AURA_PREPARATION_BEGIN ${await hash(raw)} ${chunks.length}`,
    ...chunks.map((part, index) => `AURA_PREPARATION_CHUNK ${index} ${part}`), 'AURA_PREPARATION_END'].join('\n');
}
if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  const [root, inputFile, expectedHash] = process.argv.slice(2);
  if (!root || !inputFile || !/^[a-f0-9]{64}$/.test(expectedHash ?? '')) throw new Error('Usage: remote-runner.mjs SOURCE INPUT_JSON INPUT_SHA256');
  console.log(await encodePreparationLog(await prepareCheckout({ root, requestText: await fs.readFile(inputFile, 'utf8'), requestSha256: expectedHash })));
}
