// Inactive, deterministic preparation only. No transport, credentials or claims.
import ts from 'typescript';
import { hash, canonical, gitHash, concat } from './shared.mjs';
export { hash, canonical, gitHash } from './shared.mjs';
import { prepareMultifileManifest } from '../cloud/github-multifile.mjs';

export { TASK_CLASS, checkPreparationEligibility } from './policy.mjs';
import { checkPreparationEligibility, validatePreparationPolicy, validateFreeCI, TASK_CLASS } from './policy.mjs';
const enc = new TextEncoder();
const SHA = /^[a-f0-9]{40}$/;
const HASH = /^[a-f0-9]{64}$/;
const ID = /^[A-Za-z_][A-Za-z0-9_]{0,79}$/;
const CODE = /\.(?:[cm]?[jt]sx?)$/;
const fail = (condition, code) => { if (!condition) throw new Error(`preparation_${code}`); };
const copy = value => JSON.parse(JSON.stringify(value));

function validPath(path) {
  return typeof path === 'string' && path.length <= 1024 && !/[\x00-\x1f\x7f\\]/.test(path)
    && path.split('/').every(p => p && !['.', '..', '.git'].includes(p.toLowerCase()));
}
function text(value) {
  fail(typeof value === 'string' && !value.includes('\0') && new TextDecoder('utf-8', { fatal: true }).decode(enc.encode(value)) === value, 'invalid_text');
  return value;
}

function entryOrder(a, b) {
  const aa = enc.encode(a.path + (a.type === 'tree' ? '/' : ''));
  const bb = enc.encode(b.path + (b.type === 'tree' ? '/' : ''));
  for (let i = 0; i < Math.min(aa.length, bb.length); i++) if (aa[i] !== bb[i]) return aa[i] - bb[i];
  return aa.length - bb.length;
}
export async function treeHash(entries) {
  return gitHash('tree', concat([...entries].sort(entryOrder).flatMap(e => [
    enc.encode(`${e.mode === '040000' ? '40000' : e.mode} ${e.path}\0`),
    Uint8Array.from(e.sha.match(/../g), x => parseInt(x, 16)),
  ])));
}

// Reconstruct every directory hash: a claimed "complete" flattened API listing
// alone is not trusted. Every committed code file must then have matching bytes.
async function verifyInventory(input) {
  const { source, inventory } = input;
  fail(SHA.test(source?.baseCommitSha ?? '') && SHA.test(source?.baseTreeSha ?? ''), 'source_unpinned');
  fail(inventory?.truncated === false && inventory.baseCommitSha === source.baseCommitSha
    && inventory.treeSha === source.baseTreeSha && Array.isArray(inventory.entries)
    && inventory.entries.length > 0 && inventory.entries.length <= 12000, 'inventory_incomplete');
  const byPath = new Map(), dirs = new Map([['', []]]);
  for (const e of inventory.entries) {
    fail(validPath(e.path) && SHA.test(e.sha ?? '') && !byPath.has(e.path), 'inventory_path');
    fail(({ '040000': 'tree', '100644': 'blob', '100755': 'blob', '120000': 'blob', '160000': 'commit' })[e.mode] === e.type,
      'inventory_mode_unsupported');
    byPath.set(e.path, e); if (e.type === 'tree') dirs.set(e.path, []);
  }
  for (const e of byPath.values()) {
    const slash = e.path.lastIndexOf('/'), parent = slash < 0 ? '' : e.path.slice(0, slash);
    fail(dirs.has(parent), 'inventory_parent_missing');
    dirs.get(parent).push({ path: e.path.slice(slash + 1), mode: e.mode, type: e.type, sha: e.sha });
  }
  for (const [path, entries] of dirs) {
    fail(await treeHash(entries) === (path ? byPath.get(path).sha : source.baseTreeSha), 'inventory_tree_hash');
  }
  const codeEntries = [...byPath.values()].filter(e => e.type === 'blob' && CODE.test(e.path));
  fail(Array.isArray(inventory.files) && inventory.files.length === codeEntries.length, 'code_inventory_incomplete');
  let bytes = 0; const files = new Map();
  for (const f of inventory.files) {
    const entry = byPath.get(f.path);
    fail(entry?.type === 'blob' && ['100644', '100755'].includes(entry.mode) && CODE.test(f.path)
      && !files.has(f.path), 'code_inventory_path');
    bytes += enc.encode(text(f.content)).length; fail(bytes <= 16 * 1024 * 1024, 'scan_byte_limit');
    fail(await gitHash('blob', f.content) === entry.sha, 'source_blob_mismatch');
    files.set(f.path, { ...entry, content: f.content });
  }
  fail(codeEntries.every(e => files.has(e.path)), 'code_inventory_incomplete');
  return { files, dirs, byPath };
}
const compact = s => s.replace(/\s+/g, '');
function parse(path, content) {
  const file = ts.createSourceFile(path, content, ts.ScriptTarget.Latest, true,
    path.endsWith('x') ? ts.ScriptKind.TSX : ts.ScriptKind.TS);
  fail(file.parseDiagnostics.length === 0, 'syntax_unsupported'); return file;
}
function removeLineEnd(content, end) {
  if (content.slice(end, end + 2) === '\r\n') return end + 2;
  return content[end] === '\n' ? end + 1 : end;
}
function applyEdits(content, edits) {
  edits.sort((a, b) => b.start - a.start);
  let boundary = content.length + 1;
  for (const e of edits) {
    fail(e.end <= boundary && e.start < e.end, 'overlapping_edits');
    content = content.slice(0, e.start) + e.text + content.slice(e.end); boundary = e.start;
  }
  return content;
}

function transform(files, cleanup, policy) {
  fail(cleanup && [cleanup.symbol, cleanup.valuesSymbol, cleanup.valueType].every(v => ID.test(v ?? ''))
    && new Set([cleanup.symbol, cleanup.valuesSymbol, cleanup.valueType]).size === 3, 'cleanup_schema');
  fail(policy.symbols?.includes(cleanup.symbol) && validPath(cleanup.productionPath)
    && cleanup.productionPath.endsWith('.ts') && Array.isArray(cleanup.importSources)
    && cleanup.importSources.length > 0 && cleanup.importSources.every(s => typeof s === 'string' && s.length <= 200), 'cleanup_scope');
  const production = files.get(cleanup.productionPath); fail(production, 'production_source_missing');
  const ast = parse(production.path, production.content), declarations = new Map();
  for (const statement of ast.statements) if (ts.isVariableStatement(statement)) {
    for (const d of statement.declarationList.declarations) if (ts.isIdentifier(d.name)) declarations.set(d.name.text, { d, statement });
  }
  const fixture = declarations.get(cleanup.symbol), values = declarations.get(cleanup.valuesSymbol);
  fail(fixture && values && fixture.statement.declarationList.declarations.length === 1, 'definition_unsupported');
  const expected = `export const ${cleanup.symbol} = Object.fromEntries(${cleanup.valuesSymbol}.map(instruction => [instruction, instruction])) as { readonly [Instruction in ${cleanup.valueType}]: Instruction };`;
  fail(compact(fixture.statement.getText(ast)) === compact(expected), 'definition_unsupported');
  fail((values.statement.declarationList.flags & ts.NodeFlags.Const) !== 0
    && ts.isAsExpression(values.d.initializer) && values.d.initializer.type.getText(ast) === 'const'
    && ts.isArrayLiteralExpression(values.d.initializer.expression), 'literal_values_unsupported');
  const literals = values.d.initializer.expression.elements;
  fail(literals.length > 0 && literals.length <= 128 && literals.every(n => ts.isStringLiteral(n)
    && /^[A-Za-z_][A-Za-z0-9_*]{0,50}$/.test(n.text)), 'literal_values_unsupported');
  const allowed = new Set(literals.map(n => n.text)); fail(allowed.size === literals.length, 'duplicate_values');
  const alias = ast.statements.find(s => ts.isTypeAliasDeclaration(s) && s.name.text === cleanup.valueType);
  fail(alias && compact(alias.type.getText(ast)) === `(typeof${cleanup.valuesSymbol})[number]`, 'type_alias_unsupported');
  const results = []; let replacements = 0;
  const token = new RegExp(`\\b${cleanup.symbol.replace(/[$]/g, '\\$&')}\\b`);
  for (const f of files.values()) {
    if (!token.test(f.content)) continue;
    fail(f.path.endsWith('.ts'), 'consumer_language_unsupported');
    const file = f.path === production.path ? ast : parse(f.path, f.content), edits = [], handled = new Set();
    if (f.path === production.path) {
      let end = removeLineEnd(f.content, fixture.statement.end);
      end = removeLineEnd(f.content, end);
      edits.push({ start: fixture.statement.getStart(file), end, text: '' });
      handled.add(fixture.d.name);
    } else {
      fail(/(?:\.test\.ts$|\.spec\.ts$|\/tests\/|\/__tests__\/)/.test(f.path)
        || policy.testHelperPaths?.includes(f.path), 'production_consumer');
      let foundImport = false;
      for (const statement of file.statements) if (ts.isImportDeclaration(statement)) {
        const clause = statement.importClause, bindings = clause?.namedBindings;
        if (!bindings || !ts.isNamedImports(bindings)) continue;
        const elements = [...bindings.elements], idx = elements.findIndex(n => n.name.text === cleanup.symbol || n.propertyName?.text === cleanup.symbol);
        if (idx < 0) continue;
        const item = elements[idx];
        fail(!foundImport && !item.propertyName && !item.isTypeOnly && !clause.isTypeOnly && !clause.name
          && ts.isStringLiteral(statement.moduleSpecifier) && cleanup.importSources.includes(statement.moduleSpecifier.text), 'import_unsupported');
        foundImport = true; handled.add(item.name);
        const remaining = elements.filter((_, index) => index !== idx);
        if (remaining.length && remaining.every(element => element.isTypeOnly)) {
          fail(!/\/\*|\/\//.test(statement.getText(file)), 'import_comment_unsupported');
          edits.push({ start: statement.getStart(file), end: statement.end,
            text: `import type { ${remaining.map(element => element.getText(file).replace(/^type\s+/, '')).join(', ')} } from ${statement.moduleSpecifier.getText(file)};` });
        } else if (elements.length === 1) edits.push({ start: statement.getStart(file), end: removeLineEnd(f.content, statement.end), text: '' });
        else if (idx < elements.length - 1) edits.push({ start: item.getStart(file), end: elements[idx + 1].getStart(file), text: '' });
        else edits.push({ start: elements[idx - 1].end, end: item.end, text: '' });
      }
      fail(foundImport, 'consumer_import_missing');
    }
    function walk(node) {
      if (ts.isIdentifier(node) && node.text === cleanup.symbol && !handled.has(node)) {
        const parent = node.parent; let value;
        if (ts.isPropertyAccessExpression(parent) && parent.expression === node && !parent.questionDotToken) value = parent.name.text;
        else if (ts.isElementAccessExpression(parent) && parent.expression === node && !parent.questionDotToken
          && ts.isStringLiteral(parent.argumentExpression)) value = parent.argumentExpression.text;
        fail(f.path !== production.path && allowed.has(value), 'reference_unsupported');
        // Only direct initializer/value expressions: writes, calls and optional
        // access are never rewritten. No name aliasing or shadowing is accepted.
        fail(!(ts.isBinaryExpression(parent.parent) && parent.parent.left === parent)
          && !ts.isPrefixUnaryExpression(parent.parent) && !ts.isPostfixUnaryExpression(parent.parent)
          && !(ts.isCallExpression(parent.parent) && parent.parent.expression === parent)
          && !ts.isDeleteExpression(parent.parent), 'reference_not_readonly');
        edits.push({ start: parent.getStart(file), end: parent.end, text: `'${value}' as const` }); replacements++;
      }
      ts.forEachChild(node, walk);
    }
    walk(file);
    const result = applyEdits(f.content, edits);
    fail(result !== f.content, 'no_change');
    parse(f.path, result); results.push({ path: f.path, mode: f.mode, source: f.content, result });
  }
  fail(replacements > 0 && results.some(f => f.path === production.path), 'no_supported_consumers');
  return { results, replacements };
}

export async function prepareFixtureCleanup(raw, now = Date.now()) {
  const input = copy(raw); // Snapshot across asynchronous hashing.
  const historical = input.mode === 'historical_replay';
  fail(input.mode === undefined || input.mode === 'new_work' || historical, 'mode');
  if (historical) {
    validatePreparationPolicy(input.policy, now);
    const approval = input.policy.historicalReplay;
    fail(approval?.approved === true && approval.jobId === input.job?.id && approval.specHash === input.job?.specHash
      && approval.sourceCommitSha === input.source?.baseCommitSha && SHA.test(approval.originalCommitSha ?? '')
      && HASH.test(approval.expectedFilesHash ?? '') && input.job.provider === 'averray'
      && input.job.taskClass === TASK_CLASS && input.policy.repositories.includes(input.job.repository), 'historical_replay_unapproved');
    validateFreeCI(input.observation?.ci, now);
  } else checkPreparationEligibility(input.policy, input.job, input.observation, now);
  fail(input.source.repository === input.job.repository && input.source.baseBranch === 'main', 'source_scope');
  const policyHash = await hash(canonical(input.policy));
  const inventory = await verifyInventory(input);
  const { results, replacements } = transform(inventory.files, input.cleanup, input.policy);
  fail(results.length <= input.policy.maxFiles, 'file_limit');
  const combinedBytes = results.reduce((n, f) => n + enc.encode(f.source).length + enc.encode(f.result).length, 0);
  fail(combinedBytes <= input.policy.maxCombinedBytes, 'byte_limit');
  const selectedDirs = new Set(['']);
  for (const f of results) { const parts = f.path.split('/'); parts.pop(); while (parts.length) { selectedDirs.add(parts.join('/')); parts.pop(); } }
  const files = [];
  for (const f of results) {
    const value = { path: f.path, mode: f.mode };
    for (const kind of ['source', 'result']) value[kind] = { content: f[kind], sha256: await hash(f[kind]), blobSha: await gitHash('blob', f[kind]) };
    files.push(value);
  }
  if (historical) {
    const proof = files.map(f => ({ path: f.path, sourceSha256: f.source.sha256, resultSha256: f.result.sha256 }))
      .sort((a, b) => a.path.localeCompare(b.path));
    fail(await hash(canonical(proof)) === input.policy.historicalReplay.expectedFilesHash, 'historical_result_mismatch');
  }
  fail(input.commit?.author?.name === input.policy.owner && input.commit?.committer?.name === input.policy.owner, 'commit_owner');
  const manifest = {
    schemaVersion: 1, repository: input.source.repository, baseBranch: input.source.baseBranch,
    baseCommitSha: input.source.baseCommitSha, baseTreeSha: input.source.baseTreeSha,
    commit: { ...input.commit, message: `fix(fixtures): remove ${input.cleanup.symbol} test-only export\n\nAura job: ${input.job.id}\nAura specification: ${input.job.specHash}\nAura policy: ${policyHash}\n` },
    files,
    sourceTrees: [...selectedDirs].map(path => ({ sha: path ? inventory.byPath.get(path).sha : input.source.baseTreeSha, entries: inventory.dirs.get(path) })),
  };
  const plan = await prepareMultifileManifest(manifest, input.policy.owner);
  if (historical) fail(SHA.test(input.policy.historicalReplay.originalResultTreeSha ?? '')
    && plan.resultTreeSha === input.policy.historicalReplay.originalResultTreeSha, 'historical_tree_mismatch');
  return {
    schema: 'aura.preparation-result.v1', mode: historical ? 'historical_replay' : 'new_work', admissionEligible: !historical, taskClass: TASK_CLASS, jobId: input.job.id,
    specHash: input.job.specHash, policyHash, inputHash: await hash(canonical(input)),
    sourceCommitSha: manifest.baseCommitSha, sourceTreeSha: manifest.baseTreeSha,
    manifest, manifestHash: plan.manifestHash, commitSha: plan.commitSha, resultTreeSha: plan.resultTreeSha,
    fork: plan.fork, branch: plan.branch, fileCount: files.length, combinedBytes, replacements,
    ciVerified: false, claimAuthorized: false, publicationAuthorized: false,
  };
}

// Controller supplies a durable put-if-absent implementation. An uncertain or
// concurrent replay never silently overwrites a prior prepared job identity.
export async function prepareOnce(input, store, now = Date.now()) {
  fail(typeof store?.get === 'function' && typeof store?.putIfAbsent === 'function', 'durable_store_required');
  const result = await prepareFixtureCleanup(input, now);
  const key = `preparation:${result.mode}:${result.jobId}:${result.specHash}`;
  let existing = await store.get(key);
  if (!existing) { await store.putIfAbsent(key, result); existing = await store.get(key); }
  fail(existing?.inputHash === result.inputHash && existing.manifestHash === result.manifestHash
    && existing.commitSha === result.commitSha, 'replay_conflict');
  return copy(existing);
}

export async function verifyPreparedResult(input, candidate, now = Date.now()) {
  const expected = await prepareFixtureCleanup(input, now);
  fail(canonical(candidate) === canonical(expected), 'prepared_result_mismatch');
  return { verified: true, jobId: expected.jobId, specHash: expected.specHash,
    manifestHash: expected.manifestHash, commitSha: expected.commitSha,
    claimAuthorized: false, publicationAuthorized: false };
}
