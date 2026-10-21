// Inactive preparation adapter. No runner imports this module by default.
// The caller supplies scoped transport, approval/scope checks and a durable lease.
// Only immutable Git objects and one new exact ref are created; no PR is opened.
const SHA1 = /^[a-f0-9]{40}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });
const MAX_BYTES = 256 * 1024;
const requireThat = (condition, code) => { if (!condition) throw new Error(`multifile_${code}`); };
const object = value => value !== null && typeof value === "object" && !Array.isArray(value);
const equal = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const bytes = value => {
  requireThat(typeof value === "string" && !value.includes("\0"), "invalid_text");
  const encoded = encoder.encode(value);
  requireThat(decoder.decode(encoded) === value, "invalid_unicode");
  return encoded;
};
const hex = buffer => Array.from(new Uint8Array(buffer), b => b.toString(16).padStart(2, "0")).join("");
const digest = async (algorithm, value) => hex(await crypto.subtle.digest(algorithm, value));
const joinBytes = arrays => {
  const result = new Uint8Array(arrays.reduce((n, a) => n + a.length, 0));
  let offset = 0;
  for (const array of arrays) { result.set(array, offset); offset += array.length; }
  return result;
};
async function gitHash(type, contents) {
  return digest("SHA-1", joinBytes([encoder.encode(`${type} ${contents.length}\0`), contents]));
}
function component(value) {
  requireThat(typeof value === "string" && value.length > 0 && bytes(value).length <= 255
    && !value.includes("/") && !/[\x00-\x1f\x7f]/.test(value)
    && ![".", "..", ".git"].includes(value.toLowerCase()), "invalid_path");
}
function path(value) {
  requireThat(typeof value === "string" && value.length <= 1024, "invalid_path");
  const parts = value.split("/");
  requireThat(parts.length <= 24, "path_depth_limit");
  parts.forEach(component);
  return parts;
}
function ref(value) {
  requireThat(typeof value === "string" && /^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$/.test(value)
    && !value.includes("..") && !value.endsWith(".")
    && value.split("/").every(p => p && !p.startsWith(".") && !p.endsWith(".lock")), "invalid_ref");
}
function identity(value) {
  requireThat(object(value) && typeof value.name === "string" && /^[\x20-\x7e]{1,100}$/.test(value.name)
    && !/[<>]/.test(value.name) && value.name === value.name.trim(), "commit_identity");
  requireThat(typeof value.email === "string" && /^[A-Za-z0-9._+\-]{1,100}@[A-Za-z0-9.\-]{1,150}$/.test(value.email), "commit_identity");
  requireThat(typeof value.date === "string" && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/.test(value.date)
    && Number.isFinite(Date.parse(value.date))
    && new Date(value.date).toISOString() === value.date.replace("Z", ".000Z"), "commit_date");
  return { name: value.name, email: value.email, date: value.date };
}
function compareBytes(left, right) {
  for (let i = 0; i < Math.min(left.length, right.length); i++) {
    if (left[i] !== right[i]) return left[i] - right[i];
  }
  return left.length - right.length;
}
function sortEntries(entries) {
  return [...entries].sort((a, b) => compareBytes(encoder.encode(a.path + (a.type === "tree" ? "/" : "")),
    encoder.encode(b.path + (b.type === "tree" ? "/" : ""))));
}
async function treeHash(entries) {
  const data = sortEntries(entries).flatMap(entry => [
    encoder.encode(`${entry.mode === "040000" ? "40000" : entry.mode} ${entry.path}\0`),
    Uint8Array.from(entry.sha.match(/../g), b => parseInt(b, 16)),
  ]);
  return gitHash("tree", joinBytes(data));
}
function freeze(value) {
  if (object(value) || Array.isArray(value)) { Object.values(value).forEach(freeze); Object.freeze(value); }
  return value;
}

export async function prepareMultifileManifest(input, owner) {
  // Capture before the first digest await: callers cannot change content or
  // commit metadata between checking its hashes and constructing the payload.
  input = structuredClone(input);
  requireThat(object(input) && input.schemaVersion === 1, "schema");
  requireThat(typeof input.repository === "string"
    && /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(input.repository), "repository");
  input.repository.split("/").forEach(component);
  requireThat(typeof owner === "string" && /^[A-Za-z0-9-]{1,39}$/.test(owner), "owner");
  requireThat(input.repository.split("/")[0].toLowerCase() !== owner.toLowerCase(), "fork_required");
  ref(input.baseBranch);
  requireThat(SHA1.test(input.baseCommitSha) && SHA1.test(input.baseTreeSha), "base_unpinned");
  requireThat(Array.isArray(input.files) && input.files.length >= 1 && input.files.length <= 20, "file_count_limit");
  requireThat(object(input.commit) && typeof input.commit.message === "string"
    && bytes(input.commit.message).length > 0 && bytes(input.commit.message).length <= 4096, "commit_message");
  const commit = { message: input.commit.message, author: identity(input.commit.author), committer: identity(input.commit.committer) };
  let totalBytes = 0;
  const files = [];
  const names = new Set();
  for (const file of input.files) {
    requireThat(object(file), "file_schema");
    path(file.path);
    requireThat(!names.has(file.path), "duplicate_path"); names.add(file.path);
    requireThat(["100644", "100755"].includes(file.mode), "file_mode");
    const normalized = { path: file.path, mode: file.mode };
    for (const kind of ["source", "result"]) {
      const item = file[kind];
      requireThat(object(item) && SHA256.test(item.sha256) && SHA1.test(item.blobSha), "content_unpinned");
      const content = bytes(item.content);
      totalBytes += content.length;
      requireThat(totalBytes <= MAX_BYTES, "combined_content_limit");
      requireThat(await digest("SHA-256", content) === item.sha256
        && await gitHash("blob", content) === item.blobSha, "content_hash_mismatch");
      normalized[kind] = { content: item.content, sha256: item.sha256, blobSha: item.blobSha };
    }
    requireThat(normalized.source.blobSha !== normalized.result.blobSha, "unchanged_file");
    files.push(normalized);
  }
  files.sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
  requireThat(files.every((f, i) => !files.slice(i + 1).some(other => other.path.startsWith(f.path + "/"))), "path_collision");
  requireThat(Array.isArray(input.sourceTrees) && input.sourceTrees.length >= 1
    && input.sourceTrees.length <= 128
    && encoder.encode(JSON.stringify(input.sourceTrees)).length <= 512 * 1024, "tree_proof_limit");
  const trees = new Map();
  let entryCount = 0;
  for (const tree of input.sourceTrees) {
    requireThat(object(tree) && SHA1.test(tree.sha) && !trees.has(tree.sha)
      && Array.isArray(tree.entries) && tree.truncated !== true, "tree_proof_schema");
    const entries = [];
    const seen = new Set();
    for (const entry of tree.entries) {
      requireThat(object(entry) && SHA1.test(entry.sha), "tree_entry");
      component(entry.path);
      requireThat(!seen.has(entry.path), "tree_duplicate_entry"); seen.add(entry.path);
      requireThat(({ "040000": "tree", "100644": "blob", "100755": "blob", "120000": "blob", "160000": "commit" })[entry.mode] === entry.type, "tree_entry_mode");
      entries.push({ path: entry.path, mode: entry.mode, type: entry.type, sha: entry.sha });
    }
    entryCount += entries.length;
    requireThat(entryCount <= 4096, "tree_entry_limit");
    requireThat(await treeHash(entries) === tree.sha, "tree_proof_hash_mismatch");
    trees.set(tree.sha, entries);
  }
  const visited = new Set();
  const replace = async (sha, prefix, selected) => {
    const entries = trees.get(sha);
    requireThat(entries, "tree_proof_missing"); visited.add(sha);
    const next = entries.map(entry => ({ ...entry }));
    const groups = new Map();
    for (const file of selected) {
      const relative = file.path.slice(prefix.length);
      const first = relative.split("/")[0];
      if (!groups.has(first)) groups.set(first, []);
      groups.get(first).push(file);
    }
    for (const [first, selectedFiles] of groups) {
      const entry = next.find(item => item.path === first);
      requireThat(entry, "source_path_absent");
      const file = selectedFiles[0];
      if (file.path === prefix + first) {
        requireThat(selectedFiles.length === 1 && entry.type === "blob" && entry.mode === file.mode
          && entry.sha === file.source.blobSha, "source_tree_mismatch");
        entry.sha = file.result.blobSha;
      } else {
        requireThat(entry.type === "tree" && entry.mode === "040000", "source_path_not_directory");
        entry.sha = await replace(entry.sha, `${prefix}${first}/`, selectedFiles);
      }
    }
    return treeHash(next);
  };
  const resultTreeSha = await replace(input.baseTreeSha, "", files);
  requireThat(visited.size === trees.size, "unused_tree_proof");
  const sourceTrees = [...trees].sort(([a], [b]) => a < b ? -1 : 1)
    .map(([sha, entries]) => ({ sha, entries: sortEntries(entries) }));
  const normalized = { schemaVersion: 1, repository: input.repository, baseBranch: input.baseBranch,
    baseCommitSha: input.baseCommitSha, baseTreeSha: input.baseTreeSha, commit, files, sourceTrees };
  const manifestHash = await digest("SHA-256", encoder.encode(JSON.stringify({ owner, manifest: normalized })));
  const who = person => `${person.name} <${person.email}> ${Date.parse(person.date) / 1000} +0000`;
  const rawCommit = `tree ${resultTreeSha}\nparent ${input.baseCommitSha}\nauthor ${who(commit.author)}\ncommitter ${who(commit.committer)}\n\n${commit.message}`;
  const commitSha = await gitHash("commit", encoder.encode(rawCommit));
  return freeze({ ...normalized, owner, manifestHash, totalBytes, resultTreeSha, commitSha,
    branch: `aura/multi-${manifestHash}`, fork: `${owner}/${input.repository.split("/")[1]}`,
    treeBody: { base_tree: input.baseTreeSha, tree: files.map(file => ({ path: file.path, mode: file.mode, type: "blob", content: file.result.content })) },
    commitBody: { message: commit.message, tree: resultTreeSha, parents: [input.baseCommitSha], author: commit.author, committer: commit.committer },
  });
}

export async function createMultifilePreparation({ request, manifest, owner, reviewedTarget }) {
  requireThat(typeof request === "function", "transport_required");
  // The facade validates the recipe-bound operator review before supplying this
  // optional target. Snapshot it before asynchronous hashes. It never changes
  // the manifest, object identities, branch, diff or preparation journal.
  const target = reviewedTarget === undefined ? { commitSha: manifest.baseCommitSha, treeSha: manifest.baseTreeSha }
    : JSON.parse(JSON.stringify(reviewedTarget));
  requireThat(object(target) && SHA1.test(target.commitSha ?? "") && SHA1.test(target.treeSha ?? "")
    && (reviewedTarget === undefined || target.fromCommitSha === manifest.baseCommitSha), "reviewed_target_invalid");
  const plan = await prepareMultifileManifest(manifest, owner);
  const own = `/repos/${plan.fork}`;
  const upstream = `/repos/${plan.repository}`;
  const branchPath = plan.branch.split("/").map(encodeURIComponent).join("/");
  const call = (url, options) => request("github", url, options);
  const optional = async url => { try { return await call(url); } catch (error) { if (error.status === 404) return null; throw error; } };
  const journalIdentity = { manifestHash: plan.manifestHash, owner, fork: plan.fork, branch: plan.branch,
    baseCommitSha: plan.baseCommitSha, baseTreeSha: plan.baseTreeSha, resultTreeSha: plan.resultTreeSha, commitSha: plan.commitSha };
  const phases = new Set(["source_verified", "tree_intent", "tree_ready", "commit_intent", "commit_ready", "ref_intent", "prepared"]);
  const verifyTree = tree => {
    requireThat(tree?.sha === plan.resultTreeSha, "returned_tree_mismatch");
    return tree;
  };
  const verifyCommit = commit => {
    // GitHub's commit response can omit one final LF from its message field.
    // The exact content-addressed commit SHA still pins the original raw bytes;
    // permit only that observed presentation change, never general trimming.
    const expectedMessage = plan.commit.message;
    const messageMatches = commit?.message === expectedMessage
      || (expectedMessage.endsWith("\n") && commit?.message === expectedMessage.slice(0, -1));
    requireThat(commit?.sha === plan.commitSha && commit.tree?.sha === plan.resultTreeSha
      && commit.parents?.length === 1 && commit.parents[0]?.sha === plan.baseCommitSha
      && messageMatches, "returned_commit_mismatch");
    for (const role of ["author", "committer"]) {
      const actual = commit[role], expected = plan.commit[role];
      requireThat(actual?.name === expected.name && actual.email === expected.email
        && Date.parse(actual.date) === Date.parse(expected.date), "returned_commit_identity");
    }
    return commit;
  };
  const verifyFiles = files => {
    requireThat(Array.isArray(files) && files.length === plan.files.length, "diff_file_count");
    const actual = new Map();
    for (const file of files) {
      requireThat(object(file) && typeof file.filename === "string" && !actual.has(file.filename)
        && file.status === "modified" && !file.previous_filename, "diff_file_identity");
      actual.set(file.filename, file.sha);
    }
    requireThat(plan.files.every(file => actual.get(file.path) === file.result.blobSha), "unreviewed_diff");
  };
  const verifyObjects = async () => {
    verifyCommit(await call(`${own}/git/commits/${plan.commitSha}`));
    const comparison = await call(`${own}/compare/${plan.baseCommitSha}...${plan.commitSha}?per_page=100`);
    requireThat(comparison.status === "ahead" && comparison.ahead_by === 1 && comparison.behind_by === 0
      && comparison.total_commits === 1 && comparison.commits?.length === 1
      && comparison.commits[0]?.sha === plan.commitSha && comparison.base_commit?.sha === plan.baseCommitSha
      && comparison.merge_base_commit?.sha === plan.baseCommitSha, "unreviewed_history");
    verifyFiles(comparison.files);
  };
  const verifyEnvironment = async () => {
    const user = await call("/user");
    requireThat(user.login === owner, "identity_mismatch");
    const fork = await call(own);
    requireThat(fork.fork === true && fork.parent?.full_name === plan.repository
      && fork.owner?.login === owner && fork.full_name === plan.fork, "wrong_fork");
    const baseRef = await call(`${upstream}/git/ref/heads/${plan.baseBranch.split("/").map(encodeURIComponent).join("/")}`);
    requireThat(baseRef.object?.type === "commit" && baseRef.object.sha === target.commitSha, "base_changed_reaudit");
    const baseCommit = await call(`${upstream}/git/commits/${target.commitSha}`);
    requireThat(baseCommit.sha === target.commitSha && baseCommit.tree?.sha === target.treeSha, "base_tree_changed");
  };
  const exactRef = async () => {
    const found = await optional(`${own}/git/ref/heads/${branchPath}`);
    if (found) requireThat(found.ref === `refs/heads/${plan.branch}` && found.object?.type === "commit"
      && found.object.sha === plan.commitSha, "ref_conflict");
    return found;
  };
  const verifyPrepared = async () => {
    await verifyEnvironment();
    if (!await exactRef()) return { ready: false, reason: "branch_absent" };
    await verifyObjects();
    return { ready: true, commitSha: plan.commitSha, treeSha: plan.resultTreeSha,
      branch: plan.branch, fork: plan.fork, fileCount: plan.files.length };
  };
  return Object.freeze({ manifestHash: plan.manifestHash, branch: plan.branch, fork: plan.fork,
    commitSha: plan.commitSha, resultTreeSha: plan.resultTreeSha, totalBytes: plan.totalBytes,
    verifyPrepared,
    async advance({ store, lease }) {
      requireThat(store && lease, "journal_required");
      await store.assertLease(lease);
      const id = `github-multifile:${plan.manifestHash}`;
      let state = await store.load(id);
      requireThat(Number.isSafeInteger(state.version) && state.version >= 0, "journal_version");
      if (state.version === 0) requireThat(state.phase === "new", "journal_identity");
      else requireThat(phases.has(state.phase)
        && Object.entries(journalIdentity).every(([key, value]) => state[key] === value), "journal_identity");
      const save = async phase => {
        state = await store.save(id, state, { ...journalIdentity, phase }, lease);
        return state;
      };
      await verifyEnvironment();
      if (state.phase === "new") return save("source_verified");
      if (["source_verified", "tree_intent"].includes(state.phase)) {
        const tree = await optional(`${own}/git/trees/${plan.resultTreeSha}`);
        if (tree) { verifyTree(tree); return save("tree_ready"); }
        if (state.phase !== "tree_intent") await save("tree_intent");
        await store.assertLease(lease);
        verifyTree(await call(`${own}/git/trees`, { method: "POST", body: plan.treeBody }));
        return save("tree_ready");
      }
      if (["tree_ready", "commit_intent"].includes(state.phase)) {
        const commit = await optional(`${own}/git/commits/${plan.commitSha}`);
        if (commit) { verifyCommit(commit); return save("commit_ready"); }
        if (state.phase !== "commit_intent") await save("commit_intent");
        await store.assertLease(lease);
        verifyCommit(await call(`${own}/git/commits`, { method: "POST", body: plan.commitBody }));
        return save("commit_ready");
      }
      await verifyObjects();
      if (await exactRef()) return state.phase === "prepared" ? state : save("prepared");
      requireThat(state.phase !== "prepared", "prepared_ref_disappeared");
      if (state.phase !== "ref_intent") await save("ref_intent");
      await store.assertLease(lease);
      try {
        await call(`${own}/git/refs`, { method: "POST", body: { ref: `refs/heads/${plan.branch}`, sha: plan.commitSha } });
      } catch (error) {
        // The response can be lost, or another attempt can have created this
        // exact ref. Only its canonical read, never an error code, proves success.
        if (!await exactRef()) throw error;
      }
      requireThat(await exactRef(), "ref_outcome_unresolved");
      return save("prepared");
    },
    async verifyPR(pr) {
      requireThat(Number.isSafeInteger(pr?.number) && pr.number > 0
        && pr.head?.repo?.full_name === plan.fork && pr.head.ref === plan.branch && pr.head.sha === plan.commitSha
        && pr.base?.repo?.full_name === plan.repository && pr.base.ref === plan.baseBranch
        && pr.base.sha === target.commitSha && pr.changed_files === plan.files.length
        && pr.html_url === `https://github.com/${plan.repository}/pull/${pr.number}`
        && (pr.state === "open" || Boolean(pr.merged_at)), "pr_identity");
      requireThat((await verifyPrepared()).ready, "pr_branch_absent");
      const files = await call(`${upstream}/pulls/${pr.number}/files?per_page=100`);
      verifyFiles(files);
      return { verified: true, number: pr.number, url: pr.html_url, fileCount: files.length, commitSha: plan.commitSha };
    },
  });
}
