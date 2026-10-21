// Pure browser/Worker-compatible schema and eligibility gate. Never grants
// claim/publication authority; values must originate from trusted observations.
export const TASK_CLASS = 'ts_identity_fixture_cleanup_v1';
const fail = (condition, code) => { if (!condition) throw new Error(`preparation_${code}`); };
const recent = (at, now, age = 300_000) => Number.isFinite(Date.parse(at))
  && Date.parse(at) <= now && now - Date.parse(at) <= age;
const repo = value => typeof value === 'string' && /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(value)
  && value.split('/').every(s => !['.', '..'].includes(s));
const path = value => typeof value === 'string' && value.length <= 1024
  && !/[\x00-\x1f\x7f\\]/.test(value) && value.split('/').every(s => s && !['.', '..', '.git'].includes(s.toLowerCase()));

export function validatePreparationPolicy(policy, now = Date.now(), { draft = false } = {}) {
  fail(Number.isFinite(now) && policy?.schema === 'aura.preparation-policy.v1'
    && policy.taskClass === TASK_CLASS && /^[a-z0-9][a-z0-9-]{0,79}$/.test(policy.id ?? '')
    && /^[A-Za-z0-9-]{1,39}$/.test(policy.owner ?? ''), 'policy_schema');
  fail(policy.allowClaims === false && policy.allowPublication === false && policy.maxSpendRaw === '0'
    && policy.maxConcurrentWork === 1, 'policy_authority');
  fail(Number.isInteger(policy.maxFiles) && policy.maxFiles >= 1 && policy.maxFiles <= 20
    && Number.isInteger(policy.maxCombinedBytes) && policy.maxCombinedBytes > 0 && policy.maxCombinedBytes <= 262144, 'policy_limits');
  fail(Array.isArray(policy.repositories) && policy.repositories.length >= 1 && policy.repositories.length <= 5
    && policy.repositories.every(repo) && new Set(policy.repositories).size === policy.repositories.length, 'policy_repositories');
  fail(Array.isArray(policy.symbols) && policy.symbols.length >= 1 && policy.symbols.length <= 10
    && policy.symbols.every(s => /^[A-Za-z_][A-Za-z0-9_]{0,79}$/.test(s))
    && new Set(policy.symbols).size === policy.symbols.length, 'policy_symbols');
  fail(Array.isArray(policy.testHelperPaths) && policy.testHelperPaths.length <= 20
    && policy.testHelperPaths.every(p => path(p) && p.endsWith('.ts'))
    && new Set(policy.testHelperPaths).size === policy.testHelperPaths.length, 'policy_helpers');
  fail(recent(policy.reviewedAt, now, 30 * 86_400_000) && Date.parse(policy.expiresAt) > now
    && Date.parse(policy.expiresAt) - Date.parse(policy.reviewedAt) <= 30 * 86_400_000, 'policy_expired');
  if (draft) {
    fail(policy.lifecycle === 'draft' && policy.executionEnabled === false, 'draft_policy_state');
  } else {
    fail(policy.authorization?.source === 'owner_reviewed_preparation_policy'
      && policy.authorization?.approved === true && policy.lifecycle === 'approved_preparation_only'
      && policy.executionEnabled === false, 'policy_unapproved');
  }
  return { valid: true, taskClass: TASK_CLASS, claimAuthorized: false, publicationAuthorized: false };
}

export function checkPreparationEligibility(policy, job, observation, now = Date.now()) {
  validatePreparationPolicy(policy, now);
  fail(job?.provider === 'averray' && /^[a-z0-9][a-z0-9-]{0,199}$/.test(job.id ?? '')
    && /^0x[a-f0-9]{64}$/.test(job.specHash ?? '') && job.taskClass === TASK_CLASS, 'unsupported_job');
  fail(policy.repositories.includes(job.repository) && repo(job.repository), 'repository_scope');
  fail(recent(observation?.observedAt, now) && observation.jobId === job.id && observation.specHash === job.specHash,
    'eligibility_stale_or_unbound');
  fail(observation.claimable === true && observation.ownerEligible === true
    && observation.policyReviewed === true && observation.overlappingWork === false, 'eligibility_unknown_or_rejected');
  fail(observation.openWorkCount === 0 && observation.claimAttemptCount === 0, 'work_already_active');
  fail(['claimFeeRaw', 'claimStakeRaw', 'workerGasRaw', 'workerLockRaw'].every(k => observation[k] === '0')
    && observation.sponsoredGas === true && observation.onboardingWaiverEligible === true, 'cost_not_zero');
  fail(Number.isInteger(observation.waiverClaimsRemaining) && observation.waiverClaimsRemaining > 0
    && observation.waiverClaimsRemaining <= 3, 'waiver_exhausted_or_unknown');
  fail(typeof observation.firstContributorOnly === 'boolean'
    && (!observation.firstContributorOnly || observation.priorContributions === 0), 'first_contributor_ineligible_or_unknown');
  validateFreeCI(observation.ci, now);
  return { eligible: true, claimAuthorized: false, publicationAuthorized: false };
}

export function validateFreeCI(ci, now = Date.now()) {
  fail(ci?.repositoryPublic === true && ci.standardGitHubHostedLinux === true
    && ci.billingVerifiedFree === true && ci.paidOverageDisabled === true
    && Number.isInteger(ci.availableRuns) && ci.availableRuns >= 1 && ci.activeRuns === 0
    && ci.artifactsEnabled === false && ci.cacheEnabled === false
    && recent(ci.verifiedAt, now, 86_400_000), 'free_ci_unverified_or_quota_exhausted');
  return { verified: true };
}
