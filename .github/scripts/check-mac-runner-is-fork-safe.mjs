#!/usr/bin/env node
// No fork's pull request can run on the self-hosted Mac runners.
//
// This repository is public, so a pull request from a fork is code written by
// anybody, and the Mac (`apple-48gb-metal`) keeps its state between jobs. The
// only thing between a fork's PR and that machine is one expression in
// `runs-on`, so there is ONE accepted shape and anything else naming the pool
// fails here:
//
//   ${{ [matrix.<k> == '<v>' && ]vars.CITADEL_MAC_RUNNER == '1'
//       && (github.event_name != 'pull_request'
//           || github.event.pull_request.head.repo.full_name == github.repository)
//       && fromJSON('["self-hosted","macOS","ARM64","apple-48gb-metal"]')
//       || '<hosted label>' | matrix.<k> }}
//
// Unset, the org variable sends every job to its hosted fallback: that is the
// escape hatch when the Mac is down. The guard only understands `pull_request`;
// under `pull_request_target`, `issue_comment` or `workflow_run` the event name
// is something else, the guard is TRUE, and a fork could land here. So those
// triggers are refused for any workflow that routes to the pool, including one
// reached through `workflow_call` (validate.yml is called by exec.yml).
//
// Same rules as the parent repository's scripts/lib/mac-runner-routing.mjs
// (Avarok-Cybersecurity/citadel-workspace). Dependency-free: it reads text.
//
//   node .github/scripts/check-mac-runner-is-fork-safe.mjs              # the gate
//   node .github/scripts/check-mac-runner-is-fork-safe.mjs --self-test  # its negative controls
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';

const OPT_IN = "vars.CITADEL_MAC_RUNNER == '1'";
const SAME_REPO_GUARD =
  "(github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository)";
const POOL = `fromJSON('["self-hosted","macOS","ARM64","apple-48gb-metal"]')`;
/** Anything that reaches the pool, however it is spelled. */
const POOL_TOKENS = /self-hosted|apple-48gb-metal|CITADEL_MAC_RUNNER/;
/** Triggers whose `github.event_name` the guard reasons about correctly. */
const SAFE_TRIGGERS = new Set(['pull_request', 'push', 'workflow_dispatch', 'schedule', 'workflow_call', 'merge_group']);

const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const CANONICAL = new RegExp(
  '^\\$\\{\\{ ' +
  "(?:matrix\\.[A-Za-z0-9_-]+ == '[^']+' && )?" +
  `${esc(OPT_IN)} && ${esc(SAME_REPO_GUARD)} && ${esc(POOL)} \\|\\| ` +
  "(?:'(?<label>[^']+)'|matrix\\.[A-Za-z0-9_-]+) \\}\\}$",
);

/** A line with its comment removed, unless the `#` sits inside quotes. */
function stripComment(line) {
  if (/^\s*#/.test(line)) return '';
  const hash = line.search(/\s#/);
  if (hash < 0) return line;
  const before = line.slice(0, hash);
  const quotes = (before.match(/'/g) || []).length + (before.match(/"/g) || []).length;
  return quotes % 2 === 0 ? before : line;
}

const collapse = (s) => s.replace(/\s+/g, ' ').trim();

/** The workflow's trigger names, from a block or an inline `on:`. */
function triggersOf(source) {
  const lines = source.split('\n').map(stripComment);
  const start = lines.findIndex((l) => /^(on|"on"|'on'|true):/.test(l));
  if (start < 0) return [];
  const inline = lines[start].replace(/^[^:]+:\s*/, '').trim();
  if (inline) return inline.replace(/[[\]]/g, '').split(',').map((t) => t.trim()).filter(Boolean);
  const found = [];
  for (const line of lines.slice(start + 1)) {
    if (/^\S/.test(line)) break;
    const key = line.match(/^ {2}([A-Za-z_]+):/);
    if (key) found.push(key[1]);
  }
  return found;
}

/**
 * Jobs as { name, runsOn, strategy, calls }. `strategy` is the matrix text: the
 * only other place a runner label can come from, since runs-on may read it.
 */
function jobsOf(source) {
  const lines = source.split('\n').map(stripComment);
  const jobs = [];
  let inJobs = false;
  let job = null;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (/^jobs:\s*$/.test(line)) { inJobs = true; continue; }
    if (!inJobs) continue;
    if (/^\S/.test(line)) { inJobs = false; job = null; continue; }
    const key = line.match(/^ {2}([A-Za-z0-9_-]+):\s*$/);
    if (key) { job = { name: key[1], runsOn: null, strategy: [], calls: null, inStrategy: false }; jobs.push(job); continue; }
    if (!job) continue;
    const call = line.match(/^ {4}uses:\s*(\S+)/);
    if (call) job.calls = call[1];
    if (/^ {4}\S/.test(line)) job.inStrategy = /^ {4}strategy:/.test(line);
    if (job.inStrategy) job.strategy.push(line);
    const runsOn = line.match(/^ {4}runs-on:\s*(.*)$/);
    if (!runsOn) continue;
    let value = runsOn[1].trim();
    if (/^[>|][-+]?$/.test(value)) {
      value = '';
      while (i + 1 < lines.length && (/^ {6,}\S/.test(lines[i + 1]) || lines[i + 1].trim() === '')) value += ` ${lines[++i]}`;
    }
    job.runsOn = collapse(value).replace(/^(['"])(.*)\1$/, '$2');
  }
  return jobs.map(({ inStrategy, ...j }) => ({ ...j, strategy: j.strategy.join('\n') }));
}

/** Is this `runs-on` the one accepted shape? Returns null when it is, else why not. */
function routingProblem(runsOn) {
  const match = CANONICAL.exec(runsOn ?? '');
  if (!match) {
    return 'names the Mac pool without the one accepted runs-on expression (opt-in variable, same-repo guard, pool array, hosted fallback)';
  }
  if (match.groups.label && POOL_TOKENS.test(match.groups.label)) {
    return `falls back to '${match.groups.label}', which is the pool itself: with the variable unset it still runs here`;
  }
  return null;
}

/**
 * Judge every workflow at once, because a reusable workflow is only as safe as
 * whatever calls it. `files` is [{ name, source }]; returns { problems, jobs, routed }.
 */
function judge(files) {
  const problems = [];
  let jobs = 0;
  const routed = [];
  const parsed = files.map(({ name, source }) => ({ name, triggers: triggersOf(source), jobs: jobsOf(source) }));
  const routesToPool = new Set();
  for (const wf of parsed) {
    for (const job of wf.jobs) {
      jobs += 1;
      const where = `${wf.name}:${job.name}`;
      const inRunsOn = POOL_TOKENS.test(job.runsOn ?? '');
      if (POOL_TOKENS.test(job.strategy)) {
        problems.push(`${where} names the Mac pool in its matrix; a matrix value cannot carry the guard`);
      }
      if (!inRunsOn) continue;
      routesToPool.add(wf.name);
      routed.push(where);
      const why = routingProblem(job.runsOn);
      if (why) problems.push(`${where} ${why}`);
      const unsafe = wf.triggers.filter((t) => !SAFE_TRIGGERS.has(t));
      if (unsafe.length) {
        problems.push(`${where} routes to the Mac pool in a workflow triggered by ${unsafe.join(', ')}; the same-repo guard only recognises pull_request, so a fork's code could run there`);
      }
    }
  }
  for (const wf of parsed) {
    const unsafe = wf.triggers.filter((t) => !SAFE_TRIGGERS.has(t));
    if (!unsafe.length) continue;
    for (const job of wf.jobs) {
      const callee = job.calls?.match(/^\.\/\.github\/workflows\/(.+)$/)?.[1];
      if (callee && routesToPool.has(callee)) {
        problems.push(`${wf.name}:${job.name} calls ${callee}, which routes to the Mac pool, from ${unsafe.join(', ')}; the callee's guard cannot tell that event from a trusted one`);
      }
    }
  }
  return { problems, jobs, routed };
}

const ROUTE = `\${{ ${OPT_IN} && ${SAME_REPO_GUARD} && ${POOL} || 'ubuntu-latest' }}`;
const fixture = (on, runsOn, extra = '') =>
  `on:\n${on}\njobs:\n  build:\n    runs-on: ${runsOn}\n${extra}    steps:\n      - run: echo hi\n`;
const one = (source) => judge([{ name: 'ci.yml', source }]).problems;

/** [name, problems, expected count or regex]: each NEGATIVE must turn the gate red. */
function selfTest() {
  const leg = `\${{ matrix.os == 'macos-latest' && ${OPT_IN} && ${SAME_REPO_GUARD} && ${POOL} || matrix.os }}`;
  const folded = `>-\n      \${{ ${OPT_IN}\n        && ${SAME_REPO_GUARD}\n        && ${POOL}\n        || 'macos-latest' }}`;
  const caller = 'on:\n  workflow_run:\n    workflows: [x]\njobs:\n  v:\n    uses: ./.github/workflows/validate.yml\n';
  const cases = [
    ['the accepted expression passes', one(fixture('  pull_request:', ROUTE)), 0],
    ['a folded runs-on passes', one(fixture('  pull_request:', folded)), 0],
    ['a guarded matrix leg passes', one(fixture('  pull_request:', leg)), 0],
    ['prose naming the pool is not routing', one(fixture('  pull_request:', 'ubuntu-latest', '    env:\n      X: self-hosted\n')), 0],
    ['NEGATIVE: no same-repo guard', one(fixture('  pull_request:', `\${{ ${OPT_IN} && ${POOL} || 'ubuntu-latest' }}`)), /without the one accepted/],
    ['NEGATIVE: bare label list', one(fixture('  pull_request:', '[self-hosted, macOS, ARM64, apple-48gb-metal]')), /without the one accepted/],
    ['NEGATIVE: no opt-in variable', one(fixture('  push:', `\${{ ${SAME_REPO_GUARD} && ${POOL} || 'ubuntu-latest' }}`)), /without the one accepted/],
    ['NEGATIVE: fallback is the pool', one(fixture('  pull_request:', ROUTE.replace("'ubuntu-latest'", "'self-hosted'"))), /falls back to 'self-hosted'/],
    ['NEGATIVE: pool in a matrix value', one(fixture('  pull_request:', '${{ matrix.os }}', '    strategy:\n      matrix:\n        os: [ubuntu-latest, self-hosted]\n')), /in its matrix/],
    ['NEGATIVE: pull_request_target', one(fixture('  pull_request_target:', ROUTE)), /triggered by pull_request_target/],
    ['NEGATIVE: inline issue_comment trigger', one(fixture('', ROUTE).replace('on:\n\n', 'on: [push, issue_comment]\n')), /issue_comment/],
    ['NEGATIVE: routed callee called from workflow_run',
      judge([{ name: 'validate.yml', source: fixture('  workflow_call:', ROUTE) }, { name: 'after.yml', source: caller }]).problems, /after\.yml:v calls validate\.yml/],
  ];
  let failed = 0;
  for (const [name, problems, want] of cases) {
    const ok = typeof want === 'number' ? problems.length === want : problems.some((p) => want.test(p));
    if (!ok) { failed += 1; console.error(`::error::self-test '${name}' got ${JSON.stringify(problems)}`); }
  }
  if (failed) process.exit(1);
  console.log(`  Mac runner fork guard self-test: ${cases.length} case(s), ${cases.filter((c) => c[0].startsWith('NEGATIVE')).length} negative control(s) red as required  ok`);
}

function gate() {
  const dir = '.github/workflows';
  if (!existsSync(dir)) { console.error(`::error::${dir} not found; run from the repository root`); process.exit(1); }
  const files = readdirSync(dir).filter((f) => /\.ya?ml$/.test(f)).map((name) => ({ name, source: readFileSync(join(dir, name), 'utf8') }));
  const { problems, jobs, routed } = judge(files);
  if (jobs === 0) problems.push('no jobs found in any workflow; the parser no longer matches the files');
  if (problems.length) {
    console.error('\n  A job could put untrusted code on the self-hosted Mac:\n');
    for (const p of problems) console.error(`::error::${p}`);
    process.exit(1);
  }
  console.log(`  Mac runner fork guard: ${jobs} job(s) in ${files.length} workflow(s), ${routed.length} routed to the Mac, every one guarded  ok`);
}

if (process.argv.includes('--self-test')) selfTest(); else gate();
