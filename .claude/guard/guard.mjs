#!/usr/bin/env node
// Claude guard — an AI that checks the AI.
//
// One script, wired to Claude Code's hooks in .claude/settings.json. It runs on
// every prompt, before and after every tool call, and when Claude says it is
// finished. The four checks are the ones AiSOC applies to its own agents:
//
//   1. LEDGER    Every prompt, tool call and decision is appended to
//                .claude/guard/ledger.jsonl, secrets redacted. Refusals too.
//   2. SECRETS   A key or password is refused before it reaches the model or
//                a file: in a prompt, in a Write/Edit, in a shell command.
//   3. GROUNDING When Claude says "pushed", "tests pass", "build is clean",
//                the ledger must show the command that proves it. If not,
//                Claude is sent back to run it or correct the claim.
//   4. APPROVAL  Risky actions (force-push, hard reset, deploys, deleting
//                data, turning this guard off) wait for a human to approve.
//
// Repo-specific rules live in .claude/guard/rules.json. No dependencies.
// If node is missing the hooks fail open; see README.md.

import fs from "node:fs";
import path from "node:path";

const VERSION = "1.0.0";
const HERE = path.dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1"));

// ---------------------------------------------------------------- secrets ---

// Known key formats: refused outright wherever they appear.
export const SECRET_PATTERNS = [
  ["private key", /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----/],
  ["AWS access key", /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/],
  ["GitHub token", /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b/],
  ["Anthropic key", /\bsk-ant-[A-Za-z0-9_-]{20,}/],
  ["OpenAI key", /\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,}/],
  ["OpenRouter key", /\bsk-or-v1-[A-Za-z0-9]{32,}/],
  ["Google API key", /\bAIza[0-9A-Za-z_-]{35}\b/],
  ["Slack token", /\bxox[abprs]-[A-Za-z0-9-]{10,}/],
  ["Stripe live key", /\b(?:sk|rk)_live_[A-Za-z0-9]{20,}/],
  ["Telegram bot token", /\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b/],
  ["Discord bot token", /\b[MN][A-Za-z\d]{23,25}\.[\w-]{6}\.[\w-]{27,}\b/],
  ["JWT", /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/],
  ["connection string with password", /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^\s:@/]+:[^\s@/]{3,}@/],
];

// A literal value assigned to something named like a password. Only asks,
// because tests and fixtures have these legitimately.
const ASSIGNED_SECRET =
  /\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|kata[_-]?sandi|sandi)\b["']?\s*[:=]\s*["']([^"'\s]{6,})["']/i;
const PLACEHOLDER = /^(?:\$\{?|<|\*{3,}|x{4,}|\.{3}|process\.env|env\.|changeme$|example|placeholder|your[_-]|redacted|todo)/i;

export function findSecret(text) {
  if (!text) return null;
  for (const [name, re] of SECRET_PATTERNS) if (re.test(text)) return name;
  return null;
}

export function findAssignedSecret(text) {
  if (!text) return null;
  const m = String(text).match(new RegExp(ASSIGNED_SECRET, "gi")) || [];
  for (const hit of m) {
    const v = hit.match(ASSIGNED_SECRET)?.[1] || "";
    if (!PLACEHOLDER.test(v)) return hit.split(/[:=]/)[0].replace(/["'\s]/g, "");
  }
  return null;
}

export function redact(text) {
  let s = String(text ?? "");
  for (const [, re] of SECRET_PATTERNS) s = s.replace(new RegExp(re.source, "g"), "[REDACTED]");
  s = s.replace(new RegExp(ASSIGNED_SECRET.source, "gi"), (all, v) => all.replace(v, "[REDACTED]"));
  return s;
}

// ------------------------------------------------------------------ rules ---

// Shell commands that wait for a human. [pattern, reason]
const BASE_BASH_ASK = [
  [/\bgit\s+push\b[^|;&]*\s(?:--force(?!-with-lease)|-f\b|--force-with-lease|\+\S)/, "force-push rewrites history on the remote"],
  [/\bgit\s+push\b[^|;&]*\s(?:origin\s+)?(?:HEAD:)?(?:main|master|production|prod)\b(?![-\w/])/, "pushes straight to a main/production branch"],
  [/\bgit\s+push\b[^|;&]*\s--delete\b|\bgit\s+push\b[^|;&]*\s:\S/, "deletes a remote branch"],
  [/\bgit\s+reset\s+[^|;&]*--hard\b/, "git reset --hard throws away uncommitted work"],
  [/\bgit\s+clean\s+-[a-z]*f/, "git clean -f deletes untracked files"],
  [/\bgit\s+(?:checkout|restore)\s+(?:--\s+)?\.(?:\s|$)/, "discards every uncommitted change"],
  [/\bgit\s+branch\s+-D\b/, "force-deletes a branch"],
  [/\bgit\s+(?:commit|push|merge|rebase)\b[^|;&]*--no-verify\b/, "skips the repo's git hooks"],
  [/\bgit\s+filter-(?:branch|repo)\b/, "rewrites repository history"],
  [/\brm\s+(?:-[a-zA-Z]*[rR][a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*[rR]|-r\s+-f|-f\s+-r|--recursive\s+--force|--force\s+--recursive)\b/, "recursive forced delete"],
  [/\b(?:DROP\s+(?:TABLE|DATABASE|SCHEMA|INDEX)|TRUNCATE\s+(?:TABLE\s+)?\w)/i, "drops or empties database objects"],
  [/\bDELETE\s+FROM\s+[\w."`\[\]]+\s*(?:;|"|'|$)/im, "DELETE without a WHERE clause"],
  [/\b(?:curl|wget)\b[^|;&]*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b/, "pipes a downloaded script straight into a shell"],
  [/\bchmod\s+(?:-R\s+)?0?777\b/, "makes files world-writable"],
  [/\b(?:npm|pnpm|yarn)\s+publish\b|\bcargo\s+publish\b|\btwine\s+upload\b/, "publishes a package publicly"],
  [/\bsudo\b/, "runs as root"],
  [/\b(?:printenv|env)\s*(?:$|[|;&>])|\bcat\b[^|;&]*(?:^|\/|\s)(?:\.env(?!\.example|\.sample|\.template)(?:\.[\w-]+)?|\.dev\.vars|id_rsa|id_ed25519|[\w.-]+\.pem)\b/, "prints secrets to the transcript"],
];

// Shell commands refused outright.
const BASE_BASH_DENY = [
  [/\brm\s+-[a-zA-Z]*[rR][a-zA-Z]*\s+(?:-[a-zA-Z]+\s+)*(?:\/|~|\$HOME)(?:\s|\/?\*?\s*$|$)/, "deletes the filesystem root or home directory"],
  [/:\(\)\s*\{\s*:\|:&\s*\};:/, "fork bomb"],
  [/\bmkfs\b|\bdd\s+[^|;&]*of=\/dev\//, "overwrites a disk"],
];

// Files that wait for a human before Claude edits them.
const BASE_PATH_ASK = [
  [/(?:^|\/)\.claude\/(?:settings(?:\.local)?\.json|guard\/)/, "changes the guard that checks Claude"],
  [/(?:^|\/)\.env(?:\.[\w-]+)?$|(?:^|\/)\.dev\.vars$/, "a secrets file"],
  [/(?:^|\/)\.github\/workflows\//, "CI workflow (runs with repo secrets)"],
];

// Files Claude should not even read without a human saying yes.
const BASE_READ_ASK = [
  [/(?:^|\/)\.env(?:\.(?!example$|sample$|template$)[\w-]+)?$|(?:^|\/)\.dev\.vars$/, "a secrets file"],
  [/(?:^|\/)(?:id_rsa|id_ed25519|id_ecdsa)$|\.pem$|\.p12$|\.key$/, "a private key"],
];

// Commands that prove a claim. Repo rules add to `checks`.
const BASE_PROOFS = {
  pushed: /\bgit\s+push\b/,
  committed: /\bgit\s+commit\b/,
  tested: /\b(?:npm|pnpm|yarn|bun)\s+(?:run\s+)?test\b|\bnode\s+--test\b|\bvitest\b|\bjest\b|\bpytest\b|\bgo\s+test\b|\bcargo\s+test\b|\bplaywright\s+test\b/,
  built: /\b(?:npm|pnpm|yarn|bun)\s+(?:run\s+)?build\b|\bnext\s+build\b|\bvite\s+build\b|\bcargo\s+build\b|\bgo\s+build\b|\btsc\b/,
  typechecked: /\btsc\b|\b(?:npm|pnpm|yarn)\s+(?:run\s+)?(?:typecheck|type-check|check|lint)\b|\bmypy\b|\bpyright\b/,
};

// What Claude might say, and which proof it needs.
const CLAIMS = [
  ["pushed", /\b(?:I(?:'ve| have)?\s+pushed|(?:changes?|commits?|branch|work|it)\s+(?:is|are|was|were|has been|have been)\s+pushed|pushed\s+(?:to|it|the|this|them|all|everything)|sudah\s+(?:di-?)?push)\b/i],
  ["committed", /\b(?:I(?:'ve| have)?\s+committed|(?:changes?|work|it)\s+(?:is|are|was|were|has been|have been)\s+committed|committed\s+(?:to|it|the|this|as))\b/i],
  ["tested", /\b(?:(?:all\s+)?(?:\d+\s+)?tests?\s+(?:all\s+)?(?:pass(?:es|ed)?|are\s+(?:passing|green)|(?:is|are)\s+green)|tests?\s+passing)\b/i],
  ["built", /\b(?:build\s+(?:is\s+|was\s+)?(?:clean|passes|passed|succeeds|succeeded|green|works)|builds?\s+(?:cleanly|successfully|fine)|npm run build\s+(?:is\s+)?clean)\b/i],
  ["typechecked", /\b(?:tsc\b[^.\n]{0,20}\b(?:clean|passes|passed|no errors)|type-?checks?\s+(?:is\s+)?(?:clean|pass(?:es|ed)?|succeed)|no\s+type\s+errors)\b/i],
];
const NEGATION = /\b(?:not|n't|never|haven't|hasn't|didn't|wasn't|weren't|won't|cannot|can't|couldn't|unable|before|until|once|after|if|when|belum|tidak|bukan|still need|need to|will|should|would|could|to be)\b[^.\n]{0,40}$/i;

function loadRules(dir) {
  const file = path.join(dir, "rules.json");
  let r = {};
  try { r = JSON.parse(fs.readFileSync(file, "utf8")); } catch { /* no repo rules */ }
  const rx = (list = []) => list.map((x) => [new RegExp(x.pattern, x.flags ?? "i"), x.reason, !!x.existingOnly]);
  const crx = (list = []) => list.map((x) => ({
    path: new RegExp(x.path, "i"), content: new RegExp(x.pattern, x.flags ?? "i"), reason: x.reason,
  }));
  return {
    name: r.name || "",
    bashAsk: [...BASE_BASH_ASK, ...rx(r.bashAsk)],
    bashDeny: [...BASE_BASH_DENY, ...rx(r.bashDeny)],
    pathAsk: [...BASE_PATH_ASK, ...rx(r.pathAsk)],
    pathDeny: rx(r.pathDeny),
    readAsk: [...BASE_READ_ASK, ...rx(r.readAsk)],
    contentDeny: crx(r.contentDeny),
    contentAsk: crx(r.contentAsk),
    // Commands the repo requires before Claude may say it is done.
    doneRequires: (r.doneRequires || []).map((x) => ({ re: new RegExp(x.pattern, x.flags ?? "i"), label: x.label })),
    proofs: { ...BASE_PROOFS, ...Object.fromEntries(Object.entries(r.proofs || {}).map(([k, v]) => [k, new RegExp(v, "i")])) },
  };
}

// ----------------------------------------------------------------- checks ---

const first = (list, s) => list.find(([re]) => re.test(s));

function relPath(p, cwd) {
  if (!p) return "";
  const abs = path.isAbsolute(p) ? p : path.join(cwd || ".", p);
  return path.relative(cwd || ".", abs).split(path.sep).join("/") || p;
}

function writtenText(tool, input) {
  if (tool === "Write") return input.content ?? "";
  if (tool === "Edit") return input.new_string ?? "";
  if (tool === "MultiEdit") return (input.edits || []).map((e) => e.new_string ?? "").join("\n");
  if (tool === "NotebookEdit") return input.new_source ?? "";
  return "";
}

// Returns {decision: "allow"|"ask"|"deny", reason}
export function checkTool(tool, input, rules, cwd) {
  input = input || {};
  if (tool === "Bash" || tool === "PowerShell") {
    const cmd = String(input.command ?? "");
    const d = first(rules.bashDeny, cmd);
    if (d) return { decision: "deny", reason: d[1] };
    const s = findSecret(cmd);
    if (s) return { decision: "deny", reason: `the command contains a ${s}; read it from the environment instead of pasting it` };
    const a = first(rules.bashAsk, cmd);
    if (a) return { decision: "ask", reason: a[1] };
    // Writing into the guard through the shell is still turning it off.
    if (/(?:>|\btee\b|\bsed\s+-i|\bmv\b|\brm\b|\bcp\b)[^|;&]*\.claude\/(?:settings|guard)/.test(cmd))
      return { decision: "ask", reason: "changes the guard that checks Claude" };
    return { decision: "allow" };
  }

  const file = input.file_path ?? input.notebook_path ?? input.path ?? "";
  const rel = relPath(file, cwd);

  if (tool === "Read" || tool === "Grep" || tool === "Glob") {
    const r = file && first(rules.readAsk, rel);
    return r ? { decision: "ask", reason: `reading ${rel}: ${r[1]}` } : { decision: "allow" };
  }

  if (["Write", "Edit", "MultiEdit", "NotebookEdit"].includes(tool)) {
    const text = writtenText(tool, input);
    const pd = first(rules.pathDeny, rel);
    if (pd) return { decision: "deny", reason: `${rel}: ${pd[1]}` };
    const s = findSecret(text);
    if (s) return { decision: "deny", reason: `writes a ${s} into ${rel}; keep secrets in the environment or a secrets manager` };
    for (const c of rules.contentDeny) {
      if (c.path.test(rel) && c.content.test(text)) return { decision: "deny", reason: `${rel}: ${c.reason}` };
    }
    for (const c of rules.contentAsk) {
      if (c.path.test(rel) && c.content.test(text)) return { decision: "ask", reason: `${rel}: ${c.reason}` };
    }
    const abs = path.isAbsolute(file) ? file : path.join(cwd || ".", file);
    const pa = rules.pathAsk.find(([re, , existingOnly]) => re.test(rel) && (!existingOnly || fs.existsSync(abs)));
    if (pa) return { decision: "ask", reason: `${rel}: ${pa[1]}` };
    const as = findAssignedSecret(text);
    if (as) return { decision: "ask", reason: `writes a literal value for "${as}" into ${rel}; is that a real secret?` };
    return { decision: "allow" };
  }

  // Web fetches and MCP tools: refuse to send a secret out.
  const s = findSecret(JSON.stringify(input));
  if (s) return { decision: "deny", reason: `sends a ${s} to ${tool}` };
  return { decision: "allow" };
}

export function checkPrompt(prompt) {
  const s = findSecret(prompt);
  return s
    ? { decision: "block", reason: `Your message contains a ${s}. It was not sent to Claude, because prompts are stored in transcripts. Put it in the environment's secrets and refer to it by name.` }
    : { decision: "allow" };
}

// Grounding: does what Claude said match what the ledger shows it did?
export function checkClaims(text, sessionEntries, rules) {
  if (!text) return [];
  const ran = sessionEntries.filter((e) => e.event === "PostToolUse" && e.tool === "Bash" && !e.failed);
  const did = (re) => ran.some((e) => re.test(e.command || ""));
  const problems = [];
  for (const [kind, re] of CLAIMS) {
    const g = new RegExp(re.source, "gi");
    let m;
    while ((m = g.exec(text))) {
      const before = text.slice(Math.max(0, m.index - 60), m.index);
      if (NEGATION.test(before)) continue;
      if (!did(rules.proofs[kind])) problems.push(`you said "${m[0].trim()}" but no successful ${kind === "pushed" ? "`git push`" : kind === "committed" ? "`git commit`" : kind + " command"} ran this session`);
      break;
    }
  }
  const saysDone = /\b(?:done|complete[d]?|finished|ready|all set|selesai|beres)\b/i.test(text) &&
    !/\b(?:not|n't|almost|nearly|once|when|until)\s+(?:yet\s+)?(?:done|complete|finished|ready)/i.test(text);
  const touchedCode = sessionEntries.some((e) => e.event === "PostToolUse" && ["Write", "Edit", "MultiEdit"].includes(e.tool));
  if (saysDone && touchedCode) {
    for (const r of rules.doneRequires) {
      if (!did(r.re)) problems.push(`this repo requires \`${r.label}\` before calling work done, and it has not run successfully this session`);
    }
  }
  return [...new Set(problems)];
}

// ----------------------------------------------------------------- ledger ---

function ledgerPath() { return process.env.CLAUDE_GUARD_LEDGER || path.join(HERE, "ledger.jsonl"); }

function append(entry) {
  try {
    fs.appendFileSync(ledgerPath(), JSON.stringify({ t: new Date().toISOString(), v: VERSION, ...entry }) + "\n");
  } catch { /* a read-only checkout must not break Claude */ }
}

function sessionEntries(sessionId) {
  try {
    return fs.readFileSync(ledgerPath(), "utf8").split("\n").filter(Boolean)
      .map((l) => { try { return JSON.parse(l); } catch { return null; } })
      .filter((e) => e && e.session === sessionId);
  } catch { return []; }
}

function summarize(tool, input) {
  input = input || {};
  if (tool === "Bash" || tool === "PowerShell") return { command: redact(input.command).slice(0, 2000) };
  const file = input.file_path ?? input.notebook_path ?? input.path;
  const out = {};
  if (file) out.file = file;
  if (input.url) out.url = redact(input.url).slice(0, 500);
  if (input.pattern) out.pattern = redact(input.pattern).slice(0, 200);
  if (!file && !input.url) out.input = redact(JSON.stringify(input)).slice(0, 500);
  return out;
}

function lastAssistantText(input) {
  if (typeof input.last_assistant_message === "string") return input.last_assistant_message;
  try {
    const lines = fs.readFileSync(input.transcript_path, "utf8").trim().split("\n");
    for (let i = lines.length - 1; i >= 0; i--) {
      const e = JSON.parse(lines[i]);
      if (e.type === "user" && typeof e.message?.content === "string") break; // the human spoke: stop there
      if (e.type !== "assistant") continue;
      const c = e.message?.content;
      const text = Array.isArray(c) ? c.filter((b) => b.type === "text").map((b) => b.text).join("\n") : String(c ?? "");
      if (text.trim()) return text;
    }
  } catch { /* no transcript */ }
  return "";
}

// ------------------------------------------------------------------- main ---

function out(obj) { process.stdout.write(JSON.stringify(obj)); }

export function handle(input, dir = HERE) {
  const rules = loadRules(dir);
  const ev = input.hook_event_name;
  const base = { session: input.session_id, event: ev };

  if (ev === "UserPromptSubmit") {
    const r = checkPrompt(input.prompt);
    append({ ...base, prompt: redact(input.prompt).slice(0, 1000), decision: r.decision, reason: r.reason });
    return r.decision === "block" ? { decision: "block", reason: r.reason } : null;
  }

  if (ev === "PreToolUse") {
    const r = checkTool(input.tool_name, input.tool_input, rules, input.cwd);
    append({ ...base, tool: input.tool_name, ...summarize(input.tool_name, input.tool_input), decision: r.decision, reason: r.reason });
    if (r.decision === "allow") return null; // leave normal permissions in charge
    return {
      hookSpecificOutput: {
        hookEventName: "PreToolUse",
        permissionDecision: r.decision,
        permissionDecisionReason: `Claude guard${rules.name ? ` (${rules.name})` : ""}: ${r.reason}.`,
      },
    };
  }

  if (ev === "PostToolUse" || ev === "PostToolUseFailure") {
    const resp = input.tool_response;
    const failed = ev === "PostToolUseFailure" ||
      (resp && typeof resp === "object" && (resp.interrupted === true || resp.is_error === true ||
        (typeof resp.exit_code === "number" && resp.exit_code !== 0) ||
        (typeof resp.exitCode === "number" && resp.exitCode !== 0)));
    append({ event: "PostToolUse", session: input.session_id, tool: input.tool_name, ...summarize(input.tool_name, input.tool_input), failed: !!failed });
    return null;
  }

  if (ev === "Stop" || ev === "SubagentStop") {
    if (input.stop_hook_active) { append({ ...base, decision: "allow", reason: "already sent back once" }); return null; }
    const problems = checkClaims(lastAssistantText(input), sessionEntries(input.session_id), rules);
    append({ ...base, decision: problems.length ? "block" : "allow", reason: problems.join("; ") || undefined });
    if (!problems.length) return null;
    return {
      decision: "block",
      reason: `Claude guard — claim not backed by the ledger: ${problems.join("; ")}. Run the command now and report its real result, or correct what you told the user.`,
    };
  }

  append({ ...base });
  return null;
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === path.resolve(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1"));
if (isMain) {
  let raw = "";
  process.stdin.setEncoding("utf8");
  process.stdin.on("data", (c) => (raw += c));
  process.stdin.on("end", () => {
    let input;
    try { input = JSON.parse(raw || "{}"); } catch { process.exit(0); }
    try {
      const res = handle(input);
      if (res) out(res);
    } catch (e) {
      // Never wedge a session on a guard bug: log it and let normal permissions decide.
      append({ session: input?.session_id, event: "guard-error", error: String(e?.stack || e).slice(0, 1000) });
    }
    process.exit(0);
  });
}
