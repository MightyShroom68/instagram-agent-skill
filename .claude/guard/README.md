# Claude guard — the AI that checks the AI

A set of Claude Code hooks that watches every Claude session in this repository.
It applies the four checks the open-source AiSOC project
([beenuar/AiSOC](https://github.com/beenuar/AiSOC)) applies to its own AI agents,
in a form that needs no server, no database and no dependencies: one Node script.

This is documentation for whoever changes the code, so it is in English.

| Check | What happens |
|---|---|
| **1. Ledger** | Every prompt, every tool call, and every decision the guard made is appended to `.claude/guard/ledger.jsonl`, with secrets redacted. Refusals are written too, not only the actions that went through. The file is git-ignored: it stays on the machine where Claude ran. |
| **2. Secrets** | A recognisable key (GitHub, AWS, Anthropic, OpenAI, OpenRouter, Google, Slack, Stripe, Telegram, Discord, JWT, private keys, database URLs with a password) is **refused** before it reaches the model, a file, a shell command, a web fetch or an MCP tool. A literal value assigned to something called `password`/`secret`/`api_key` **asks** first. |
| **3. Grounding** | When Claude finishes a turn and says "I've pushed", "tests pass", "build is clean" or "tsc is clean", the guard looks in the ledger for the command that proves it, and requires that command to have succeeded. If it isn't there, Claude is sent back once to run it or correct the claim. If the repo lists required checks (`doneRequires`), Claude cannot call changed code "done" without them. |
| **4. Approval** | Risky actions **wait for a human**: force-push, pushing to `main`, `reset --hard`, `clean -f`, `rm -rf`, `DROP`/`TRUNCATE`/`DELETE` without `WHERE`, `curl … \| sh`, `npm publish`, `sudo`, printing `.env`, `--no-verify`, editing CI workflows, and **editing this guard**. A few are refused outright (`rm -rf /`, `rm -rf ~`, `mkfs`, fork bombs). |

## Files

| File | Same in every repo? | Purpose |
|---|---|---|
| `.claude/settings.json` | yes | Wires the hooks (`UserPromptSubmit`, `PreToolUse`, `PostToolUse`, `PostToolUseFailure`, `Stop`, `SubagentStop`) to the script. |
| `.claude/guard/guard.mjs` | yes | The guard. |
| `.claude/guard/test.mjs` | yes | Tests: `node --test .claude/guard/test.mjs` |
| `.claude/guard/rules.json` | **no** | This repo's own rules, added on top of the base rules, with their own test cases. |
| `.claude/guard/ledger.jsonl` | — | The record. Git-ignored. |

## This repo's rules

`rules.json` keys, all optional. Every `pattern` is a JavaScript regex (case-insensitive unless `flags` says otherwise). File paths are matched relative to the repo root.

- `name` — shown in every message the guard gives.
- `bashDeny`, `bashAsk` — shell commands to refuse or to hold for approval.
- `pathDeny`, `pathAsk` — files Claude may not write, or must ask before writing. `existingOnly: true` asks only when the file already exists (for example, a migration that may have run in production).
- `readAsk` — files Claude must ask before reading.
- `contentDeny`, `contentAsk` — `{path, pattern, reason}`: text that may not be written into matching files.
- `doneRequires` — `{pattern, label}`: commands that must have run successfully before Claude says changed code is done.
- `proofs` — override the command that proves a claim (`pushed`, `committed`, `tested`, `built`, `typechecked`).
- `tests` — `{tool, input, expect}` examples; `test.mjs` checks each one gives `allow`, `ask` or `deny`.

## What it does not do

- **It is a seatbelt, not a lock.** It reads commands as text. Someone determined to get around it (or a model told to) can split a string or encode it. It catches mistakes and the obvious cases; it is not a sandbox.
- **It only runs where Claude Code reads `.claude/settings.json`**: Claude Code in the terminal, the desktop app, and claude.ai/code sessions on this repo. It does not watch other AI tools, and it does not run inside the app itself.
- **If `node` is not installed, the hooks fail open** (Claude Code treats a hook that cannot start as a non-blocking error). claude.ai/code cloud sessions have Node. On your own computer, install Node (nodejs.org) if `node --version` says it is missing.
- **Grounding reads words, not meaning.** It recognises the common ways of saying "pushed / tests pass / build clean / done" in English and a few in Indonesian. It skips sentences that say something has *not* happened yet. It sends Claude back at most once per turn, so a false alarm costs one extra step, not a loop.
- An "ask" in a session nobody is watching waits until someone answers.

## Updating

`guard.mjs`, `test.mjs` and `settings.json` are identical in every repository that has the guard. Change them in one place, run the tests, then copy the three files to the others. Keep `rules.json` per repo. Editing any of these files asks for approval. That is intended: an AI that can quietly turn off its own checker is not being checked.
