# Local PR Tools (Gitea / GitHub + Ollama)

Two tools that run fully on your Mac, so no code leaves the machine. They use only the Python standard library (no pip installs).

- **`review_pr.py`**: paste a PR link and get a risk report grouped as **Critical / High / Medium**.
- **`describe_pr.py`**: drafts a PR description (title, summary, changes, how to test, risks) ready to paste.

## One-time setup

1. Install Ollama and download the model (about 4.7 GB; needs disk space):
   ```bash
   brew install ollama
   brew services start ollama
   ollama pull qwen2.5-coder:7b
   ```
2. Create a Gitea token: Gitea → **Settings → Applications → Generate New Token**,
   with **read** permission on *repository* (and *user* if your Gitea version asks).
3. Add the token to your shell (put this line in `~/.zshrc` to keep it):
   ```bash
   export GITEA_TOKEN=paste_your_token_here
   ```
4. Optional, for GitHub: create a token at GitHub → **Settings → Developer settings →
   Fine-grained tokens**, with read-only *Contents* and *Pull requests* access.
   Public repos work without it (limited to 60 requests/hour).
   ```bash
   export GITHUB_TOKEN=paste_your_github_token_here
   ```

## Usage

```bash
python3 review_pr.py https://<gitea-host>/<owner>/<repo>/pulls/42     # Gitea
python3 review_pr.py https://github.com/<owner>/<repo>/pull/42        # GitHub
```

The server type is detected from the link: Gitea links use `/pulls/`, GitHub links use `/pull/`
(GitHub Enterprise hosts work too). If detection is ever wrong, add `--platform gitea` or `--platform github`.

A text summary prints in the terminal, and an HTML report is saved as `review-<owner>-<repo>-pr42.html`
and opened in your browser. The HTML report has severity counts, a merge verdict, filters, a search box
and the code around each finding with the flagged line highlighted. It works offline and follows the
system light/dark theme. Reports are git-ignored because they quote internal code.

| Option | What it does |
|---|---|
| `--no-open` | Save the HTML report without opening the browser |
| `--out report.md` | Save the plain-text report instead (`.md` or `.txt`); `--out x.html` picks the HTML file name |
| `--insecure` | Use if the server has an internal/self-signed SSL certificate |
| `--dry-run` | List files that would be reviewed/skipped, without running the model |
| `--min-confidence low` | Show more findings (more false positives); default is `medium` |
| `--model qwen2.5-coder:14b` | Use a different Ollama model |
| `--ctx 8192` | Smaller context: faster and less memory; larger diffs get split more |
| `--diff-file x.diff` | Review a local diff (e.g. `git diff main > x.diff`) instead of a PR |

## PR description writer

```bash
python3 describe_pr.py https://<gitea-host>/<owner>/<repo>/pulls/42    # existing Gitea PR
python3 describe_pr.py https://github.com/<owner>/<repo>/pull/42       # existing GitHub PR
python3 describe_pr.py --base main                                    # your current branch, BEFORE opening the PR
python3 describe_pr.py --base develop --repo ~/code/game-server       # a repo in another folder
```

It summarizes each changed file (small files are batched together), then writes one description from those
summaries plus the commit messages and any description the author already wrote. You get:

- `description-<...>.html`, opened in your browser, with a preview and **Copy title** / **Copy Markdown** buttons
- `description-<...>.md`, the same text as a file

Paste it into the PR on Gitea or GitHub and **edit it before posting**. Nothing is posted automatically.

What it does to stay accurate with a small model:
- Asks for literal "what changed" summaries and forbids made-up reasons ("for security", "fixes a leak").
- Ticket IDs like `GAME-142` are taken from the branch name, title and commits and kept in the title.
- Command-line options are read from the added code, and any bullet that mentions an option that is not
  in the code (a common small-model mistake) is removed, with a note in the terminal.
- Unity assets, lock files and binaries are not sent to the model; they are listed as counts instead.

Options: `--no-open`, `--out name.html`, `--model`, `--ctx`, `--insecure`, `--platform`, `--diff-file`
(same meaning as for `review_pr.py`). Expect about 30–90 s for a typical PR on an M1.

## Good to know (M1, 16 GB)

- Speed: roughly 20–60 s per file on an M1. A 15-file PR takes several minutes.
  Close heavy apps (Unity, Chrome tabs) while it runs.
- Lock files, Unity `.meta/.prefab/.asset`, images, binaries, `build/`, `dist/`, `node_modules/`
  and deleted files are skipped automatically (see `SKIP_PATTERNS` in the script).
- Review rules per language are in `LANG_RULES`. Add your team's own rules there.
- It's a first pass: a 7B model will miss some issues and sometimes flag false ones.
  You still do the real review and the manual merge.

## Regression tests

`tests/` has two diffs with planted bugs. Re-run them after changing prompts or the model:

```bash
python3 review_pr.py --diff-file tests/sample1.diff
python3 review_pr.py --diff-file tests/sample2.diff
```

Expected with `qwen2.5-coder:7b`: sample1 → 2 Critical (buffer overflow, XSS).
sample2 → Critical: use-after-free, SQL injection, hardcoded key; Medium: 2 Unity `Update` perf issues.
Known false positive: `Banner.ts` (fixed-string `innerHTML` + `textContent`) is wrongly reported as XSS.
