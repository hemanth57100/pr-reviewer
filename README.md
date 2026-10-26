# Local PR Reviewer (Gitea / GitHub + Ollama)

Paste a Gitea or GitHub PR link and get a risk report grouped as **Critical / High / Medium**.
It runs fully on your Mac, so no code leaves the machine, and it uses only the Python standard library (no pip installs).

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

The report prints in the terminal and is also saved as `review-<owner>-<repo>-pr42.md`.

| Option | What it does |
|---|---|
| `--insecure` | Use if the server has an internal/self-signed SSL certificate |
| `--dry-run` | List files that would be reviewed/skipped, without running the model |
| `--min-confidence low` | Show more findings (more false positives); default is `medium` |
| `--model qwen2.5-coder:14b` | Use a different Ollama model |
| `--ctx 8192` | Smaller context: faster and less memory; larger diffs get split more |
| `--diff-file x.diff` | Review a local diff (e.g. `git diff main > x.diff`) instead of a PR |

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
