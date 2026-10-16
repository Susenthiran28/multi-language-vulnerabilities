# Git-history secret fixtures

`sdlc/scan/secret/history.go` scans commit history, not just the working tree. That
path cannot be exercised by checked-in files alone — a secret has to exist in an
*older* commit and be absent from `HEAD`.

Checking such a commit into this repository would plant a credential-shaped string
in Vigilnz's own history permanently, which is exactly what the scanner is meant to
flag. So the fixture is a generator instead: it builds a throwaway repository
outside the project tree.

## Usage

```bash
bash make-history-fixture.sh /tmp/secret-history-fixture
```

The script creates a repo whose history looks like this:

| Commit | Working tree | What the scanner should see |
|---|---|---|
| 1 | `config.js` with an AWS key and a GitHub PAT | secret present |
| 2 | key replaced by `process.env.*` | secret gone from HEAD, still in history |
| 3 | `.env` added with a Stripe key | secret present |
| 4 | `.env` deleted | file absent from HEAD, still in history |

A working-tree-only scan should report **zero** findings. A history scan should
report **four**: two from commit 1, two from commits 3 and 4.

Delete the directory when you are done — it is disposable.
