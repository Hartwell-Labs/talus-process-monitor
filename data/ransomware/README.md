# Ransomware knowledge base

`knowledge.ext` is the canonical database, written in
[Externum](https://github.com/Hartwell-Labs/externum). It stores one entry per
ransomware family: aliases, operating model, first-seen year, status,
platforms, family-specific file extensions, ransom notes, initial access,
MITRE ATT&CK techniques, targets, extortion model, description and references.

Two artifacts are generated:

- `knowledge.markers` — sorted, one extension per line, only the data the
detector needs. Talus embeds this tiny file with `include_str!` and binary-
searches it using only `std`.
- `knowledge.notes` — distinctive ransom-note basenames, lowercased and sorted.
Generic names such as `README.txt` are excluded. Talus embeds this too.
- `knowledge.json` — the full database for analysts and tools. It is **not**
embedded in the binary.

Generated artifacts are deterministic. Deployed agents do not need an Externum
runtime.

## Regenerate

```bash
./data/ransomware/generate.sh
```

The script requires `externum` on `PATH` (or set `EXTERNUM=/path/to/externum`).
Commit the `.ext` source and all regenerated artifacts (`.json`, `.markers`,
`.notes`).

## Adding a family

1. Add a `F_<ID>: Any = { ... }` block in `knowledge.ext`.
2. Append `F_<ID>` to the `FAMILIES` list.
3. Regenerate both artifacts.
4. Run `cargo test` and `cargo clippy --all-targets -- -D warnings`.

Leave `extensions` empty when no stable family-specific marker is known —
Hunters and BadRabbit already lost `.locked` and `.encrypted` this way. This
table is the only marker list the detector consults; behavioural scoring
(burst rate, destructive activity, ransom notes) still applies, and a guessed
or generic extension such as `.enc`, `.vmdk` or `.locked` only creates false
positives on backups, encryption jobs and VM hosts.
