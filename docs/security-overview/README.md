# Aegis Sentinel technical overview

[`AEGIS_SENTINEL_TECHNICAL_OVERVIEW.pdf`](AEGIS_SENTINEL_TECHNICAL_OVERVIEW.pdf) explains the
system from end to end for a security engineer who is new to the repository: purpose and
limits, input formats, interfaces, architecture, two traced file journeys, every detection
layer, scoring, completeness and failure handling, external services and privacy,
protection and delivery, deployments and trust boundaries, and the evidence behind each
claim. It is the public, repository-safe edition: technical content only.

## Baseline

| Item | Value |
|---|---|
| Document date | 2026-11-19 |
| Code baseline | `d45715a` (last application-code commit) |
| Reviewed tree | `e012d3f`, branch `review/production-hardening` (local, not pushed) |
| Engine / schema / registry | 4.8.0 / 1.4 / 2026.10.23-1 |

## Limitations

- **Implemented is not verified.** The document labels each statement: implemented, tested
  locally (one macOS arm64 host), verified in CI (last on `3e5a3f2`, 164 commits older),
  not verified, optional, proposed. Docker, Kubernetes, Linux, Windows, real external
  services and real samples were not exercised for this document.
- No detection or false-positive rate exists; the document makes no such claim.
- The test numbers quoted (2,161 passed at `d45715a`) come from the last recorded run
  (`docs/HANDOFF.md`); this documentation task did not re-run the suite.
- The Graphify page in `docs/architecture/` is an older snapshot; the diagrams were checked
  against the code itself (see [DIAGRAM_REVIEW](DIAGRAM_REVIEW.md)).

## Files

| Path | What it is |
|---|---|
| `src/*.md` | the editable text, one file per chapter; `src/meta.json` the cover |
| `src/facts.json` | numbers the text quotes as `{{fact:name}}`, read from the code by `facts.py` |
| `facts.py` | reads those numbers from the code (clean environment, temporary HOME, no network) |
| `build_overview.py` | the build: facts check, diagram build, Markdown to HTML, PDF via headless Chrome, checks |
| `style.css` | the print stylesheet (A4, landscape pages for wide tables and diagrams) |
| [`DIAGRAM_REVIEW.md`](DIAGRAM_REVIEW.md) | what was checked and corrected in each architecture diagram |
| `../architecture/uml-diagram-sources/` | the eleven diagram definitions and their SVG output |

## Build

```sh
.venv/bin/python docs/security-overview/build_overview.py
```

Requirements: the repository's virtual environment (Python 3.9+, `pypdf`, `markdown-it-py`:
`pip install markdown-it-py` if missing) and Google Chrome or Chromium 131 or later (page
margin boxes and named pages); set `CHROME=/path/to/chrome` if it is not in a standard
location. Nothing is downloaded and no network is used.

The build:

1. runs `facts.py` and stops if any quoted value differs from `src/facts.json`. After a
   reviewed change, update the text that cites the value and run
   `.venv/bin/python docs/security-overview/facts.py --write`;
2. rebuilds the diagrams (`build_diagrams.py`), which stops on a layout problem;
3. renders `src/*.md` in file-name order; diagrams are inlined as SVG (vector, searchable),
   and drawings taller than a landscape page are split where the cut crosses the fewest boxes;
4. prints twice with headless Chrome: the first print finds the page of every chapter and
   section, the second fills them into the contents; Chrome writes the bookmarks and links;
5. checks the PDF with pypdf: text on every page, bookmarks, links, no leftover markers or
   placeholders.

Options: `--check-only` (facts and diagrams), `--skip-diagrams`, `--keep-html PATH`,
`--allow-drift` (draft builds only). `--extension DIR --diagram-dir DIR --meta FILE` build a
separately kept edition with extra chapters; such an edition must be written outside the
repository and the script refuses an output path inside it.

Markdown conventions: `[[impl]]`, `[[local]]`, `[[ci]]`, `[[pending]]`, `[[optional]]`,
`[[proposed]]` produce status labels; `@diagram file.svg | caption | landscape` inlines a
diagram; `@landscape` ... `@endlandscape` puts content on landscape pages; `@note warn | text`
is a call-out.
