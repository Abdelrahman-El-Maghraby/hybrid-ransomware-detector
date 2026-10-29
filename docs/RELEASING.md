# Releasing Aegis Sentinel

For the owner. Releases are made by pushing a tag; nothing is published from a
branch.

## 1. Before the tag

1. `integration/v4.8` (or the release branch) is merged into `main` through a pull
   request with every check green: `tests`, `quality`, `docker`. The release
   workflow enforces this for the tagged commit itself: its `gate` job stops the
   release unless each of the three workflows has a successful run for exactly
   that commit (the push to `main` after the merge runs all three). Tag a
   commit only after those runs have finished.
2. `ENGINE_VERSION` in `engine/config.py`, `version` in `pyproject.toml` and the
   `CHANGELOG.md` heading say the same version.
3. The readiness matrix (`docs/RELEASE_READINESS.md`) has no open blocker for this
   release.

## 2. Tag

```bash
git switch main && git pull
git tag -a v4.7.0 -m "Aegis Sentinel 4.7.0"
git push origin v4.7.0
```

A tag with a suffix (`v4.7.0-rc1`) becomes a pre-release. `release.yml` then:

| Job | Produces |
|---|---|
| `gate` | nothing: it fails the release when `tests`, `quality` or `docker` has no successful run for the tagged commit |
| `build` (Windows, macOS, Linux) | `hrd-scanner-<version>-<os>-<arch>.zip` / `.tar.gz`, smoke-tested by `build.py` (fails when a required layer is missing), and `<same name>.cdx.json`: the SBOM of the environment that build packaged |
| `image` | `aegis-sentinel-server-<version>-linux-amd64.tar.gz` (the server and proxy images, after `deploy/check-deployment.sh` passed on them), its `.cdx.json` (Python packages) and `.debian-packages.txt` |
| `publish` | `SHA256SUMS`, a keyless Sigstore signature (`*.sigstore.json`) for every file, and the GitHub release |

## 3. Verify what was published

```bash
sha256sum -c SHA256SUMS
python -m pip install sigstore
python -m sigstore verify github aegis-sentinel-server-4.7.0-linux-amd64.tar.gz \
  --cert-identity https://github.com/Abdelrahman-El-Maghraby/hybrid-ransomware-detector/.github/workflows/release.yml@refs/tags/v4.7.0
```

A customer installs the images offline with:

```bash
docker load -i aegis-sentinel-server-4.7.0-linux-amd64.tar.gz
AEGIS_VERSION=4.7.0 docker compose up -d --no-build --wait
```

## 4. Code signing and notarisation (needs certificates: X2)

The desktop binaries are **unsigned** until the certificates exist. Sigstore
proves where a file came from; it does not change what Windows or macOS show.

* **Windows (Authenticode).** Needs a code-signing certificate from a CA, which
  today is issued on a hardware token or a cloud HSM. Sign `hrd-scanner.exe` (and
  the GUI executable) with `signtool sign /fd SHA256 /tr <RFC 3161 timestamp URL>
  /td SHA256 ...` before zipping, then `signtool verify /pa`. A newly signed
  publisher still builds SmartScreen reputation over time: signing reduces the
  warning; it does not guarantee that none is shown.
* **macOS (Developer ID + notarisation).** Needs an Apple Developer ID Application
  certificate. Sign with the hardened runtime (`codesign --options runtime
  --timestamp`), submit with `xcrun notarytool submit --wait`, then `xcrun stapler
  staple` the app. Gatekeeper then opens it without the `xattr` step in the README.
* In CI both steps go into the `build` job, before `package`, with the certificate
  in an encrypted secret or a signing service, and only on tags.

## 5. Notes for 4.7.0

Carry into the release notes:

* The start-up "Detection layers" line of the 4.6.0 binaries did not list `pe:on`
  (cosmetic; the layer ran). Fixed in the next release (PR #21).
