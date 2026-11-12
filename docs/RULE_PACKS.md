# Rule packs: publishing, rollback, key rotation and compromise recovery

Detection content (YARA rules, fuzzy signatures) updates without a new program
release through signed rule packs (`core/rulepack.py`, `tools/rulepack.py`).

## What an install checks

`--update-rules PACK` (in Docker: `docker compose run --rm -v "$PWD/packs:/import:ro"
content --update-rules /import/PACK`) installs a pack only when:

* its Ed25519 signature (`PACK.sig`) verifies against a key in
  `RULEPACK_PUBLIC_KEYS` - keys come from configuration, never from the pack;
* every file is listed in the manifest with a matching SHA-256, and every entry
  is a plain file under `rules/` or the fuzzy-signature file;
* its version is **newer** than the active pack. An older pack, or the same pack
  again, is always refused, so an old pack whose rules are known to be bypassed
  cannot be replayed. `--allow-downgrade` is refused since 4.7;
* the rules compile, and the engine is new enough.

`active.json` records the version, the key that signed it (`signer`, a key
fingerprint) and, for a rollback, `rollback_of`. Every scan result names the rules
version and their SHA-256 in `provenance.rules`, and a running scanner reloads a
changed pack before its next scan.

## Publishing

```bash
python tools/rulepack.py keygen ~/aegis-keys                 # once; keep the .pem offline
python tools/rulepack.py build rules/ --version 2026.11.02 --out aegis-rules-2026.11.02.tar.gz
python tools/rulepack.py sign aegis-rules-2026.11.02.tar.gz --key ~/aegis-keys/rulepack_private.pem
python tools/rulepack.py verify aegis-rules-2026.11.02.tar.gz --pub "$(cat ~/aegis-keys/rulepack_public.txt)"
```

Versions are compared numerically, part by part (`2026.11.10` is newer than
`2026.11.9`); a scheme such as `YYYY.MM.DD[.N]` keeps them in date order.
A version (and a rollback's `rollback_of`) must be purely numeric: one to six
dot-separated groups of digits. It names the install folder, so `build`,
`rollback`, `verify` and every install refuse anything else, even when the pack
is validly signed.

## Rolling back a defective pack (signed rollback)

A rollback is a new pack, not older content: the previous good rules re-issued
under a higher version, signed like any pack.

```bash
python tools/rulepack.py rollback aegis-rules-2026.11.02.tar.gz --version 2026.11.04 \
       --out aegis-rules-2026.11.04.tar.gz --pub "$(cat ~/aegis-keys/rulepack_public.txt)"
python tools/rulepack.py sign aegis-rules-2026.11.04.tar.gz --key ~/aegis-keys/rulepack_private.pem
```

The manifest carries `rollback_of: 2026.11.02`; installs accept it because
2026.11.04 is newer than the defective 2026.11.03.

## No key configured (M27)

A pack is used only while the key that signed it is configured. With
`RULEPACK_PUBLIC_KEYS` empty, an installed pack that records its signer (every
pack installed since 4.7) is **not used**: the scanner logs `rulepack_no_key`
each time it loads its rules and falls back to the bundled ones, and `provenance.rules` no
longer names the pack. Nothing is deleted; setting the key again (and
restarting) puts the pack back in use. Packs installed before 4.7 recorded no
signer and stay in use.

Deployment impact: an installation that used a pack but has lost or never kept
its key (for example a Docker host whose `.env` lacks `RULEPACK_PUBLIC_KEYS`, or
an upgraded desktop whose key was only set in an old shell) now scans with the
bundled rules until the key is configured. After upgrading, check the log for
`rulepack_no_key` or check `provenance.rules` in a recent result.

## Rotating the signing key

1. Generate the new key pair; keep the private key offline.
2. Customers set `RULEPACK_PUBLIC_KEYS=<old>,<new>` (any listed key may sign).
3. Sign the next packs with the new key only.
4. Once every customer has installed a pack signed by the new key, they remove the
   old key. Packs signed by a removed key are no longer used (next point).

## Recovering from a compromised signing key

An attacker with the private key can sign a pack with malicious rules or with an
enormous version (`9999.1`) so that no later pack is "newer".

1. **Customers remove the compromised key** from `RULEPACK_PUBLIC_KEYS` and restart
   the scanner. A pack signed by a key that is no longer trusted is not used: the
   scanner falls back to the bundled rules at once (`rulepack_untrusted` in the
   log), and such a pack does not count as "installed" when checking versions.
   This also holds when no key is left: since M27, a pack that records its signer is
   not used while `RULEPACK_PUBLIC_KEYS` is empty (`rulepack_no_key` in the log),
   and the bundled rules are used instead. Add the new key (step 2) in the same
   change so the next pack can be installed. In Docker, set the keys in the `.env`
   next to `docker-compose.yml`; compose passes them to `analysis` and `content`.
2. **Publish a pack signed by a new key**, add that key to the customers'
   configuration, and they install it with `--update-rules`. From then on versions
   are monotonic again, against the new pack.
3. Check the rules version and hash in recent results (`provenance.rules`) to see
   which scans ran with the compromised content.

Packs installed before 4.7 did not record their signer; they stay in use until the
next install. After a compromise, install a pack signed by the new key so that the
active pack has a recorded signer.
