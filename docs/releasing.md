# Releasing

A release is a `vX.Y.Z` tag on a commit on `main`. `.github/workflows/release.yml`
then runs the unit tests, builds the multi-arch image, scans it, signs it and
attaches SBOMs and provenance before moving the version tags to it (see
[Verifying images](verifying-images.md)).

1. Move the `Unreleased` entries in `CHANGELOG.md` under the new version and
   date, and merge that to `main`.
2. Tag the merged commit and push the tag:
   `git tag -a vX.Y.Z -m vX.Y.Z && git push origin vX.Y.Z`.
3. Check the `release` run, then verify the published image as described in
   [Verifying images](verifying-images.md).

## Before the first release
These are repository settings, not files, so CI cannot set them:

1. **Private vulnerability reporting** (Settings → Code security): `SECURITY.md` points reporters there.
2. **Secret scanning with push protection** (Settings → Code security).
3. **A ruleset for `main`**: require pull requests with one approval and review from Code Owners (`.github/CODEOWNERS`; with a single maintainer, allow the repository admin to bypass), and require these status checks, which are named after the jobs: `lint`, `test`, `build`, `validate`, `integration`, `codeql (go)`, `codeql (actions)`, `govulncheck`, `gitleaks`, `zizmor`. (`dependency-review` runs only on pull requests, so do not require it on pushes.)
4. **A tag ruleset for `v*`**: only maintainers may create release tags; the release workflow also refuses tags that are not on `main`.
5. **After the first release, make the GHCR package public** (Packages → ailuros → Package settings): new organisation packages start private, and the [verification commands](verifying-images.md) fail for others until it is public.
6. **After a few runs**, switch Harden-Runner in `release.yml` from `egress-policy: audit` to `block` with the endpoints the audit logs show.
