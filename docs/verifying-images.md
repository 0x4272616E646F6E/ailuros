# Verifying images
Release images on `ghcr.io/0x4272616E646F6E/ailuros` are built by
`.github/workflows/release.yml`: pushed by digest, scanned with Grype and
given an SPDX SBOM per platform (linux/amd64 and linux/arm64), signed
keylessly with cosign, and given SLSA build provenance. Only then do the
version tags move to them, so an image that is not signed by that workflow
is not a release. A release `vX.Y.Z` is tagged `X.Y.Z` and `X.Y` (no `v`, and
no `latest`); `<version>` below is `X.Y.Z`. Verify the signature:

```bash
cosign verify ghcr.io/0x4272616E646F6E/ailuros:<version> \
  --certificate-identity-regexp '^https://github\.com/0x4272616E646F6E/ailuros/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

a platform's SBOM, attached to that platform's image (find the digests with
`docker buildx imagetools inspect ghcr.io/0x4272616E646F6E/ailuros:<version>`):

```bash
cosign verify-attestation --type spdxjson ghcr.io/0x4272616E646F6E/ailuros@<linux/amd64 or linux/arm64 digest> \
  --certificate-identity-regexp '^https://github\.com/0x4272616E646F6E/ailuros/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

and the build provenance:

```bash
gh attestation verify oci://ghcr.io/0x4272616E646F6E/ailuros:<version> \
  --repo 0x4272616E646F6E/ailuros --signer-workflow 0x4272616E646F6E/ailuros/.github/workflows/release.yml
```
