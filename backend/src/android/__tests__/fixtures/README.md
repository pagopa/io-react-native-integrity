# Test fixtures

- `allowed_signers`, `attestation*.json` and `attestation*.json.sig` mimic the GrapheneOS
  [attestation keys list](https://grapheneos.org/articles/attestation-compatibility-guide).
  They are signed with a throwaway test key with `ssh-keygen -Y sign -n "attestation keys"`,
  whose private key has been discarded. Do not reformat these files, otherwise the signatures become invalid.
- `google-caiman-tee-ec-rkp.pem` and `google-tegu-sb-ec-2026-root.pem` are real key attestation chains
  rooted at the Google Hardware Attestation RSA root and at the "Key Attestation CA1" ECDSA root.
  They are copied from the `testdata` of the [Android Key Attestation Verifier](https://github.com/android/keyattestation)
  (`caiman/sdk36/TEE_EC_RKP.pem` and `tegu/sdk36/SB_EC_2026_ROOT.pem`), Copyright Google LLC,
  licensed under the Apache License 2.0.
