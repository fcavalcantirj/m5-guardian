/**
 * The M5 Guardian release-signing PUBLIC key (ECDSA P-256 over SHA-256, DER signatures): a copy of
 * release/release-public-key.json (G26), whose private half signs every release manifest
 * (tools/release_publish.sh). The install page serves a release only when its manifest.sig verifies with this key.
 * lib/firmware-release.test.ts compares this copy with the repository file and the fingerprint.
 */
export const RELEASE_PUBLIC_KEY_PEM = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEWr8dES3PNVwl6qW1SNSTlTaHpitj
bJXxitKaIAMJ/TtT2xNE4FfqvPlJAFrDqMREs3qGt+R3Y0E8TFEXUGMX4A==
-----END PUBLIC KEY-----
`;

/** SHA-256 of the key's DER SubjectPublicKeyInfo (spki_der_sha256 in release/release-public-key.json). */
export const RELEASE_PUBLIC_KEY_SHA256 = "070fda9b871a87bb7d45295016b1cfce5bb579957623fb121ce6c7af302ca17b";
