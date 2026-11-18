# Release notes: httpsign v0.6.3 (draft)

Draft for the next release after v0.6.2. Update when cutting the tag.

---

## Summary

Derived-component normalization fixes for RFC 9421, plus custom signature-parameter and HMAC key-length updates. Sign and verify use the same derived-component rules, so pairs that upgrade together stay consistent.

### `@authority` normalization (RFC 9421 §2.2.3)

Hostname is lowercased; default port is omitted (`443` for `https`, `80` for `http`). See [#44](https://github.com/yaronf/httpsign/pull/44).

### `@request-target` / `@path` encoding (RFC 9421 §2.2.5–2.2.6)

`@request-target` keeps percent-encoded path octets (`EscapedPath`) and a trailing empty query delimiter (`ForceQuery`). Empty `@path` normalizes to `/`. See [#43](https://github.com/yaronf/httpsign/pull/43).

### `@scheme` lowercase (RFC 9421 §2.2.4)

`@scheme` is lowercased before it enters the signature base, including values from `WithScheme` / `SetSchemeFromRequest`. See [#45](https://github.com/yaronf/httpsign/issues/45) / [#46](https://github.com/yaronf/httpsign/pull/46).

### `[]byte` custom signature parameters

`AddCustomParam` accepts `[]byte` values and serializes them as RFC 8941 Byte Sequences. `MessageDetails.CustomParams` may contain `[]byte` after parsing. See [#48](https://github.com/yaronf/httpsign/pull/48).

### HMAC-SHA256 minimum key length

`NewHMACSHA256Signer` / `NewHMACSHA256Verifier` now require at least **32** bytes (was 64), matching the SHA-256 output length `L` in [RFC 2104 §3](https://www.rfc-editor.org/rfc/rfc2104.html#section-3). See [#48](https://github.com/yaronf/httpsign/pull/48).

### Upgrade notes / behavioral change

**HMAC keys:** keys of 32–63 bytes that were previously rejected at construction are now accepted. Keys shorter than 32 bytes are still rejected.

**Cross-version mismatch (derived components):** if one peer still emits a non-normalized component and the other verifies with this release, signatures that cover that component will fail. Examples:

| Component | Old value (example) | This release |
|-----------|---------------------|--------------|
| `@authority` | `EXAMPLE.com:443` | `example.com` |
| `@request-target` | `/a/b` from `/a%2Fb` | `/a%2Fb` |
| `@request-target` | `/path` from `/path?` | `/path?` |
| `@path` | empty string | `/` |
| `@scheme` | `HTTPS` | `https` |

Align both peers on a build that includes these changes, or ensure inputs are already RFC-normalized before signing.

Values that were already compliant are unaffected.
