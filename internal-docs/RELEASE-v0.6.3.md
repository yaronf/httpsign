# Release notes: httpsign v0.6.3

Ready to cut as tag `v0.6.3` after [#43](https://github.com/yaronf/httpsign/pull/43) merges.

---

## Summary

RFC 9421 derived-component normalization, `[]byte` custom signature parameters, and a corrected HMAC-SHA256 key-length floor. Sign and verify apply the same derived-component rules, so peers that upgrade together stay consistent.

### `@authority` normalization (RFC 9421 §2.2.3) — [#44](https://github.com/yaronf/httpsign/pull/44)

Hostname is lowercased; default port is omitted (`443` for `https`, `80` for `http`). IPv6 (including IPv4-mapped and zone IDs) is bracketed like `net.JoinHostPort` when the port is dropped.

### `@request-target` / `@path` encoding (RFC 9421 §2.2.5–2.2.6) — [#43](https://github.com/yaronf/httpsign/pull/43)

`@request-target` keeps percent-encoded path octets (`EscapedPath`) and a trailing empty query delimiter (`ForceQuery`). Empty `@path` and empty request-target path normalize to `/`.

### `@scheme` lowercase (RFC 9421 §2.2.4) — [#46](https://github.com/yaronf/httpsign/pull/46) / [#45](https://github.com/yaronf/httpsign/issues/45)

`@scheme` is lowercased in the signature base, including values from `WithScheme` / `SetSchemeFromRequest`. An absent scheme still defaults to `http` (unchanged).

### `[]byte` custom signature parameters — [#48](https://github.com/yaronf/httpsign/pull/48)

`AddCustomParam` accepts `[]byte` and serializes them as RFC 8941 Byte Sequences. `MessageDetails.CustomParams` may contain `[]byte` after parsing.

### HMAC-SHA256 minimum key length — [#48](https://github.com/yaronf/httpsign/pull/48)

`NewHMACSHA256Signer` / `NewHMACSHA256Verifier` require at least **32** bytes (was 64), matching the SHA-256 output length `L` in [RFC 2104 §3](https://www.rfc-editor.org/rfc/rfc2104.html#section-3).

## Upgrade notes

| Area | Before | After |
|------|--------|--------|
| HMAC key construction | Rejected keys shorter than 64 bytes | Accepts 32–63 byte keys; still rejects &lt; 32 |
| `@authority` | Host/port as provided | Lowercased host; default port omitted |
| `@request-target` | Decoded path; dropped bare `?` | Percent-encoding and empty `?` preserved |
| `@path` | Empty path stayed empty | Empty path is `/` |
| `@scheme` | Case preserved | Lowercased |
| Custom params | `int64`, `string`, `bool` | Also `[]byte` |

**Cross-version mismatch:** if one peer still emits a non-normalized derived component and the other verifies with v0.6.3, signatures that cover that component can fail. Upgrade both sides, or ensure Host / path / scheme inputs are already RFC-normalized before signing.

Values that were already compliant are unaffected.

## PRs in this release

- [#43](https://github.com/yaronf/httpsign/pull/43) — `@request-target` / `@path`
- [#44](https://github.com/yaronf/httpsign/pull/44) — `@authority`
- [#46](https://github.com/yaronf/httpsign/pull/46) — `@scheme`
- [#48](https://github.com/yaronf/httpsign/pull/48) — `[]byte` custom params; HMAC key length
