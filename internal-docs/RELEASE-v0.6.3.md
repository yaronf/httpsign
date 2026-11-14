# Release notes: httpsign v0.6.3 (draft)

Draft for the next release after v0.6.2. Update when cutting the tag.

---

## Summary

Derived-component normalization fixes for RFC 9421. Sign and verify use the same rules, so pairs that upgrade together stay consistent.

### `@authority` normalization (RFC 9421 §2.2.3)

Hostname is lowercased; default port is omitted (`443` for `https`, `80` for `http`). See [#44](https://github.com/yaronf/httpsign/pull/44).

### `@request-target` / `@path` encoding (RFC 9421 §2.2.5–2.2.6)

`@request-target` keeps percent-encoded path octets (`EscapedPath`) and a trailing empty query delimiter (`ForceQuery`). Empty `@path` normalizes to `/`. See [#43](https://github.com/yaronf/httpsign/pull/43).

### `@scheme` lowercase (RFC 9421 §2.2.4)

`@scheme` is lowercased before it enters the signature base, including values from `WithScheme` / `SetSchemeFromRequest`. See [#45](https://github.com/yaronf/httpsign/issues/45).

### Upgrade notes / behavioral change

**Cross-version mismatch:** if one peer still emits a non-normalized component and the other verifies with this release, signatures that cover that component will fail. Examples:

| Component | Old value (example) | This release |
|-----------|---------------------|--------------|
| `@authority` | `EXAMPLE.com:443` | `example.com` |
| `@request-target` | `/a/b` from `/a%2Fb` | `/a%2Fb` |
| `@request-target` | `/path` from `/path?` | `/path?` |
| `@path` | empty string | `/` |
| `@scheme` | `HTTPS` | `https` |

Align both peers on a build that includes these changes, or ensure inputs are already RFC-normalized before signing.

Values that were already compliant are unaffected.
