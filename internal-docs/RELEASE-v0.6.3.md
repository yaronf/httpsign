# Release notes: httpsign v0.6.3 (draft)

Draft for the next release after v0.6.2. Update when cutting the tag.

---

## Summary

### `@authority` normalization (RFC 9421 §2.2.3)

`@authority` is now normalized before it enters the signature base: the hostname is lowercased, and the default port is omitted (`443` for `https`, `80` for `http`). See [#44](https://github.com/yaronf/httpsign/pull/44).

### Upgrade notes / behavioral change

Sign and verify both use the same normalization, so pairs that upgrade together stay consistent.

**Cross-version mismatch:** if one side still emits a non-normalized authority (for example `EXAMPLE.com:443`) and the other side verifies with this release (`example.com`), signatures that cover `@authority` will fail. Align both peers on a build that includes this change, or ensure the Host / authority value is already RFC-normalized before signing.

Hosts that were already lowercase and omitted the default port are unaffected.
