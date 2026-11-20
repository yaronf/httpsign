# Release notes: httpsign v0.6.4 (shipped)

Published GitHub release for tag `v0.6.4`. Kept here for maintainers; do not treat as a draft for retagging.

---

## Summary

`@target-uri` no longer includes the URL fragment or userinfo. Sign and verify apply the same rule, so peers that upgrade together stay consistent when signatures cover `@target-uri`.

### `@target-uri` excludes fragment and userinfo (RFC 9421 §2.2.2 / HTTP §7.1) — [#50](https://github.com/yaronf/httpsign/pull/50)

The component value is built from a copy of `req.URL` with `Fragment` / `RawFragment` cleared and `User` set to `nil`. The caller's URL is not modified. Other derived components already ignore fragment and userinfo.

## Upgrade notes

| Area | Before | After |
|------|--------|--------|
| `@target-uri` | `url.String()` kept `#fragment` and `user:pass@` | Fragment and userinfo omitted |

**Cross-version mismatch:** if a signer still embeds a fragment (or userinfo) in `@target-uri` and the verifier runs v0.6.4, signatures that cover `@target-uri` can fail. Upgrade both sides, or ensure URLs used for signing have no fragment/userinfo.

Values that were already free of fragment and userinfo are unaffected.

## PRs in this release

- [#50](https://github.com/yaronf/httpsign/pull/50) — `@target-uri` fragment and userinfo
