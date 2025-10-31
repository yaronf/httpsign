# jwx v2 to v3 Migration Plan

## Executive Summary

This document outlines the plan for migrating the `httpsign` library from `jwx` v2 to v3. The jwx library is used for generic JWS (JSON Web Signature) algorithm support, providing extensibility for signature algorithms beyond those natively implemented in this library.

**✅ BACKWARD COMPATIBLE MIGRATION**: This migration will maintain backward compatibility by keeping the existing v2-based functions and adding new v3-based functions. Users can migrate at their own pace, and existing code will continue to work without changes.

## Quick Reference

| Aspect | Details |
|--------|---------|
| **Breaking Change?** | ❌ NO - backward compatible migration |
| **Migration Strategy** | Separate functions - keep old, add new with V3 suffix |
| **Who is affected?** | Only users who want to use jwx v3 features (optional upgrade) |
| **Existing users impact** | ✅ ZERO - existing code continues to work |
| **Required version bump** | Minor version (e.g., v1.2.x → v1.3.0) |
| **Signature compatibility** | ✅ Compatible - both v2 and v3 generate valid signatures |
| **Migration effort (users)** | Optional - users can migrate when ready |
| **Migration effort (maintainers)** | Medium - maintain two code paths + testing both |
| **Deprecation timeline** | TBD - can deprecate v2 functions in future major release |

## Current Usage Analysis

### Dependencies
- **Current Version**: `github.com/lestrrat-go/jwx/v2 v2.1.2`
- **Target Version**: `github.com/lestrrat-go/jwx/v3` (latest stable)

### Files Using jwx

1. **crypto.go** (Lines 15-16)
   - `github.com/lestrrat-go/jwx/v2/jwa` - For `SignatureAlgorithm` type
   - `github.com/lestrrat-go/jwx/v2/jws` - For `NewSigner` and `NewVerifier` functions

2. **crypto_test.go** (Lines 11-12)
   - Same imports for testing JWS functionality

### Functions Using jwx

1. **`NewJWSSigner()`** (crypto.go:131-149)
   - Takes `jwa.SignatureAlgorithm` as a parameter
   - Calls `jws.NewSigner(alg)` to create a signer
   - Returns a `Signer` with `foreignSigner` field set to `jws.Signer`

2. **`NewJWSVerifier()`** (crypto.go:306-327)
   - Takes `jwa.SignatureAlgorithm` as a parameter
   - Calls `jws.NewVerifier(alg)` to create a verifier
   - Returns a `Verifier` with `foreignVerifier` field set to `jws.Verifier`

3. **`Signer.sign()`** (crypto.go:151-200)
   - Uses type assertion to check for `jws.Signer`
   - Calls `signer.Sign(buff, s.key)` method

4. **`Verifier.verify()`** (crypto.go:329-382)
   - Uses type assertion to check for `jws.Verifier`
   - Calls `verifier.Verify(buff, sig, v.key)` method

### Test Coverage

1. **`TestForeignSigner()`** (crypto_test.go:136-164)
   - Tests ES256 (ECDSA P-256) signing and verification
   - Uses `jwa.ES256` constant

2. **`TestMessageForeignSigner()`** (crypto_test.go:167-199)
   - Similar test using Message API

3. **`TestNewJWSVerifier()`** (crypto_test.go:250-326)
   - Tests HS256 (HMAC SHA-256) verification
   - Uses `jwa.SignatureAlgorithm("HS256")` and `jwa.NoSignature`

## Backward Compatible Migration Strategy

**✅ GOOD NEWS: This is NOT a breaking change. Existing code will continue to work.**

### Approach: Dual Function Support

We will maintain both jwx v2 and v3 functions side-by-side:

**Existing functions (unchanged, using jwx v2):**
- `httpsign.NewJWSSigner()` - Uses `github.com/lestrrat-go/jwx/v2/jwa`
- `httpsign.NewJWSVerifier()` - Uses `github.com/lestrrat-go/jwx/v2/jwa`

**New functions (added, using jwx v3):**
- `httpsign.NewJWSSignerV3()` - Uses `github.com/lestrrat-go/jwx/v3/jwa`
- `httpsign.NewJWSVerifierV3()` - Uses `github.com/lestrrat-go/jwx/v3/jwa`

### Why This Approach?

The `NewJWSSigner()` and `NewJWSVerifier()` functions expose `jwa.SignatureAlgorithm` in their signatures:

```go
func NewJWSSigner(alg jwa.SignatureAlgorithm, key interface{}, config *SignConfig, fields Fields) (*Signer, error)
func NewJWSVerifier(alg jwa.SignatureAlgorithm, key interface{}, config *VerifyConfig, fields Fields) (*Verifier, error)
```

Since these are **rarely used functions** (most users rely on native algorithms), forcing a breaking change would be disproportionate. The dual-function approach:

1. ✅ Preserves backward compatibility
2. ✅ Allows gradual migration
3. ✅ No user disruption
4. ✅ Enables jwx v3 adoption when users are ready
5. ✅ Can be cleaned up in a future major version

### Who is NOT Affected? (Everyone!)

**All existing users can continue using their code without any changes.** This includes:

Users of native algorithm functions:
- `NewHMACSHA256Signer()` / `NewHMACSHA256Verifier()`
- `NewRSASigner()` / `NewRSAVerifier()`
- `NewRSAPSSSigner()` / `NewRSAPSSVerifier()`
- `NewP256Signer()` / `NewP256Verifier()`
- `NewP384Signer()` / `NewP384Verifier()`
- `NewEd25519Signer()` / `NewEd25519Verifier()`
- `NewEd25519SignerFromSeed()`

Users of JWS functions (jwx v2-based):
- `NewJWSSigner()` - **continues to work, unchanged**
- `NewJWSVerifier()` - **continues to work, unchanged**

### Optional Migration for Users

Users who want to adopt jwx v3 can optionally migrate to the new functions:

#### 1. Update go.mod to add jwx v3 (keep v2 for now)
```bash
# Add v3 alongside v2
go get github.com/lestrrat-go/jwx/v3@latest

go mod tidy
```

#### 2. Update code to use new V3 functions
```go
// OLD - using jwx v2 (still works!)
import (
    jwav2 "github.com/lestrrat-go/jwx/v2/jwa"
    "github.com/yaronf/httpsign"
)

signer, err := httpsign.NewJWSSigner(jwav2.ES256, privateKey, config, fields)

// NEW - using jwx v3 (optional upgrade)
import (
    jwav3 "github.com/lestrrat-go/jwx/v3/jwa"
    "github.com/yaronf/httpsign"
)

signer, err := httpsign.NewJWSSignerV3(jwav3.ES256, privateKey, config, fields)
```

#### 3. Eventually remove jwx v2 dependency (when ready)
```bash
# Once all code is migrated to V3 functions
go get github.com/lestrrat-go/jwx/v2@none
go mod tidy
```

### Example: Gradual Migration

**Current code (no changes needed):**
```go
package main

import (
    "github.com/lestrrat-go/jwx/v2/jwa"
    "github.com/yaronf/httpsign"
)

func main() {
    signer, err := httpsign.NewJWSSigner(
        jwa.ES256,
        privateKey,
        httpsign.NewSignConfig(),
        httpsign.Headers("@method", "content-digest"),
    )
    // ... use signer
}
```

**Optional upgrade to v3 (when user is ready):**
```go
package main

import (
    "github.com/lestrrat-go/jwx/v3/jwa"  // ← Upgrade to v3
    "github.com/yaronf/httpsign"
)

func main() {
    signer, err := httpsign.NewJWSSignerV3(  // ← Use new V3 function
        jwa.ES256,
        privateKey,
        httpsign.NewSignConfig(),
        httpsign.Headers("@method", "content-digest"),
    )
    // ... use signer - same behavior
}
```

### Communication Plan

1. **Update README** with information about new V3 functions
2. **Update CHANGELOG** noting new functions added (non-breaking)
3. **Add documentation** explaining the difference between v2 and v3 functions
4. **Announce in release notes** - new jwx v3 support available
5. **Mark v2 functions as deprecated** (in a future release, with timeline)
6. **Plan removal** of v2 functions for next major version (e.g., v2.0.0)

### Migration Approach: Option B (Chosen)

**✅ SELECTED: Separate Functions for Backward Compatibility**

Since `NewJWSSigner()` and `NewJWSVerifier()` are rarely used (most users rely on native algorithms), we will maintain backward compatibility by creating separate V3 functions.

#### Implementation:
```go
// Existing functions (keep unchanged, using jwx v2)
func NewJWSSigner(alg jwav2.SignatureAlgorithm, ...) (*Signer, error)
func NewJWSVerifier(alg jwav2.SignatureAlgorithm, ...) (*Verifier, error)

// New functions (add, using jwx v3)
func NewJWSSignerV3(alg jwav3.SignatureAlgorithm, ...) (*Signer, error)
func NewJWSVerifierV3(alg jwav3.SignatureAlgorithm, ...) (*Verifier, error)
```

#### Pros:
- ✅ No breaking changes for existing users
- ✅ Zero migration pressure - users migrate when ready
- ✅ Gradual adoption of jwx v3
- ✅ Can deprecate v2 functions in future major version
- ✅ Proportional to usage (low usage = low impact approach)

#### Cons:
- ⚠️ API bloat (4 functions instead of 2)
- ⚠️ Maintenance burden (must maintain both v2 and v3 code paths)
- ⚠️ Dependency bloat (httpsign depends on both jwx v2 and v3)
- ⚠️ Potential confusion about which function to use

#### Deprecation Path:
1. **Now (v1.3.0)**: Add V3 functions, keep v2 functions working
2. **Later (v1.4.0)**: Mark v2 functions as deprecated with migration notice
3. **Future (v2.0.0)**: Remove v2 functions in next major version

### Alternative Options Considered (Not Chosen)

#### Option A: Major Version Bump (Not Chosen)
- Would force breaking change on all users
- Disproportionate impact for rarely-used functions
- ❌ Rejected due to high impact vs. low usage

#### Option C: Build Tags (Not Chosen)
- Complex build and testing process
- Poor developer experience
- ❌ Rejected due to complexity

## Migration Strategy

### Phase 1: Research and Preparation

- [x] Analyze current jwx v2 usage
- [ ] Review jwx v3 official migration guide: https://github.com/lestrrat-go/jwx/blob/develop/v3/Changes-v3.md
- [ ] Identify breaking changes that affect this codebase
- [ ] Check for deprecated APIs
- [ ] Review jwx v3 performance improvements and new features

### Phase 2: Expected Breaking Changes

Based on typical major version upgrades, expect the following potential changes:

1. **Import Path Changes**
   - `github.com/lestrrat-go/jwx/v2/jwa` → `github.com/lestrrat-go/jwx/v3/jwa`
   - `github.com/lestrrat-go/jwx/v2/jws` → `github.com/lestrrat-go/jwx/v3/jws`

2. **API Changes to Monitor**
   - Constructor signatures (e.g., `jws.NewSigner`, `jws.NewVerifier`)
   - Interface method signatures (e.g., `Sign()`, `Verify()`)
   - Type names or structure changes
   - Error handling patterns
   - Constant/enum values (e.g., `jwa.SignatureAlgorithm`, `jwa.NoSignature`)

3. **Potential New Features**
   - Additional signature algorithms
   - Performance optimizations
   - Enhanced error messages
   - Better API ergonomics

### Phase 3: Implementation Steps

#### Step 1: Add jwx v3 Dependency
```bash
# Add jwx v3 (keep v2 for backward compatibility)
go get github.com/lestrrat-go/jwx/v3@latest

go mod tidy
```

#### Step 2: Update Import Statements in crypto.go

**File to update:** `crypto.go`

**Add v3 imports (keep v2 imports):**
```go
import (
    // ... existing imports ...
    
    // JWX v2 (existing, keep for backward compatibility)
    jwav2 "github.com/lestrrat-go/jwx/v2/jwa"
    jwsv2 "github.com/lestrrat-go/jwx/v2/jws"
    
    // JWX v3 (new, for V3 functions)
    jwav3 "github.com/lestrrat-go/jwx/v3/jwa"
    jwsv3 "github.com/lestrrat-go/jwx/v3/jws"
)
```

#### Step 3: Create New V3 Functions

Add new functions alongside existing ones in `crypto.go`:

**Add after existing `NewJWSSigner()`:**
```go
// NewJWSSigner creates a generic signer using JWX v2 (legacy, for backward compatibility)
// For new code, consider using NewJWSSignerV3() instead.
func NewJWSSigner(alg jwav2.SignatureAlgorithm, key interface{}, config *SignConfig, fields Fields) (*Signer, error) {
    // ... existing implementation unchanged ...
}

// NewJWSSignerV3 creates a generic signer using JWX v3 algorithms
func NewJWSSignerV3(alg jwav3.SignatureAlgorithm, key interface{}, config *SignConfig, fields Fields) (*Signer, error) {
    if key == nil {
        return nil, fmt.Errorf("key must not be nil")
    }
    if alg == jwav3.NoSignature {
        return nil, fmt.Errorf("the NONE signing algorithm is expressly disallowed")
    }
    jwsSigner, err := jwsv3.NewSigner(alg)
    if err != nil {
        return nil, err
    }
    return &Signer{
        key:           key,
        alg:           "",
        config:        config,
        fields:        fields,
        foreignSigner: jwsSigner,
    }, nil
}
```

**Add after existing `NewJWSVerifier()`:**
```go
// NewJWSVerifier creates a generic verifier using JWX v2 (legacy, for backward compatibility)
// For new code, consider using NewJWSVerifierV3() instead.
func NewJWSVerifier(alg jwav2.SignatureAlgorithm, key interface{}, config *VerifyConfig, fields Fields) (*Verifier, error) {
    // ... existing implementation unchanged ...
}

// NewJWSVerifierV3 creates a generic verifier using JWX v3 algorithms
func NewJWSVerifierV3(alg jwav3.SignatureAlgorithm, key interface{}, config *VerifyConfig, fields Fields) (*Verifier, error) {
    if key == nil {
        return nil, fmt.Errorf("key must not be nil")
    }
    if config == nil {
        config = NewVerifyConfig()
    }
    if alg == jwav3.NoSignature {
        return nil, fmt.Errorf("the NONE signing algorithm is expressly disallowed")
    }
    verifier, err := jwsv3.NewVerifier(alg)
    if err != nil {
        return nil, err
    }
    return &Verifier{
        key:             key,
        alg:             "",
        config:          config,
        fields:          fields,
        foreignVerifier: verifier,
    }, nil
}
```

#### Step 4: Update Internal Methods (if needed)

The internal `sign()` and `verify()` methods should already handle both v2 and v3 jwx.Signer/Verifier interfaces since they use type assertion. Verify this works correctly:

- `Signer.sign()` - Should work with both `jwsv2.Signer` and `jwsv3.Signer`
- `Verifier.verify()` - Should work with both `jwsv2.Verifier` and `jwsv3.Verifier`

If type compatibility issues arise, may need to use interface adapters.

#### Step 5: Add Tests for V3 Functions

Add new tests in `crypto_test.go` for the V3 functions:

```go
import (
    jwav2 "github.com/lestrrat-go/jwx/v2/jwa"
    jwsv2 "github.com/lestrrat-go/jwx/v2/jws"
    jwav3 "github.com/lestrrat-go/jwx/v3/jwa"
    jwsv3 "github.com/lestrrat-go/jwx/v3/jws"
)

// New test for V3 signer
func TestForeignSignerV3(t *testing.T) {
    // Similar to TestForeignSigner but using NewJWSSignerV3/NewJWSVerifierV3
    // and jwav3.ES256
}

// New test for V3 verifier
func TestNewJWSVerifierV3(t *testing.T) {
    // Similar to TestNewJWSVerifier but using jwav3 types
}
```

**Keep existing tests unchanged** to ensure backward compatibility.

#### Step 6: Run All Tests

Ensure all tests pass with both v2 and v3:
```bash
go test -v ./...
```

**Critical tests to verify:**

**V2 Tests (existing, must still pass):**
- `TestForeignSigner` - ES256 signing/verification with v2
- `TestMessageForeignSigner` - Message-based signing with v2
- `TestNewJWSVerifier` - Verifier creation with v2
- `TestVerify` - Verification logic

**V3 Tests (new):**
- `TestForeignSignerV3` - ES256 signing/verification with v3
- `TestMessageForeignSignerV3` - Message-based signing with v3
- `TestNewJWSVerifierV3` - Verifier creation with v3
- Cross-compatibility tests (sign with v2, verify with v3, and vice versa)

#### Step 7: Cross-Version Compatibility Testing

Verify that signatures generated with v2 can be verified with v3 and vice versa:
- Sign with v2 signer, verify with v3 verifier
- Sign with v3 signer, verify with v2 verifier
- Test with various algorithms: ES256, HS256, etc.

### Phase 4: Validation and Testing

1. **Unit Tests**
   - Run full test suite: `go test ./...`
   - Check test coverage: `go test -cover ./...`
   - Run race detector: `go test -race ./...`

2. **Integration Tests**
   - Test with real HTTP requests
   - Verify signature generation
   - Verify signature validation
   - Test error cases

3. **Backward Compatibility Validation**
   - ✅ **NOTE**: This is NOT a breaking change - existing functions continue to work
   - Verify that existing v2 functions still work correctly
   - Verify that new v3 functions work correctly
   - Test cross-compatibility: v2 signatures verified by v3, and vice versa
   - Ensure native algorithm functions remain unaffected
   - Verify both v2 and v3 code paths work correctly

4. **Performance Testing**
   - Benchmark signing operations
   - Benchmark verification operations
   - Compare performance with v2

### Phase 5: Documentation Updates

1. **Update go.mod**
   - Reflect new jwx v3 dependency
   - Update minimum Go version if required

2. **Update Documentation**
   - Update any references to jwx v2
   - Document any new features or improvements
   - Update examples if API changed
   - **Create MIGRATION.md** for end users with step-by-step upgrade instructions

3. **CHANGELOG**
   - Document the jwx upgrade as a **BREAKING CHANGE**
   - Clearly state who is affected (users of `NewJWSSigner` and `NewJWSVerifier`)
   - Provide migration instructions
   - Mention benefits of the upgrade

4. **User Communication**
   - Create GitHub issue announcing the breaking change
   - Consider GitHub Discussions post for Q&A
   - Update README with migration notice
   - Prepare release notes with clear migration guide
   - Consider blog post or announcement if library has significant users

## Risk Assessment

### No Breaking Changes
**✅ LOW RISK**: Using the backward compatible approach (Option B), there are NO breaking changes for users. Existing code continues to work without modifications.

### Low Risk Areas
- Adding new V3 functions alongside existing ones (additive, non-breaking)
- Existing v2 functions remain unchanged (zero risk to current users)
- Users of native algorithms are completely unaffected
- Optional migration - users can upgrade at their own pace

### Medium Risk Areas
- **Dependency size**: httpsign will depend on both jwx v2 and v3 temporarily
- **Maintenance burden**: Must maintain and test both v2 and v3 code paths
- **API confusion**: Users might be unsure which function to use
- **API signature changes in jwx v3**: Could require code changes in V3 functions
- **Behavioral differences**: v2 and v3 might behave slightly differently
- **Error handling differences**: Error messages may differ between v2 and v3
- **Type compatibility**: May need adapters if jwsv2.Signer and jwsv3.Signer interfaces differ

### Medium-High Risk Areas
- **Cross-version compatibility**: Signatures generated with v2 must be verifiable by v3 (and vice versa)
- **Interface incompatibility**: If `jws.Signer`/`jws.Verifier` interfaces changed significantly in v3
- **Algorithm constant changes**: If `jwa.ES256` or other constants changed names or values in v3

### Mitigation Strategies
1. **Extensive testing**: Test both v2 and v3 code paths thoroughly
2. **Cross-compatibility tests**: Verify v2 and v3 can interoperate
3. **Documentation**: Clear guidance on which function to use
4. **Deprecation timeline**: Plan for eventual removal of v2 functions

## Rollback Plan

Since this is a backward compatible approach, rollback is straightforward and low-risk:

### If Critical Issues are Discovered with V3 Functions:

**Option 1: Remove V3 functions (clean rollback)**
   ```bash
   # Remove jwx v3 dependency
   go get github.com/lestrrat-go/jwx/v3@none
   go mod tidy
   ```
   - Delete `NewJWSSignerV3()` and `NewJWSVerifierV3()` functions
   - Remove v3 import statements
   - Existing v2 functions remain untouched
   - No user impact (V3 functions were new, no one depends on them yet)

**Option 2: Mark V3 functions as experimental**
   - Add `// EXPERIMENTAL: This function is under development` to docs
   - Keep them in codebase but discourage use
   - Fix issues in next release

**Option 3: Keep both, document issues**
   - Document known issues with V3 functions
   - Recommend users stick with v2 functions for now
   - Fix issues incrementally

### Document Issues
- Document any blocking issues found
- Report bugs to jwx repository if applicable
- Create plan for addressing issues in future release
- Communicate to users about any limitations

## Success Criteria

### Code Quality
- ✅ All existing unit tests pass (v2 functionality preserved)
- ✅ All new unit tests pass (v3 functionality works)
- ✅ All integration tests pass
- ✅ No performance regressions for v2 functions
- ✅ V3 functions have comparable or better performance
- ✅ No new linter warnings or errors
- ✅ Code coverage maintained or improved

### Compatibility
- ✅ Existing v2 functions work identically (zero breaking changes)
- ✅ Signatures generated with v2 remain compatible with RFC 9421
- ✅ Signatures generated with v3 remain compatible with RFC 9421
- ✅ Cross-compatibility: v2 signatures can be verified by v3 verifiers
- ✅ Cross-compatibility: v3 signatures can be verified by v2 verifiers
- ✅ Native algorithm functions work identically (unaffected)

### Documentation
- ✅ Documentation updated (README with V3 function info)
- ✅ CHANGELOG updated noting new functions added (non-breaking)
- ✅ API documentation clearly explains v2 vs v3 functions
- ✅ Clear guidance on when to use v2 vs v3
- ✅ Deprecation timeline documented for v2 functions
- ✅ Examples provided for both v2 and v3 usage

### Release Management
- ✅ Release notes clearly describe new V3 functions
- ✅ Appropriate semantic versioning (minor version bump: e.g., v1.2.x → v1.3.0)
- ✅ No breaking changes for existing users
- ✅ Clear migration path documented for users who want to upgrade
- ✅ Backward compatibility maintained

## Timeline Estimate

1. **Phase 1: Research** - 2-4 hours
   - Review jwx v3 changes and migration guide
   - Identify any API differences
   - Plan implementation strategy for dual functions

2. **Phase 2: Implementation** - 3-5 hours
   - Add jwx v3 dependency alongside v2
   - Add aliased imports for both versions
   - Create NewJWSSignerV3() function
   - Create NewJWSVerifierV3() function
   - Verify internal methods handle both v2 and v3 interfaces
   - Add deprecation comments to v2 functions

3. **Phase 3: Testing** - 5-10 hours
   - Create tests for V3 functions (mirror existing v2 tests)
   - Run full test suite for v2 functions (ensure unchanged)
   - Run full test suite for v3 functions
   - Cross-compatibility testing (v2 ↔ v3)
   - Performance benchmarking (compare v2 vs v3)
   - Integration testing with real HTTP requests

4. **Phase 4: Documentation & Communication** - 2-4 hours
   - Update README with V3 function information
   - Write CHANGELOG entry (new functions added)
   - Add API documentation for V3 functions
   - Document when to use v2 vs v3
   - Document deprecation timeline for v2 functions
   - Prepare release notes
   - Update examples (show both v2 and v3 usage)

**Total Estimated Time**: 12-23 hours (accounting for dual code path maintenance)

**Note**: Ongoing maintenance cost of supporting both v2 and v3 until v2 functions are deprecated and removed.

## Post-Migration Tasks

### Immediate (After Release)
1. Monitor for issues reported by users (especially with V3 functions)
2. Track adoption of V3 functions vs continued use of v2 functions
3. Provide support for users migrating to V3 functions
4. Watch for any compatibility issues between v2 and v3

### Short-term (1-3 months)
1. Gather feedback on V3 function usage
2. Identify any issues with dual dependency (jwx v2 + v3)
3. Monitor dependency size impact
4. Evaluate jwx v3 performance improvements

### Medium-term (6-12 months)
1. Add deprecation warnings to v2 functions (when V3 adoption is sufficient)
2. Update documentation to recommend V3 functions as default
3. Plan timeline for removing v2 functions
4. Consider if any jwx v3 exclusive features should be exposed

### Long-term (Next Major Version)
1. Remove v2 functions (`NewJWSSigner`, `NewJWSVerifier`)
2. Remove jwx v2 dependency
3. Rename V3 functions (remove "V3" suffix) or keep for clarity
4. Clean up API surface

## Additional Resources

- jwx v3 Repository: https://github.com/lestrrat-go/jwx
- jwx v3 Migration Guide: https://github.com/lestrrat-go/jwx/blob/develop/v3/Changes-v3.md
- jwx v3 Documentation: https://pkg.go.dev/github.com/lestrrat-go/jwx/v3
- RFC 9421 (HTTP Message Signatures): https://www.rfc-editor.org/rfc/rfc9421.html

## Important Notes

### For httpsign Maintainers
- The jwx library is only used for "foreign" JWS algorithm support
- Native algorithms (HMAC-SHA256, RSA, ECDSA P-256/P-384, Ed25519) do not depend on jwx
- **Backward compatible approach**: Keep v2 functions, add V3 functions
- Both jwx v2 and v3 will be dependencies temporarily
- Must maintain and test both v2 and v3 code paths
- Plan deprecation path for v2 functions in future major version
- Internal methods should handle both jwsv2 and jwsv3 interfaces

### For httpsign Users  
- **✅ NO BREAKING CHANGES** - existing code continues to work
- Current users of `NewJWSSigner()` and `NewJWSVerifier()` are NOT affected
- Users of native algorithm functions (NewRSASigner, NewP256Signer, etc.) are NOT affected
- New `NewJWSSignerV3()` and `NewJWSVerifierV3()` functions available for jwx v3 support
- Migration to V3 functions is **optional** - users can migrate when ready
- The migration is a minor version bump (e.g., v1.2.x → v1.3.0)
- Signatures remain fully compatible between v2 and v3
- Most users (estimated 80-90%) who only use native algorithms see zero impact
- Users who want jwx v3 features can optionally adopt V3 functions

### Trade-offs of This Approach
**Pros:**
- Zero breaking changes for users
- Gradual, optional migration path
- Users control when they upgrade
- Low risk rollback (just remove V3 functions if needed)

**Cons:**
- API bloat (4 functions instead of 2)
- Maintenance burden (two code paths)
- Dependency bloat (both jwx v2 and v3)
- Must eventually clean up in major version

### Future Cleanup
- v2 functions will be marked deprecated in ~6-12 months
- v2 functions will be removed in next major version (e.g., v2.0.0)
- At that point, V3 functions become the standard (or renamed without V3 suffix)

