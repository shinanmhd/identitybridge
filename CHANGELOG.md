# Changelog

All notable changes to `identitybridge` will be documented in this file.

## [0.1.0] - Unreleased

### Added

- Account-deletion OTP request and confirmation methods, with a typed fresh-authentication proof.
- Scoped service methods to revoke all identity sessions and permanently erase an identity.
- Explicit W3C trace-context propagation and `Idempotency-Key` forwarding for erasure commands.
- Safe typed deletion failures with stable categories, status, and bounded retry timing.
