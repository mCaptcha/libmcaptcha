## 0.1.4

## Changed:

- `PoWConfig` has an extra field to send internal `PoW` salt to clients.
  Salt is used to prevent dictionary attacks using rainbow tables. This
  salt shouldn't be used elsewhere in the program as it's exposed to the
  internet. Ideally `mCaptcha` should automatically generate random
  salt and rotate periodically, maybe in the next version.

- Migrated immutable, shared `String` to `Arc<String>`. There were
  plenty of them so a bunch of structs changed. See
  [865f2d1](https://github.com/mCaptcha/mCaptcha/commit/865f2d1c4a7627d352715118508499d4b333fe4a).

## 0.1.3

## Added

- `HashCache` was extended to store captcha responses
- `HashCache` was extended to cache site keys when caching `PoW` configurations
  as a result:
- <strike>`Retrieve`</strike> `RetrievePoW` now returns `CachedPoWConfig`
- random token generation post `PoW` verification
- token validation

## Changed

- `Cache` became `CachePoW` (`HashCache` extension)
- `Retrieve` became `RetrievePoW`(`HashCache` extension)
- `DeleteString` became `DeletePoW` (`HashCache` extension)
- `Save` trait now requires three new message impls (`HashCache` extension\_
- `System.verify_pow` now returns a `String` instead of `bool`

## Removed

- `CachePoW` constructor was removed in favour of `CachwPoWBuilder`

## Fixed

- a bug in `mCaptcha/pow_sha256` was causing errors in PoW computation

## 0.1.2

## Changed

- actix upgraded to `0.11`

## 0.1.1

### Added

- `Master` packs a garbage collector to stop and get rid of inactive
  `MCaptcha` actors
- `serde::{Serialize, Deserialize}` impls (shouldn't break anything)

### Changed

- typo fix: `MCaptcha::decrement_visiotr()` became `MCaptcha::decrement_visitor()`
- `MCaptcha` throws error when duration is 0
- `Visitor` is changed to `AddVisitor`
- `Master` constructor accepts a parameter to configure GC(see previous
  point) period
