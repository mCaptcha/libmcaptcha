## 0.1.3
## Fixed
- a bug in `mCaptcha/pow_sha256` was causing errors in PoW computation

## Changed
- `Cache` became `CachePoW` (`HashCache` extension)
- `Retrieve` became `RetrievePoW`(`HashCache` extension)
- `DeleteString` became `DeletePoW` (`HashCache` extension)
- `Save` trait now requires three new message impls (`HashCache` extension_

## Added
- `HashCache` was extended to store captcha responses


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
