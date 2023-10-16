## 0.2.4

### Fixed

1. Fix typo already fixed in redis module name (#12)

## 0.2.3

### Fixed:

1. `crossbeam::channel::Receiver::try_recv` is non-blocking and results
   in busy waiting, which caused high CPU usage even when idling.
   Switching to `crossbeam::channel::Receiver::recv` to fixed this.

2. `System::verify_pow` returns `CaptchaResult<(String, u32)>`, where
   the second `u32` is the difficulty factor of the challenge factor.

## 0.2.2

### Added:

-   `libmcaptcha::system::System`: extra parameter `queue_length`. PoW
    IP queues are limited by queue_length

## 0.2.1

### Added:

-   `libmcaptcha::system::System`: extra parameter `runners`. PoW
    are now scheduled for execution based on IP addresses.

## 0.1.4

### Added:

-   `Master` trait: provides methods to manage mCaptcha
-   `MCaptcha::get_defense()`: returns the `MCaptcha` instance's defense
    configuration

### Changed:

-   `PoWConfig` has an extra field to send internal `PoW` salt to clients.
    Salt is used to prevent dictionary attacks using rainbow tables. This
    salt shouldn't be used elsewhere in the program as it's exposed to the
    internet. Ideally `mCaptcha` should automatically generate random
    salt and rotate periodically, maybe in the next version.

-   `master::Master` is moved to `master::embedded::master` in preparation
    for Redis based implementation.

-   `AddSite` message for `Master` now requires an instance of
    `crate::mcaptcha::MCaptcha`. In the case of
    `crate::master::embedded::master`, it automatically starts `Counter`
    actor.

-   `System::get_pow` returns `errors::CaptchaResult<Option<PoWConfig>>`
    instead of `Option<PoWConfig>`

### Removed

-   `MCaptcha::decrement_visiotr`: seemed redundant when
    `MCaptcha::decrement_visitor_by` was available

## 0.1.3

### Added

-   `HashCache` was extended to store captcha responses
-   `HashCache` was extended to cache site keys when caching `PoW` configurations
    as a result:
-   <strike>`Retrieve`</strike> `RetrievePoW` now returns `CachedPoWConfig`
-   random token generation post `PoW` verification
-   token validation

### Changed

-   `Cache` became `CachePoW` (`HashCache` extension)
-   `Retrieve` became `RetrievePoW`(`HashCache` extension)
-   `DeleteString` became `DeletePoW` (`HashCache` extension)
-   `Save` trait now requires three new message impls (`HashCache` extension\_
-   `System.verify_pow` now returns a `String` instead of `bool`

### Removed

-   `CachePoW` constructor was removed in favour of `CachwPoWBuilder`

### Fixed

-   a bug in `mCaptcha/pow_sha256` was causing errors in PoW computation

## 0.1.2

### Changed

-   `actix` upgraded to `0.11`

## 0.1.1

#### Added

-   `Master` packs a garbage collector to stop and get rid of inactive
    `MCaptcha` actors
-   `serde::{Serialize, Deserialize}` impls (shouldn't break anything)

### Changed

-   typo fix: `MCaptcha::decrement_visiotr()` became `MCaptcha::decrement_visitor()`
-   `MCaptcha` throws error when duration is 0
-   `Visitor` is changed to `AddVisitor`
-   `Master` constructor accepts a parameter to configure GC(see previous
    point) period
