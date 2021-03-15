# 0.1.1
- typo fix: `MCaptcha::decrement_visiotr()` became `MCaptcha::decrement_visitor()`
- `serde::{Serialize, Deserialize}` impls (shouldn't break anything)
- `MCaptcha` throws error when duration is 0
- `Visitor` is changed to `AddVisitor`
- `Master` packs a garbage collector to stop and get rid of inactive
  `MCaptcha` actors
- `Master` constructor accepts a parameter to configure GC(see previous
  point) period
