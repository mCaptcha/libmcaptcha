/*
 * mCaptcha - A proof of work based DoS protection system
 * Copyright © 2021 Aravinth Manivannan <realravinth@batsense.net>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
//! Cache is used to save proofof work details and nonces to prevent replay attacks
//! and rainbow/dictionary attacks
pub use hashcache::HashCache;
use messages::*;

pub mod hashcache;

/// Describes actor handler trait impls that are required by a cache implementation
pub trait Save:
    actix::Actor + actix::Handler<Retrive> + actix::Handler<Cache> + actix::Handler<DeleteString>
{
}
pub mod messages {
    //! Messages that can be sent to cache data structures implementing [Save][super::Save]
    use actix::dev::*;
    use derive_builder::Builder;
    use serde::{Deserialize, Serialize};

    use crate::errors::*;
    use crate::mcaptcha::AddVisitorResult;
    use crate::pow::PoWConfig;

    /// Message to cache PoW difficulty factor and string
    #[derive(Message, Serialize, Deserialize, Builder)]
    #[rtype(result = "CaptchaResult<()>")]
    pub struct Cache {
        pub string: String,
        pub difficulty_factor: u32,
        pub duration: u64,
    }

    impl Cache {
        pub fn new(p: &PoWConfig, v: &AddVisitorResult) -> Self {
            CacheBuilder::default()
                .string(p.string.clone())
                .difficulty_factor(v.difficulty_factor)
                .duration(v.duration)
                .build()
                .unwrap()
        }
    }

    /// Message to retrive the the difficulty factor for the specified
    /// string from the cache
    #[derive(Message)]
    #[rtype(result = "CaptchaResult<Option<u32>>")]
    pub struct Retrive(pub String);

    /// Message to delete cached PoW difficulty factor and string
    /// when they expire
    #[derive(Message)]
    #[rtype(result = "CaptchaResult<()>")]
    pub struct DeleteString(pub String);
}
