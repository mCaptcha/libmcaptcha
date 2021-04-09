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
    actix::Actor
    + actix::Handler<RetrivePoW>
    + actix::Handler<CachePoW>
    + actix::Handler<DeletePoW>
    + actix::Handler<CacheResult>
    + actix::Handler<VerifyCaptchaResult>
    + actix::Handler<DeleteCaptchaResult>
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
    pub struct CachePoW {
        pub string: String,
        pub difficulty_factor: u32,
        pub duration: u64,
    }

    impl CachePoW {
        pub fn new(p: &PoWConfig, v: &AddVisitorResult) -> Self {
            CachePoWBuilder::default()
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
    pub struct RetrivePoW(pub String);

    /// Message to delete cached PoW difficulty factor and string
    /// when they expire
    #[derive(Message)]
    #[rtype(result = "CaptchaResult<()>")]
    pub struct DeletePoW(pub String);

    /// Message to cache captcha result and the captcha key for which
    /// it was generated
    #[derive(Message, Serialize, Deserialize, Builder)]
    #[rtype(result = "CaptchaResult<()>")]
    pub struct CacheResult {
        pub result: String,
        // key is Captcha identifier
        pub key: String,
        pub duration: u64,
    }

    /// Message to verify captcha result against
    /// the stored captcha key
    #[derive(Message)]
    #[rtype(result = "CaptchaResult<bool>")]
    pub struct VerifyCaptchaResult {
        pub result: String,
        pub key: String,
    }

    /// Message to delete cached capthca result when it expires
    #[derive(Message)]
    #[rtype(result = "CaptchaResult<()>")]
    pub struct DeleteCaptchaResult {
        pub result: String,
    }
}
