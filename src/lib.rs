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
//! mCaptcha is a proof of work based Denaial-of-Service attack protection system.
//! This is is a server library that you can embed in your services to protect your
//! servers.
//!
//! A commercial managed solution is in the works but I'd much rather prefer
//! folks host their own instances as it will make the more decentralized and free.
//!
//! In mCaptcha, defense is adjusted in discrete levels that depend on the
//! ammount of traffic that a service is experiencing. So users of this library are
//! requested to benchmark their target machines before configuring their mCaptcha
//! component.
//!
//! ## Terminology:
//! - Difficulty(Factor): Minimum ammount of work that a client must do to make a valid
//! request.
//! - [Defense]: A datatype that various visitor-difficulty mappigns
//! - Visitor: Smallest unit of traffic, usually a single request. The more you have, the busier
//! your service is. Determines mCaptcha defense defense
//! - Visitor threshold: The threshold at which [MCaptcha] will adjust defense defense
//! - [Cache][crate::cache] : A datatype that implements [Save][crate::cache::Save]. Used to store
//! PoW requirements to defend against replay attacks and dictionary attacks.
//! - [Master][crate::master::Master]: A datatype that manages
//! [MCaptcha][crate::mcaptcha::MCaptcha] actors. Works like a DNS for
//! [AddVisitor][crate::mcaptcha::AddVisitor] messages.
//! - [System][crate::system::System]: mCaptcha system that manages cache, master and provides
//! useful abstractions. An mCaptcha system/instance can have only a single
//! [System][crate::system::System]
//!
//! ## Example:
//!
//! ```rust
//! use libmcaptcha::{
//!     cache::{messages::VerifyCaptchaResult, hashcache::HashCache},
//!     master::embedded::master:: Master,
//!     master::messages::AddSiteBuilder,
//!     pow::{ConfigBuilder, Work},
//!     system::SystemBuilder,
//!     DefenseBuilder, LevelBuilder, MCaptchaBuilder,
//! };
//! // traits from actix needs to be in scope for starting actor
//! use actix::prelude::*;
//!
//! #[actix_rt::main]
//! async fn main() -> std::io::Result<()> {
//!     // start cahce actor
//!     // cache is used to store PoW requirements that are sent to clients
//!     // This way, it can be verified that the client computed work over a config
//!     // that _we_ sent. Offers protection against rainbow tables powered dictionary attacks
//!     let cache = HashCache::default().start();
//!
//!     // create PoW config with unique salt. Salt has to be safely guarded.
//!     // salts protect us from replay attacks
//!     let pow = ConfigBuilder::default()
//!         .salt("myrandomsaltisnotlongenoug".into())
//!         .build()
//!         .unwrap();
//!
//!     // start master actor. Master actor is responsible for managing MCaptcha actors
//!     // each mCaptcha system should have only one master
//!     let master = Master::new(5).start();
//!
//!     // Create system. System encapsulates master and cache and provides useful abstraction
//!     // each mCaptcha system should have only one system
//!     let system = SystemBuilder::default()
//!         .master(master)
//!         .cache(cache)
//!         .pow(pow.clone())
//!         .runners(4)
//!         .queue_length(2000)
//!         .build();
//!
//!     // configure defense. This is a per site configuration. A site can have several levels
//!     // of defenses configured
//!     let defense = DefenseBuilder::default()
//!         // add as many defense as you see fit
//!         .add_level(
//!             LevelBuilder::default()
//!                 // visitor_threshold is the threshold/limit at which
//!                 // mCaptcha will adjust difficulty defense
//!                 // it is advisable to set small values for the first
//!                 // defense visitor_threshold and difficulty_factor
//!                 // as this will be the work that clients will be
//!                 // computing when there's no load
//!                 .visitor_threshold(50)
//!                 .difficulty_factor(500)
//!                 .unwrap()
//!                 .build()
//!                 .unwrap(),
//!         )
//!         .unwrap()
//!         .add_level(
//!             LevelBuilder::default()
//!                 .visitor_threshold(5000)
//!                 .difficulty_factor(50000)
//!                 .unwrap()
//!                 .build()
//!                 .unwrap(),
//!         )
//!         .unwrap()
//!         .build()
//!         .unwrap();
//!
//!     // create and start MCaptcha actor that uses the above defense configuration
//!     // This is what manages the difficulty factor of sites that an mCaptcha protects
//!     let mcaptcha = MCaptchaBuilder::default()
//!         .defense(defense)
//!         // leaky bucket algorithm's emission interval
//!         .duration(30)
//!         //   .cache(cache)
//!         .build()
//!         .unwrap();
//!
//!     // unique value identifying an MCaptcha actor
//!     let mcaptcha_name = "batsense.net";
//!
//!     // add MCaptcha to Master
//!     let msg = AddSiteBuilder::default()
//!         .id(mcaptcha_name.into())
//!         .mcaptcha(mcaptcha)
//!         .build()
//!         .unwrap();
//!     system.master.send(msg).await.unwrap();
//!
//!     // Get PoW config. Should be called everytime there's a visitor for a
//!     // managed site(here mcaptcha_name)
//!     let work_req = system.get_pow(mcaptcha_name.into()).await.unwrap().unwrap();
//!
//!     // the following computation should be done on the client but for the purpose
//!     // of this illustration, we are going to do it on the server it self
//!     let work = pow
//!         .prove_work(&work_req.string, work_req.difficulty_factor)
//!         .unwrap();
//!
//!     // the payload that the client sends to the server
//!     let payload = Work {
//!         string: work_req.string,
//!         result: work.result,
//!         nonce: work.nonce,
//!         key: mcaptcha_name.into(),
//!     };
//!
//!     // Server evaluates client's work. Returns true if everything
//!     // checksout and Err() if something fishy is happening
//!     let res = system.verify_pow(payload.clone(), "192.168.0.103".into()).await;
//!     assert!(res.is_ok());
//!
//!    // The client should submit the token to the mCaptcha protected service
//!    // The service should validate the token received from the client
//!    // with the mCaptcha server before processing client's
//!    // request
//!
//!    // mcaptcha protected service sends the following paylaod to mCaptcha
//!    // server:
//!    let verify_msg = VerifyCaptchaResult {
//!        token: res.unwrap(),
//!        key: mcaptcha_name.into(),
//!    };
//!
//!    // on mCaptcha server:
//!    let res = system.validate_verification_tokens(verify_msg).await;
//!    // mCaptcha will return true if token is valid and false if
//!    // token is invalid
//!    assert!(res.is_ok());
//!    assert!(res.unwrap());
//!
//!    Ok(())
//! }
//! ```
#![forbid(unsafe_code)]
pub mod defense;
pub mod errors;
pub mod master;

#[cfg(feature = "full")]
pub mod redis;

/// message datatypes to interact with [MCaptcha] actor
pub mod cache;
pub mod mcaptcha;
#[cfg(feature = "full")]
pub mod pow;
#[cfg(feature = "full")]
mod queue;
#[cfg(feature = "full")]
pub mod system;
#[cfg(feature = "full")]
mod utils;

#[cfg(feature = "full")]
pub use crate::cache::hashcache::HashCache;
#[cfg(feature = "full")]
pub use master::embedded::counter::Counter;

pub use crate::defense::{Defense, DefenseBuilder, LevelBuilder};
pub use crate::master::AddVisitorResult;
pub use crate::master::CreateMCaptcha;
pub use crate::mcaptcha::{MCaptcha, MCaptchaBuilder};

#[cfg(feature = "minimal")]
pub mod dev {
    pub use super::AddVisitorResult;
    pub use super::CreateMCaptcha;
    pub use crate::defense;
    pub use crate::defense::{Defense, DefenseBuilder, LevelBuilder};
    pub use crate::mcaptcha;
    pub use crate::mcaptcha::{MCaptcha, MCaptchaBuilder};
}
