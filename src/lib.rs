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
//! - [Visitor][crate::message::Visitor]: Smallest unit of traffic, usually a single request. The more you have, the busier
//! your service is. Determines mCaptcha defense defense
//! - Visitor threshold: The threshold at which [MCaptcha] will adjust defense defense
//!
//! ## Example:
//!
//! ```rust
//! use m_captcha::{LevelBuilder, cache::HashCache, DefenseBuilder, message::Visitor, MCaptchaBuilder};
//! // traits from actix needs to be in scope for starting actor
//! use actix::prelude::*;
//!
//! #[actix_rt::main]
//! async fn main() -> std::io::Result<()> {
//!     // configure defense
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
//!     //let cache = HashCache::default().start();
//!
//!     // create and start MCaptcha actor
//!     let mcaptcha = MCaptchaBuilder::default()
//!         .defense(defense)
//!         // leaky bucket algorithm's emission interval
//!         .duration(30)
//!      //   .cache(cache)
//!         .build()
//!         .unwrap()
//!         .start();
//!
//!     // increment count when user visits protected routes
//!     mcaptcha.send(Visitor).await.unwrap();
//!
//!     Ok(())
//! }
//! ```

pub mod defense;
pub mod errors;
pub mod master;
pub mod mcaptcha;

/// message datatypes to interact with [MCaptcha] actor
pub mod message {
    pub use crate::mcaptcha::Visitor;
}

/// message datatypes to interact with [MCaptcha] actor
pub mod cache;
pub mod pow;
mod utils;

pub use crate::cache::hashcache::HashCache;

pub use defense::{Defense, DefenseBuilder, LevelBuilder};
pub use mcaptcha::{MCaptcha, MCaptchaBuilder};
