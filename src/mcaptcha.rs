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
//! MCaptcha actor module that manages defense levels
//!
//! ## Usage:
//! ```rust
//! use m_captcha::{message::Visitor, MCaptchaBuilder, cache::HashCache, LevelBuilder, DefenseBuilder};
//! // traits from actix needs to be in scope for starting actor
//! use actix::prelude::*;
//!
//! #[actix_rt::main]
//! async fn main() -> std::io::Result<()> {
//!     // configure defense
//!     let defense = DefenseBuilder::default()
//!         // add as many levels as you see fit
//!         .add_level(
//!             LevelBuilder::default()
//!                 // visitor_threshold is the threshold/limit at which
//!                 // mCaptcha will adjust difficulty levels
//!                 // it is advisable to set small values for the first
//!                 // levels visitor_threshold and difficulty_factor
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
//!     // create and start MCaptcha actor
//!     //let cache = HashCache::default().start();
//!     let mcaptcha = MCaptchaBuilder::default()
//!         .defense(defense)
//!         // leaky bucket algorithm's emission interval
//!         .duration(30)
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

use std::time::Duration;

use actix::dev::*;
use derive_builder::Builder;

use crate::defense::Defense;

/// This struct represents the mCaptcha state and is used
/// to configure leaky-bucket lifetime and manage defense
#[derive(Clone, Debug, Builder)]
pub struct MCaptcha {
    #[builder(default = "0", setter(skip))]
    visitor_threshold: u32,
    defense: Defense,
    duration: u64,
}

impl MCaptcha {
    /// incerment visiotr count by one
    pub fn add_visitor(&mut self) {
        self.visitor_threshold += 1;
        if self.visitor_threshold > self.defense.visitor_threshold() {
            self.defense.tighten_up();
        } else {
            self.defense.loosen_up();
        }
    }

    /// deccerment visiotr count by one
    pub fn decrement_visiotr(&mut self) {
        if self.visitor_threshold > 0 {
            self.visitor_threshold -= 1;
        }
    }

    /// get current difficulty factor
    pub fn get_difficulty(&self) -> u32 {
        self.defense.get_difficulty()
    }
}
impl Actor for MCaptcha {
    type Context = Context<Self>;
}

/// Message to decrement the visitor count
#[derive(Message)]
#[rtype(result = "()")]
struct DeleteVisitor;

impl Handler<DeleteVisitor> for MCaptcha {
    type Result = ();
    fn handle(&mut self, _msg: DeleteVisitor, _ctx: &mut Self::Context) -> Self::Result {
        self.decrement_visiotr();
    }
}

/// Message to increment the visitor count
#[derive(Message)]
#[rtype(result = "u32")]
pub struct Visitor;

impl Handler<Visitor> for MCaptcha {
    type Result = u32;

    fn handle(&mut self, _: Visitor, ctx: &mut Self::Context) -> Self::Result {
        use actix::clock::delay_for;

        let addr = ctx.address();

        let duration: Duration = Duration::new(self.duration.clone(), 0);
        let wait_for = async move {
            delay_for(duration).await;
            addr.send(DeleteVisitor).await.unwrap();
        }
        .into_actor(self);
        ctx.spawn(wait_for);

        self.add_visitor();
        self.get_difficulty()
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::defense::*;

    // constants for testing
    // (visitor count, level)
    pub const LEVEL_1: (u32, u32) = (50, 50);
    pub const LEVEL_2: (u32, u32) = (500, 500);
    pub const DURATION: u64 = 10;

    type MyActor = Addr<MCaptcha>;

    pub fn get_defense() -> Defense {
        DefenseBuilder::default()
            .add_level(
                LevelBuilder::default()
                    .visitor_threshold(LEVEL_1.0)
                    .difficulty_factor(LEVEL_1.1)
                    .unwrap()
                    .build()
                    .unwrap(),
            )
            .unwrap()
            .add_level(
                LevelBuilder::default()
                    .visitor_threshold(LEVEL_2.0)
                    .difficulty_factor(LEVEL_2.1)
                    .unwrap()
                    .build()
                    .unwrap(),
            )
            .unwrap()
            .build()
            .unwrap()
    }

    async fn race(addr: Addr<MCaptcha>, count: (u32, u32)) {
        for _ in 0..count.0 as usize - 1 {
            let _ = addr.send(Visitor).await.unwrap();
        }
    }

    pub fn get_counter() -> MCaptcha {
        MCaptchaBuilder::default()
            .defense(get_defense())
            .duration(DURATION)
            .build()
            .unwrap()
    }

    #[actix_rt::test]
    async fn counter_defense_tightenup_works() {
        let addr: MyActor = get_counter().start();

        let mut difficulty_factor = addr.send(Visitor).await.unwrap();
        assert_eq!(difficulty_factor, LEVEL_1.0);

        race(addr.clone(), LEVEL_2).await;
        difficulty_factor = addr.send(Visitor).await.unwrap();
        assert_eq!(difficulty_factor, LEVEL_2.1);
    }

    #[actix_rt::test]
    async fn counter_defense_loosenup_works() {
        use actix::clock::delay_for;
        let addr: MyActor = get_counter().start();

        race(addr.clone(), LEVEL_2).await;
        race(addr.clone(), LEVEL_2).await;
        let mut difficulty_factor = addr.send(Visitor).await.unwrap();
        assert_eq!(difficulty_factor, LEVEL_2.1);

        let duration = Duration::new(DURATION, 0);
        delay_for(duration).await;

        difficulty_factor = addr.send(Visitor).await.unwrap();
        assert_eq!(difficulty_factor, LEVEL_1.1);
    }
}
