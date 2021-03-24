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
//! use m_captcha::{mcaptcha::AddVisitor, MCaptchaBuilder, cache::HashCache, LevelBuilder, DefenseBuilder};
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
//!     mcaptcha.send(AddVisitor).await.unwrap();
//!
//!     Ok(())
//! }
//! ```

use std::time::Duration;

use actix::clock::sleep;
use actix::dev::*;
use serde::{Deserialize, Serialize};

use crate::{
    defense::Defense,
    errors::{CaptchaError, CaptchaResult},
};

/// Builder for [MCaptcha]
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct MCaptchaBuilder {
    visitor_threshold: u32,
    defense: Option<Defense>,
    duration: Option<u64>,
}

impl Default for MCaptchaBuilder {
    fn default() -> Self {
        MCaptchaBuilder {
            visitor_threshold: 0,
            defense: None,
            duration: None,
        }
    }
}

/// This struct represents the mCaptcha state and is used
/// to configure leaky-bucket lifetime and manage defense
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct MCaptcha {
    visitor_threshold: u32,
    defense: Defense,
    duration: u64,
}

impl MCaptchaBuilder {
    /// set defense
    pub fn defense(&mut self, d: Defense) -> &mut Self {
        self.defense = Some(d);
        self
    }

    /// set duration
    pub fn duration(&mut self, d: u64) -> &mut Self {
        self.duration = Some(d);
        self
    }

    /// Builds new [MCaptcha]
    pub fn build(&mut self) -> CaptchaResult<MCaptcha> {
        if self.duration.is_none() {
            Err(CaptchaError::PleaseSetValue("duration".into()))
        } else if self.defense.is_none() {
            Err(CaptchaError::PleaseSetValue("defense".into()))
        } else if self.duration <= Some(0) {
            Err(CaptchaError::CaptchaDurationZero)
        } else {
            let m = MCaptcha {
                duration: self.duration.unwrap(),
                defense: self.defense.clone().unwrap(),
                visitor_threshold: self.visitor_threshold,
            };
            Ok(m)
        }
    }
}

impl MCaptcha {
    /// increments the visitor count by one
    pub fn add_visitor(&mut self) {
        self.visitor_threshold += 1;
        if self.visitor_threshold > self.defense.visitor_threshold() {
            self.defense.tighten_up();
        } else {
            self.defense.loosen_up();
        }
    }

    /// decrements the visitor count by one
    pub fn decrement_visitor(&mut self) {
        if self.visitor_threshold > 0 {
            self.visitor_threshold -= 1;
        }
    }

    /// get current difficulty factor
    pub fn get_difficulty(&self) -> u32 {
        self.defense.get_difficulty()
    }

    /// get [MCaptcha]'s lifetime
    pub fn get_duration(&self) -> u64 {
        self.duration
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
        self.decrement_visitor();
    }
}

/// Message to increment the visitor count
/// returns difficulty factor and lifetime
#[derive(Message)]
#[rtype(result = "AddVisitorResult")]
pub struct AddVisitor;

/// Struct representing the return datatime of
/// [AddVisitor] message. Contains MCaptcha lifetime
/// and difficulty factor
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AddVisitorResult {
    pub duration: u64,
    pub difficulty_factor: u32,
}

impl AddVisitorResult {
    fn new(m: &MCaptcha) -> Self {
        AddVisitorResult {
            duration: m.get_duration(),
            difficulty_factor: m.get_difficulty(),
        }
    }
}

impl Handler<AddVisitor> for MCaptcha {
    type Result = MessageResult<AddVisitor>;

    fn handle(&mut self, _: AddVisitor, ctx: &mut Self::Context) -> Self::Result {
        let addr = ctx.address();

        let duration: Duration = Duration::new(self.duration.clone(), 0);
        let wait_for = async move {
            sleep(duration).await;
            addr.send(DeleteVisitor).await.unwrap();
        }
        .into_actor(self);
        ctx.spawn(wait_for);

        self.add_visitor();
        MessageResult(AddVisitorResult::new(&self))
    }
}

/// Message to get the visitor count
#[derive(Message)]
#[rtype(result = "u32")]
pub struct GetCurrentVisitorCount;

impl Handler<GetCurrentVisitorCount> for MCaptcha {
    type Result = MessageResult<GetCurrentVisitorCount>;

    fn handle(&mut self, _: GetCurrentVisitorCount, _ctx: &mut Self::Context) -> Self::Result {
        MessageResult(self.visitor_threshold)
    }
}

/// Message to stop [MCaptcha]
#[derive(Message)]
#[rtype(result = "()")]
pub struct Stop;

impl Handler<Stop> for MCaptcha {
    type Result = ();

    fn handle(&mut self, _: Stop, ctx: &mut Self::Context) -> Self::Result {
        ctx.stop()
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
    pub const DURATION: u64 = 5;

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
            let _ = addr.send(AddVisitor).await.unwrap();
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

        let mut mcaptcha = addr.send(AddVisitor).await.unwrap();
        assert_eq!(mcaptcha.difficulty_factor, LEVEL_1.0);

        race(addr.clone(), LEVEL_2).await;
        mcaptcha = addr.send(AddVisitor).await.unwrap();
        assert_eq!(mcaptcha.difficulty_factor, LEVEL_2.1);
    }

    #[actix_rt::test]
    async fn counter_defense_loosenup_works() {
        use actix::clock::sleep;
        let addr: MyActor = get_counter().start();

        race(addr.clone(), LEVEL_2).await;
        race(addr.clone(), LEVEL_2).await;
        let mut mcaptcha = addr.send(AddVisitor).await.unwrap();
        assert_eq!(mcaptcha.difficulty_factor, LEVEL_2.1);

        let duration = Duration::new(DURATION, 0);
        sleep(duration).await;

        mcaptcha = addr.send(AddVisitor).await.unwrap();
        assert_eq!(mcaptcha.difficulty_factor, LEVEL_1.1);
    }

    #[test]
    fn test_mcatcptha_builder() {
        let defense = get_defense();
        let m = MCaptchaBuilder::default()
            .duration(0)
            .defense(defense.clone())
            .build();

        assert_eq!(m.err(), Some(CaptchaError::CaptchaDurationZero));

        let m = MCaptchaBuilder::default().duration(30).build();
        assert_eq!(
            m.err(),
            Some(CaptchaError::PleaseSetValue("defense".into()))
        );

        let m = MCaptchaBuilder::default().defense(defense.clone()).build();
        assert_eq!(
            m.err(),
            Some(CaptchaError::PleaseSetValue("duration".into()))
        );
    }

    #[actix_rt::test]
    async fn get_current_visitor_count_works() {
        let addr: MyActor = get_counter().start();

        addr.send(AddVisitor).await.unwrap();
        addr.send(AddVisitor).await.unwrap();
        addr.send(AddVisitor).await.unwrap();
        addr.send(AddVisitor).await.unwrap();
        let count = addr.send(GetCurrentVisitorCount).await.unwrap();

        assert_eq!(count, 4);
    }

    #[actix_rt::test]
    #[should_panic]
    async fn stop_works() {
        let addr: MyActor = get_counter().start();
        addr.send(Stop).await.unwrap();
        addr.send(AddVisitor).await.unwrap();
    }
}
