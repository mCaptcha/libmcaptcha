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
//!     let cache = HashCache::default().start();
//!     let mcaptcha = MCaptchaBuilder::default()
//!         .defense(defense)
//!         // leaky bucket algorithm's emission interval
//!         .duration(30)
//!         .cache(cache)
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

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use actix::dev::*;
use actix::prelude::*;
use async_trait::async_trait;
use derive_builder::Builder;
use pow_sha256::PoW as ShaPoW;
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use serde::{Deserialize, Serialize};

use crate::defense::Defense;
use crate::errors::*;
use crate::hashcache::*;

//#[async_trait]
//pub trait PersistPow {
//    async fn save(&mut self, config: Arc<PoWConfig>) -> CaptchaResult<()>;
//    async fn retrive(&mut self, string: &str) -> CaptchaResult<Option<u32>>;
//}

pub trait Save: actix::Actor + actix::Handler<Retrive> + actix::Handler<Cache> {}

/// This struct represents the mCaptcha state and is used
/// to configure leaky-bucket lifetime and manage defense
#[derive(Clone, Builder)]
pub struct MCaptcha<T>
where
    //     Actor + Handler<Cache>,
    T: Save,
    <T as Actor>::Context: ToEnvelope<T, Retrive> + ToEnvelope<T, Cache>,
    //    <T as Actor>::Context: ToEnvelope<T, Cache>,
{
    #[builder(default = "0", setter(skip))]
    visitor_threshold: u32,
    defense: Defense,
    duration: u64,
    cache: Addr<T>,
}

//#[async_trait]
//impl PersistPow for HashCache {
//    async fn save(&mut self, config: Arc<PoWConfig>) -> CaptchaResult<()> {
//        self.insert(config.string.clone(), config.difficulty_factor);
//        Ok(())
//    }
//
//    async fn retrive(&mut self, string: &str) -> CaptchaResult<Option<u32>> {
//        if let Some(difficulty_factor) = self.get(string) {
//            Ok(Some(difficulty_factor.to_owned()))
//        } else {
//            Ok(None)
//        }
//    }
//}

impl<T> MCaptcha<T>
where
    T: Save,
    <T as Actor>::Context: ToEnvelope<T, Retrive> + ToEnvelope<T, Cache>,
{
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

    //    /// cache PoW configuration: difficulty and string
    //    pub async fn cache_pow(&mut self, pow: Arc<PoWConfig>) -> CaptchaResult<()> {
    //        unimplemented!();
    //        Ok(self.cache.save(pow).await?)
    //    }
    //
    //    /// retrivee PoW configuration: difficulty and string
    //    pub async fn retrive_pow(&mut self, pow: &PoWConfig) -> CaptchaResult<Option<u32>> {
    //        unimplemented!();
    //        Ok(self.cache.retrive(&pow.string).await?)
    //    }
}
impl<T> Actor for MCaptcha<T>
where
    T: Save,
    <T as Actor>::Context: ToEnvelope<T, Retrive> + ToEnvelope<T, Cache>,
{
    type Context = Context<Self>;
}

/// Message to decrement the visitor count
#[derive(Message)]
#[rtype(result = "()")]
struct DeleteVisitor;

impl<T> Handler<DeleteVisitor> for MCaptcha<T>
where
    T: Save,
    <T as Actor>::Context: ToEnvelope<T, Retrive> + ToEnvelope<T, Cache>,
{
    type Result = ();
    fn handle(&mut self, _msg: DeleteVisitor, _ctx: &mut Self::Context) -> Self::Result {
        self.decrement_visiotr();
    }
}

/// PoW Config that will be sent to clients for generating PoW
#[derive(Clone, Serialize, Debug)]
pub struct PoWConfig {
    pub string: String,
    pub difficulty_factor: u32,
}

impl PoWConfig {
    pub fn new<T>(m: &MCaptcha<T>) -> Self
    where
        T: Save,
        <T as Actor>::Context: ToEnvelope<T, Retrive> + ToEnvelope<T, Cache>,
    {
        PoWConfig {
            string: thread_rng().sample_iter(&Alphanumeric).take(32).collect(),
            difficulty_factor: m.get_difficulty(),
        }
    }
}

/// Message to increment the visitor count
#[derive(Message)]
#[rtype(result = "CaptchaResult<PoWConfig>")]
//#[rtype(result = "()")]
pub struct Visitor;

impl<T> Handler<Visitor> for MCaptcha<T>
where
    T: Save,
    <T as Actor>::Context: ToEnvelope<T, Retrive> + ToEnvelope<T, Cache>,
{
    type Result = ResponseActFuture<Self, CaptchaResult<PoWConfig>>;
    fn handle(&mut self, _: Visitor, ctx: &mut Self::Context) -> Self::Result {
        use crate::hashcache::Cache;
        use actix::clock::delay_for;
        use actix::fut::wrap_future;

        let addr = ctx.address();

        let duration: Duration = Duration::new(self.duration.clone(), 0);
        let wait_for = async move {
            delay_for(duration).await;
            addr.send(DeleteVisitor).await.unwrap();
        }
        .into_actor(self);
        ctx.spawn(wait_for);

        self.add_visitor();
        let res = Arc::new(PoWConfig::new(&self));

        let act_fut = wrap_future::<_, Self>(self.cache.send(Cache(res.clone()))).map(
            |result, _actor, _ctx| match result {
                Ok(Ok(())) => Ok(Arc::try_unwrap(res).unwrap()),
                Ok(Err(e)) => Err(e),
                Err(_) => Err(CaptchaError::MailboxError), //TODO do typecasting from mailbox error to captcha error
            },
        );
        Box::pin(act_fut)
    }
}

/// Message to decrement the visitor count
#[derive(Message, Deserialize)]
#[rtype(result = "()")]
pub struct VerifyPoW {
    pow: ShaPoW<Vec<u8>>,
    id: String,
}

impl<T> Handler<VerifyPoW> for MCaptcha<T>
where
    T: Save,
    <T as Actor>::Context: ToEnvelope<T, Retrive> + ToEnvelope<T, Cache>,
{
    type Result = ();
    fn handle(&mut self, msg: VerifyPoW, _ctx: &mut Self::Context) -> Self::Result {
        self.decrement_visiotr();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::defense::*;

    // constants for testing
    // (visitor count, level)
    const LEVEL_1: (u32, u32) = (50, 50);
    const LEVEL_2: (u32, u32) = (500, 500);
    const DURATION: u64 = 10;

    type MyActor = Addr<MCaptcha<HashCache>>;
    type CacheAddr = Addr<HashCache>;

    fn get_defense() -> Defense {
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

    async fn race<T>(addr: Addr<MCaptcha<T>>, count: (u32, u32))
    where
        //     Actor + Handler<Cache>,
        T: Save,
        <T as Actor>::Context: ToEnvelope<T, Retrive> + ToEnvelope<T, Cache>,
    {
        for _ in 0..count.0 as usize - 1 {
            let _ = addr.send(Visitor).await.unwrap();
        }
    }

    fn get_counter() -> MCaptcha<crate::cache::HashCache> {
        use actix::prelude::*;
        let cache: CacheAddr = HashCache::default().start();
        MCaptchaBuilder::default()
            .defense(get_defense())
            .cache(cache)
            .duration(DURATION)
            .build()
            .unwrap()
    }

    #[actix_rt::test]
    async fn counter_defense_tightenup_works() {
        let addr: MyActor = get_counter().start();

        let mut difficulty_factor = addr.send(Visitor).await.unwrap().unwrap();
        assert_eq!(difficulty_factor.difficulty_factor, LEVEL_1.0);

        race(addr.clone(), LEVEL_2).await;
        difficulty_factor = addr.send(Visitor).await.unwrap().unwrap();
        assert_eq!(difficulty_factor.difficulty_factor, LEVEL_2.1);
    }

    #[actix_rt::test]
    async fn counter_defense_loosenup_works() {
        use actix::clock::delay_for;
        let addr: MyActor = get_counter().start();

        race(addr.clone(), LEVEL_2).await;
        race(addr.clone(), LEVEL_2).await;
        let mut difficulty_factor = addr.send(Visitor).await.unwrap().unwrap();
        assert_eq!(difficulty_factor.difficulty_factor, LEVEL_2.1);

        let duration = Duration::new(DURATION, 0);
        delay_for(duration).await;

        difficulty_factor = addr.send(Visitor).await.unwrap().unwrap();
        assert_eq!(difficulty_factor.difficulty_factor, LEVEL_1.1);
    }
}
