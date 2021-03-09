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
//! In-memory cache implementation that uses [HashMap]
use std::collections::HashMap;

use actix::prelude::*;

use super::messages::*;
use super::Save;
use crate::errors::*;

#[derive(Clone, Default)]
/// cache datastructure implementing [Save]
pub struct HashCache(HashMap<String, u32>);

impl HashCache {
    // save [PoWConfig] to cache
    fn save(&mut self, config: Cache) -> CaptchaResult<()> {
        self.0.insert(config.string, config.difficulty_factor);
        Ok(())
    }

    // retrive [PoWConfig] from cache. Deletes config post retrival
    fn retrive(&mut self, string: String) -> CaptchaResult<Option<u32>> {
        if let Some(difficulty_factor) = self.remove(&string) {
            Ok(Some(difficulty_factor.to_owned()))
        } else {
            Ok(None)
        }
    }

    // delete [PoWConfig] from cache
    fn remove(&mut self, string: &str) -> Option<u32> {
        self.0.remove(string)
    }
}

impl Save for HashCache {}

impl Actor for HashCache {
    type Context = Context<Self>;
}

/// cache a PoWConfig
impl Handler<Cache> for HashCache {
    type Result = MessageResult<Cache>;
    fn handle(&mut self, msg: Cache, ctx: &mut Self::Context) -> Self::Result {
        use actix::clock::delay_for;
        use std::time::Duration;

        let addr = ctx.address();
        let del_msg = DeleteString(msg.string.clone());

        let duration: Duration = Duration::new(msg.duration.clone(), 0);
        let wait_for = async move {
            delay_for(duration).await;
            addr.send(del_msg).await.unwrap().unwrap();
        }
        .into_actor(self);
        ctx.spawn(wait_for);

        MessageResult(self.save(msg))
    }
}

/// Delte a PoWConfig
impl Handler<DeleteString> for HashCache {
    type Result = MessageResult<DeleteString>;
    fn handle(&mut self, msg: DeleteString, _ctx: &mut Self::Context) -> Self::Result {
        self.remove(&msg.0);
        MessageResult(Ok(()))
    }
}

/// Retrive PoW difficulty_factor for a PoW string
impl Handler<Retrive> for HashCache {
    type Result = MessageResult<Retrive>;
    fn handle(&mut self, msg: Retrive, _ctx: &mut Self::Context) -> Self::Result {
        MessageResult(self.retrive(msg.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcaptcha::VisitorResult;
    use crate::pow::PoWConfig;

    async fn sleep(time: u64) {
        use actix::clock::delay_for;
        use std::time::Duration;

        let duration: Duration = Duration::new(time, 0);
        delay_for(duration).await;
    }

    #[actix_rt::test]
    async fn hashcache_works() {
        const DIFFICULTY_FACTOR: u32 = 54;
        const DURATION: u64 = 5;
        let addr = HashCache::default().start();
        let pow: PoWConfig = PoWConfig::new(DIFFICULTY_FACTOR);
        let visitor_result = VisitorResult {
            difficulty_factor: DIFFICULTY_FACTOR,
            duration: DURATION,
        };
        let string = pow.string.clone();
        let msg = Cache::new(&pow, &visitor_result);

        addr.send(msg).await.unwrap().unwrap();

        let cache_difficulty_factor = addr.send(Retrive(string.clone())).await.unwrap().unwrap();
        assert_eq!(DIFFICULTY_FACTOR, cache_difficulty_factor.unwrap());

        sleep(DURATION + DURATION).await;

        let expired_string = addr.send(Retrive(string)).await.unwrap().unwrap();
        assert_eq!(None, expired_string);
    }
}
