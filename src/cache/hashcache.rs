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

use std::collections::HashMap;

use actix::prelude::*;

use super::messages::*;
use super::Save;
use crate::errors::*;
use crate::pow::PoWConfig;

#[derive(Clone, Default)]
pub struct HashCache(HashMap<String, u32>);

impl HashCache {
    fn save(&mut self, config: PoWConfig) -> CaptchaResult<()> {
        self.0.insert(config.string, config.difficulty_factor);
        Ok(())
    }

    fn retrive(&mut self, string: String) -> CaptchaResult<Option<u32>> {
        if let Some(difficulty_factor) = self.0.get(&string) {
            Ok(Some(difficulty_factor.to_owned()))
        } else {
            Ok(None)
        }
    }
}

/* TODO cache of pow configs need to have lifetimes to prevent replay attacks
 * where lifetime = site's cool down period so that people can't generate pow
 * configs when the site is cool and  use them later with rainbow tables
 * when it's under attack.
 *
 * This comment stays until this feature is implemented.
 */

impl Save for HashCache {}

impl Actor for HashCache {
    type Context = Context<Self>;
}

/// cache a PoWConfig
impl Handler<Cache> for HashCache {
    type Result = MessageResult<Cache>;
    fn handle(&mut self, msg: Cache, _ctx: &mut Self::Context) -> Self::Result {
        MessageResult(self.save(msg.0))
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

    #[actix_rt::test]
    async fn hashcache_works() {
        let addr = HashCache::default().start();
        let cache: PoWConfig = PoWConfig::new(54);
        let string = cache.string.clone();
        addr.send(Cache(cache)).await.unwrap().unwrap();
        let difficulty_factor = addr.send(Retrive(string)).await.unwrap().unwrap();
        assert_eq!(difficulty_factor.unwrap(), 54);
    }
    //
    //    #[actix_rt::test]
    //    async fn counter_defense_loosenup_works() {
    //        use actix::clock::delay_for;
    //        let addr: MyActor = get_counter().start();
    //
    //        race(addr.clone(), LEVEL_2).await;
    //        race(addr.clone(), LEVEL_2).await;
    //        let mut difficulty_factor = addr.send(Visitor).await.unwrap();
    //        assert_eq!(difficulty_factor.difficulty_factor, LEVEL_2.1);
    //
    //        let duration = Duration::new(DURATION, 0);
    //        delay_for(duration).await;
    //
    //        difficulty_factor = addr.send(Visitor).await.unwrap();
    //        assert_eq!(difficulty_factor.difficulty_factor, LEVEL_1.1);
    //    }
}
