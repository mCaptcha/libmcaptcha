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
//! Cache implementation that uses Redis
use actix::prelude::*;
use tokio::sync::oneshot;

use super::messages::*;
use super::AddChallenge;
use super::Save;
use crate::errors::*;
use crate::redis::mcaptcha_redis::MCaptchaRedis;
use crate::redis::RedisConfig;

pub struct RedisCache(MCaptchaRedis);

impl RedisCache {
    pub async fn new(redis: RedisConfig) -> CaptchaResult<Self> {
        let redis = MCaptchaRedis::new(redis).await?;
        let master = Self(redis);
        Ok(master)
    }
}

impl Save for RedisCache {}

impl Actor for RedisCache {
    type Context = Context<Self>;
}

/// cache a PoWConfig
impl Handler<CachePoW> for RedisCache {
    type Result = MessageResult<CachePoW>;
    fn handle(&mut self, msg: CachePoW, ctx: &mut Self::Context) -> Self::Result {
        let (tx, rx) = oneshot::channel();

        let con = self.0.get_client();
        let fut = async move {
            let payload: AddChallenge = AddChallenge {
                challenge: msg.string,
                difficulty: msg.difficulty_factor,
                duration: msg.duration,
            };

            let res = con.add_challenge(&msg.key, &payload).await;
            tx.send(res).unwrap();
        }
        .into_actor(self);
        ctx.wait(fut);

        MessageResult(rx)
    }
}

/// Retrive PoW difficulty_factor for a PoW string
impl Handler<RetrivePoW> for RedisCache {
    type Result = MessageResult<RetrivePoW>;
    fn handle(&mut self, msg: RetrivePoW, ctx: &mut Self::Context) -> Self::Result {
        let (tx, rx) = oneshot::channel();
        let con = self.0.get_client();

        let fut = async move {
            let r = match con.get_challenge(&msg.0).await {
                Err(e) => Err(e),
                Ok(val) => {
                    let res = CachedPoWConfig {
                        duration: val.duration,
                        difficulty_factor: val.difficulty_factor,
                        key: msg.0.key,
                    };
                    Ok(Some(res))
                }
            };

            tx.send(r).unwrap();
        }
        .into_actor(self);
        ctx.wait(fut);
        MessageResult(rx)
    }
}

/// cache PoW result
impl Handler<CacheResult> for RedisCache {
    type Result = MessageResult<CacheResult>;
    fn handle(&mut self, msg: CacheResult, ctx: &mut Self::Context) -> Self::Result {
        let (tx, rx) = oneshot::channel();

        let con = self.0.get_client();
        let fut = async move {
            let r = con.add_token(&msg).await;
            tx.send(r).unwrap();
        }
        .into_actor(self);
        ctx.wait(fut);
        MessageResult(rx)
    }
}

/// Retrive PoW difficulty_factor for a PoW string
impl Handler<VerifyCaptchaResult> for RedisCache {
    type Result = MessageResult<VerifyCaptchaResult>;
    fn handle(&mut self, msg: VerifyCaptchaResult, ctx: &mut Self::Context) -> Self::Result {
        let (tx, rx) = oneshot::channel();

        let con = self.0.get_client();
        let fut = async move {
            let r = con.get_token(&msg).await;
            tx.send(r).unwrap();
        }
        .into_actor(self);
        ctx.wait(fut);

        MessageResult(rx)
    }
}

/// Delte a PoWConfig
impl Handler<DeleteCaptchaResult> for RedisCache {
    type Result = MessageResult<DeleteCaptchaResult>;
    fn handle(&mut self, _msg: DeleteCaptchaResult, _ctx: &mut Self::Context) -> Self::Result {
        MessageResult(Ok(()))
    }
}

/// Delte a PoWConfig
impl Handler<DeletePoW> for RedisCache {
    type Result = MessageResult<DeletePoW>;
    fn handle(&mut self, _msg: DeletePoW, _ctx: &mut Self::Context) -> Self::Result {
        //self.remove_pow_config(&msg.0);
        MessageResult(Ok(()))
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    use std::time::Duration;

    use actix::clock::sleep;
    //use crate::master::AddVisitorResult;
    //use crate::pow::PoWConfig;

    //   async fn sleep(time: u64) {
    //       //use actix::clock::sleep;
    //       use actix::clock::delay_for;
    //       use std::time::Duration;

    //       let duration: Duration = Duration::new(time, 0);
    //       //sleep(duration).await;
    //       delay_for(duration).await;
    //   }

    const REDIS_URL: &str = "redis://127.0.1.1/";

    #[actix_rt::test]
    async fn rediscache_pow_cache_works() {
        const DIFFICULTY_FACTOR: u32 = 54;
        const DURATION: u64 = 5;
        const KEY: &str = "mcaptchakey";
        const CHALLENGE: &str = "redischallenge1";

        let addr = RedisCache::new(RedisConfig::Single(REDIS_URL.into()))
            .await
            .unwrap()
            .start();

        let msg = CachePoWBuilder::default()
            .string(CHALLENGE.into())
            .difficulty_factor(DIFFICULTY_FACTOR)
            .duration(DURATION)
            .key(KEY.into())
            .build()
            .unwrap();

        addr.send(msg.clone())
            .await
            .unwrap()
            .await
            .unwrap()
            .unwrap();

        let msg = VerifyCaptchaResult {
            token: CHALLENGE.into(),
            key: KEY.into(),
        };

        let cache_difficulty_factor = addr
            .send(RetrivePoW(msg.clone()))
            .await
            .unwrap()
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            DIFFICULTY_FACTOR,
            cache_difficulty_factor.unwrap().difficulty_factor
        );

        let duration: Duration = Duration::new(5, 0);
        //delay_for(duration + duration).await;
        sleep(duration + duration).await;

        let expired_string = addr.send(RetrivePoW(msg)).await.unwrap().await.unwrap();
        assert!(expired_string.is_err());
    }

    #[actix_rt::test]
    async fn redishashcache_result_cache_works() {
        use std::time::Duration;
        //use actix::clock::delay_for;

        const DURATION: u64 = 5;
        const KEY: &str = "a";
        const RES: &str = "b";
        let addr = RedisCache::new(RedisConfig::Single(REDIS_URL.into()))
            .await
            .unwrap()
            .start();

        // send value to cache
        // send another value to cache for auto delete
        // verify_captcha_result
        // delete
        // wait for timeout and verify_captcha_result against second value

        let add_cache = CacheResult {
            key: KEY.into(),
            token: RES.into(),
            duration: DURATION,
        };

        addr.send(add_cache).await.unwrap().await.unwrap().unwrap();

        let verify_msg = VerifyCaptchaResult {
            key: KEY.into(),
            token: RES.into(),
        };

        assert!(addr
            .send(verify_msg.clone())
            .await
            .unwrap()
            .await
            .unwrap()
            .unwrap());
        // duplicate
        assert!(!addr.send(verify_msg).await.unwrap().await.unwrap().unwrap());

        let verify_msg = VerifyCaptchaResult {
            key: "cz".into(),
            token: RES.into(),
        };
        assert!(!addr.send(verify_msg).await.unwrap().await.unwrap().unwrap());

        let duration: Duration = Duration::new(5, 0);
        //delay_for(duration + duration).await;
        sleep(duration + duration).await;

        let verify_msg = VerifyCaptchaResult {
            key: KEY.into(),
            token: RES.into(),
        };
        assert!(!addr.send(verify_msg).await.unwrap().await.unwrap().unwrap());
    }
}
