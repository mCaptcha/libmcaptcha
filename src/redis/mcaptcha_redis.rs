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
use redis::Value;

use crate::cache::messages::CacheResult;
use crate::cache::messages::VerifyCaptchaResult;
use crate::cache::AddChallenge;
use crate::errors::*;
use crate::master::messages::{AddSite, AddVisitor};
use crate::master::AddVisitorResult;
use crate::master::CreateMCaptcha;
use crate::redis::Redis;
use crate::redis::RedisConfig;
use crate::redis::RedisConnection;

/// Redis instance with mCaptcha Redis module loaded
pub struct MCaptchaRedis(Redis);

/// Connection to Redis instance with mCaptcha Redis module loaded
pub struct MCaptchaRedisConnection(RedisConnection);

const GET: &str = "MCAPTCHA_CACHE.GET";
const ADD_VISITOR: &str = "MCAPTCHA_CACHE.ADD_VISITOR";
const DEL: &str = "MCAPTCHA_CACHE.DELETE_CAPTCHA";
const ADD_CAPTCHA: &str = "MCAPTCHA_CACHE.ADD_CAPTCHA";
const CAPTCHA_EXISTS: &str = "MCAPTCHA_CACHE.CAPTCHA_EXISTS";
const ADD_CHALLENGE: &str = "MCAPTCHA_CACHE.ADD_CHALLENGE";
const GET_CHALLENGE: &str = "MCAPTCHA_CACHE.GET_CHALLENGE";
const DELETE_CHALLENGE: &str = "MCAPTCHA_CACHE.DELETE_CHALLENGE";

const MODULE_NAME: &str = "mcaptcha_cahce";

impl MCaptchaRedis {
    /// Get new [MCaptchaRedis]. Use this when executing commands that are
    /// only supported by mCaptcha Redis module. Internally, when object
    /// is created, checks are performed to check if the module is loaded and if
    /// the required commands are available
    pub async fn new(redis: RedisConfig) -> CaptchaResult<Self> {
        let redis = Redis::new(redis).await?;
        let m = MCaptchaRedis(redis);
        m.get_client().is_module_loaded().await?;
        Ok(m)
    }

    /// Get connection to a Redis instance with mCaptcha Redis module loaded
    ///
    /// Uses interior mutability so look out for panics!
    pub fn get_client(&self) -> MCaptchaRedisConnection {
        MCaptchaRedisConnection(self.0.get_client())
    }
}

impl MCaptchaRedisConnection {
    async fn is_module_loaded(&self) -> CaptchaResult<()> {
        let modules: Vec<Vec<String>> = self
            .0
            .exec(redis::cmd("MODULE").arg(&["LIST"]))
            .await
            .unwrap();

        for list in modules.iter() {
            match list.iter().find(|module| module.as_str() == MODULE_NAME) {
                Some(_) => (),
                None => return Err(CaptchaError::MCaptchaRedisModuleIsNotLoaded),
            }
        }

        let commands = vec![
            ADD_VISITOR,
            ADD_CAPTCHA,
            DEL,
            CAPTCHA_EXISTS,
            GET,
            ADD_CHALLENGE,
            GET_CHALLENGE,
            DELETE_CHALLENGE,
        ];

        for cmd in commands.iter() {
            if let Value::Bulk(mut val) = self
                .0
                .exec(redis::cmd("COMMAND").arg(&["INFO", cmd]))
                .await
                .unwrap()
            {
                if let Some(Value::Nil) = val.pop() {
                    return Err(CaptchaError::MCaptchaRediSModuleCommandNotFound(
                        cmd.to_string(),
                    ));
                };
            };
        }

        Ok(())
    }

    /// Add visitor
    pub async fn add_visitor(&self, msg: AddVisitor) -> CaptchaResult<Option<AddVisitorResult>> {
        let res: String = self.0.exec(redis::cmd(ADD_VISITOR).arg(&[msg.0])).await?;
        let res: AddVisitorResult = serde_json::from_str(&res).unwrap();
        Ok(Some(res))
    }

    /// Register new mCaptcha with Redis
    pub async fn add_mcaptcha(&self, msg: AddSite) -> CaptchaResult<()> {
        let name = msg.id;
        let captcha: CreateMCaptcha = msg.mcaptcha.into();
        let payload = serde_json::to_string(&captcha).unwrap();
        self.0
            .exec(redis::cmd(ADD_CAPTCHA).arg(&[name, payload]))
            .await?;
        Ok(())
    }

    /// Check if an mCaptcha object is available in Redis
    pub async fn check_captcha_exists(&self, captcha: &str) -> CaptchaResult<bool> {
        let exists: usize = self
            .0
            .exec(redis::cmd(CAPTCHA_EXISTS).arg(&[captcha]))
            .await?;
        if exists == 1 {
            Ok(false)
        } else if exists == 0 {
            Ok(true)
        } else {
            log::error!(
                "mCaptcha redis module responded with {} when for {}",
                exists,
                CAPTCHA_EXISTS
            );
            Err(CaptchaError::MCaptchaRedisModuleError)
        }
    }

    /// Delete an mCaptcha object from Redis
    pub async fn delete_captcha(&self, captcha: &str) -> CaptchaResult<()> {
        self.0.exec(redis::cmd(DEL).arg(&[captcha])).await?;
        Ok(())
    }

    /// Add PoW Challenge object to Redis
    pub async fn add_challenge(
        &self,
        captcha: &str,
        challlenge: &AddChallenge,
    ) -> CaptchaResult<()> {
        let payload = serde_json::to_string(challlenge).unwrap();
        self.0
            .exec(redis::cmd(ADD_CHALLENGE).arg(&[captcha, &payload]))
            .await?;
        Ok(())
    }

    /// Get PoW Challenge object from Redis
    pub async fn get_challenge(
        &self,
        msg: &VerifyCaptchaResult,
    ) -> CaptchaResult<AddVisitorResult> {
        let challege: String = self
            .0
            .exec(redis::cmd(GET_CHALLENGE).arg(&[&msg.key, &msg.token]))
            .await?;
        Ok(serde_json::from_str(&challege).unwrap())
    }

    /// Get PoW Challenge object from Redis
    pub async fn delete_challenge(&self, msg: &VerifyCaptchaResult) -> CaptchaResult<()> {
        let _: () = self
            .0
            .exec(redis::cmd(DELETE_CHALLENGE).arg(&[&msg.key, &msg.token]))
            .await?;
        Ok(())
    }

    /// Get number of visitors of an mCaptcha object from Redis
    pub async fn get_visitors(&self, captcha: &str) -> CaptchaResult<usize> {
        let visitors: usize = self.0.exec(redis::cmd(GET).arg(&[captcha])).await?;
        Ok(visitors)
    }

    /// Add PoW Token object to Redis
    pub async fn add_token(&self, msg: &CacheResult) -> CaptchaResult<()> {
        use redis::RedisResult;
        // mcaptcha:token:captcha::token
        let key = format!("mcaptcha:token:{}:{}", &msg.key, &msg.token);
        let e: RedisResult<()> = self
            .0
            .exec(redis::cmd("SET").arg(&[&key, &msg.key, "EX", msg.duration.to_string().as_str()]))
            .await;
        if let Err(e) = e {
            panic!("{}", e);
        }
        Ok(())
    }

    /// Get PoW Token object to Redis
    pub async fn get_token(&self, msg: &VerifyCaptchaResult) -> CaptchaResult<bool> {
        //use redis::RedisResult;
        // mcaptcha:token:captcha::token
        let key = format!("mcaptcha:token:{}:{}", &msg.key, &msg.token);
        let res = self.0.exec(redis::cmd("DEL").arg(&[&key])).await?;
        println!("{}", res);
        match res {
            1 => Ok(true),
            0 => Ok(false),
            _ => Err(CaptchaError::MCaptchaRedisModuleError),
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::master::embedded::counter::tests::get_mcaptcha;
    use crate::redis::*;

    const CAPTCHA_NAME: &str = "REDIS_CAPTCHA_TEST";
    const REDIS_URL: &str = "redis://127.0.1.1/";
    const CHALLENGE: &str = "randomchallengestring";

    #[actix_rt::test]
    async fn redis_master_works() {
        let redis = Redis::new(RedisConfig::Single(REDIS_URL.into()))
            .await
            .unwrap();

        let r = MCaptchaRedis(redis);
        let r = r.get_client();
        {
            let _ = r.delete_captcha(CAPTCHA_NAME).await;
        }

        let mcaptcha = get_mcaptcha();
        // let duration = mcaptcha.get_duration();

        assert!(r.is_module_loaded().await.is_ok());
        assert!(!r.check_captcha_exists(CAPTCHA_NAME).await.unwrap());
        let add_mcaptcha_msg = AddSite {
            id: CAPTCHA_NAME.into(),
            mcaptcha,
        };

        assert!(r.add_mcaptcha(add_mcaptcha_msg).await.is_ok());
        assert!(r.check_captcha_exists(CAPTCHA_NAME).await.unwrap());

        let add_visitor_msg = AddVisitor(CAPTCHA_NAME.into());
        assert!(r.add_visitor(add_visitor_msg).await.is_ok());
        let visitors = r.get_visitors(CAPTCHA_NAME).await.unwrap();
        assert_eq!(visitors, 1);

        let add_visitor_msg = AddVisitor(CAPTCHA_NAME.into());
        let resp = r.add_visitor(add_visitor_msg.clone()).await;
        assert!(resp.is_ok());
        assert!(resp.unwrap().is_some());
        let visitors = r.get_visitors(CAPTCHA_NAME).await.unwrap();
        assert_eq!(visitors, 2);

        let add_visitor_res = r.add_visitor(add_visitor_msg).await.unwrap().unwrap();
        let add_challenge_msg = AddChallenge {
            difficulty: add_visitor_res.difficulty_factor,
            duration: add_visitor_res.duration,
            challenge: CHALLENGE.into(),
        };

        assert!(r
            .add_challenge(CAPTCHA_NAME, &add_challenge_msg)
            .await
            .is_ok());

        let verify_msg = VerifyCaptchaResult {
            token: CHALLENGE.into(),
            key: CAPTCHA_NAME.into(),
        };
        let x = r.get_challenge(&verify_msg).await.unwrap();
        assert_eq!(x.duration, add_challenge_msg.duration);
        assert_eq!(x.difficulty_factor, add_challenge_msg.difficulty);

        assert!(r
            .add_challenge(CAPTCHA_NAME, &add_challenge_msg)
            .await
            .is_ok());

        assert!(r.delete_challenge(&verify_msg).await.is_ok());

        let add_challenge_msg = CacheResult {
            key: CAPTCHA_NAME.into(),
            token: CHALLENGE.into(),
            duration: 10,
        };

        r.add_token(&add_challenge_msg).await.unwrap();

        let mut challenge_msg = VerifyCaptchaResult {
            key: CAPTCHA_NAME.into(),
            token: CHALLENGE.into(),
        };

        challenge_msg.token = CAPTCHA_NAME.into();
        assert!(!r.get_token(&challenge_msg).await.unwrap());

        challenge_msg.token = CHALLENGE.into();
        assert!(r.get_token(&challenge_msg).await.unwrap());

        assert!(r.delete_captcha(CAPTCHA_NAME).await.is_ok());
    }
}
