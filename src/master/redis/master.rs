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
use actix::dev::*;
use tokio::sync::oneshot;

use crate::errors::*;
use crate::master::messages::{AddSite, AddVisitor};
use crate::master::Master as MasterTrait;
use crate::redis::mcaptcha_redis::MCaptchaRedis;
use crate::redis::RedisConfig;

#[derive(Clone)]
pub struct Master {
    pub redis: MCaptchaRedis,
}

impl Master {
    pub async fn new(redis: RedisConfig) -> CaptchaResult<Self> {
        let redis = MCaptchaRedis::new(redis).await?;
        let master = Self { redis };
        Ok(master)
    }
}

impl MasterTrait for Master {}

impl Actor for Master {
    type Context = Context<Self>;
}

impl Handler<AddVisitor> for Master {
    type Result = MessageResult<AddVisitor>;

    fn handle(&mut self, m: AddVisitor, ctx: &mut Self::Context) -> Self::Result {
        let (tx, rx) = oneshot::channel();

        let con = self.redis.get_client();
        let fut = async move {
            let res = con.add_visitor(m).await;
            let _ = tx.send(res);
        }
        .into_actor(self);
        ctx.wait(fut);
        MessageResult(rx)
    }
}

impl Handler<AddSite> for Master {
    type Result = MessageResult<AddSite>;

    fn handle(&mut self, m: AddSite, ctx: &mut Self::Context) -> Self::Result {
        let (tx, rx) = oneshot::channel();
        let con = self.redis.get_client();
        let fut = async move {
            let res = con.add_mcaptcha(m).await;
            let _ = tx.send(res);
        }
        .into_actor(self);
        ctx.wait(fut);
        MessageResult(rx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::master::embedded::counter::tests::get_mcaptcha;
    use crate::master::redis::master::Master;
    use crate::redis::RedisConfig;

    const REDIS_URL: &str = "redis://127.0.1.1/";

    #[actix_rt::test]
    async fn redis_master_works() {
        const CAPTCHA_NAME: &str = "REDIS_MASTER_CAPTCHA_TEST";
        let master = Master::new(RedisConfig::Single(REDIS_URL.into())).await;
        let sec_master = Master::new(RedisConfig::Single(REDIS_URL.into())).await;
        let r = sec_master.unwrap().redis.get_client();

        assert!(master.is_ok());
        let master = master.unwrap();
        {
            let _ = master.redis.get_client().delete_captcha(CAPTCHA_NAME).await;
        }

        let addr = master.start();

        let mcaptcha = get_mcaptcha();
        let duration = mcaptcha.get_duration();

        let add_mcaptcha_msg = AddSite {
            id: CAPTCHA_NAME.into(),
            mcaptcha,
        };
        addr.send(add_mcaptcha_msg).await.unwrap();

        let add_visitor_msg = AddVisitor(CAPTCHA_NAME.into());
        addr.send(add_visitor_msg).await.unwrap();
        let visitors = r.get_visitors(CAPTCHA_NAME).await.unwrap();
        assert_eq!(visitors, 1);

        let timer_expire = std::time::Duration::new(duration, 0);
        actix::clock::delay_for(timer_expire).await;
        let visitors = r.get_visitors(CAPTCHA_NAME).await.unwrap();
        assert_eq!(visitors, 0);
    }

    #[actix_rt::test]
    async fn race_redis_master() {
        const CAPTCHA_NAME: &str = "REDIS_MASTER_CAPTCHA_RACE";

        let master = Master::new(RedisConfig::Single(REDIS_URL.into())).await;
        let sec_master = Master::new(RedisConfig::Single(REDIS_URL.into())).await;
        let r = sec_master.unwrap().redis.get_client();

        assert!(master.is_ok());
        let master = master.unwrap();
        {
            let _ = master.redis.get_client().delete_captcha(CAPTCHA_NAME).await;
        }

        let addr = master.start();

        let mcaptcha = get_mcaptcha();
        let duration = mcaptcha.get_duration();

        let add_mcaptcha_msg = AddSite {
            id: CAPTCHA_NAME.into(),
            mcaptcha,
        };
        addr.send(add_mcaptcha_msg).await.unwrap();

        let add_visitor_msg = AddVisitor(CAPTCHA_NAME.into());
        for _ in 0..500 {
            addr.send(add_visitor_msg.clone()).await.unwrap();
        }
        let visitors = r.get_visitors(CAPTCHA_NAME).await.unwrap();
        assert_eq!(visitors, 500);

        let timer_expire = std::time::Duration::new(duration, 0);
        actix::clock::delay_for(timer_expire).await;
        let visitors = r.get_visitors(CAPTCHA_NAME).await.unwrap();
        assert_eq!(visitors, 0);
    }
}
