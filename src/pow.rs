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
use derive_builder::Builder;
use pow_sha256::{Config, PoW};
use serde::Serialize;

use crate::cache::messages;
use crate::cache::Save;
use crate::errors::*;
use crate::master::Master;

/// PoW Config that will be sent to clients for generating PoW
#[derive(Clone, Serialize, Debug)]
pub struct PoWConfig {
    pub string: String,
    pub difficulty_factor: u32,
}
impl PoWConfig {
    pub fn new(m: u32) -> Self {
        use crate::utils::get_random;

        PoWConfig {
            string: get_random(32),
            difficulty_factor: m,
        }
    }
}

#[derive(Clone, Builder)]
pub struct Actors<T: Save> {
    master: Addr<Master<'static>>,
    cache: Addr<T>,
    pow: Config,
}

impl<T> Actors<T>
where
    T: Save,
    <T as actix::Actor>::Context: ToEnvelope<T, messages::Cache> + ToEnvelope<T, messages::Retrive>,
{
    pub async fn get_pow(&self, id: String) -> Option<PoWConfig> {
        use crate::cache::messages::Cache;
        use crate::master::GetSite;
        use crate::mcaptcha::Visitor;

        let site_addr = self.master.send(GetSite(id)).await.unwrap();
        if site_addr.is_none() {
            return None;
        }
        let difficulty_factor = site_addr.unwrap().send(Visitor).await.unwrap();
        let pow_config = PoWConfig::new(difficulty_factor);
        self.cache
            .send(Cache(pow_config.clone()))
            .await
            .unwrap()
            .unwrap();
        Some(pow_config)
    }

    pub async fn verify_pow(&self, work: Work) -> CaptchaResult<bool> {
        use crate::cache::messages::Retrive;

        let string = work.string.clone();
        let msg = Retrive(string.clone());
        let difficulty = self.cache.send(msg).await.unwrap();
        let pow: PoW<String> = work.into();
        match difficulty {
            Ok(Some(difficulty)) => {
                if self.pow.is_sufficient_difficulty(&pow, difficulty) {
                    Ok(self.pow.is_valid_proof(&pow, &string))
                } else {
                    Err(CaptchaError::InsuffiencientDifficulty)
                }
            }
            Ok(None) => Err(CaptchaError::StringNotFound),
            Err(_) => Err(CaptchaError::Default),
        }
    }
}

#[derive(Clone, Serialize, Debug)]
pub struct Work {
    pub string: String,
    pub result: String,
    pub nonce: u64,
}

impl From<Work> for PoW<String> {
    fn from(w: Work) -> Self {
        use pow_sha256::PoWBuilder;
        PoWBuilder::default()
            .result(w.result)
            .nonce(w.nonce)
            .build()
            .unwrap()
    }
}

#[cfg(test)]
mod tests {

    use pow_sha256::ConfigBuilder;

    use super::*;
    use crate::cache::HashCache;
    use crate::master::*;
    use crate::mcaptcha::tests::*;

    const MCAPTCHA_NAME: &str = "batsense.net";

    async fn boostrap_system() -> Actors<HashCache> {
        let master = Master::new().start();
        let mcaptcha = get_counter().start();
        let pow = get_config();

        let cache = HashCache::default().start();
        let msg = AddSiteBuilder::default()
            .id(MCAPTCHA_NAME.into())
            .addr(mcaptcha.clone())
            .build()
            .unwrap();

        master.send(msg).await.unwrap();

        ActorsBuilder::default()
            .master(master)
            .cache(cache)
            .pow(pow)
            .build()
            .unwrap()
    }

    fn get_config() -> Config {
        ConfigBuilder::default()
            .salt("myrandomsaltisnotlongenoug".into())
            .build()
            .unwrap()
    }

    #[actix_rt::test]
    async fn get_pow_works() {
        let actors = boostrap_system().await;
        let pow = actors.get_pow(MCAPTCHA_NAME.into()).await.unwrap();
        assert_eq!(pow.difficulty_factor, LEVEL_1.0);
    }

    #[actix_rt::test]
    async fn verify_pow_works() {
        let actors = boostrap_system().await;
        let work_req = actors.get_pow(MCAPTCHA_NAME.into()).await.unwrap();
        let config = get_config();

        let work = config
            .prove_work(&work_req.string, work_req.difficulty_factor)
            .unwrap();

        let insufficient_work = config.prove_work(&work_req.string, 1).unwrap();
        let insufficient_work_payload = Work {
            string: work_req.string.clone(),
            result: insufficient_work.result,
            nonce: insufficient_work.nonce,
        };

        let mut payload = Work {
            string: work_req.string,
            result: work.result,
            nonce: work.nonce,
        };

        let res = actors.verify_pow(payload.clone()).await.unwrap();
        assert!(res);

        payload.string = "wrongstring".into();
        let res = actors.verify_pow(payload.clone()).await;
        assert_eq!(res, Err(CaptchaError::StringNotFound));

        let res = actors.verify_pow(insufficient_work_payload.clone()).await;

        assert_eq!(res, Err(CaptchaError::InsuffiencientDifficulty));
    }
}
