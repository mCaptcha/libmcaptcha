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
//! module describing mCaptcha system
use actix::dev::*;
use derive_builder::Builder;
use pow_sha256::Config;

use crate::cache::messages::*;
use crate::cache::Save;
use crate::errors::*;
use crate::master::Master;
use crate::pow::*;

/// struct describing various bits of data required for an mCaptcha system
#[derive(Clone, Builder)]
pub struct System<T: Save> {
    pub master: Addr<Master>,
    cache: Addr<T>,
    pow: Config,
}

impl<T> System<T>
where
    T: Save,
    <T as actix::Actor>::Context: ToEnvelope<T, CachePoW>
        + ToEnvelope<T, RetrivePoW>
        + ToEnvelope<T, CacheResult>
        + ToEnvelope<T, VerifyCaptchaResult>,
{
    /// utility function to get difficulty factor of site `id` and cache it
    pub async fn get_pow(&self, id: String) -> Option<PoWConfig> {
        use crate::master::GetSite;
        use crate::mcaptcha::AddVisitor;

        let site_addr = self.master.send(GetSite(id.clone())).await.unwrap();
        if site_addr.is_none() {
            return None;
        }
        let mcaptcha = site_addr.unwrap().send(AddVisitor).await.unwrap();
        let pow_config = PoWConfig::new(mcaptcha.difficulty_factor, self.pow.salt.clone());

        let cache_msg = CachePoWBuilder::default()
            .string(pow_config.string.clone())
            .difficulty_factor(mcaptcha.difficulty_factor)
            .duration(mcaptcha.duration)
            .key(id)
            .build()
            .unwrap();

        self.cache.send(cache_msg).await.unwrap().unwrap();
        Some(pow_config)
    }

    /// utility function to verify [Work]
    pub async fn verify_pow(&self, work: Work) -> CaptchaResult<String> {
        let string = work.string.clone();
        let msg = RetrivePoW(string.clone());

        let cached_config = self.cache.send(msg).await.unwrap()?;

        if cached_config.is_none() {
            return Err(CaptchaError::StringNotFound);
        }

        let cached_config = cached_config.unwrap();

        if work.key != cached_config.key {
            return Err(CaptchaError::MCaptchaKeyValidationFail);
        }

        let pow = work.into();

        if !self
            .pow
            .is_sufficient_difficulty(&pow, cached_config.difficulty_factor)
        {
            return Err(CaptchaError::InsuffiencientDifficulty);
        }

        if !self.pow.is_valid_proof(&pow, &string) {
            return Err(CaptchaError::InvalidPoW);
        }

        let msg: CacheResult = cached_config.into();
        let res = msg.token.clone();
        self.cache.send(msg).await.unwrap()?;
        Ok(res)
    }

    /// utility function to validate verification tokens
    pub async fn validate_verification_tokens(
        &self,
        msg: VerifyCaptchaResult,
    ) -> CaptchaResult<bool> {
        self.cache.send(msg).await.unwrap()
    }
}

#[cfg(test)]
mod tests {

    use pow_sha256::ConfigBuilder;

    use super::System;
    use super::*;
    use crate::cache::HashCache;
    use crate::master::*;
    use crate::mcaptcha::tests::*;

    const MCAPTCHA_NAME: &str = "batsense.net";

    async fn boostrap_system(gc: u64) -> System<HashCache> {
        let master = Master::new(gc).start();
        let mcaptcha = get_counter().start();
        let pow = get_config();

        let cache = HashCache::default().start();
        let msg = AddSiteBuilder::default()
            .id(MCAPTCHA_NAME.into())
            .addr(mcaptcha.clone())
            .build()
            .unwrap();

        master.send(msg).await.unwrap();

        SystemBuilder::default()
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
        let actors = boostrap_system(10).await;
        let pow = actors.get_pow(MCAPTCHA_NAME.into()).await.unwrap();
        assert_eq!(pow.difficulty_factor, LEVEL_1.0);
    }

    #[actix_rt::test]
    async fn verify_pow_works() {
        // start system
        let actors = boostrap_system(10).await;
        // get work
        let work_req = actors.get_pow(MCAPTCHA_NAME.into()).await.unwrap();
        // get config
        let config = get_config();

        // generate proof
        let work = config
            .prove_work(&work_req.string, work_req.difficulty_factor)
            .unwrap();
        // generate proof payload
        let mut payload = Work {
            string: work_req.string,
            result: work.result,
            nonce: work.nonce,
            key: MCAPTCHA_NAME.into(),
        };

        // verifiy proof
        let res = actors.verify_pow(payload.clone()).await;
        assert!(res.is_ok());

        // verify validation token
        let mut verifi_msg = VerifyCaptchaResult {
            token: res.unwrap(),
            key: MCAPTCHA_NAME.into(),
        };
        assert!(actors
            .validate_verification_tokens(verifi_msg.clone())
            .await
            .unwrap());

        // verify wrong validation token
        verifi_msg.token = MCAPTCHA_NAME.into();
        assert!(!actors
            .validate_verification_tokens(verifi_msg)
            .await
            .unwrap());

        payload.string = "wrongstring".into();
        let res = actors.verify_pow(payload.clone()).await;
        assert_eq!(res, Err(CaptchaError::StringNotFound));

        let insufficient_work_req = actors.get_pow(MCAPTCHA_NAME.into()).await.unwrap();
        let insufficient_work = config.prove_work(&insufficient_work_req.string, 1).unwrap();
        let insufficient_work_payload = Work {
            string: insufficient_work_req.string,
            result: insufficient_work.result,
            nonce: insufficient_work.nonce,
            key: MCAPTCHA_NAME.into(),
        };
        let res = actors.verify_pow(insufficient_work_payload.clone()).await;
        assert_eq!(res, Err(CaptchaError::InsuffiencientDifficulty));

        let sitekeyfail_config = actors.get_pow(MCAPTCHA_NAME.into()).await.unwrap();
        let sitekeyfail_work = config
            .prove_work(
                &sitekeyfail_config.string,
                sitekeyfail_config.difficulty_factor,
            )
            .unwrap();

        let sitekeyfail = Work {
            string: sitekeyfail_config.string,
            result: sitekeyfail_work.result,
            nonce: sitekeyfail_work.nonce,
            key: "example.com".into(),
        };

        let res = actors.verify_pow(sitekeyfail).await;
        assert_eq!(res, Err(CaptchaError::MCaptchaKeyValidationFail));
    }
}
