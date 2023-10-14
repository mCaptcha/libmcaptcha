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
use std::sync::Arc;

use actix::dev::*;
use mcaptcha_pow_sha256::Config;

use crate::cache::messages::*;
use crate::cache::Save;
use crate::errors::*;
use crate::master::messages::*;
use crate::master::Master;
use crate::pow::*;
use crate::queue::Manager;

pub struct SystemBuilder<T: Save, X: Master> {
    pub master: Option<Addr<X>>,
    cache: Option<Addr<T>>,
    pow: Option<Config>,
    runners: Option<usize>,
    queue_length: Option<usize>,
}

impl<T: Master, S: Save> Default for SystemBuilder<S, T> {
    fn default() -> Self {
        Self {
            pow: None,
            cache: None,
            master: None,
            runners: None,
            queue_length: None,
        }
    }
}

impl<T: Master, S: Save> SystemBuilder<S, T> {
    pub fn master(mut self, m: Addr<T>) -> Self {
        self.master = Some(m);
        self
    }

    pub fn cache(mut self, c: Addr<S>) -> Self {
        self.cache = Some(c);
        self
    }

    pub fn pow(mut self, p: Config) -> Self {
        self.pow = Some(p);
        self
    }

    pub fn runners(mut self, workers: usize) -> Self {
        self.runners = Some(workers);
        self
    }

    pub fn queue_length(mut self, queue_length: usize) -> Self {
        self.queue_length = Some(queue_length);
        self
    }

    pub fn build(self) -> System<S, T> {
        let runners = Manager::new(self.runners.unwrap(), self.queue_length.unwrap());
        System {
            master: self.master.unwrap(),
            pow: Arc::new(self.pow.unwrap()),
            cache: self.cache.unwrap(),
            runners,
        }
    }
}

/// struct describing various bits of data required for an mCaptcha system
pub struct System<T: Save, X: Master> {
    pub master: Addr<X>,
    cache: Addr<T>,
    pow: Arc<Config>,
    runners: Manager,
}

impl<T, X> System<T, X>
where
    T: Save,
    <T as actix::Actor>::Context: ToEnvelope<T, CachePoW>
        + ToEnvelope<T, RetrivePoW>
        + ToEnvelope<T, CacheResult>
        + ToEnvelope<T, VerifyCaptchaResult>,
    X: Master,
    <X as actix::Actor>::Context: ToEnvelope<X, AddVisitor> + ToEnvelope<X, AddSite>,
{
    /// utility function to get difficulty factor of site `id` and cache it
    pub async fn get_pow(&self, id: String) -> CaptchaResult<Option<PoWConfig>> {
        match self.master.send(AddVisitor(id.clone())).await?.await? {
            Ok(Some(mcaptcha)) => {
                let pow_config = PoWConfig::new(mcaptcha.difficulty_factor, self.pow.salt.clone());

                let cache_msg = CachePoWBuilder::default()
                    .string(pow_config.string.clone())
                    .difficulty_factor(mcaptcha.difficulty_factor)
                    .duration(mcaptcha.duration)
                    .key(id)
                    .build()
                    .unwrap();

                self.cache.send(cache_msg).await?.await??;
                Ok(Some(pow_config))
            }
            _ => Ok(None),
        }
    }

    /// utility function to verify [Work]
    pub async fn verify_pow(&self, work: Work, ip: String) -> CaptchaResult<(String, u32)> {
        use crossbeam_channel::TryRecvError;

        let string = work.string.clone();
        let msg = VerifyCaptchaResult {
            token: string.clone(),
            key: work.key.clone(),
        };
        let msg = RetrivePoW(msg);

        let cached_config = self.cache.send(msg).await?.await??;

        if cached_config.is_none() {
            return Err(CaptchaError::StringNotFound);
        }

        let cached_config = cached_config.unwrap();

        if work.key != cached_config.key {
            return Err(CaptchaError::MCaptchaKeyValidationFail);
        }

        let pow = work.into();

        let res_difficulty_factor = cached_config.difficulty_factor;

        let (queued_work, rx) = QueuedWork::new(
            self.pow.clone(),
            pow,
            string,
            cached_config.difficulty_factor,
        );
        self.runners.add(ip, Box::new(queued_work)).await?;
        loop {
            match rx.try_recv() {
                Err(TryRecvError::Empty) => continue,
                Err(TryRecvError::Disconnected) => {
                    return Err(CaptchaError::InsuffiencientDifficulty);
                }
                Ok(t) => {
                    if !t {
                        return Err(CaptchaError::InsuffiencientDifficulty);
                    }
                    break;
                }
            };
        }

        //        if !self
        //            .pow
        //            .is_sufficient_difficulty(&pow, cached_config.difficulty_factor)
        //        {
        //            return Err(CaptchaError::InsuffiencientDifficulty);
        //        }
        //
        //        if !self.pow.is_valid_proof(&pow, &string) {
        //            return Err(CaptchaError::InvalidPoW);
        //        }
        //
        let msg: CacheResult = cached_config.into();
        let res = msg.token.clone();
        self.cache.send(msg).await?.await??;
        Ok((res, res_difficulty_factor))
    }

    /// utility function to validate verification tokens
    pub async fn validate_verification_tokens(
        &self,
        msg: VerifyCaptchaResult,
    ) -> CaptchaResult<bool> {
        self.cache.send(msg).await?.await?
    }
}

#[cfg(test)]
mod tests {

    use mcaptcha_pow_sha256::ConfigBuilder;

    use super::System;
    use super::*;
    use crate::cache::hashcache::HashCache;
    use crate::master::embedded::counter::tests::*;
    use crate::master::embedded::master::Master;

    const MCAPTCHA_NAME: &str = "batsense.net";

    async fn boostrap_system(gc: u64) -> System<HashCache, Master> {
        let master = Master::new(gc).start();
        let mcaptcha = get_mcaptcha();
        let pow = get_config();

        let cache = HashCache::default().start();
        let msg = AddSiteBuilder::default()
            .id(MCAPTCHA_NAME.into())
            .mcaptcha(mcaptcha)
            .build()
            .unwrap();

        master.send(msg).await.unwrap();

        SystemBuilder::default()
            .master(master)
            .cache(cache)
            .pow(pow)
            .runners(2)
            .queue_length(2000)
            .build()
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
        let pow = actors.get_pow(MCAPTCHA_NAME.into()).await.unwrap().unwrap();
        assert_eq!(pow.difficulty_factor, LEVEL_1.0);
    }

    #[actix_rt::test]
    async fn verify_pow_works() {
        // start system
        let actors = boostrap_system(10).await;
        // get work
        let work_req = actors.get_pow(MCAPTCHA_NAME.into()).await.unwrap().unwrap();
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
        let res = actors.verify_pow(payload.clone(), "1".into()).await;
        assert!(res.is_ok());
        let (res, res_difficulty_factor) = res.unwrap();
        assert_eq!(res_difficulty_factor, work_req.difficulty_factor);

        // verify validation token
        let mut verifi_msg = VerifyCaptchaResult {
            token: res,
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
        let res = actors.verify_pow(payload.clone(), "1".into()).await;
        assert_eq!(res, Err(CaptchaError::StringNotFound));

        let insufficient_work_req = actors.get_pow(MCAPTCHA_NAME.into()).await.unwrap().unwrap();
        let insufficient_work = config.prove_work(&insufficient_work_req.string, 1).unwrap();
        let insufficient_work_payload = Work {
            string: insufficient_work_req.string,
            result: insufficient_work.result,
            nonce: insufficient_work.nonce,
            key: MCAPTCHA_NAME.into(),
        };
        let res = actors
            .verify_pow(insufficient_work_payload.clone(), "1".into())
            .await;
        assert_eq!(res, Err(CaptchaError::InsuffiencientDifficulty));

        let sitekeyfail_config = actors.get_pow(MCAPTCHA_NAME.into()).await.unwrap().unwrap();
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

        let res = actors.verify_pow(sitekeyfail, "1".into()).await;
        assert_eq!(res, Err(CaptchaError::MCaptchaKeyValidationFail));
    }
}
