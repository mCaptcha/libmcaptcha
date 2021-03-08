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
use serde::Serialize;

use crate::cache::messages;
use crate::cache::Save;
use crate::master::Master;

/// PoW Config that will be sent to clients for generating PoW
#[derive(Clone, Serialize, Debug)]
pub struct PoWConfig {
    pub string: String,
    pub difficulty_factor: u32,
}
impl PoWConfig {
    pub fn new(m: u32) -> Self {
        use std::iter;

        use rand::{distributions::Alphanumeric, rngs::ThreadRng, thread_rng, Rng};

        let mut rng: ThreadRng = thread_rng();

        let string = iter::repeat(())
            .map(|()| rng.sample(Alphanumeric))
            .map(char::from)
            .take(32)
            .collect::<String>();

        PoWConfig {
            string,
            difficulty_factor: m,
        }
    }
}

#[derive(Clone, Builder)]
pub struct Actors<T: Save> {
    master: Addr<Master<'static>>,
    cache: Addr<T>,
}

impl<T> Actors<T>
where
    T: Save,
    <T as actix::Actor>::Context: ToEnvelope<T, messages::Cache>,
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::HashCache;
    use crate::master::*;
    use crate::mcaptcha::tests::*;

    #[actix_rt::test]
    async fn get_pow_works() {
        let master = Master::new().start();
        let mcaptcha = get_counter().start();
        let mcaptcha_name = "batsense.net";

        let cache = HashCache::default().start();
        let msg = AddSiteBuilder::default()
            .id(mcaptcha_name.into())
            .addr(mcaptcha.clone())
            .build()
            .unwrap();

        master.send(msg).await.unwrap();

        let actors = ActorsBuilder::default()
            .master(master)
            .cache(cache)
            .build()
            .unwrap();

        let pow = actors.get_pow(mcaptcha_name.into()).await.unwrap();

        assert_eq!(pow.difficulty_factor, LEVEL_1.0);
    }
}
