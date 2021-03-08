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
use std::collections::BTreeMap;

use actix::dev::*;
use derive_builder::Builder;

use crate::mcaptcha::MCaptcha;

/// This struct represents the mCaptcha state and is used
/// to configure leaky-bucket lifetime and manage defense
#[derive(Clone)]
pub struct Master<'a> {
    sites: BTreeMap<&'a str, Addr<MCaptcha>>,
}

impl Master<'static> {
    pub fn add_site(&mut self, details: AddSite) {
        self.sites.insert(details.id, details.addr.to_owned());
    }

    pub fn new() -> Self {
        Master {
            sites: BTreeMap::new(),
        }
    }

    pub fn get_site<'a, 'b>(&'a self, id: &'b str) -> Option<&'a Addr<MCaptcha>> {
        self.sites.get(id)
    }
}

impl Actor for Master<'static> {
    type Context = Context<Self>;
}

/// Message to increment the visitor count
#[derive(Message)]
#[rtype(result = "Option<Addr<MCaptcha>>")]
pub struct GetSite(pub String);

impl Handler<GetSite> for Master<'static> {
    type Result = MessageResult<GetSite>;

    fn handle(&mut self, m: GetSite, _ctx: &mut Self::Context) -> Self::Result {
        let addr = self.get_site(&m.0);
        if addr.is_none() {
            return MessageResult(None);
        } else {
            return MessageResult(Some(addr.unwrap().clone()));
        }
    }
}

/// Message to increment the visitor count
#[derive(Message, Builder)]
#[rtype(result = "()")]
pub struct AddSite {
    pub id: &'static str,
    pub addr: Addr<MCaptcha>,
}

impl Handler<AddSite> for Master<'static> {
    type Result = ();

    fn handle(&mut self, m: AddSite, _ctx: &mut Self::Context) -> Self::Result {
        self.add_site(m);
    }
}

///// Message to decrement the visitor count
//#[derive(Message, Deserialize)]
//#[rtype(result = "()")]
//pub struct VerifyPoW {
//    pow: ShaPoW<Vec<u8>>,
//    id: String,
//}
//
//impl Handler<VerifyPoW> for MCaptcha {
//    type Result = ();
//    fn handle(&mut self, msg: VerifyPoW, _ctx: &mut Self::Context) -> Self::Result {
//        self.decrement_visiotr();
//    }
//}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::defense::*;

    //    use crate::cache::HashCache;
    //
    //    // constants for testing
    //    // (visitor count, level)
    const LEVEL_1: (u32, u32) = (50, 50);
    const LEVEL_2: (u32, u32) = (500, 500);
    const DURATION: u64 = 10;

    type MyActor = Addr<MCaptcha>;

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

    fn get_counter() -> MCaptcha {
        use crate::MCaptchaBuilder;

        MCaptchaBuilder::default()
            .defense(get_defense())
            .duration(DURATION)
            .build()
            .unwrap()
    }

    #[actix_rt::test]
    async fn master() {
        let addr = Master::new().start();

        let id = "yo";
        let mcaptcha = get_counter().start();
        let msg = AddSiteBuilder::default()
            .id(id)
            .addr(mcaptcha)
            .build()
            .unwrap();
        addr.send(msg).await.unwrap();
    }
    //
    //    #[actix_rt::test]
    //    async fn counter_defense_loosenup_works() {
    //        use actix::clock::delay_for;
    //        let addr: MyActor = get_counter().start();
    //
    //        race(addr.clone(), LEVEL_2).await;
    //        race(addr.clone(), LEVEL_2).await;
    //        let mut difficulty_factor = addr.send(Visitor).await.unwrap().unwrap();
    //        assert_eq!(difficulty_factor, LEVEL_2.1);
    //
    //        let duration = Duration::new(DURATION, 0);
    //        delay_for(duration).await;
    //
    //        difficulty_factor = addr.send(Visitor).await.unwrap().unwrap();
    //        assert_eq!(difficulty_factor, LEVEL_1.1);
    //    }
}
