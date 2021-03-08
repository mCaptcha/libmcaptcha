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
//! [Master] actor module that manages [MCaptcha] actors
use std::collections::BTreeMap;

use actix::dev::*;
use derive_builder::Builder;

use crate::mcaptcha::MCaptcha;

/// This Actor manages the [MCaptcha] actors.
/// A service can have several [MCaptcha] actors with
/// varying [Defense][crate::defense::Defense] configurations
/// so a "master" actor is needed to manage them all
#[derive(Clone)]
pub struct Master<'a> {
    sites: BTreeMap<&'a str, Addr<MCaptcha>>,
}

impl Master<'static> {
    /// add [MCaptcha] actor to [Master]
    pub fn add_site(&mut self, details: AddSite) {
        self.sites.insert(details.id, details.addr.to_owned());
    }

    /// create new master
    pub fn new() -> Self {
        Master {
            sites: BTreeMap::new(),
        }
    }

    /// get [MCaptcha] actor from [Master]
    pub fn get_site<'a, 'b>(&'a self, id: &'b str) -> Option<&'a Addr<MCaptcha>> {
        self.sites.get(id)
    }
}

impl Actor for Master<'static> {
    type Context = Context<Self>;
}

/// Message to get an [MCaptcha] actor from master
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

/// Message to add an [MCaptcha] actor to [Master]
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcaptcha::tests::*;

    #[actix_rt::test]
    async fn master_actor_works() {
        let addr = Master::new().start();

        let id = "yo";
        let mcaptcha = get_counter().start();
        let msg = AddSiteBuilder::default()
            .id(id)
            .addr(mcaptcha.clone())
            .build()
            .unwrap();
        addr.send(msg).await.unwrap();

        let mcaptcha_addr = addr.send(GetSite(id.into())).await.unwrap();
        assert_eq!(mcaptcha_addr, Some(mcaptcha));

        let addr_doesnt_exist = addr.send(GetSite("a".into())).await.unwrap();
        assert!(addr_doesnt_exist.is_none());
    }
}
