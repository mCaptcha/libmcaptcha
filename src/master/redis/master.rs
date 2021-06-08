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
use std::cell::RefCell;
use std::cell::RefMut;
use std::rc::Rc;
use std::sync::mpsc;

use actix::dev::*;
use redis::cluster::ClusterClient;
use redis::RedisError;
//use redis::cluster::ClusterConnection;
use redis::Client;
//use redis::Connection;
use redis::RedisResult;
use redis::Value;
use redis::{aio::Connection, cluster::ClusterConnection};
use serde::{Deserialize, Serialize};

use crate::defense::Level;
use crate::errors::*;
use crate::master::AddVisitorResult;
use crate::master::{AddSite, AddVisitor, Master as MasterTrait};

use super::connection::RedisConnection;


#[derive(Clone)]
pub enum Redis {
    Single(Client),
    Cluster(ClusterClient),
}

#[derive(Serialize, Deserialize)]
pub struct CreateMCaptcha {
    pub levels: Vec<Level>,
    pub duration: u64,
}
pub struct Master {
    pub redis: Redis,
    pub con: Rc<RedisConnection>,
}

impl Master {
    async fn new(redis: Redis) -> Self {
        let con = Self::connect(&redis).await;
        con.is_module_loaded().await;
        let con = Rc::new(con);
        let master = Self { redis, con };
        master
    }

    async fn connect(redis: &Redis) -> RedisConnection {
        match &redis {
            Redis::Single(c) => {
                let con = c.get_async_connection().await.unwrap();
                RedisConnection::Single(Rc::new(RefCell::new(con)))
            }
            Redis::Cluster(c) => {
                let con = c.get_connection().unwrap();
                RedisConnection::Cluster(Rc::new(RefCell::new(con)))
            }
        }
    }
}

impl MasterTrait for Master {}

impl Actor for Master {
    type Context = Context<Self>;
}

impl Handler<AddVisitor> for Master {
    type Result = MessageResult<AddVisitor>;

    fn handle(&mut self, m: AddVisitor, ctx: &mut Self::Context) -> Self::Result {
        let (tx, rx) = mpsc::channel();

        let con = Rc::clone(&self.con);
        let fut = async move {
            let res = con.add_visitor(m).await;
            tx.send(res).unwrap()
        }
        .into_actor(self);
        ctx.wait(fut);
        MessageResult(rx)
    }
}

impl Handler<AddSite> for Master {
    type Result = ();

    fn handle(&mut self, m: AddSite, ctx: &mut Self::Context) -> Self::Result {
        let (tx, rx) = mpsc::channel();

        let con = Rc::clone(&self.con);
        let fut = async move {
            let res = con.add_mcaptcha(m).await;
            tx.send(res).unwrap();
        }
        .into_actor(self);
        ctx.wait(fut);
    }
}
