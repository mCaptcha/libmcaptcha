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
use redis::cluster::ClusterClient;
//use redis::cluster::ClusterConnection;
use redis::Client;
//use redis::Connection;
use redis::RedisResult;
use redis::{aio::Connection, cluster::ClusterConnection};

//use crate::errors::*;
use crate::master::{AddSite, AddVisitor, Master as MasterTrait};

#[derive(Clone)]
pub enum Redis {
    Single(Client),
    Cluster(ClusterClient),
}

pub enum RedisConnection {
    Single(Connection),
    Cluster(ClusterConnection),
}

const INCR: &str = "MCAPTCHA_CACHE.COUNT";
const GET: &str = "MCAPTCHA_CACHE.GET";

#[derive(Clone)]
pub struct Master {
    pub redis: Redis,
}

macro_rules! exec {
    ($cmd:expr, $con:expr) => {
        match $con {
            RedisConnection::Single(mut con) => $cmd.query_async(&mut con).await,
            RedisConnection::Cluster(mut con) => $cmd.query(&mut con),
        }
    };
}

impl Master {
    async fn add_visitor(&mut self, key: &str) {
        let mut cmd = redis::cmd(INCR);
        cmd.arg(&[key]);
        let a: RedisResult<usize> = exec!(cmd, self.get_connection().await);

        unimplemented!("Have to check return types of INCR command")
    }

    async fn get_visitors(&mut self, key: &str) {
        let mut cmd = redis::cmd(GET);
        cmd.arg(&[key]);
        let a: RedisResult<usize> = exec!(cmd, self.get_connection().await);

        unimplemented!("Have to check return types of GET command")
    }

    async fn get_connection(&mut self) -> RedisConnection {
        match &self.redis {
            Redis::Single(c) => {
                let con = c.get_async_connection().await.unwrap();
                RedisConnection::Single(con)
            }
            Redis::Cluster(c) => {
                let con = c.get_connection().unwrap();
                RedisConnection::Cluster(con)
            }
        }
    }

    async fn module_is_loaded(&mut self) -> () {
        let mut cmd = redis::cmd("COMMAND");
        cmd.arg(&["INFO", INCR]);
        let a: RedisResult<usize> = exec!(cmd, self.get_connection().await);

        let mut cmd = redis::cmd("COMMAND");
        cmd.arg(&["INFO", GET]);
        let a: RedisResult<usize> = exec!(cmd, self.get_connection().await);

        unimplemented!("Have to check return types of INFO command")
    }
}

impl MasterTrait for Master {}

impl Actor for Master {
    type Context = Context<Self>;
}

impl Handler<AddVisitor> for Master {
    type Result = MessageResult<AddVisitor>;

    fn handle(&mut self, m: AddVisitor, ctx: &mut Self::Context) -> Self::Result {
        let fut = async {
            self.add_visitor(&m.0).await;
        };
        unimplemented!();
    }
}

impl Handler<AddSite> for Master {
    type Result = ();

    fn handle(&mut self, m: AddSite, _ctx: &mut Self::Context) -> Self::Result {
        unimplemented!();
    }
}

//#[derive(Clone)]
//pub struct Cluster(pub ClusterClient);
//#[derive(Clone)]
//pub struct Single(pub Client);
//
//pub trait Redis: 'static + Unpin + Clone {
//    type Result;
//    fn get_connection(&'static self) -> Self::Result;
//}
//impl Redis for Cluster {
//    type Result = RedisResult<ClusterConnection>;
//    fn get_connection(&self) -> Self::Result {
//        self.0.get_connection()
//    }
//}
//
//impl Redis for Single {
//    type Result = impl Future;
//    fn get_connection(&'static self) -> Self::Result {
//        self.0.get_async_connection()
//    }
//}

//#[derive(Clone)]
//pub struct Master {
//    pub redis: usize,
//}

//impl MasterTrait for Master {}
//
//impl Actor for Master {
//    type Context = Context<Self>;
//}
//
//impl Handler<AddVisitor> for Master {
//    type Result = MessageResult<AddVisitor>;
//
//    fn handle(&mut self, m: AddVisitor, ctx: &mut Self::Context) -> Self::Result {
//        let fut = async {
//            let test = "1";
//        };
//        unimplemented!();
//    }
//}
//
//impl Handler<AddSite> for Master {
//    type Result = ();
//
//    fn handle(&mut self, m: AddSite, _ctx: &mut Self::Context) -> Self::Result {
//        unimplemented!();
//    }
//}

//pub struct Master<T: Redis> {
//    pub redis: T,
//}
//
//impl<T: Redis> MasterTrait for Master<T> {}
//
//impl<T: Redis> Actor for Master<T> {
//    type Context = Context<Self>;
//}
//
//impl<T: Redis> Handler<AddVisitor> for Master<T> {
//    type Result = MessageResult<AddVisitor>;
//
//    fn handle(&mut self, m: AddVisitor, ctx: &mut Self::Context) -> Self::Result {
//        let fut = async {
//            self.redis.get_connection();
//            let test = "1";
//        };
//        unimplemented!();
//    }
//}
//
//impl<T: Redis> Handler<AddSite> for Master<T> {
//    type Result = ();
//
//    fn handle(&mut self, m: AddSite, _ctx: &mut Self::Context) -> Self::Result {
//        unimplemented!();
//    }
//}
