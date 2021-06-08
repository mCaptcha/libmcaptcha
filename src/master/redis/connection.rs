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

use redis::cluster::ClusterClient;
use redis::RedisError;
//use redis::cluster::ClusterConnection;
use redis::Client;
//use redis::Connection;
use redis::RedisResult;
use redis::Value;
use redis::{aio::Connection, cluster::ClusterConnection};

use crate::errors::*;
use crate::master::{AddSite, AddVisitor, AddVisitorResult, CreateMCaptcha};

pub enum RedisConnection {
    Single(Rc<RefCell<Connection>>),
    Cluster(Rc<RefCell<ClusterConnection>>),
}

#[allow(dead_code)]
const GET: &str = "MCAPTCHA_CACHE.GET";
#[allow(dead_code)]
const ADD_VISITOR: &str = "MCAPTCHA_CACHE.ADD_VISITOR";
#[allow(dead_code)]
const DEL: &str = "MCAPTCHA_CACHE.DELETE_CAPTCHA";
#[allow(dead_code)]
const ADD_CAPTCHA: &str = "MCAPTCHA_CACHE.ADD_CAPTCHA";
#[allow(dead_code)]
const CAPTCHA_EXISTS: &str = "MCAPTCHA_CACHE.CAPTCHA_EXISTS";

const MODULE_NAME: &str = "mcaptcha_cahce";
macro_rules! exec {
    ($cmd:expr, $con:expr) => {
        match *$con {
            RedisConnection::Single(con) => $cmd.query_async(&mut *con.borrow_mut()).await,
            RedisConnection::Cluster(con) => $cmd.query(&mut *con.borrow_mut()),
        }
    };
}

impl RedisConnection {
    pub async fn is_module_loaded(&self) -> CaptchaResult<()> {
        let modules: Vec<Vec<String>> = exec!(redis::cmd("MODULE").arg(&["LIST"]), &self).unwrap();

        for list in modules.iter() {
            match list.iter().find(|module| module.as_str() == MODULE_NAME) {
                Some(_) => (),
                None => return Err(CaptchaError::MCaptchaRedisModuleIsNotLoaded),
            }
        }

        let commands = vec![ADD_VISITOR, ADD_CAPTCHA, DEL, CAPTCHA_EXISTS, GET];

        for cmd in commands.iter() {
            match exec!(redis::cmd("COMMAND").arg(&["INFO", cmd]), &self).unwrap() {
                Value::Bulk(mut val) => {
                    match val.pop() {
                        Some(Value::Nil) => {
                            return Err(CaptchaError::MCaptchaRediSModuleCommandNotFound(
                                cmd.to_string(),
                            ))
                        }
                        _ => (),
                    };
                }

                _ => (),
            };
        }

        Ok(())
    }

    pub async fn add_visitor(&self, msg: AddVisitor) -> CaptchaResult<Option<AddVisitorResult>> {
        let res: String = exec!(redis::cmd(ADD_VISITOR).arg(&[msg.0]), &self)?;
        let res: AddVisitorResult = serde_json::from_str(&res).unwrap();
        Ok(Some(res))
    }

    pub async fn add_mcaptcha(&self, msg: AddSite) -> CaptchaResult<()> {
        let name = msg.id;
        let captcha: CreateMCaptcha = msg.mcaptcha.into();
        let payload = serde_json::to_string(&captcha).unwrap();
        exec!(redis::cmd(ADD_CAPTCHA).arg(&[name, payload]), &self)?;
        Ok(())
    }

    pub async fn check_captcha_exists(&self, captcha: &str) -> CaptchaResult<bool> {
        let exists: usize = exec!(redis::cmd(CAPTCHA_EXISTS).arg(&[captcha]), &self)?;
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

    pub async fn delete_captcha(&self, captcha: &str) -> CaptchaResult<()> {
        exec!(redis::cmd(DEL).arg(&[captcha]), &self)?;
        Ok(())
    }

    pub async fn get_visitors(&self, captcha: &str) -> CaptchaResult<usize> {
        let visitors: usize = exec!(redis::cmd(GET).arg(&[captcha]), &self)?;
        Ok(visitors)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::defense::{Level, LevelBuilder};
    use crate::master::embedded::counter::tests::get_mcaptcha;
    use crate::master::redis::master::{Master, Redis};

    pub async fn connect(redis: &Redis) -> RedisConnection {
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

    const CAPTCHA_NAME: &str = "REDIS_CAPTCHA_TEST";
    const DURATION: usize = 10;

    #[actix_rt::test]
    async fn redis_master_works() {
        let client = redis::Client::open("redis://127.0.0.1/").unwrap();
        let r = connect(&Redis::Single(client)).await;
        {
            let _ = r.delete_captcha(CAPTCHA_NAME).await;
        }
        assert!(r.is_module_loaded().await.is_ok());
        assert!(!r.check_captcha_exists(CAPTCHA_NAME).await.unwrap());
        let add_mcaptcha_msg = AddSite {
            id: CAPTCHA_NAME.into(),
            mcaptcha: get_mcaptcha(),
        };

        assert!(r.add_mcaptcha(add_mcaptcha_msg).await.is_ok());
        assert!(r.check_captcha_exists(CAPTCHA_NAME).await.unwrap());

        let add_visitor_msg = AddVisitor(CAPTCHA_NAME.into());
        assert!(r.add_visitor(add_visitor_msg).await.is_ok());
        let visitors = r.get_visitors(CAPTCHA_NAME).await.unwrap();
        assert_eq!(visitors, 1);

        let add_visitor_msg = AddVisitor(CAPTCHA_NAME.into());
        assert!(r.add_visitor(add_visitor_msg).await.is_ok());
        let visitors = r.get_visitors(CAPTCHA_NAME).await.unwrap();
        assert_eq!(visitors, 2);

        assert!(r.delete_captcha(CAPTCHA_NAME).await.is_ok());
    }
}
