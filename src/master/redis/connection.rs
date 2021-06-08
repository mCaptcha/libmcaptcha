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

use super::CreateMCaptcha;
use crate::errors::*;
use crate::master::{AddSite, AddVisitor, AddVisitorResult};

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
    pub async fn is_module_loaded(&self) {
        let modules: Vec<Vec<String>> = exec!(redis::cmd("MODULE").arg(&["LIST"]), &self).unwrap();

        for list in modules.iter() {
            match list.iter().find(|module| module.as_str() == MODULE_NAME) {
                Some(_) => println!("module exists"),
                None => println!("Module doesn't exist"),
            }
        }

        let commands = vec![ADD_VISITOR, ADD_CAPTCHA, DEL, CAPTCHA_EXISTS, GET];

        for cmd in commands.iter() {
            match exec!(redis::cmd("COMMAND").arg(&["INFO", cmd]), &self).unwrap() {
                Value::Bulk(mut val) => {
                    let x = val.pop();
                    match x {
                        Some(Value::Nil) => println!("Command: {} doesn't exist", &cmd),
                        _ => println!("commands {} exists", &cmd),
                    };
                }

                _ => println!("commands exists"),
            };
        }
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
