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

mod connection;
mod master;

pub use master::*;
