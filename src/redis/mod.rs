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
//! Redis Client/Connection manager that can handle both single and clustered Redis Instances
use std::cell::RefCell;
use std::rc::Rc;

use redis::cluster::ClusterClient;
use redis::Client;
use redis::FromRedisValue;
use redis::{aio::Connection, cluster::ClusterConnection};

pub mod mcaptcha_redis;
use crate::errors::*;

/// Client configuration
#[derive(Clone)]
pub enum RedisConfig {
    /// Redis server URL
    Single(String),
    /// List of URL of Redis nodes in cluster mode
    Cluster(Vec<String>),
}

impl RedisConfig {
    /// Create Redis connection
    pub fn connect(&self) -> RedisClient {
        match self {
            Self::Single(url) => {
                let client = Client::open(url.as_str()).unwrap();
                RedisClient::Single(client)
            }
            Self::Cluster(nodes) => {
                let cluster_client = ClusterClient::open(nodes.to_owned()).unwrap();
                RedisClient::Cluster(cluster_client)
            }
        }
    }
}

/// Redis connection - manages both single and clustered deployments
pub enum RedisConnection {
    Single(Rc<RefCell<Connection>>),
    Cluster(Rc<RefCell<ClusterConnection>>),
}

impl RedisConnection {
    #[inline]
    /// Get client. Uses interior mutability, so lookout for panics
    pub fn get_client(&self) -> Self {
        match self {
            Self::Single(con) => Self::Single(Rc::clone(&con)),
            Self::Cluster(con) => Self::Cluster(Rc::clone(&con)),
        }
    }
    #[inline]
    /// execute a redis command against a [Self]
    pub async fn exec<T: FromRedisValue>(&self, cmd: &mut redis::Cmd) -> redis::RedisResult<T> {
        match self {
            RedisConnection::Single(con) => cmd.query_async(&mut *con.borrow_mut()).await,
            RedisConnection::Cluster(con) => cmd.query(&mut *con.borrow_mut()),
        }
    }
}

#[derive(Clone)]
/// Client Configuration that can be used to get new connection shuld [RedisConnection] fail
pub enum RedisClient {
    Single(Client),
    Cluster(ClusterClient),
}

/// A Redis Client Object that encapsulates [RedisClient] and [RedisConnection].
/// Use this when you need a Redis Client
pub struct Redis {
    _client: RedisClient,
    connection: RedisConnection,
}

impl Redis {
    /// create new [Redis]. Will try to connect to Redis instance specified in [RedisConfig]
    pub async fn new(redis: RedisConfig) -> CaptchaResult<Self> {
        let (_client, connection) = Self::connect(redis).await;
        let master = Self {
            _client,
            connection,
        };
        Ok(master)
    }

    /// Get client to do interact with Redis server.
    ///
    /// Uses Interior mutability so look out for panics
    pub fn get_client(&self) -> RedisConnection {
        self.connection.get_client()
    }

    async fn connect(redis: RedisConfig) -> (RedisClient, RedisConnection) {
        let redis = redis.connect();
        let client = match &redis {
            RedisClient::Single(c) => {
                let con = c.get_async_connection().await.unwrap();
                RedisConnection::Single(Rc::new(RefCell::new(con)))
            }
            RedisClient::Cluster(c) => {
                let con = c.get_connection().unwrap();
                RedisConnection::Cluster(Rc::new(RefCell::new(con)))
            }
        };
        (redis, client)
    }
}
