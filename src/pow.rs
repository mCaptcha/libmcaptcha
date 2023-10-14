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
//! PoW datatypes used in client-server interaction
use std::sync::Arc;

use crossbeam_channel::{self, Receiver, Sender};
use log::debug;
use mcaptcha_pow_sha256::Config;
pub use mcaptcha_pow_sha256::ConfigBuilder;
use mcaptcha_pow_sha256::PoW;
use serde::{Deserialize, Serialize};

use crate::queue::Runnable;

/// PoW requirement datatype that is be sent to clients for generating PoW
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct PoWConfig {
    pub string: String,
    pub difficulty_factor: u32,
    pub salt: String,
}
impl PoWConfig {
    /// create new instance of [PoWConfig]
    pub fn new(difficulty_factor: u32, salt: String) -> Self {
        use crate::utils::get_random;

        PoWConfig {
            string: get_random(32),
            difficulty_factor,
            salt,
        }
    }
}

/// PoW datatype that clients send to server
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Work {
    pub string: String,
    pub result: String,
    pub nonce: u64,
    pub key: String,
}

impl From<Work> for PoW<String> {
    fn from(w: Work) -> Self {
        use mcaptcha_pow_sha256::PoWBuilder;
        PoWBuilder::default()
            .result(w.result)
            .nonce(w.nonce)
            .build()
            .unwrap()
    }
}

#[derive(Debug)]
pub struct QueuedWork {
    tx: Sender<bool>,
    pow: Arc<Config>,
    work: PoW<String>,
    string: String,
    difficulty_factor: u32,
}

impl QueuedWork {
    pub fn new(
        pow: Arc<Config>,
        work: PoW<String>,
        string: String,
        difficulty_factor: u32,
    ) -> (Self, Receiver<bool>) {
        let (tx, rx) = crossbeam_channel::bounded(2);
        (
            Self {
                tx,
                pow,
                work,
                difficulty_factor,
                string,
            },
            rx,
        )
    }
    fn validate(&self) {
        if !self
            .pow
            .is_sufficient_difficulty(&self.work, self.difficulty_factor)
        {
            if let Err(e) = self.tx.send(false) {
                debug!("[ERROR] unable to send work result: {e}");
            }
        }

        if !self.pow.is_valid_proof(&self.work, &self.string) {
            if let Err(e) = self.tx.send(false) {
                debug!("[ERROR] unable to send work result: {e}");
            }
        }

        if let Err(e) = self.tx.send(true) {
            debug!("[ERROR] unable to send work result: {e}");
        }
    }
}

impl Runnable for QueuedWork {
    fn run(&self) {
        self.validate()
    }
}
