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
use std::sync::mpsc::Receiver;

use actix::dev::*;
use derive_builder::Builder;
use serde::{Deserialize, Serialize};

use crate::errors::CaptchaResult;

pub mod embedded;
#[allow(
    unused_variables,
    unused_imports,
    unused_variables,
    dead_code,
    unused_macros
)]
use crate::mcaptcha::*;
#[allow(
    unused_variables,
    unused_imports,
    unused_variables,
    dead_code,
    unused_macros
)]
pub mod redis;

/// Describes actor handler trait impls that are required by a cache implementation
pub trait Master: actix::Actor + actix::Handler<AddVisitor> + actix::Handler<AddSite> {}

//+ actix::Handler<AddSite>

/// Message to add visitor to an [MCaptcha] actor
#[derive(Message)]
#[rtype(result = "Receiver<CaptchaResult<Option<AddVisitorResult>>>")]
pub struct AddVisitor(pub String);

/// Struct representing the return datatime of
/// [AddVisitor] message. Contains MCaptcha lifetime
/// and difficulty factor
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AddVisitorResult {
    pub duration: u64,
    pub difficulty_factor: u32,
}

/// Message to add an [Counter] actor to [Master]
#[derive(Message, Builder)]
#[rtype(result = "()")]
pub struct AddSite {
    pub id: String,
    pub mcaptcha: MCaptcha,
}

impl AddVisitorResult {
    fn new(m: &MCaptcha) -> Self {
        AddVisitorResult {
            duration: m.get_duration(),
            difficulty_factor: m.get_difficulty(),
        }
    }
}
