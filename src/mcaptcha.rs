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

use serde::{Deserialize, Serialize};

use crate::defense::Defense;
use crate::errors::*;

/// Builder for [MCaptcha]
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct MCaptchaBuilder {
    visitor_threshold: u32,
    defense: Option<Defense>,
    duration: Option<u64>,
}

impl Default for MCaptchaBuilder {
    fn default() -> Self {
        MCaptchaBuilder {
            visitor_threshold: 0,
            defense: None,
            duration: None,
        }
    }
}

impl MCaptchaBuilder {
    /// set defense
    pub fn defense(&mut self, d: Defense) -> &mut Self {
        self.defense = Some(d);
        self
    }

    /// set duration
    pub fn duration(&mut self, d: u64) -> &mut Self {
        self.duration = Some(d);
        self
    }

    /// Builds new [MCaptcha]
    pub fn build(self: &mut MCaptchaBuilder) -> CaptchaResult<MCaptcha> {
        if self.duration.is_none() {
            Err(CaptchaError::PleaseSetValue("duration".into()))
        } else if self.defense.is_none() {
            Err(CaptchaError::PleaseSetValue("defense".into()))
        } else if self.duration <= Some(0) {
            Err(CaptchaError::CaptchaDurationZero)
        } else {
            let m = MCaptcha {
                duration: self.duration.unwrap(),
                defense: self.defense.clone().unwrap(),
                visitor_threshold: self.visitor_threshold,
            };
            Ok(m)
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct MCaptcha {
    visitor_threshold: u32,
    defense: Defense,
    duration: u64,
}

impl From<MCaptcha> for crate::master::redis::CreateMCaptcha {
    fn from(m: MCaptcha) -> Self {
        Self {
            levels: m.defense.into(),
            duration: m.duration,
        }
    }
}

impl MCaptcha {
    /// increments the visitor count by one
    #[inline]
    pub fn add_visitor(&mut self) {
        self.visitor_threshold += 1;
        if self.visitor_threshold > self.defense.visitor_threshold() {
            self.defense.tighten_up();
        } else {
            self.defense.loosen_up();
        }
    }

    /// decrements the visitor count by one
    #[inline]
    pub fn decrement_visitor(&mut self) {
        if self.visitor_threshold > 0 {
            self.visitor_threshold -= 1;
        }
    }

    /// decrements the visitor count by specified count
    #[inline]
    pub fn decrement_visitor_by(&mut self, count: u32) {
        if self.visitor_threshold > 0 {
            if self.visitor_threshold >= count {
                self.visitor_threshold -= count;
            } else {
                self.visitor_threshold = 0;
            }
        }
    }

    /// get current difficulty factor
    #[inline]
    pub fn get_difficulty(&self) -> u32 {
        self.defense.get_difficulty()
    }

    /// get [Counter]'s lifetime
    #[inline]
    pub fn get_duration(&self) -> u64 {
        self.duration
    }

    /// get [Counter]'s current visitor_threshold
    #[inline]
    pub fn get_visitors(&self) -> u32 {
        self.visitor_threshold
    }
}
