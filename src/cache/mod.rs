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

pub use hashcache::HashCache;
use messages::*;

pub mod hashcache;

pub trait Save: actix::Actor + actix::Handler<Retrive> + actix::Handler<Cache> {}

pub mod messages {
    use crate::pow::PoWConfig;
    use actix::dev::*;

    use crate::errors::*;

    /// Message to decrement the visitor count
    #[derive(Message)]
    #[rtype(result = "CaptchaResult<()>")]
    pub struct Cache(pub PoWConfig);

    /// Message to decrement the visitor count
    #[derive(Message)]
    #[rtype(result = "CaptchaResult<Option<u32>>")]
    pub struct Retrive(pub String);
}
