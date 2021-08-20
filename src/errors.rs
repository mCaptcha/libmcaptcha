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

//! Errors and Result module
use derive_more::{Display, Error};
#[cfg(feature = "full")]
use redis::RedisError;
#[cfg(feature = "full")]
use tokio::sync::oneshot::error::RecvError;

/// Error datatype
#[derive(Debug, PartialEq, Display, Error)]
#[cfg(not(tarpaulin_include))]
pub enum CaptchaError {
    /// When configuring libmcaptcha, [DefenseBuilder][crate::defense::DefenseBuilder]
    /// must be passed atleast one `LevelConfig` if not this error will arise
    #[display(fmt = "LevelBuilder should have atleaset one level configured")]
    LevelEmpty,

    /// Visitor count must be a whole number(zero and above).
    /// When configuring libmcaptcha, [LevelBuilder][crate::defense::LevelBuilder].
    /// difficulty_factor must be set to greater than zero.
    #[display(fmt = "difficulty factor must be greater than zero")]
    DifficultyFactorZero,

    /// captcha cooldown duration must be greater than 0
    #[display(fmt = "difficulty factor must be greater than zero")]
    CaptchaDurationZero,

    /// Difficulty factor must be set
    #[display(fmt = "Set difficulty factor")]
    SetDifficultyFactor,

    /// Visitor threshold must be set
    #[display(fmt = "Set visitor threshold")]
    SetVisitorThreshold,

    /// Visitor count must be Unique
    #[display(fmt = "Duplicate visitor count")]
    DuplicateVisitorCount,

    /// Difficulty factor should increase with level
    #[display(fmt = "Difficulty factor should increase with level")]
    DecreaseingDifficultyFactor,

    /// Difficulty factor should increase with level
    #[display(fmt = "Actor mailbox error")]
    MailboxError,

    /// Happens when submitted work doesn't satisfy the required
    /// difficulty factor
    #[display(fmt = "Insuffiencient Difficulty")]
    InsuffiencientDifficulty,

    /// Happens when submitted work is computed over string that
    /// isn't in cache
    #[display(fmt = "String now found")]
    StringNotFound,

    /// Happens when submitted work is computed over configuration intended for
    /// a different mCAptcha sitekey
    #[display(fmt = "PoW computed over configuration not intended for target sitekey")]
    MCaptchaKeyValidationFail,

    /// Submitted PoW is invalid
    #[display(fmt = "Invalid PoW")]
    InvalidPoW,

    /// Used in builder structs when a value is not set
    #[display(fmt = "Please set value: {}", _0)]
    PleaseSetValue(#[error(not(source))] String),

    /// RedisError
    #[display(fmt = "{}", _0)]
    #[cfg(feature = "full")]
    RedisError(RedisError),

    /// Channel receive error
    #[display(fmt = "{}", _0)]
    #[cfg(feature = "full")]
    RecvError(RecvError),

    /// Weird behaviour from mcaptcha redis module
    #[display(
        fmt = "Something weird happening with mCaptcha redis module. Please file bug report"
    )]
    MCaptchaRedisModuleError,

    /// When libmcaptcha is ordered to connect to a Redis instance that doesn't have mCaptcha
    /// Redis module loaded
    #[display(
        fmt = "You are trying to connect to a Redis instance that doesn't have mCaptcha redis module loaded.
        Please see https://github.com/mCaptcha/cache for details on how to install mCaptcha redis module moudle"
    )]
    MCaptchaRedisModuleIsNotLoaded,

    /// MCaptcha redis module is loaded but it doesn't have the necessary Redis commands.
    /// Usually a version mismatch
    #[display(
        fmt = "The Redis instance that libmcaptcha is trying to connect to has mCaptcha Redis module loaded,
        but it's probably outdated and as a result, we are not able to find all required commands to operate mCaptcha
        Command {} is not found",
        _0
    )]
    MCaptchaRediSModuleCommandNotFound(#[error(not(source))] String),
}

#[cfg(feature = "full")]
#[cfg(not(tarpaulin_include))]
impl From<RedisError> for CaptchaError {
    fn from(e: RedisError) -> Self {
        Self::RedisError(e)
    }
}

#[cfg(feature = "full")]
#[cfg(not(tarpaulin_include))]
impl From<RecvError> for CaptchaError {
    fn from(e: RecvError) -> Self {
        log::error!("{:?}", e);
        Self::RecvError(e)
    }
}

#[cfg(feature = "full")]
#[cfg(not(tarpaulin_include))]
impl From<actix::MailboxError> for CaptchaError {
    fn from(_: actix::MailboxError) -> Self {
        Self::MailboxError
    }
}

/// [Result] datatype for libmcaptcha
pub type CaptchaResult<V> = std::result::Result<V, CaptchaError>;
