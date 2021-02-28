//! Error datatypes
use derive_more::{Display, Error};

/// Errors that can occur when interacting with the blockchain
#[derive(Debug, PartialEq, Display, Clone, Error)]
#[cfg(not(tarpaulin_include))]
pub enum CaptchaError {
    /// when configuring m_captcha, `DefenseBuilder` must be passed atleast
    /// one `LevelConfig` if not this error will arise
    #[display(fmt = "LevelBuilder should have atleaset one level configured")]
    LevelEmpty,
    /// Visitor count must be an integer
    /// when configuring m_captcha, `LevelBuilder` difficulty_factor
    /// must be set to greater than zero.
    #[display(fmt = "difficulty factor must be greater than zero")]
    DifficultyFactorZero,
    /// Difficulty factor must be set
    #[display(fmt = "Set difficulty factor")]
    SetDifficultyFactor,
    /// Visitor count must be set
    #[display(fmt = "Set visitor count")]
    SetVisitorCount,

    /// Visitor count must be Unique
    #[display(fmt = "Duplicate visitor count")]
    DuplicateVisitorCount,

    /// Difficulty factor should increase with level
    #[display(fmt = "Difficulty factor should increase with level")]
    DecreaseingDifficultyFactor,
}

/// [Result] datatype for m_captcha
pub type CaptchaResult<V> = std::result::Result<V, CaptchaError>;
