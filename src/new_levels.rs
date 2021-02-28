// //! ```rust
// //! DefenseBuilder::default()
// //!        .add_level(
// //!            LevelBuilder::default()
// //!                .visitor_count(50)
// //!                .difficulty_factor(50)
// //!                .unwrap()
// //!                .build()
// //!                .unwrap(),
// //!        )
// //!        .unwrap()
// //!        .add_level(
// //!            LevelBuilder::default()
// //!                .visitor_count(500)
// //!                .difficulty_factor(500)
// //!                .unwrap()
// //!                .build()
// //!                .unwrap(),
// //!        )
// //!        .unwrap()
// //!        .build()
// //!        .unwrap();
// //! ```

use crate::errors::*;

/// Level struct
#[derive(Debug, Copy, Clone, PartialEq)]
pub struct Level {
    visitor_count: u32,
    difficulty_factor: u32,
}

impl Default for Level {
    fn default() -> Self {
        Level {
            visitor_count: 0,
            difficulty_factor: 0,
        }
    }
}

/// set difficulty configuration
#[derive(Debug, Copy, Clone, PartialEq)]
pub struct LevelBuilder {
    visitor_count: Option<u32>,
    difficulty_factor: Option<u32>,
}

impl Default for LevelBuilder {
    fn default() -> Self {
        LevelBuilder {
            visitor_count: None,
            difficulty_factor: None,
        }
    }
}

impl LevelBuilder {
    /// set visitor count for level
    pub fn visitor_count(&mut self, visitor_count: u32) -> &mut Self {
        self.visitor_count = Some(visitor_count);
        self
    }

    /// set difficulty factor for level
    /// difficulty_factor can't be zero because
    /// Difficulty is calculated as
    /// ```no_run
    /// let difficulty_factor = 500;
    /// let difficulty = u128::max_value() - u128::max_value() / difficulty_factor;
    /// ```
    /// the higher the `difficulty_factor`, the higher the difficulty.
    pub fn difficulty_factor(&mut self, difficulty_factor: u32) -> CaptchaResult<&mut Self> {
        if difficulty_factor > 0 {
            self.difficulty_factor = Some(difficulty_factor);
            Ok(self)
        } else {
            Err(CaptchaError::DifficultyFactorZero)
        }
    }

    /// build Level
    pub fn build(&mut self) -> CaptchaResult<Level> {
        if self.visitor_count.is_none() {
            Err(CaptchaError::SetVisitorCount)
        } else if self.difficulty_factor.is_none() {
            Err(CaptchaError::SetDifficultyFactor)
        } else {
            Ok(Level {
                difficulty_factor: self.difficulty_factor.unwrap(),
                visitor_count: self.visitor_count.unwrap(),
            })
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Defense {
    levels: Vec<Level>,
    // index of current visitor threshold
    current_visitor_threshold: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DefenseBuilder {
    levels: Vec<Level>,
}

impl Default for DefenseBuilder {
    fn default() -> Self {
        DefenseBuilder { levels: vec![] }
    }
}

impl DefenseBuilder {
    pub fn add_level(&mut self, level: Level) -> CaptchaResult<&mut Self> {
        for i in self.levels.iter() {
            if i.visitor_count == level.visitor_count {
                return Err(CaptchaError::DuplicateVisitorCount);
            }
        }
        self.levels.push(level);
        Ok(self)
    }

    pub fn build(&mut self) -> CaptchaResult<Defense> {
        if !self.levels.is_empty() {
            // sort levels to arrange in ascending order
            self.levels.sort_by_key(|a| a.visitor_count);

            // as visitor count increases, difficulty_factor too should increse

            for level in self.levels.iter() {
                if level.difficulty_factor == 0 {
                    return Err(CaptchaError::DifficultyFactorZero);
                }
            }

            for i in 0..self.levels.len() - 1 {
                if self.levels[i].difficulty_factor > self.levels[i + 1].difficulty_factor {
                    return Err(CaptchaError::DecreaseingDifficultyFactor);
                }
            }

            Ok(Defense {
                levels: self.levels.to_owned(),
                current_visitor_threshold: 0,
            })
        } else {
            Err(CaptchaError::LevelEmpty)
        }
    }
}

impl Default for Defense {
    fn default() -> Self {
        Defense {
            levels: vec![Level::default()],
            current_visitor_threshold: 0,
        }
    }
}

impl Defense {
    ///! Difficulty is calculated as
    ///! ```rust
    ///! let difficulty = u128::max_value() - u128::max_value() / difficulty_factor;
    ///! ```
    ///! the higher the `difficulty_factor`, the higher the difficulty.

    /// get difficulty factor of current level of defense
    pub fn get_difficulty(&self) -> u32 {
        self.levels[self.current_visitor_threshold].difficulty_factor
    }

    /// tighten up defense. Increases defense level by a factor of one
    /// when defense is at max level, calling this method will have no effect
    pub fn tighten_up(&mut self) {
        if self.current_visitor_threshold != self.levels.len() - 1 {
            self.current_visitor_threshold += 1;
        }
    }
    /// loosen up defense. Decreases defense level by a factor of one
    /// when defense is at the lowest level, calling this method will have no effect
    pub fn loosen_up(&mut self) {
        if self.current_visitor_threshold != 0 {
            self.current_visitor_threshold -= 1;
        }
    }

    /// set defense to maximum level
    pub fn max_defense(&mut self) {
        self.current_visitor_threshold = self.levels.len() - 1;
    }

    /// set defense to minimum level
    pub fn min_defense(&mut self) {
        self.current_visitor_threshold = 0;
    }

    pub fn visitor_threshold(&self) -> u32 {
        self.levels[self.current_visitor_threshold].visitor_count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn level_builder_works() {
        let level = LevelBuilder::default()
            .difficulty_factor(1)
            .unwrap()
            .visitor_count(0)
            .build()
            .unwrap();

        assert_eq!(level.visitor_count, 0);
        assert_eq!(level.difficulty_factor, 1);

        assert_eq!(
            LevelBuilder::default().difficulty_factor(0),
            Err(CaptchaError::DifficultyFactorZero)
        );
    }

    #[test]
    fn defense_builder_duplicate_visitor_count() {
        let mut defense_builder = DefenseBuilder::default();
        let err = defense_builder
            .add_level(
                LevelBuilder::default()
                    .visitor_count(50)
                    .difficulty_factor(50)
                    .unwrap()
                    .build()
                    .unwrap(),
            )
            .unwrap()
            .add_level(
                LevelBuilder::default()
                    .visitor_count(50)
                    .difficulty_factor(50)
                    .unwrap()
                    .build()
                    .unwrap(),
            );
        assert_eq!(err, Err(CaptchaError::DuplicateVisitorCount));
    }

    #[test]
    fn defense_builder_decreasing_difficulty_factor() {
        let mut defense_builder = DefenseBuilder::default();
        let err = defense_builder
            .add_level(
                LevelBuilder::default()
                    .visitor_count(50)
                    .difficulty_factor(50)
                    .unwrap()
                    .build()
                    .unwrap(),
            )
            .unwrap()
            .add_level(
                LevelBuilder::default()
                    .visitor_count(500)
                    .difficulty_factor(10)
                    .unwrap()
                    .build()
                    .unwrap(),
            )
            .unwrap()
            .build();
        assert_eq!(err, Err(CaptchaError::DecreaseingDifficultyFactor));
    }

    fn get_defense() -> Defense {
        DefenseBuilder::default()
            .add_level(
                LevelBuilder::default()
                    .visitor_count(50)
                    .difficulty_factor(50)
                    .unwrap()
                    .build()
                    .unwrap(),
            )
            .unwrap()
            .add_level(
                LevelBuilder::default()
                    .visitor_count(500)
                    .difficulty_factor(5000)
                    .unwrap()
                    .build()
                    .unwrap(),
            )
            .unwrap()
            .add_level(
                LevelBuilder::default()
                    .visitor_count(5000)
                    .difficulty_factor(50000)
                    .unwrap()
                    .build()
                    .unwrap(),
            )
            .unwrap()
            .add_level(
                LevelBuilder::default()
                    .visitor_count(50000)
                    .difficulty_factor(500000)
                    .unwrap()
                    .build()
                    .unwrap(),
            )
            .unwrap()
            .add_level(
                LevelBuilder::default()
                    .visitor_count(500000)
                    .difficulty_factor(5000000)
                    .unwrap()
                    .build()
                    .unwrap(),
            )
            .unwrap()
            .build()
            .unwrap()
    }
    #[test]
    fn defense_builder_works() {
        let defense = get_defense();

        assert_eq!(defense.levels[0].difficulty_factor, 50);
        assert_eq!(defense.levels[1].difficulty_factor, 5000);
        assert_eq!(defense.levels[2].difficulty_factor, 50_000);
        assert_eq!(defense.levels[3].difficulty_factor, 500_000);
        assert_eq!(defense.levels[4].difficulty_factor, 5_000_000);
    }

    #[test]
    fn tighten_up_works() {
        let mut defense = get_defense();

        assert_eq!(defense.get_difficulty(), 50);

        defense.tighten_up();
        assert_eq!(defense.get_difficulty(), 5_000);

        defense.tighten_up();
        assert_eq!(defense.get_difficulty(), 50_000);

        defense.tighten_up();
        assert_eq!(defense.get_difficulty(), 500_000);

        defense.tighten_up();
        assert_eq!(defense.get_difficulty(), 5_000_000);

        defense.tighten_up();
        assert_eq!(defense.get_difficulty(), 5_000_000);
    }

    #[test]
    fn max_defense_works() {
        let mut defense = get_defense();
        defense.max_defense();
        assert_eq!(defense.get_difficulty(), 5_000_000);
    }

    #[test]
    fn minimum_defense_works() {
        let mut defense = get_defense();
        defense.min_defense();
        assert_eq!(defense.get_difficulty(), 50);
    }

    #[test]
    fn loosen_up_works() {
        let mut defense = get_defense();
        defense.max_defense();

        assert_eq!(defense.get_difficulty(), 5_000_000);

        defense.loosen_up();
        assert_eq!(defense.get_difficulty(), 500_000);

        defense.loosen_up();
        assert_eq!(defense.get_difficulty(), 50_000);

        defense.loosen_up();
        assert_eq!(defense.get_difficulty(), 5_000);

        defense.loosen_up();
        assert_eq!(defense.get_difficulty(), 50);

        defense.loosen_up();
        assert_eq!(defense.get_difficulty(), 50);
    }

    //    #[test]
    //    fn threshold_works() {
    //        let mut level = Levels::default();
    //
    //        assert_eq!(level.threshold(), Levels::One as usize);
    //        level.next();
    //        assert_eq!(level.threshold(), Levels::Two as usize);
    //        level.next();
    //        assert_eq!(level.threshold(), Levels::Three as usize);
    //    }
    //
    //    #[test]
    //    fn difficulty_works() {
    //        let mut level = Levels::default();
    //
    //        assert_eq!(level.get_difficulty(), Levels::One as u32);
    //        level.next();
    //        assert_eq!(level.get_difficulty(), Levels::Two as u32);
    //        level.next();
    //        assert_eq!(level.get_difficulty(), 100_000);
    //        level.next();
    //        assert_eq!(level.get_difficulty(), 1_000_000);
    //    }
}
