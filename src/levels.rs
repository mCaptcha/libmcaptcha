#[derive(Debug, Copy, Clone, PartialEq)]
pub enum Levels {
    One = 500,
    Two = 1000,
    Three = 2000,
    Four = 4000,
}

impl Default for Levels {
    fn default() -> Self {
        Levels::One
    }
}

impl Levels {
    pub fn relax(&mut self) -> u32 {
        self.rev().next();
        *self as u32
    }

    ///! Difficulty is calculated as
    ///! ```rust
    ///! let difficulty = u128::max_value() - u128::max_value() / difficulty_factor;
    ///! ```
    ///! the higher the `difficulty_factor`, the higher the difficulty.

    pub fn get_difficulty(&self) -> u32 {
        match self {
            Levels::Three => 100_000,
            Levels::Four => 1_000_000,
            _ => *self as u32,
        }
    }

    pub fn threshold(&self) -> usize {
        *self as usize
    }

    pub fn focus(&mut self) -> u32 {
        self.next();
        *self as u32
    }
}

impl DoubleEndedIterator for Levels {
    fn next_back(&mut self) -> Option<Self::Item> {
        match self {
            Levels::One => {
                *self = Levels::One;
            }
            Levels::Two => {
                *self = Levels::One;
            }
            Levels::Three => {
                *self = Levels::Two;
            }
            Levels::Four => {
                *self = Levels::Three;
            }
        };

        Some(())
    }
}

impl Iterator for Levels {
    type Item = ();

    fn next(&mut self) -> Option<()> {
        match self {
            Levels::One => {
                *self = Levels::Two;
            }
            Levels::Two => {
                *self = Levels::Three;
            }
            Levels::Three => {
                *self = Levels::Four;
            }
            Levels::Four => {
                *self = Levels::Four;
            }
        };

        Some(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn levels_enum_works() {
        let mut level = Levels::default();

        assert_eq!(level, Levels::One);

        level.next();
        assert_eq!(level, Levels::Two);

        level.next();
        assert_eq!(level, Levels::Three);

        level.next();
        assert_eq!(level, Levels::Four);

        level.next();
        assert_eq!(level, Levels::Four);
    }

    #[test]
    fn focus_works() {
        let mut level = Levels::default();

        assert_eq!(level, Levels::One);
        assert_eq!(level.focus(), Levels::Two as u32);
        assert_eq!(level.focus(), Levels::Three as u32);
        assert_eq!(level.focus(), Levels::Four as u32);
        assert_eq!(level.focus(), Levels::Four as u32);
    }

    #[test]
    fn relax_works() {
        let mut level = Levels::default();

        assert_eq!(level, Levels::One);
        assert_eq!(level.focus(), Levels::Two as u32);
        assert_eq!(level.focus(), Levels::Three as u32);
        assert_eq!(level.focus(), Levels::Four as u32);

        assert_eq!(level.relax(), Levels::Three as u32);
        assert_eq!(level.relax(), Levels::Two as u32);

        assert_eq!(level.relax(), Levels::One as u32);
        assert_eq!(level.relax(), Levels::One as u32);
    }

    #[test]
    fn threshold_works() {
        let mut level = Levels::default();

        assert_eq!(level.threshold(), Levels::One as usize);
        level.next();
        assert_eq!(level.threshold(), Levels::Two as usize);
        level.next();
        assert_eq!(level.threshold(), Levels::Three as usize);
    }

    #[test]
    fn difficulty_works() {
        let mut level = Levels::default();

        assert_eq!(level.get_difficulty(), Levels::One as u32);
        level.next();
        assert_eq!(level.get_difficulty(), Levels::Two as u32);
        level.next();
        assert_eq!(level.get_difficulty(), 100_000);
        level.next();
        assert_eq!(level.get_difficulty(), 1_000_000);
    }
}
