use std::time::Duration;

use actix::prelude::*;
use derive_builder::Builder;
//use lazy_static::*;

use crate::levels::Defense;
//use crate::new_levels::Levels;

// TODO move this into config parameter
// lazy_static! {
//     pub static ref DURATION: Duration = Duration::new(POW_SESSION_DURATION, 0);
// }

/// Add visitor message
#[derive(Message)]
#[rtype(result = "u32")]
pub struct Visitor;

#[derive(Message)]
#[rtype(result = "()")]
struct DeleteVisitor;

#[derive(Builder)]
pub struct Counter {
    #[builder(default = "0", setter(skip))]
    visitor_count: u32,
    defense: Defense,
    duration: u64,
}

// impl Default for Counter {
//     fn default() -> Self {
//         Counter {
//             visitor_count: 0,
//             levels: Levels::default(),
//             duration: 30,
//         }
//     }
// }

impl Counter {
    /// incerment visiotr count by one
    pub fn add_visitor(&mut self) {
        self.visitor_count += 1;
        if self.visitor_count > self.defense.visitor_threshold() {
            self.defense.tighten_up();
        } else {
            self.defense.loosen_up();
        }
    }

    /// deccerment visiotr count by one
    pub fn decrement_visiotr(&mut self) {
        if self.visitor_count > 0 {
            self.visitor_count -= 1;
        }
    }

    /// get current difficulty factor
    pub fn get_difficulty(&self) -> u32 {
        self.defense.get_difficulty()
    }
}

impl Actor for Counter {
    type Context = Context<Self>;
}

impl Handler<Visitor> for Counter {
    type Result = u32;
    fn handle(&mut self, _: Visitor, ctx: &mut Self::Context) -> Self::Result {
        use actix::clock::delay_for;

        let addr = ctx.address();

        let duration: Duration = Duration::new(self.duration.clone(), 0);
        let wait_for = async move {
            delay_for(duration).await;
            addr.send(DeleteVisitor).await.unwrap();
        }
        .into_actor(self);
        ctx.spawn(wait_for);

        self.add_visitor();
        self.get_difficulty()
    }
}

impl Handler<DeleteVisitor> for Counter {
    type Result = ();
    fn handle(&mut self, _msg: DeleteVisitor, _ctx: &mut Self::Context) -> Self::Result {
        self.decrement_visiotr();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::levels::*;

    // constants foor testing
    // (visitor count, level)
    const LEVEL_1: (u32, u32) = (50, 50);
    const LEVEL_2: (u32, u32) = (500, 500);
    const DURATION: u64 = 10;

    fn get_defense() -> Defense {
        DefenseBuilder::default()
            .add_level(
                LevelBuilder::default()
                    .visitor_count(LEVEL_1.0)
                    .difficulty_factor(LEVEL_1.1)
                    .unwrap()
                    .build()
                    .unwrap(),
            )
            .unwrap()
            .add_level(
                LevelBuilder::default()
                    .visitor_count(LEVEL_2.0)
                    .difficulty_factor(LEVEL_2.1)
                    .unwrap()
                    .build()
                    .unwrap(),
            )
            .unwrap()
            .build()
            .unwrap()
    }

    async fn race(addr: Addr<Counter>, count: (u32, u32)) {
        for _ in 0..count.0 as usize - 1 {
            let _ = addr.send(Visitor).await.unwrap();
        }
    }

    fn get_counter() -> Counter {
        CounterBuilder::default()
            .defense(get_defense())
            .duration(DURATION)
            .build()
            .unwrap()
    }

    #[actix_rt::test]
    async fn counter_defense_tightenup_works() {
        let addr = get_counter().start();

        let mut difficulty_factor = addr.send(Visitor).await.unwrap();
        assert_eq!(difficulty_factor, LEVEL_1.0);

        race(addr.clone(), LEVEL_2).await;
        difficulty_factor = addr.send(Visitor).await.unwrap();
        assert_eq!(difficulty_factor, LEVEL_2.1);
    }

    #[actix_rt::test]
    async fn counter_defense_loosenup_works() {
        use actix::clock::delay_for;
        let addr = get_counter().start();

        race(addr.clone(), LEVEL_2).await;
        race(addr.clone(), LEVEL_2).await;
        let mut difficulty_factor = addr.send(Visitor).await.unwrap();
        assert_eq!(difficulty_factor, LEVEL_2.1);

        let duration = Duration::new(DURATION, 0);
        delay_for(duration).await;

        difficulty_factor = addr.send(Visitor).await.unwrap();
        assert_eq!(difficulty_factor, LEVEL_1.1);
    }
}
