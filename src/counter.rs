use std::time::Duration;

use actix::prelude::*;
use derive_builder::Builder;
//use lazy_static::*;

use crate::levels::Levels;

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
    visitor_count: usize,
    levels: Levels,
    duration: u64,
}

impl Default for Counter {
    fn default() -> Self {
        Counter {
            visitor_count: 0,
            levels: Levels::default(),
            duration: 30,
        }
    }
}

impl Actor for Counter {
    type Context = Context<Self>;

    //    fn started(&mut self, ctx: &mut Self::Context) {
    //        ctx.set_mailbox_capacity(usize::MAX / 2);
    //    }
}

impl Handler<Visitor> for Counter {
    type Result = u32;
    fn handle(&mut self, _: Visitor, ctx: &mut Self::Context) -> Self::Result {
        use actix::clock::delay_for;

        self.visitor_count += 1;

        let addr = ctx.address();

        let duration: Duration = Duration::new(self.duration.clone(), 0);
        let wait_for = async move {
            delay_for(duration).await;
            addr.send(DeleteVisitor).await.unwrap();
        }
        .into_actor(self);
        ctx.spawn(wait_for);

        if self.visitor_count > self.levels.threshold() {
            self.levels.focus();
        } else {
            self.levels.relax();
        }

        self.levels.get_difficulty()
    }
}

impl Handler<DeleteVisitor> for Counter {
    type Result = ();
    fn handle(&mut self, _msg: DeleteVisitor, _ctx: &mut Self::Context) -> Self::Result {
        if self.visitor_count > 0 {
            self.visitor_count -= 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn race(addr: Addr<Counter>, count: Levels) {
        for _ in 0..count as usize - 1 {
            let _ = addr.send(Visitor).await.unwrap();
        }
    }
    #[actix_rt::test]
    async fn counter_focus_works() {
        let four = Levels::Four.get_difficulty();
        let three = Levels::Three.get_difficulty();
        let two = Levels::Two.get_difficulty();
        let one = Levels::One.get_difficulty();

        let addr = Counter::default().start();

        let mut difficulty_factor = addr.send(Visitor).await.unwrap();
        assert_eq!(difficulty_factor, one);

        let addr = Counter::default().start();
        race(addr.clone(), Levels::One).await;
        difficulty_factor = addr.send(Visitor).await.unwrap();
        assert_eq!(difficulty_factor, one);

        let addr = Counter::default().start();
        race(addr.clone(), Levels::Two).await;
        addr.send(Visitor).await.unwrap();
        difficulty_factor = addr.send(Visitor).await.unwrap();
        assert_eq!(difficulty_factor, two);

        let addr = Counter::default().start();
        race(addr.clone(), Levels::Three).await;
        difficulty_factor = addr.send(Visitor).await.unwrap();
        assert_eq!(difficulty_factor, three);

        let addr = Counter::default().start();
        race(addr.clone(), Levels::Four).await;
        addr.send(Visitor).await.unwrap();
        difficulty_factor = addr.send(Visitor).await.unwrap();
        assert_eq!(difficulty_factor, four);
    }

    #[actix_rt::test]
    async fn counter_relax_works() {
        use actix::clock::delay_for;
        let four = Levels::Four.get_difficulty();
        let three = Levels::Three.get_difficulty();
        let two = Levels::Two.get_difficulty();
        let one = Levels::One.get_difficulty();

        let addr = Counter::default().start();

        let mut difficulty_factor = addr.send(Visitor).await.unwrap();

        let addr = Counter::default().start();
        race(addr.clone(), Levels::Four).await;
        addr.send(Visitor).await.unwrap();
        difficulty_factor = addr.send(Visitor).await.unwrap();
        assert_eq!(difficulty_factor, four);

        // could break when default duration for counter actor changes
        let duration = Duration::new(30, 0);

        delay_for(duration).await;

        difficulty_factor = addr.send(Visitor).await.unwrap();
        assert_eq!(difficulty_factor, three);
        difficulty_factor = addr.send(Visitor).await.unwrap();
        assert_eq!(difficulty_factor, two);
        difficulty_factor = addr.send(Visitor).await.unwrap();
        assert_eq!(difficulty_factor, one);
    }
}
