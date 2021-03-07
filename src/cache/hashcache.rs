use std::collections::HashMap;
use std::sync::Arc;

use actix::prelude::*;

use super::messages::*;
use super::Save;
use crate::errors::*;

#[derive(Clone, Default)]
pub struct HashCache(HashMap<String, u32>);

impl HashCache {
    fn save(&mut self, config: Arc<PoWConfig>) -> CaptchaResult<()> {
        self.0
            .insert(config.string.clone(), config.difficulty_factor);
        Ok(())
    }

    fn retrive(&mut self, string: Arc<String>) -> CaptchaResult<Option<u32>> {
        if let Some(difficulty_factor) = self.0.get(&*string) {
            Ok(Some(difficulty_factor.to_owned()))
        } else {
            Ok(None)
        }
    }
}

impl Save for HashCache {}

impl Actor for HashCache {
    type Context = Context<Self>;
}

impl Handler<Cache> for HashCache {
    type Result = MessageResult<Cache>;
    fn handle(&mut self, msg: Cache, _ctx: &mut Self::Context) -> Self::Result {
        //        if let Err(e) = self.save(msg.0.clone()) {
        //            MessageResult(Err(e))
        //        } else {
        //            MessageResult(Ok(msg.0))
        //        }
        MessageResult(self.save(msg.0))
    }
}

impl Handler<Retrive> for HashCache {
    type Result = MessageResult<Retrive>;
    fn handle(&mut self, msg: Retrive, _ctx: &mut Self::Context) -> Self::Result {
        MessageResult(self.retrive(msg.0.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[actix_rt::test]
    async fn counter_defense_tightenup_works() {
        let addr = HashCache::default().start();
        let p = Arc::new("ewerw".to_string());
        addr.send(Retrive(p)).await.unwrap().unwrap();
    }
    //
    //    #[actix_rt::test]
    //    async fn counter_defense_loosenup_works() {
    //        use actix::clock::delay_for;
    //        let addr: MyActor = get_counter().start();
    //
    //        race(addr.clone(), LEVEL_2).await;
    //        race(addr.clone(), LEVEL_2).await;
    //        let mut difficulty_factor = addr.send(Visitor).await.unwrap();
    //        assert_eq!(difficulty_factor.difficulty_factor, LEVEL_2.1);
    //
    //        let duration = Duration::new(DURATION, 0);
    //        delay_for(duration).await;
    //
    //        difficulty_factor = addr.send(Visitor).await.unwrap();
    //        assert_eq!(difficulty_factor.difficulty_factor, LEVEL_1.1);
    //    }
}
