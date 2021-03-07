pub use hashcache::HashCache;
use messages::*;

pub mod hashcache;

pub trait Save: actix::Actor + actix::Handler<Retrive> + actix::Handler<Cache> {}

pub mod messages {
    use std::sync::Arc;

    use actix::dev::*;
    use rand::{distributions::Alphanumeric, thread_rng, Rng};
    use serde::Serialize;

    use super::Save;
    use crate::errors::*;
    use crate::mcaptcha::MCaptcha;

    /// Message to decrement the visitor count
    #[derive(Message)]
    #[rtype(result = "CaptchaResult<()>")]
    pub struct Cache(pub Arc<PoWConfig>);

    /// Message to decrement the visitor count
    #[derive(Message)]
    #[rtype(result = "CaptchaResult<Option<u32>>")]
    pub struct Retrive(pub Arc<String>);

    /// PoW Config that will be sent to clients for generating PoW
    #[derive(Clone, Serialize, Debug)]
    pub struct PoWConfig {
        pub string: String,
        pub difficulty_factor: u32,
    }

    impl PoWConfig {
        pub fn new<T>(m: &MCaptcha<T>) -> Self
        where
            T: Save,
            <T as Actor>::Context: ToEnvelope<T, Retrive> + ToEnvelope<T, Cache>,
        {
            PoWConfig {
                string: thread_rng().sample_iter(&Alphanumeric).take(32).collect(),
                difficulty_factor: m.get_difficulty(),
            }
        }
    }
}
