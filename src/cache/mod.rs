pub use hashcache::HashCache;
use messages::*;

pub mod hashcache;

pub trait Save: actix::Actor + actix::Handler<Retrive> + actix::Handler<Cache> {}

pub mod messages {
    use std::sync::Arc;

    use actix::dev::*;
    use serde::Serialize;

    use crate::errors::*;

    /// Message to decrement the visitor count
    #[derive(Message)]
    #[rtype(result = "CaptchaResult<()>")]
    pub struct Cache(pub PoWConfig);

    /// Message to decrement the visitor count
    #[derive(Message)]
    #[rtype(result = "CaptchaResult<Option<u32>>")]
    pub struct Retrive(pub String);

    /// PoW Config that will be sent to clients for generating PoW
    #[derive(Clone, Serialize, Debug)]
    pub struct PoWConfig {
        pub string: String,
        pub difficulty_factor: u32,
    }

    impl PoWConfig {
        pub fn new(m: u32) -> Self {
            use std::iter;

            use rand::{distributions::Alphanumeric, rngs::ThreadRng, thread_rng, Rng};

            let mut rng: ThreadRng = thread_rng();

            let string = iter::repeat(())
                .map(|()| rng.sample(Alphanumeric))
                .map(char::from)
                .take(32)
                .collect::<String>();

            PoWConfig {
                string,
                difficulty_factor: m,
            }
        }
    }
}
