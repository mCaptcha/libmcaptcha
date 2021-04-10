use m_captcha::{
    cache::HashCache,
    master::{AddSiteBuilder, Master},
    pow::{ConfigBuilder, Work},
    system::SystemBuilder,
    DefenseBuilder, LevelBuilder, MCaptchaBuilder,
};
// traits from actix needs to be in scope for starting actor
use actix::prelude::*;

#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    // start cahce actor
    // cache is used to store PoW requirements that are sent to clients
    // This way, it can be verified that the client computed work over a config
    // that _we_ sent. Offers protection against rainbow tables powered dictionary attacks
    let cache = HashCache::default().start();

    // create PoW config with unique salt. Salt has to be safely guarded.
    // salts protect us from replay attacks
    let pow = ConfigBuilder::default()
        .salt("myrandomsaltisnotlongenoug".into())
        .build()
        .unwrap();

    // start master actor. Master actor is responsible for managing MCaptcha actors
    // each mCaptcha system should have only one master
    let master = Master::new(60).start();

    // Create system. System encapsulates master and cache and provides useful abstraction
    // each mCaptcha system should have only one system
    let system = SystemBuilder::default()
        .master(master)
        .cache(cache)
        .pow(pow.clone())
        .build()
        .unwrap();

    // configure defense. This is a per site configuration. A site can have several levels
    // of defenses configured
    let defense = DefenseBuilder::default()
        // add as many defense as you see fit
        .add_level(
            LevelBuilder::default()
                // visitor_threshold is the threshold/limit at which
                // mCaptcha will adjust difficulty defense
                // it is advisable to set small values for the first
                // defense visitor_threshold and difficulty_factor
                // as this will be the work that clients will be
                // computing when there's no load
                .visitor_threshold(50)
                .difficulty_factor(500)
                .unwrap()
                .build()
                .unwrap(),
        )
        .unwrap()
        .add_level(
            LevelBuilder::default()
                .visitor_threshold(5000)
                .difficulty_factor(50000)
                .unwrap()
                .build()
                .unwrap(),
        )
        .unwrap()
        .build()
        .unwrap();

    // create and start MCaptcha actor that uses the above defense configuration
    // This is what manages the difficulty factor of sites that an mCaptcha protects
    let mcaptcha = MCaptchaBuilder::default()
        .defense(defense)
        // leaky bucket algorithm's emission interval
        .duration(30)
        //   .cache(cache)
        .build()
        .unwrap()
        .start();

    // unique value identifying an MCaptcha actor
    let mcaptcha_name = "batsense.net";

    // add MCaptcha to Master
    let msg = AddSiteBuilder::default()
        .id(mcaptcha_name.into())
        .addr(mcaptcha.clone())
        .build()
        .unwrap();
    system.master.send(msg).await.unwrap();

    // Get PoW config. Should be called everytime there's a visitor for a
    // managed site(here mcaptcha_name)
    let work_req = system.get_pow(mcaptcha_name.into()).await.unwrap();

    // the following computation should be done on the client but for the purpose
    // of this illustration, we are going to do it on the server it self
    let work = pow
        .prove_work(&work_req.string, work_req.difficulty_factor)
        .unwrap();

    // the payload that the client sends to the server
    let payload = Work {
        string: work_req.string,
        result: work.result,
        nonce: work.nonce,
        key: mcaptcha_name.into(),
    };

    // Server evaluates client's work. Returns true if everything
    // checksout and Err() if something fishy is happening
    let res = system.verify_pow(payload.clone()).await;
    assert!(res.is_ok());
    // TODO add server-sideverification

    Ok(())
}
