use libmcaptcha::{
    cache::{hashcache::HashCache, messages::VerifyCaptchaResult},
    master::embedded::master::Master,
    master::messages::AddSiteBuilder,
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
        .runners(4)
        .queue_length(2000)
        .build();

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
        .unwrap();

    // unique value identifying an MCaptcha actor
    let mcaptcha_name = "batsense.net";

    // add MCaptcha to Master
    let msg = AddSiteBuilder::default()
        .id(mcaptcha_name.into())
        .mcaptcha(mcaptcha)
        .build()
        .unwrap();
    system.master.send(msg).await.unwrap();

    // Get PoW config. Should be called everytime there's a visitor for a
    // managed site(here mcaptcha_name)
    let work_req = system.get_pow(mcaptcha_name.into()).await.unwrap().unwrap();

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

    // mCAptcha evaluates client's work. Returns a token if everything
    // checksout and Err() if something fishy is happening
    let res = system
        .verify_pow(payload.clone(), "192.168.0.103".into())
        .await;
    assert!(res.is_ok());

    // The client should submit the token to the mCaptcha protected service
    // The service should validate the token received from the client
    // with the mCaptcha server before processing client's
    // request

    // mcaptcha protected service sends the following paylaod to mCaptcha
    // server:
    let verify_msg = VerifyCaptchaResult {
        token: res.unwrap(),
        key: mcaptcha_name.into(),
    };

    // on mCaptcha server:
    let res = system.validate_verification_tokens(verify_msg).await;
    // mCaptcha will return true if token is valid and false if
    // token is invalid
    assert!(res.is_ok());
    assert!(res.unwrap());

    Ok(())
}
