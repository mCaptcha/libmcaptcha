use clap::{App, Arg};
use pow_sha256::PoW;
// use serde::Serialize;

//#[derive(Serialize, Debug)]
//pub struct Pow(PoW<Vec<u8>>);

fn main() {
    let matches = App::new("mCaptcha PoW CLI")
        .version("0.1.0")
        .author("Aravinth Manivannan <realaravinth@batsense.net>")
        .about("Generates PoW for mCaptcha")
        .arg(
            Arg::with_name("secret")
                .short("-s")
                .long("--secret")
                .value_name("STRING")
                .help("Secret over which PoW should be computed")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("difficulty_factor")
                .short("-d")
                .long("--difficulty")
                .value_name("INTEGER")
                .help("Difficulty factor")
                .takes_value(true),
        )
        .get_matches();
    let secret = matches.value_of("secret").unwrap();
    let difficulty_factor: u128 = matches
        .value_of("difficulty_factor")
        .unwrap()
        .parse()
        .expect("Please enter an integer for difficulty");

    let difficulty = u128::max_value() - u128::max_value() / difficulty_factor as u128;

    let a = PoW::prove_work(&secret.as_bytes().to_vec(), difficulty).unwrap();

    println!("difficulty: {}", &difficulty);
    println!("nonce: {}", &a.nonce);
    println!("result: {}", &a.result);

    // let payload = serde_json::to_string(&pow(a)).unwrap();
    //    let b = pow(a);
    //    println!("{:#?}", serde_json::to_string(&b).unwrap());
}
