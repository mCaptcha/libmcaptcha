use wasm_bindgen::prelude::*;

// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
// allocator.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

use pow_sha256::PoW;

#[wasm_bindgen]
pub fn gen_pow(difficulty_factor: u32, secret: String) -> String {
    let difficulty = u128::max_value() - u128::max_value() / difficulty_factor as u128;
    let a = PoW::prove_work(&secret.as_bytes().to_vec(), difficulty).unwrap();
    let payload = serde_json::to_string(&a).unwrap();
    payload
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let payload = gen_pow(500, "MFsqLMZId629Dh2hrtux2Qdn3gBzCaSt".into());
        assert_eq!("{\"nonce\":312,\"result\":\"340175381422106372296624206295814425082\",\"_spook\":null}",    &payload );

        let payload = gen_pow(1_000, "MFsqLMZId629Dh2hrtux2Qdn3gBzCaSt".into());
        assert_eq!("{\"nonce\":312,\"result\":\"340175381422106372296624206295814425082\",\"_spook\":null}", &payload);

        let payload = gen_pow(2_000, "MFsqLMZId629Dh2hrtux2Qdn3gBzCaSt".into());
        assert_eq!(&payload, "{\"nonce\":312,\"result\":\"340175381422106372296624206295814425082\",\"_spook\":null}");

        let payload = gen_pow(100_000, "MFsqLMZId629Dh2hrtux2Qdn3gBzCaSt".into());
        assert_eq!(&payload, "{\"nonce\":59930,\"result\":\"340281433562218714678373578791487113813\",\"_spook\":null}");

        let payload = gen_pow(1_000_000, "MFsqLMZId629Dh2hrtux2Qdn3gBzCaSt".into());

        assert_eq!(&payload,"{\"nonce\":1902451,\"result\":\"340282308726676882310449308394036800665\",\"_spook\":null}");
    }
}
