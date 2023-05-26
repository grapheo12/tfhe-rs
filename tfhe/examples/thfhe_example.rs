use tfhe::thfhe::{ThFHEPubKey, ThFHE};
use tfhe::boolean::parameters::{DEFAULT_PARAMETERS, TFHE_LIB_PARAMETERS};
use tfhe::boolean::{client_key, server_key, ciphertext};
use tfhe::core_crypto::entities::LweCiphertext;
use tfhe::core_crypto::commons::ciphertext_modulus::CiphertextModulus;
use std::env;
use std::time::{Instant, Duration};

fn main() {
    let args: Vec<String> = env::args().collect();
    assert_eq!(args.len(), 3, "Args: t p");

    let t: usize = args[1].parse().unwrap();
    let p: usize = args[2].parse().unwrap();

    let boolean_params_vec = vec![
        (DEFAULT_PARAMETERS, "DEFAULT_PARAMETERS"),
        (TFHE_LIB_PARAMETERS, "TFHE_LIB_PARAMETERS"),
    ];
    for (i, (params, params_name)) in boolean_params_vec.iter().enumerate() {
        println!(
            "Generating [{} / {}] : {}",
            i + 1,
            boolean_params_vec.len(),
            params_name.to_lowercase()
        );

        let cks = client_key::ClientKey::new(params);
        let sks = server_key::ServerKey::new(&cks);
        let mut pubkey = ThFHEPubKey::from_client_key(&cks, 10);

        let mut ctext = LweCiphertext::new(0u32, pubkey.n, CiphertextModulus::new_native());
        let msg = 1u32;
        pubkey.encrypt(&mut ctext, msg);

        let __ctxt = ciphertext::Ciphertext::Encrypted(ctext);
        let dec = cks.decrypt(&__ctxt);
        println!("Original message: {} Decryption result: {}", msg, dec);

        let mut thfhe = ThFHE::new(1);

        println!("Sharing secret: {} out of {}", t, p);
        let start = Instant::now();
        thfhe.share_secret(3, 5);
        let end = Instant::now();
        let dur = end - start;
        println!("Time taken: {}ms or {}us", dur.as_millis(), dur.as_micros());
    }

}
