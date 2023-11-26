use tfhe::core_crypto::algorithms::allocate_and_generate_new_lwe_public_key;
use tfhe::thfhe::{ThFHEPubKey, ThFHE, ThFHEKeyShare, final_decrypt, TLweFromLwe};
use tfhe::boolean::parameters::{DEFAULT_PARAMETERS, TFHE_LIB_PARAMETERS};
use tfhe::boolean::{client_key, server_key, ciphertext};
use tfhe::core_crypto::entities::{LweCiphertext, LwePublicKey};
use tfhe::core_crypto::commons::ciphertext_modulus::{CiphertextModulus, self};
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
        let mut pubkey = ThFHEPubKey::from_client_key(&cks, 10, params);

        println!("Lwe Dim: {}", pubkey.n.0);
        let mut ctext = LweCiphertext::new(0u32, pubkey.n, CiphertextModulus::new_native());
        let msg = true;
        pubkey.encrypt(&mut ctext, msg);

        let __ctxt = ciphertext::Ciphertext::Encrypted(ctext.clone());
        let dec = cks.decrypt(&__ctxt);
        println!("Original message: {} Decryption result: {}", msg, dec);

        let mut thfhe = ThFHE::from_key(1, &cks, &sks, &pubkey);

        println!("Sharing secret: {} out of {}", t, p);
        let start = Instant::now();
        thfhe.share_secret(t, p);
        let end = Instant::now();
        let dur = end - start;
        println!("Time taken: {}ms or {}us", dur.as_millis(), dur.as_micros());

        let rlwe_ctxt = TLweFromLwe(&ctext);
        let mut parties = vec![];
        for i in 0..t {
            parties.push(i+1);
        }
        
        let mut part_decs = vec![];
        let N = thfhe.pk.n.0;
        let sd = 0.0f64;
        for party in &parties {
            let shares = ThFHEKeyShare::new(&thfhe, *party);
            let partdec = shares.partial_decrypt(&rlwe_ctxt, &parties, t, p, sd);
            part_decs.push(partdec);

        }


        let thresult = final_decrypt(&rlwe_ctxt, part_decs, parties, t, p, N);
        println!("Threshold decryption result: {}", thresult);



    }

}
