extern crate blas_src;

use concrete_csprng::generators::SoftwareRandomGenerator;

use crate::FheBoolParameters;
use crate::boolean::{PLAINTEXT_FALSE, PLAINTEXT_TRUE};
use crate::boolean::prelude::BooleanParameters;
// use crate::core_crypto::algorithms::slice_algorithms::*;
use crate::core_crypto::algorithms::*;
// use crate::core_crypto::commons::dispersion::DispersionParameter;
use crate::core_crypto::commons::generators::{EncryptionRandomGenerator, SecretRandomGenerator};
use crate::core_crypto::commons::math::random::{ActivatedRandomGenerator, Gaussian, RandomGenerator};

use crate::core_crypto::commons::{parameters::*, ciphertext_modulus};
// use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use crate::core_crypto::prelude::{StandardDev, UnsignedTorus};
use crate::core_crypto::seeders::new_seeder;
use std::collections::HashMap;
use std::hash::Hash;
use std::ops::IndexMut;
use crate::boolean::{client_key::ClientKey, server_key::ServerKey};
use crate::boolean::parameters::{DEFAULT_PARAMETERS, TFHE_LIB_PARAMETERS};
use crate::core_crypto::commons::numeric::Numeric;

use ndarray::prelude::*;

type TorusType = u32;
type LweSampleType = Vec<TorusType>;

pub struct ThFHEPubKey {
    pub n: LweSize,
    pub n_samples: usize,
    pub alpha: StandardDev,
    pub samples: Vec<LweCiphertext<Vec<TorusType>>>,
    prng: SecretRandomGenerator<SoftwareRandomGenerator>,
    pub params: BooleanParameters
}

impl ThFHEPubKey {
    pub fn new(sk: &LweSecretKey<LweSampleType>, n_samples_: usize, params: &BooleanParameters) -> Self {
        let mut samples = Vec::new();

        let mut seeder = new_seeder();
        let seeder = seeder.as_mut();

        let secret_generator =
            SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());

        let mut enc_generator =
            EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);

        let noise_param = params.lwe_modular_std_dev;

        for _ in 0..n_samples_ {
            let mut ctxt = LweCiphertext::new(
                0u32, sk.lwe_dimension().to_lwe_size(),
                CiphertextModulus::new_native());
            lwe_encryption::encrypt_lwe_ciphertext(
                sk, &mut ctxt, Plaintext(TorusType::ZERO),
                noise_param, &mut enc_generator);
            samples.push(ctxt);
        }

        let actual_pkey = allocate_and_generate_new_lwe_public_key(sk, LwePublicKeyZeroEncryptionCount(n_samples_), params.lwe_modular_std_dev, CiphertextModulus::new_native(), &mut enc_generator);

        Self {
            n: sk.lwe_dimension().to_lwe_size(),
            n_samples: n_samples_,
            alpha: noise_param,
            prng: secret_generator,
            samples,
            params: params.clone(),

        }


    }

    pub fn from_client_key(ck: &ClientKey, n_samples_: usize, params: &BooleanParameters) -> Self {
        Self::new(&ck.lwe_secret_key, n_samples_, params)
    }

    pub fn clone(&self) -> Self {
        let mut seeder = new_seeder();
        let seeder = seeder.as_mut();

        let secret_generator =
            SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());

        Self {
            n: self.n.clone(),
            n_samples: self.n_samples,
            alpha: self.alpha,
            samples: self.samples.clone(),
            prng: secret_generator,
            params: self.params.clone()
        }
    }

    pub fn encrypt(self: &mut Self, result: &mut LweCiphertext<LweSampleType>, message: bool) {
        // Assume result is already 0-filled
        let encoded_msg: u32 = match message {
            true => PLAINTEXT_TRUE,
            false => PLAINTEXT_FALSE,
        };
        // encrypt_lwe_ciphertext_with_public_key(&self.actual_pkey, result, Plaintext(encoded_msg), &mut self.prng);
        let mut choices = vec![0u32; self.n_samples];
        self.prng.fill_slice_with_random_uniform_binary(choices.as_mut_slice());
        let mut v = vec![0u32; self.samples[0].lwe_size().0];
        for i in 0..self.n_samples {
            if choices[i] == 0 {
                let __body = self.samples[i].clone().into_container();
                assert!(v.len() == __body.len(), "Yo!");
                slice_algorithms::slice_wrapping_add_assign(v.as_mut_slice(), __body.as_slice());
            }
        }
        result.clone_from(&LweCiphertext::<LweSampleType>::from_container(v, CiphertextModulus::new_native()));
        let rbody = result.get_mut_body();

        
        *rbody.data = (*rbody.data).wrapping_add(Plaintext(encoded_msg).0);
    }
}

pub struct ThFHE {
    ncr_cache: HashMap::<(usize, usize), usize>,
    shared_key_repo: HashMap<(usize, usize), GlweSecretKey<Vec<TorusType>>>,
    pub pk: ThFHEPubKey,
    pub sk: ClientKey,
    pub bk: ServerKey,
    pub k: usize
}

pub struct ThFHEKeyShare<'a> {
    pub shared_key_repo: HashMap<usize, GlweSecretKey<Vec<TorusType>>>,	/* Stores <group_id>: <key_share> */
    mother: &'a ThFHE
}


impl ThFHE {
    pub fn new(k: usize) -> Self {
        let cks = ClientKey::new(&TFHE_LIB_PARAMETERS);
        let sks = ServerKey::new(&cks);
        let pubkey = ThFHEPubKey::from_client_key(&cks, 10, &TFHE_LIB_PARAMETERS);
        
        Self {
            ncr_cache: HashMap::<(usize, usize), usize>::new(),
            shared_key_repo: HashMap::<(usize, usize), GlweSecretKey<LweSampleType>>::new(),
            pk: pubkey,
            sk: cks,
            bk: sks,
            k
        }
    }
    pub fn from_key(k: usize, cks: &ClientKey, sks: &ServerKey, pubkey: &ThFHEPubKey) -> Self {
        Self {
            ncr_cache: HashMap::<(usize, usize), usize>::new(),
            shared_key_repo: HashMap::<(usize, usize), GlweSecretKey<LweSampleType>>::new(),
            pk: pubkey.clone(),
            sk: cks.clone(),
            bk: sks.clone(),
            k
        }
    }
    fn ncr(self: &Self, n: usize, r: usize) -> usize {
        if r == 0 {
            return 1;
        }else if r == 1 {
            return n;
        }

        match self.ncr_cache.get(&(n, r)) {
            Some(val) => *val,
            None => {
                self.ncr(n, r - 1) + self.ncr(n - 1, r - 1)
            }
            
        }
    }

}

pub(crate) fn matrix_copy(dst: &mut Array2<u32>, src: &Array2<u32>, dstR: usize, dstC: usize) {
    // for i in dstR..(dstR + src.dim().0){
    //     for j in dstC..(dstC + src.dim().1){
    //         (*dst)[[i, j]] = (*src)[[i - dstR, j - dstC]];
    //     }
    // }
    assert!(dstR + src.dim().0 <= dst.dim().0);
    assert!(dstC + src.dim().1 <= dst.dim().1);
    dst.slice_mut(s![dstR..(dstR + src.dim().0), dstC..(dstC + src.dim().1)]).assign(src);
}

pub(crate) fn opt_AND_combine(t: usize, k: usize) -> Array2<u32> {
    let I = Array::eye(k);
    let kt = k * t;
    let mut Mf = Array::zeros([kt, kt]);

    for r in 0..t {
		for c in 0..t {
			if r == 0 || c == t - r {
				matrix_copy(&mut Mf, &I, r*k, c*k);
			}
		}
	}

    Mf
}

pub(crate) fn opt_OR_combine(k: usize, t: usize, l: usize, A: Array2<u32>) -> Array2<u32> {
	let mut F = Array::zeros([A.dim().0, k]);
	let mut R = Array::zeros([A.dim().0, A.dim().1 - k]);

	for r in 0..A.dim().0 {
		for c in 0..A.dim().1{
			if c < k{
				F[[r, c]] = A[[r, c]];
			}else{
				R[[r, c - k]] = A[[r, c]];
			}
		}
	}

	let mut M = Array::zeros([l*k*t, k*(t-1) * l + k]);
	for i in 0..l {
		matrix_copy(&mut M, &F, i*k*t, 0);
		matrix_copy(&mut M, &R, i*k*t, k + i*k*(t-1));
	}

	M
}


impl ThFHE {
    fn build_distribution_matrix(self: &Self, t: usize, k: usize, p: usize) -> Array2<u32> {
        let M1 = opt_AND_combine(t, k);
        opt_OR_combine(k, t, self.ncr(p, t), M1)
    }

    fn build_rho(self: &Self, k: usize, p: usize, e: usize, key: &GlweSecretKey<Vec<TorusType>>) -> Array2<u32>{
        let N = self.pk.n.0 - 1;
        let mut rho = Array::zeros([e, N]);
        let key = key.clone().into_container();
        for row in 0..k {
            for col in 0..N {
                rho[[row,col]] = key[row * N + col];
            }
        }
        
        let mut seeder = new_seeder();
        let seeder = seeder.as_mut();

        let mut secret_generator =
            SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());

        let mut __randvals = vec![0; (e - k) * N];
        secret_generator.fill_slice_with_random_uniform_binary(__randvals.as_mut_slice());
        let mut __rj = 0;

        for row in k..e{
            for col in 0..N{
                rho[[row, col]] = __randvals[__rj];
                __rj += 1;
            }
        } 
        
        rho
    }

    fn find_parties(self: &Self, pt: &mut Vec<usize>, gid: usize, t: usize, p: usize) {
        let mut mem = 0;
        let mut tmp = 0;
        let mut gid = gid;

        pt.clear();

        for i in 1..p {
            // dbg!("{} {} {} {}", p, i, t, mem);
            if mem + 1 > t {
                break;
            }
            tmp = self.ncr(p - i, t - mem -1);
            if gid > tmp {
                gid -= tmp;
            }else{
                pt.push(i);
                mem += 1;
            }
            if mem + (p-i) == t {
                for j in (i + 1)..(p + 1) {
                    pt.push(j);
                }
                break;
            }
        }
    }

    pub fn find_group_id(self: &Self, parties: &Vec<usize>, t: usize, p: usize) -> usize{
        let mut mem = 0;
        let mut group_count = 1;
        for i in 1..(p + 1) {
            if parties.iter().position(|&x| x == i) != None {
                mem += 1;
            }else{
                group_count += self.ncr(p - i, t - mem - 1);
            }
            if mem == t {
                break;
            }
        }
        
        group_count
    }

    pub fn distribute_shares(self: &mut Self, S: Array2<u32>, t: usize, p: usize)  {
        let r = S.dim().0;
        let N = self.pk.n.0 - 1;
        let mut row = 1;
        let mut group_id: usize = 0;
        let mut row_count = 0;
        let mut parties = Vec::<usize>::new();

        while row <= r {
            group_id = ((row as f64)/((self.k*t) as f64)).ceil() as usize;
            self.find_parties(&mut parties, group_id, t, p);
            for it in 1..(t + 1) {
                row_count = row + (it - 1) * self.k;
                let mut key_vec = Vec::<TorusType>::new();
                for i in 0..self.k {
                    for j in 0..N {
                        key_vec.push(S[[row_count + i - 1, j]]);
                    }
                }
                self.shared_key_repo.insert(
                    (parties[it-1], group_id),
                    GlweSecretKey::from_container(key_vec, PolynomialSize(N))
                );
            }
            row += self.k*t;
        }
    }

    pub fn share_secret(self: &mut Self, t: usize, p: usize) {
        let key = &TLweKeyFromLweKey(&self.sk.lwe_secret_key);
        let k = self.k;
        let N = self.pk.n.0 - 1;

        let M = self.build_distribution_matrix(t, k, p);
        // println!("M = {}", M);
        let d = M.dim().0;
        let e = M.dim().1;

        let rho = self.build_rho(k, p, e, key);
        // println!("rho = {}", rho);


        let shares = M.dot(&rho);
        // println!("M . rho = {}", shares);
        
        self.distribute_shares(shares, t, p);
    }
}

impl<'a> ThFHEKeyShare<'a> {
    pub fn new(mother: &'a ThFHE, party_id: usize) -> Self {
        let mut skr = HashMap::<usize, GlweSecretKey<Vec<TorusType>>>::new();
        for it in mother.shared_key_repo.iter() {
            if it.0.0 == party_id {
                skr.insert(it.0.1, it.1.clone());
            }
        }
        Self { 
            shared_key_repo: skr, mother}
    }

    pub fn partial_decrypt(self: &Self, ciphertext: &GlweCiphertext<Vec<TorusType>>,
            parties: &Vec<usize>, t: usize, p: usize, sd: f64) -> Polynomial<Vec<TorusType>> {
        let k = self.mother.k;
        assert_eq!(k, 1);
        let N = self.mother.pk.n.0 - 1;
        let group_id = self.mother.find_group_id(&parties, t, p);
        let part_key = &self.shared_key_repo[&group_id];

        // for j in 0..N {
        //     partial_cipher->coefsT[j] = 0;
        // }
        let mut __gaussian = vec![0u32; N];
        let mut seeder = new_seeder();
        let seeder = seeder.as_mut();

        let mut gen:RandomGenerator<SoftwareRandomGenerator> = RandomGenerator::new(seeder.seed());
        gen.fill_slice_with_random_gaussian(__gaussian.as_mut_slice(), 0.0, sd);
        let mut smudging_err = Polynomial::from_container(__gaussian);
        //  GlweCiphertext::from_container(__gaussian, N, ciphertext_modulus::CiphertextModulus);
        // // for j in 0..N {
        //     smudging_err[j] = Gaussian
        // }
        let (mask, _body) = ciphertext.get_mask_and_body();
        
        polynomial_algorithms::polynomial_wrapping_add_multisum_assign(
            &mut smudging_err, &mask.as_polynomial_list(), &part_key.as_polynomial_list());
        
        // torusPolynomialAddMulR(partial_cipher, &part_key->key[j], &ciphertext->a[j]);

        // torusPolynomialAddTo(partial_cipher, smudging_err);
        // for j in 0..N {
        //     partial_ciphertext->coefsT[j] = partial_cipher->coefsT[j];
        // }

        smudging_err
    }
}

pub fn final_decrypt(ciphertext: &GlweCiphertext<Vec<TorusType>>, partial_ciphertexts: Vec<Polynomial<Vec<TorusType>>>,
        parties: Vec<usize>, t: usize, p: usize, N: usize) -> i32 {
	let mut result_msg = 0;
    let mut _c = ciphertext.clone();
    let (_mask, mut body) = _c.get_mut_mask_and_body();
	let mut result = body.as_mut_polynomial();

    for i in 0..t{
        let p = match partial_ciphertexts.get(i) {
            Some(_p) => _p,
            None => {
                panic!("Size mismatch");
            }
        };

        if i == 0 {
            polynomial_algorithms::polynomial_wrapping_sub_assign(&mut result, p);
        }else{
            polynomial_algorithms::polynomial_wrapping_add_assign(&mut result, p);
        }
    }
	
    println!("{}", result.polynomial_size().0);
	let coeff = match result.get(0) {
        Some(c) => c,
        None => {
            panic!("Not supposed to happen");
        }
    };
    if (*coeff) > 0 {
        result_msg = 1;
    } else{
        result_msg = 0;
    }
    return result_msg;
}


pub fn TLweFromLwe(cipher: &LweCiphertext<Vec<TorusType>>) -> GlweCiphertext<Vec<TorusType>>{
    let (mask, body) = cipher.get_mask_and_body();
    
    let mut v = vec![0u32; mask.lwe_dimension().0 * 2];

    println!("{} {}", cipher.lwe_size().0, mask.lwe_dimension().0);

    for i in 0..mask.lwe_dimension().0 {
        if i == 0 {
            v[i] = match mask.as_ref().get(i) {
                Some(_v) => *_v,
                None => {
                    panic!("Not supposed to happen 1");
                }
            }
        }else{
            v[i] = match mask.as_ref().get(mask.lwe_dimension().0 - i) {
                Some(_v) => (-(*_v as i32)) as u32,
                None => {
                    panic!("Not supposed to happen 2");
                }
            }
        }
    }
    v[mask.lwe_dimension().0] = *(body.data);

    GlweCiphertext::<Vec<TorusType>>::from_container(v, PolynomialSize(mask.lwe_dimension().0), cipher.ciphertext_modulus())
}


pub fn TLweKeyFromLweKey(key: &LweSecretKey<Vec<TorusType>>) -> GlweSecretKey<Vec<TorusType>> {
    GlweSecretKey::<Vec<TorusType>>::from_container(key.as_ref().to_vec(), PolynomialSize(key.lwe_dimension().0))
}