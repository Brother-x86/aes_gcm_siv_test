use anyhow::bail;
use aes_gcm_siv::{
    aead::{Aead, KeyInit, OsRng},
    Aes256GcmSiv, Nonce // Or `Aes128GcmSiv`
};

fn encrypt_decrypt() -> Result<(Vec<u8>,Vec<u8>), anyhow::Error> {
    
    let key = Aes256GcmSiv::generate_key(&mut OsRng);
    let cipher = Aes256GcmSiv::new(&key);
    let nonce_slice: &[u8; 12]=b"unique nonce";
    let nonce = Nonce::from_slice(nonce_slice); // 96-bits; unique per message
    println!("{:?}",nonce.to_ascii_lowercase());
    let ciphertext: Vec<u8> = match cipher.encrypt(nonce, b"plaintext message".as_ref()) {
        Ok(data) => data,
        Err(e) => bail!("ciphertext error: {}",e)
    };
    let plaintext: Vec<u8> = match cipher.decrypt(nonce, ciphertext.as_ref()) {
        Ok(data) => data,
        Err(e) => bail!("plaintext error: {}",e)
    };
    assert_eq!(&plaintext, b"plaintext message");
    Ok((ciphertext,plaintext))
}

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
struct CryptoMaterial{
    pub key :Vec<u8>,
    pub nonce:[u8; 12]
}

fn generate_material() -> CryptoMaterial {
    let key: aes_gcm_siv::aead::generic_array::GenericArray<u8, _> = Aes256GcmSiv::generate_key(&mut OsRng);
    //TODO randomized the nonce
    // 96-bits; unique per message
    let nonce_slice: &[u8; 12]=b"unique nonce";
    CryptoMaterial{
        key:key.as_slice().to_owned(),
        nonce:nonce_slice.to_owned()
    }
}

fn encrypt(crypto_mat:&CryptoMaterial,plaintext:Vec<u8>) -> Result<Vec<u8>, anyhow::Error> {    
    let key: aes_gcm_siv::aead::generic_array::GenericArray<u8, _> = aes_gcm_siv::aead::generic_array::GenericArray::clone_from_slice(&crypto_mat.key);
    let cipher = Aes256GcmSiv::new(&key);
    let nonce: &aes_gcm_siv::aead::generic_array::GenericArray<u8, aes_gcm_siv::aead::generic_array::typenum::UInt<aes_gcm_siv::aead::generic_array::typenum::UInt<aes_gcm_siv::aead::generic_array::typenum::UInt<aes_gcm_siv::aead::generic_array::typenum::UInt<aes_gcm_siv::aead::generic_array::typenum::UTerm, aes_gcm_siv::aead::consts::B1>, aes_gcm_siv::aead::consts::B1>, aes_gcm_siv::aead::consts::B0>, aes_gcm_siv::aead::consts::B0>> = Nonce::from_slice(&crypto_mat.nonce);
    let plaintext_u8: &[u8] = &plaintext;
    let ciphertext: Vec<u8> = match cipher.encrypt(nonce,plaintext_u8 ) {
        Ok(data) => data,
        Err(e) => bail!("ciphertext error: {}",e)
    };
    Ok(ciphertext)
}

fn decrypt(crypto_mat:&CryptoMaterial,ciphertext:Vec<u8>) -> Result<Vec<u8>, anyhow::Error> {
    let key: aes_gcm_siv::aead::generic_array::GenericArray<u8, _> = aes_gcm_siv::aead::generic_array::GenericArray::clone_from_slice(&crypto_mat.key);
    let cipher = Aes256GcmSiv::new(&key);
    let nonce = Nonce::from_slice(&crypto_mat.nonce); // 96-bits; unique per message
    let plaintext: Vec<u8> = match cipher.decrypt(nonce, ciphertext.as_ref()) {
        Ok(data) => data,
        Err(e) => bail!("plaintext error: {}",e)
    };
    Ok(plaintext)
}

fn main() {
    // step1: encrypt_decrypt same function
    let (a,b) = encrypt_decrypt().unwrap();
    println!("ciphertext: {}",String::from_utf8_lossy(&*a));
    println!("plaintext: {}",String::from_utf8_lossy(&*b));

    // step2 : encrypt() + decrypt() with CryptoMaterial that could be serialized
    println!("");
    let plaintext = b"plaintext message 2".to_vec();
    let crypto_mat= generate_material();
    let ciphertext = encrypt(&crypto_mat,plaintext).unwrap();
    println!("ciphertext: {}",String::from_utf8_lossy(&*ciphertext));
    let plaintext_new = decrypt(&crypto_mat,ciphertext).unwrap();
    println!("plaintext_new: {}",String::from_utf8_lossy(&*plaintext_new));

}
