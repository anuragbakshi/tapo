use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use base64::{engine::general_purpose, Engine as _};
use log::debug;

use rsa::pkcs8::{EncodePublicKey, LineEnding};
use sha1::{Digest, Sha1};

#[derive(Debug, Clone)]
pub(crate) struct PassthroughKeyPair {
    rsa_private: rsa::RsaPrivateKey,
    rsa_public: rsa::RsaPublicKey,
}

impl PassthroughKeyPair {
    pub fn new() -> anyhow::Result<Self> {
        debug!("Generating RSA key pair...");
        let rsa_private = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 1024)?;
        let rsa_public = rsa::RsaPublicKey::from(&rsa_private);

        Ok(Self {
            rsa_private,
            rsa_public,
        })
    }

    pub fn get_public_key(&self) -> anyhow::Result<String> {
        let public_key_pem = self.rsa_public.to_public_key_pem(LineEnding::default())?;
        let public_key = std::str::from_utf8(public_key_pem.as_bytes())?.to_string();

        Ok(public_key)
    }
}

#[derive(Debug)]
pub(crate) struct PassthroughCipher {
    key: Vec<u8>,
    iv: Vec<u8>,
}

impl PassthroughCipher {
    pub fn new(key: &str, key_pair: &PassthroughKeyPair) -> anyhow::Result<Self> {
        debug!("Will decode handshake key {:?}...", &key[..5]);

        let key_bytes = general_purpose::STANDARD.decode(key)?;

        let decrypted = key_pair
            .rsa_private
            .decrypt(rsa::Pkcs1v15Encrypt, &key_bytes)?;

        let decrypt_count = decrypted.len();
        if decrypt_count != 32 {
            return Err(anyhow::anyhow!("expected 32 bytes, got {decrypt_count}"));
        }

        Ok(PassthroughCipher {
            key: decrypted[0..16].to_vec(),
            iv: decrypted[16..32].to_vec(),
        })
    }

    pub fn encrypt(&self, data: &str) -> anyhow::Result<String> {
        let cipher_bytes = cbc::Encryptor::<aes::Aes128>::new(
            self.key.as_slice().into(),
            self.iv.as_slice().into(),
        )
        .encrypt_padded_vec_mut::<Pkcs7>(&data.as_bytes());
        let cipher_base64 = general_purpose::STANDARD.encode(cipher_bytes);

        Ok(cipher_base64)
    }

    pub fn decrypt(&self, cipher_base64: &str) -> anyhow::Result<String> {
        let cipher_bytes = general_purpose::STANDARD.decode(cipher_base64)?;
        let decrypted_bytes = cbc::Decryptor::<aes::Aes128>::new(
            self.key.as_slice().into(),
            self.iv.as_slice().into(),
        )
        .decrypt_padded_vec_mut::<Pkcs7>(cipher_bytes.as_slice())
        .unwrap();
        let decrypted = std::str::from_utf8(&decrypted_bytes)?.to_string();

        Ok(decrypted)
    }
}

impl PassthroughCipher {
    pub fn sha1_digest_username(username: String) -> String {
        let mut hasher = Sha1::new();
        hasher.update(username.as_bytes());
        let hash = hasher.finalize();

        base16ct::lower::encode_string(&hash)
    }
}
