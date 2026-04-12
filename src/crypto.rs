use std::fs;
use std::io;
use std::io::Write;

use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::{PublicKey, SecretKey, Ciphertext, SharedSecret};
use x25519_dalek::{EphemeralSecret, PublicKey as xPublicKey, StaticSecret};

use serde::{Serialize, Deserialize};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use argon2::Argon2;
use rand::RngCore;
use rand::rngs::OsRng;

use zeroize::Zeroize;


#[derive(Serialize, Deserialize)]
pub struct PrivateKeys {
    //x25519
    pub x25519_priv : [u8; 32],
    //Kyber768
    pub kyber_priv : Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct PublicKeys {
    //x25519
    pub x25519_pub : [u8; 32],
    //Kyber768
    pub kyber_pub : Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct IdentityFingerprint {
    pub onion_address: String,
    pub x25519_pub: [u8; 32],
    pub kyber_pub: Vec<u8>,
}

pub fn keygen() -> (PrivateKeys, PublicKeys) {
    // EphemeralSecret yerine doğrudan StaticSecret üretelim
    // Çünkü StaticSecret hem Diffie-Hellman yapar hem de baytlara (to_bytes) kolayca dönüşür
    let x25519_secret = StaticSecret::random_from_rng(OsRng);
    let x25519_pub = xPublicKey::from(&x25519_secret);

    // Kyber üretimi aynı kalıyor
    let (kyber_pub, kyber_sec) = pqcrypto_kyber::kyber768::keypair();

    let priv_keys = PrivateKeys {
        x25519_priv: x25519_secret.to_bytes(), // Artık doğrudan çalışır
        kyber_priv: kyber_sec.as_bytes().to_vec(),
    };

    let pub_keys = PublicKeys {
        x25519_pub: x25519_pub.to_bytes(),
        kyber_pub: kyber_pub.as_bytes().to_vec(),
    };

    (priv_keys, pub_keys)
}

#[derive(Serialize, Deserialize)]
pub struct KeyVault {
    is_encrypted : bool,
    argon2_salt : Option<[u8; 16]>,
    aes_nonce : Option<[u8; 12]>,

    blob : Vec<u8>,
}


pub fn save_identity(
    pub_path : &std::path::Path,
    priv_path : &std::path::Path,
    priv_keys : PrivateKeys,
    pub_keys : PublicKeys,
    password : Option<&str>
) -> io::Result<()> {
    // 1. Public Key kaydı
    let pub_bytes = bincode::serialize(&pub_keys)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    fs::write(pub_path, pub_bytes)?;  

    // 2. Private Key serileştirme
    let priv_serialized = bincode::serialize(&priv_keys)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    let vault = if let Some(pass) = password {
        // Argon2 salt
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);

        // --- DÜZELTME: 16 yerine 32 bayt (AES-256 için) ---
        let mut key_bytes = [0u8; 32]; 
        Argon2::default()
            .hash_password_into(pass.as_bytes(), &salt, &mut key_bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Argon2 Error: {}", e)))?;

        // AES256 nonce
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // AES256 encrypt (Artık key_bytes 32 bayt olduğu için paniklemeyecek)
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
        
        let encrypted_blob = cipher
            .encrypt(nonce, priv_serialized.as_ref())
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("AES Şifreleme Hatası: {}", e)))?;

        // Belleği temizle
        key_bytes.zeroize();

        KeyVault {
            is_encrypted: true,
            argon2_salt: Some(salt),
            aes_nonce: Some(nonce_bytes),
            blob: encrypted_blob,
        }
    } else {
        KeyVault {
            is_encrypted: false,
            argon2_salt: None,
            aes_nonce: None,
            blob: priv_serialized,
        }
    };

    let vault_bytes = bincode::serialize(&vault)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    // Dosyaya yazma ve yetkilendirme
    let mut file = fs::OpenOptions::new()
        .create(true).write(true).truncate(true).open(priv_path)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }

    file.write_all(&vault_bytes)?;
    Ok(())
}

//Check if the id is encrypted or not
pub fn is_identity_encrypted(priv_path: &std::path::Path) -> io::Result<bool> {
    let vault_bytes = fs::read(priv_path)?;
    let vault: KeyVault = bincode::deserialize(&vault_bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    
    Ok(vault.is_encrypted)
}

//Read the keys
pub fn load_identity(
    pub_path: &std::path::Path,
    priv_path: &std::path::Path,
    password: Option<&str>
) -> io::Result<(PrivateKeys, PublicKeys)> {
    
    let pub_bytes = fs::read(pub_path)?;
    let pub_keys: PublicKeys = bincode::deserialize(&pub_bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let vault_bytes = fs::read(priv_path)?;
    let vault: KeyVault = bincode::deserialize(&vault_bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let priv_bytes = if vault.is_encrypted {
        let pass = password.ok_or_else(|| {
            io::Error::new(io::ErrorKind::PermissionDenied, "Bu anahtarı açmak için şifre gerekiyor!")
        })?;

        let salt = vault.argon2_salt.ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "Salt verisi bulunamadı!")
        })?;

        let nonce_bytes = vault.aes_nonce.ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "Nonce verisi bulunamadı!")
        })?;

        // --- BURASI DA 32 BAYT OLMALI ---
        let mut key_bytes = [0u8; 32];
        Argon2::default()
            .hash_password_into(pass.as_bytes(), &salt, &mut key_bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Argon2 Error: {}", e)))?;

        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
        let nonce = Nonce::from_slice(&nonce_bytes);

        let decrypted_blob = cipher
            .decrypt(nonce, vault.blob.as_ref())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Şifre yanlış veya veri bozuk!"))?;

        key_bytes.zeroize();
        decrypted_blob
    } else {
        vault.blob
    };

    let priv_keys: PrivateKeys = bincode::deserialize(&priv_bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("Anahtarlar ayrıştırılamadı: {}", e)))?;

    Ok((priv_keys, pub_keys))
}

