use std::io;

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

use hkdf::Hkdf;
use sha2::Sha256;

use tokio::net::{TcpStream, TcpListener};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_socks::tcp::Socks5Stream;

use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use rusqlite::Connection;

use bincode;

use crate::crypto::{PrivateKeys, PublicKeys};


const TOR_PROXY: &str = "127.0.0.1:9050";
const APP_PORT: u16 = 4242;

#[derive(Serialize, Deserialize, Debug)]
pub struct SessionOffer {
    pub ephemeral_x25519_pub: [u8; 32],
    pub ephemeral_kyber_pub: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SessionAccept {
    pub ephemeral_x25519_pub: [u8; 32],
    pub ephemeral_kyber_ciphertext: Vec<u8>,
    pub static_kyber_ciphertext: Vec<u8>,
}

pub struct EphemeralState {
    pub x25519_secret: EphemeralSecret,
    pub kyber_secret: Vec<u8>,
}


#[derive(Serialize, Deserialize, Debug)]
pub enum TorquePacket {
    // PFS Session setup packages
    HandshakeOffer {
        sender_onion : String,
        offer : SessionOffer
    },
    HandshakeAccept(SessionAccept),
    
    // Encrypted data
    EncryptedPayload{
        sender_onion : String,
        data : Vec<u8>
    },
    
    // Health check
    IsOk,
    OkResponse,

    KeyRequest,
    KeyResponse { 
        x25519_pub: [u8; 32], 
        kyber_pub: Vec<u8> 
    },
}

pub fn create_session_offer() -> (SessionOffer, EphemeralState) {
    // Geçici X25519 üretimi
    let eph_x25519_sec = EphemeralSecret::random_from_rng(OsRng);
    let eph_x25519_pub = xPublicKey::from(&eph_x25519_sec);

    // Geçici Kyber üretimi
    let (eph_kyber_pub, eph_kyber_sec) = pqcrypto_kyber::kyber768::keypair();

    let offer = SessionOffer {
        ephemeral_x25519_pub: eph_x25519_pub.to_bytes(),
        ephemeral_kyber_pub: eph_kyber_pub.as_bytes().to_vec(),
    };

    let state = EphemeralState {
        x25519_secret: eph_x25519_sec,
        kyber_secret: eph_kyber_sec.as_bytes().to_vec(),
    };

    (offer, state)
}

pub fn accept_session_offer(
    offer: &SessionOffer,
    static_priv_own: &PrivateKeys,
    static_pub_peer: &PublicKeys,
) -> Result<(SessionAccept, [u8; 32]), io::Error> {

    let eph_x25519_sec_own = EphemeralSecret::random_from_rng(OsRng);
    let eph_x25519_pub_own = xPublicKey::from(&eph_x25519_sec_own);
    
    let eph_x25519_pub_peer = xPublicKey::from(offer.ephemeral_x25519_pub);
    let eph_dh_secret = eph_x25519_sec_own.diffie_hellman(&eph_x25519_pub_peer);

    //Ephemeral Kyber Encapsulation
    let eph_kyber_pub_peer = pqcrypto_kyber::kyber768::PublicKey::from_bytes(&offer.ephemeral_kyber_pub)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let (eph_kyber_ss, eph_kyber_ct) = pqcrypto_kyber::kyber768::encapsulate(&eph_kyber_pub_peer);

    // Id verification
    let static_x25519_own = StaticSecret::from(static_priv_own.x25519_priv);
    let static_x25519_pub_peer = xPublicKey::from(static_pub_peer.x25519_pub);
    let static_dh_secret = static_x25519_own.diffie_hellman(&static_x25519_pub_peer);

    let static_kyber_pub_peer = pqcrypto_kyber::kyber768::PublicKey::from_bytes(&static_pub_peer.kyber_pub)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let (static_kyber_ss, static_kyber_ct) = pqcrypto_kyber::kyber768::encapsulate(&static_kyber_pub_peer);

    //Master Session Key Derivation
    let mut combined = Vec::new();
    combined.extend_from_slice(eph_dh_secret.as_bytes());       // PFS classic
    combined.extend_from_slice(eph_kyber_ss.as_bytes());        // PFS PQC
    combined.extend_from_slice(static_dh_secret.as_bytes());    // Auth classic
    combined.extend_from_slice(static_kyber_ss.as_bytes());     // Auth PQC

    let hkdf = Hkdf::<Sha256>::new(None, &combined);
    let mut session_key = [0u8; 32];
    hkdf.expand(b"p2p-tor-session-v1", &mut session_key)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("HKDF Error: {}", e)))?;

    let accept_payload = SessionAccept {
        ephemeral_x25519_pub : eph_x25519_pub_own.to_bytes(),
        ephemeral_kyber_ciphertext : eph_kyber_ct.as_bytes().to_vec(),
        static_kyber_ciphertext : static_kyber_ct.as_bytes().to_vec(),
    };

    Ok((accept_payload, session_key))
}

pub fn finalize_session(
    accept: &SessionAccept,
    state_own: EphemeralState,
    static_priv_own: &PrivateKeys,
    static_pub_peer: &PublicKeys,
) -> Result<[u8; 32], io::Error> {

    // 1. PFS Ephemeral DH
    let eph_x25519_pub_peer = xPublicKey::from(accept.ephemeral_x25519_pub);
    let eph_dh_secret = state_own.x25519_secret.diffie_hellman(&eph_x25519_pub_peer);

    // 2. PFS Ephemeral Kyber Decapsulation
    let eph_kyber_sec_own = pqcrypto_kyber::kyber768::SecretKey::from_bytes(&state_own.kyber_secret)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let eph_kyber_ct = pqcrypto_kyber::kyber768::Ciphertext::from_bytes(&accept.ephemeral_kyber_ciphertext)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let eph_kyber_ss = pqcrypto_kyber::kyber768::decapsulate(&eph_kyber_ct, &eph_kyber_sec_own);

    //Id verification
    let static_x25519_own = StaticSecret::from(static_priv_own.x25519_priv);
    let static_x25519_pub_peer = xPublicKey::from(static_pub_peer.x25519_pub);
    let static_dh_secret = static_x25519_own.diffie_hellman(&static_x25519_pub_peer);

    let static_kyber_sec_own = pqcrypto_kyber::kyber768::SecretKey::from_bytes(&static_priv_own.kyber_priv)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let static_kyber_ct = pqcrypto_kyber::kyber768::Ciphertext::from_bytes(&accept.static_kyber_ciphertext)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let static_kyber_ss = pqcrypto_kyber::kyber768::decapsulate(&static_kyber_ct, &static_kyber_sec_own);

    // 4. HKDF
    let mut combined = Vec::new();
    combined.extend_from_slice(eph_dh_secret.as_bytes());
    combined.extend_from_slice(eph_kyber_ss.as_bytes());
    combined.extend_from_slice(static_dh_secret.as_bytes());
    combined.extend_from_slice(static_kyber_ss.as_bytes());

    let hkdf = Hkdf::<Sha256>::new(None, &combined);
    let mut session_key = [0u8; 32];
    hkdf.expand(b"p2p-tor-session-v1", &mut session_key)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("HKDF Error: {}", e)))?;

    Ok(session_key)
}

pub async fn send_packet(onion_address: &str, packet: TorquePacket) -> Result<TorquePacket, std::io::Error> {
    
    let target = format!("{}:{}", onion_address, APP_PORT);
    
    // Tor SOCKS5
    let mut stream = Socks5Stream::connect(TOR_PROXY, target).await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::ConnectionRefused, format!("Tor Proxy Error: {}", e)))?;

    // Make packet bytes using bincode
    let packet_bytes = bincode::serialize(&packet)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    // Send data length, then data
    let length = packet_bytes.len() as u32;
    stream.write_all(&length.to_be_bytes()).await?;
    stream.write_all(&packet_bytes).await?;

    // Wait response
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let reply_len = u32::from_be_bytes(len_buf) as usize;

    let mut reply_buf = vec![0u8; reply_len];
    stream.read_exact(&mut reply_buf).await?;

    // Parse response
    let reply_packet: TorquePacket = bincode::deserialize(&reply_buf)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    Ok(reply_packet)
    // End of scope, so tcp
}

pub fn pack_encrypted_message(
    message: &str, 
    session_key: &[u8; 32],
    my_onion: &str // EKLENDİ
) -> Result<TorquePacket, io::Error> {
    
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(session_key));
    let ciphertext = cipher
        .encrypt(nonce, message.as_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Encryption error: {}", e)))?;

    let mut payload = nonce_bytes.to_vec();
    payload.extend(ciphertext);

    // Güncellendi: Artık sender_onion içeriyor
    Ok(TorquePacket::EncryptedPayload { 
        sender_onion: my_onion.to_string(), 
        data: payload 
    })
}

pub fn unpack_encrypted_message(
    payload_data: &[u8],
    session_key: &[u8; 32],
) -> Result<String, io::Error> {
    
    // Check data length
    if payload_data.len() < 12 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Payload too short!"));
    }

    // First 12 bytes nonce, others data
    let (nonce_bytes, ciphertext) = payload_data.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);
    
    // Start AES engine
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(session_key));

    // Decrypt
    let decrypted_bytes = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("AES Decryption error: {}", e)))?;

    // Translate to utf8
    String::from_utf8(decrypted_bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("UTF-8 error: {}", e)))
}


pub async fn start_listener(
    addr: &str,
    db_conn: Arc<Mutex<Connection>>, 
    active_sessions: Arc<Mutex<HashMap<String, [u8; 32]>>>,
    my_priv_keys: Arc<crate::crypto::PrivateKeys>,
    my_pub_keys : Arc<crate::crypto::PublicKeys>
) -> io::Result<()> {
    
    let listener = TcpListener::bind(addr).await?;

    loop {
        let (mut socket, _) = listener.accept().await?;
        
        // Thread-safe klonlar yaratıyoruz
        let db_clone = Arc::clone(&db_conn);
        let sessions_clone = Arc::clone(&active_sessions);
        let my_priv_keys_clone = Arc::clone(&my_priv_keys); // Clon for handshake
        let my_pub_keys_clone = Arc::clone(&my_pub_keys);

        tokio::spawn(async move {
            let mut len_buf = [0u8; 4];
            if socket.read_exact(&mut len_buf).await.is_ok() {
                let len = u32::from_be_bytes(len_buf) as usize;
                let mut buf = vec![0u8; len];
                
                if socket.read_exact(&mut buf).await.is_ok() {
                    
                    // Güvenlik: unwrap() kaldırıldı, if let kullanıldı.
                    if let Ok(packet) = bincode::deserialize::<TorquePacket>(&buf) {
                        match packet {
                            TorquePacket::IsOk => {
                                let response = bincode::serialize(&TorquePacket::OkResponse).unwrap();
                                let resp_len = (response.len() as u32).to_be_bytes();
                                let _ = socket.write_all(&resp_len).await;
                                let _ = socket.write_all(&response).await;
                            },
                            
                            TorquePacket::EncryptedPayload { sender_onion, data } => {
                                // Find session keys
                                let session_key_opt = {
                                    let sessions = sessions_clone.lock().unwrap();
                                    sessions.get(&sender_onion).cloned()
                                };

                                if let Some(session_key) = session_key_opt {
                                    // Decrypt message
                                    match unpack_encrypted_message(&data, &session_key) {
                                        Ok(message_text) => {

                                            {
                                            // Write to database
                                            let conn = db_clone.lock().unwrap();
                        
                                            // Check sender
                                            match crate::database::get_contact_info(&conn, &sender_onion) {
                                                Ok((sender_id, nickname_opt)) => {
                                                    let _ = crate::database::add_message(&conn, sender_id, &message_text);
                            
                                                    // find nickname
                                                    if let Some(nick) = nickname_opt {
                                                        println!("{}> {}", nick, message_text);
                                                    } else {
                                                        println!("${}> {}", sender_onion, message_text);
                                                    }
                                                },
                                                Err(rusqlite::Error::QueryReturnedNoRows) => {
                                                    // no
                                                    println!("${}> {}", sender_onion, message_text);
                            
                                                    // Add nameless
                                                    if let Ok(new_sender_id) = crate::database::add_contact(&conn, &sender_onion, None) {
                                                        let _ = crate::database::add_message(&conn, new_sender_id, &message_text);
                                                    }
                                                },
                                                Err(e) => println!("Database read error: {}", e),
                                            }
                                            }
                                            let response = bincode::serialize(&TorquePacket::OkResponse).unwrap();
                                            let resp_len = (response.len() as u32).to_be_bytes();
                                            let _ = socket.write_all(&resp_len).await;
                                            let _ = socket.write_all(&response).await;
                                        },
                                        Err(e) => println!("Decryption error! {}", e),
                                    }
                                } else {
                                    println!("A message without session ({})", sender_onion);
                                }
                            },   
                            
                            // Handshake
                            TorquePacket::HandshakeOffer { sender_onion, offer } => {
                                // 1. Veritabanı sorgusunu kilidin yaşadığı parantezin İÇİNE alıyoruz
                                let peer_pub_keys_res = {
                                    let conn = db_clone.lock().unwrap();
                                    // Sorgu burada yapılır, sonuç peer_pub_keys_res değişkenine aktarılır
                                    crate::database::get_contact_pub_keys(&conn, &sender_onion)
                                }; // <--- 'conn' burada ölür (kilit bırakılır), ama 'peer_pub_keys_res' yaşar.

                               // 2. Artık elimizde kilit yok, güvenle devam edebiliriz
                                if let Ok(peer_pub_keys) = peer_pub_keys_res {
                                    match accept_session_offer(&offer, &my_priv_keys_clone, &peer_pub_keys) {
                                        Ok((accept_payload, session_key)) => {
                                            // Oturum anahtarını kaydetmek için kısa süreliğine kilit aç
                                            {
                                                let mut sessions = sessions_clone.lock().unwrap();
                                                sessions.insert(sender_onion.clone(), session_key);
                                            } 

                                            let response = bincode::serialize(&TorquePacket::HandshakeAccept(accept_payload)).unwrap();
                                            let resp_len = (response.len() as u32).to_be_bytes();
                
                                            // .await geldiğinde hiçbir MutexGuard (conn veya sessions) elde değil.
                                            // Rust artık mutlu.
                                            let _ = socket.write_all(&resp_len).await;
                                            let _ = socket.write_all(&response).await;
                
                                            println!("🔒 Kriptografik oturum kuruldu: {}", sender_onion);
                                        },
                                        Err(e) => println!("Handshake Hatası: {}", e),
                                    }
                                } else {
                                    println!("⚠️ Bilinmeyen birinden Handshake teklifi geldi: {}", sender_onion);
                                }
                            },
                            TorquePacket::KeyRequest => {
                                let response = TorquePacket::KeyResponse {
                                    x25519_pub: my_pub_keys_clone.x25519_pub,
                                    kyber_pub: my_pub_keys_clone.kyber_pub.clone(),
                                };
                                let response_bytes = bincode::serialize(&response).unwrap();
                                let resp_len = (response_bytes.len() as u32).to_be_bytes();
                                let _ = socket.write_all(&resp_len).await;
                                let _ = socket.write_all(&response_bytes).await;
                                 println!("({}) requested our public keys.", socket.peer_addr().unwrap());
                            },

                            TorquePacket::HandshakeAccept(_) => {
                                //
                            },
                            
                            _ => {}
                        }
                    }
                }
            }
        });
    }
}
