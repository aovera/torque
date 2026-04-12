use std::io;
use std::convert::TryInto;

use rusqlite::{Connection, Result};
use bincode;

use serde::{Serialize, Deserialize};

use crate::crypto::{IdentityFingerprint, PublicKeys};

pub fn init_db(db_path: &std::path::Path, password: Option<&str>) -> Result<Connection> {
    let conn = Connection::open(db_path)?;

    if let Some(pass) = password {
        // SQLCipher yerleşik parola yönetimi
        // SQL Injection riskine karşı PRAGMA için rusqlite'ın pragma_update metodunu kullanıyoruz
        conn.pragma_update(None, "key", pass)?;
        
        // Şifrelemeyi/Parolayı Test Et
        // DÜZELTME: SELECT komutları execute ile değil, query_row ile çalıştırılmalıdır.
        conn.query_row("SELECT count(*) FROM sqlite_master;", [], |_| Ok(()))?;
    } else {
        // Veritabanı şifresizse de okunabildiğini doğrula
        conn.query_row("SELECT count(*) FROM sqlite_master;", [], |_| Ok(()))?;
    }

    // Yabancı anahtar (Foreign Key) desteğini aktif et
    // Durum değiştiren PRAGMA komutları execute ile çalıştırılabilir
    conn.execute("PRAGMA foreign_keys = ON;", [])?;

    // Tabloları Oluştur
    conn.execute(
        "CREATE TABLE IF NOT EXISTS contacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            special_address TEXT NOT NULL UNIQUE,
            nickname TEXT,
            trust_level INTEGER DEFAULT 0,
            x25519_pub BLOB,
            kyber_pub BLOB
        )",
        [],
    )?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )",
        [],
    )?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER NOT NULL,
            content TEXT NOT NULL,
            status TEXT DEFAULT 'pending', -- 'pending', 'sent', 'failed'
            received_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(sender_id) REFERENCES contacts(id) ON DELETE CASCADE
        )",
        [],
    )?;

    Ok(conn)
}

pub fn add_contact(conn: &Connection, address: &str, nickname: Option<&str>) -> Result<i64> {
    conn.execute(
        "INSERT OR IGNORE INTO contacts (special_address, nickname) VALUES (?1, ?2)",
        rusqlite::params![address, nickname],
    )?;
    
    let id = conn.query_row(
        "SELECT id FROM contacts WHERE special_address = ?1",
        [address],
        |row| row.get(0),
    )?;
    
    Ok(id)
}

pub fn add_message(conn: &Connection, sender_id: i64, content: &str) -> Result<()> {
    conn.execute(
        "INSERT INTO messages (sender_id, content) VALUES (?1, ?2)",
        rusqlite::params![sender_id, content],
    )?;
    Ok(())
}

pub fn update_message_status(conn: &Connection, msg_id: i64, new_status: &str) -> Result<()> {
    conn.execute(
        "UPDATE messages SET status = ?1 WHERE id = ?2",
        rusqlite::params![new_status, msg_id],
    )?;
    Ok(())
}

pub fn get_contact_info(conn: &Connection, address: &str) -> Result<(i64, Option<String>)> {
    conn.query_row(
        "SELECT id, nickname FROM contacts WHERE special_address = ?1",
        [address],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )
}


pub fn get_contact_pub_keys(conn: &Connection, address: &str) -> Result<PublicKeys> {
    conn.query_row(
        "SELECT x25519_pub, kyber_pub FROM contacts WHERE special_address = ?1",
        [address],
        |row| {
            // Read blobs
            let x25519_vec: Vec<u8> = row.get(0)?;
            let kyber_vec: Vec<u8> = row.get(1)?;

            let x25519_pub: [u8; 32] = x25519_vec.try_into().map_err(|_| {
                rusqlite::Error::InvalidColumnType(
                    0, 
                    "X25519 is not 32 bytes!".into(), 
                    rusqlite::types::Type::Blob
                )
            })?;

            Ok(PublicKeys {
                x25519_pub,
                kyber_pub: kyber_vec,
            })
        },
    )
}

pub fn resolve_address(conn: &Connection, target: &str) -> Result<String> {
    if target.ends_with(".onion") {
        return Ok(target.to_string());
    }

    // search name
    conn.query_row(
        "SELECT special_address FROM contacts WHERE nickname = ?1",
        [target],
        |row| row.get(0),
    ).map_err(|e| {
        rusqlite::Error::QueryReturnedNoRows
    })
}

pub fn update_contact_keys(
    conn: &Connection, 
    address: &str, 
    x25519: &[u8; 32], 
    kyber: &[u8]
) -> Result<()> {
    // Kişi veritabanında var mı kontrol et
    let exists: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM contacts WHERE special_address = ?1)",
        [address],
        |row| row.get(0),
    )?;

    if exists {
        conn.execute(
            "UPDATE contacts SET x25519_pub = ?1, kyber_pub = ?2 WHERE special_address = ?3",
            rusqlite::params![x25519, kyber, address],
        )?;
    } else {
        conn.execute(
            "INSERT INTO contacts (special_address, x25519_pub, kyber_pub) VALUES (?1, ?2, ?3)",
            rusqlite::params![address, x25519, kyber],
        )?;
    }
    
    Ok(())
}

pub fn get_setting(conn: &Connection, key: &str) -> Result<String> {
    conn.query_row(
        "SELECT value FROM settings WHERE key = ?1",
        [key],
        |row| row.get(0),
    )
}

/// Veritabanına belirli bir ayarı yazar (Varsa günceller, yoksa ekler)
pub fn set_setting(conn: &Connection, key: &str, value: &str) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO settings (key, value) VALUES (?1, ?2)",
        rusqlite::params![key, value],
    )?;
    Ok(())
}


impl IdentityFingerprint {
    //Id verify token
    pub fn export_to_base64(&self) -> Result<String, io::Error> {
        let bytes = bincode::serialize(self)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        
        // Base64 encode
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        Ok(STANDARD.encode(bytes))
    }
}

//Id verifier
pub fn verify_contact_physically(
    conn: &Connection, 
    scanned_base64: &str,
    stored_pub_keys: &PublicKeys
) -> Result<bool, io::Error> {
    
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    
    // Decode base64
    let bytes = STANDARD.decode(scanned_base64)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Broken id format"))?;
        
    let fingerprint: IdentityFingerprint = bincode::deserialize(&bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    // Crypto match
    let is_x25519_match = fingerprint.x25519_pub == stored_pub_keys.x25519_pub;
    let is_kyber_match = fingerprint.kyber_pub == stored_pub_keys.kyber_pub;

    if is_x25519_match && is_kyber_match {
        //If successful
        conn.execute(
            "UPDATE contacts SET trust_level = 1 WHERE special_address = ?1",
            rusqlite::params![fingerprint.onion_address],
        ).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        
        Ok(true)
    } else {
        // Mismatch
        Ok(false)
    }
}


