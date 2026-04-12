use std::fs;
use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use tokio::io::{self as tokio_io, AsyncBufReadExt};

use directories::ProjectDirs;
mod crypto;
mod database;
mod network;


#[tokio::main]
async fn main() -> io::Result<()> {
    let proj_dirs = ProjectDirs::from("com", "aovera", "torque")
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Unable to find home!"))?;

    let config_dir = proj_dirs.config_dir();
    let data_dir = proj_dirs.data_dir();

    // Create directories
    fs::create_dir_all(config_dir)?;
    fs::create_dir_all(data_dir)?;

    
    let db_path = config_dir.join("database.bin");
    let publicKeyPath = config_dir.join("id_torque.pub");
    let privateKeyPath = config_dir.join("id_torque");

    let mut loaded_priv_keys: Option<crypto::PrivateKeys> = None;
    let mut loaded_pub_keys: Option<crypto::PublicKeys> = None;

    // Setup
    if !publicKeyPath.exists() || !privateKeyPath.exists() {
        println!("No identity found, Creating keys...");

        let (new_priv_keys, new_pub_keys) = crypto::keygen();

        println!("Do you want to protect your keys with a password? (y/n)");
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        if input.trim().to_lowercase() == "y" {
            print!("Enter password: ");
            io::stdout().flush()?;

            let password = rpassword::read_password()?;

            if password.is_empty() {
                println!("Password cannot be empty!");
                return Ok(());
            }

            print!("Enter the password again: ");
            io::stdout().flush()?;
            let password_confirm = rpassword::read_password()?;

            if password != password_confirm {
                println!("Error: Password mismatch!");
                return Ok(());
            }

            crypto::save_identity(&publicKeyPath, &privateKeyPath, new_priv_keys, new_pub_keys, Some(&password))?;
        }else {
            println!("Continuing without encryption...");
            crypto::save_identity(&publicKeyPath, &privateKeyPath, new_priv_keys, new_pub_keys, None)?;

        }

        println!("Keys saved.");
    }

    if crypto::is_identity_encrypted(&privateKeyPath)? {
        print!("Enter id password: ");
        io::stdout().flush()?;
        let password = rpassword::read_password()?;

        let (priv_key, pub_key) = crypto::load_identity(&publicKeyPath, &privateKeyPath, Some(&password))?;
        loaded_priv_keys = Some(priv_key);
        loaded_pub_keys = Some(pub_key);
        println!("Id loaded successfully.");
    } else {
        let (priv_key, pub_key) = crypto::load_identity(&publicKeyPath, &privateKeyPath, None)?;
        loaded_priv_keys = Some(priv_key);
        loaded_pub_keys = Some(pub_key);
        println!("Id loaded successfully.");
    }



    // --- DATABASE PHASE ---
    let is_db_new = !db_path.exists();
    let mut db_password_string = String::new();
    let mut db_password_opt: Option<&str> = None;

    if is_db_new {
        println!("\nNo database found. Creating a new one...");
        println!("Do you want to encrypt your database? (y/n)");
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        if input.trim().to_lowercase() == "y" {
            print!("Enter NEW database password: ");
            io::stdout().flush()?;
            let db_pass = rpassword::read_password()?;
            
            print!("Confirm database password: ");
            io::stdout().flush()?;
            let db_pass_confirm = rpassword::read_password()?;

            if db_pass != db_pass_confirm || db_pass.is_empty() {
                println!("Error: Password mismatch or empty!");
                return Ok(());
            }
            db_password_string = db_pass;
            db_password_opt = Some(&db_password_string);
        }
    } else {
        println!("\nDatabase found.");
        print!("If it's encrypted, enter the password (press Enter to skip): ");
        io::stdout().flush()?;
        let db_pass = rpassword::read_password()?;
        if !db_pass.is_empty() {
            db_password_string = db_pass;
            db_password_opt = Some(&db_password_string);
        }
    }

    // Unlock and nitialize database
    let conn = match database::init_db(&db_path, db_password_opt) {
        Ok(c) => c,
        Err(e) => {
            println!("Fatal Error: Failed to open database. Incorrect password or corrupted file!");
            println!("Details: {}", e);
            std::process::exit(1);
        }
    };

    println!("Database is ready and unlocked.");

    let my_onion = match database::get_setting(&conn, "my_onion") {
        Ok(onion) => {
            println!("Your onion url: {}", onion);
            onion
        },
        Err(rusqlite::Error::QueryReturnedNoRows) => {
            // Ayar bulunamadıysa (İlk Kurulum) kullanıcıya sor
            println!("\n[Setup] Need your onion url.");
            print!("Url (eg: h4ck...onion): ");
            io::stdout().flush()?;
            
            let mut input_onion = String::new();
            io::stdin().read_line(&mut input_onion)?;
            let clean_onion = input_onion.trim().to_string();

            if clean_onion.is_empty() || !clean_onion.ends_with(".onion") {
                println!("Wrong or empty addresss");
                std::process::exit(1);
            }

            // Veritabanına güvenle kaydet
            database::set_setting(&conn, "my_onion", &clean_onion)
                .expect("Could not write setting!");
            
            println!("Onion url saved.");
            clean_onion
        },
        Err(e) => {
            println!("Db read error (Settings): {}", e);
            std::process::exit(1);
        }
    };

    // --- SHARED STATE PREP ---
    // Make db connection thread safe
    let shared_db = Arc::new(Mutex::new(conn));
    
    // Session Keys
    let active_sessions: Arc<Mutex<HashMap<String, [u8; 32]>>> = Arc::new(Mutex::new(HashMap::new()));
    
    let priv_keys_own = Arc::new(loaded_priv_keys.expect("Critical error: Could not find private keys!"));
    let pub_keys_own = Arc::new(loaded_pub_keys.expect("Critical error: Could not find public keys!"));

    let listener_db = Arc::clone(&shared_db);
    let listener_sessions = Arc::clone(&active_sessions);
    let listener_keys = Arc::clone(&priv_keys_own);
    let listener_pub_keys = Arc::clone(&pub_keys_own);

    // --- START LISTENER ---
    tokio::spawn(async move {
        if let Err(e) = network::start_listener("127.0.0.1:4242", listener_db, listener_sessions, listener_keys, listener_pub_keys).await {
            println!("Listener Error: {}", e);
        }
    });

    println!("Torque started");

    // --- CLI LOOP ---

    println!("Command listener started. : for help.");

    let stdin = tokio_io::stdin();
    let mut reader = tokio_io::BufReader::new(stdin);
    let mut line = String::new();
    
    let mut active_dialogue: Option<String> = None;


    loop {
        // Terminal prompt
        if let Some(ref current_contact) = active_dialogue {
            print!("[{}]> ", current_contact);
        } else {
            print!("torque> ");
        }
        io::stdout().flush()?;
        line.clear();

        // Read line
        if reader.read_line(&mut line).await? == 0 {
            break; // EOF
        }

        let input = line.trim();
        if input.is_empty() { continue; }

        if input.starts_with(':') {
            // parse
            let parts: Vec<&str> = input[1..].splitn(3, ' ').collect();
            let cmd = parts[0].to_lowercase();

            match cmd.as_str() {
                "add" => {
                    // Usage: :add [onion] [name]
                    if parts.len() >= 3 {
                        let onion = parts[1];
                        let name = parts[2];
                        let conn = shared_db.lock().unwrap();
                        match database::add_contact(&conn, onion, Some(name)) {
                            Ok(_) => println!("Added as '{}': {}", name, onion),
                            Err(e) => println!("Error: {}", e),
                        }
                    } else {
                        println!("Usage: :add [onion_address] [nickname]");
                    }
                },
                "dialogue" => {
                    if parts.len() >= 2 {
                        let conn = shared_db.lock().unwrap();
                        match database::resolve_address(&conn, parts[1]) {
                            Ok(onion) => {
                                active_dialogue = Some(onion);
                                println!("Entered dialogue mod. :enddialogue to stop.");
                            },
                            Err(_) => println!("Could not find: {}", parts[1]),
                        }
                    } else {
                        println!("Usage: :dialogue [name or address]");
                    }
                },
                "enddialogue" => {
                    active_dialogue = None;
                    println!("Dialogue ended.");
                },
                "check" => {
                    if parts.len() >= 2 {
                        let conn = shared_db.lock().unwrap();
                        if let Ok(onion) = database::resolve_address(&conn, parts[1]) {
                            println!("Check connection: {} ...", onion);
                            // Tor Ping
                            match network::send_packet(&onion, network::TorquePacket::IsOk).await {
                                Ok(network::TorquePacket::OkResponse) => println!("OK"),
                                _ => println!("Connection error or peer offline."),
                            }
                        } else {
                            println!("Could not found {}", parts[1]);
                        }
                    } else {
                        println!("Usage: :check [name or address]");
                    }
                },
                "msg" => {
                    if parts.len() >= 3 {
                        let target = parts[1];
                        let message = parts[2];
        
                        // 1. Hedefin Onion adresini DB'den çöz
                        let target_onion = {
                            let conn = shared_db.lock().unwrap();
                            database::resolve_address(&conn, target).unwrap_or_default()
                        };

                        if target_onion.is_empty() {
                            println!("❌ Kişi bulunamadı. Adresi kontrol edin veya ':add' ile ekleyin.");
                            continue;
                        }

                        // 2. RAM'de aktif bir oturum (Session Key) var mı kontrol et
                        let mut session_key_opt = {
                            let sessions = active_sessions.lock().unwrap();
                            sessions.get(&target_onion).cloned()
                        };

                        // 3. Oturum yoksa, Kriptografik Handshake başlat
                        if session_key_opt.is_none() {
                            println!("🔄 {} ile aktif oturum yok. Handshake başlatılıyor...", target_onion);
            
                            // Karşı tarafın açık anahtarlarını veritabanından al
                            let peer_pub_keys_opt = {
                                let conn = shared_db.lock().unwrap();
                                database::get_contact_pub_keys(&conn, &target_onion).ok()
                            };

                            if let Some(peer_pub_keys) = peer_pub_keys_opt {
                                // Teklif paketi oluştur
                                let (offer, state) = network::create_session_offer();
                                let offer_packet = network::TorquePacket::HandshakeOffer {
                                    sender_onion: my_onion.clone(),
                                    offer,
                                };

                                // Tor üzerinden yolla ve kabul (Accept) bekle
                                match network::send_packet(&target_onion, offer_packet).await {
                                    Ok(network::TorquePacket::HandshakeAccept(accept_payload)) => {
                                        // Kendi anahtarlarımızla oturumu doğrula ve Session Key üret
                                        match network::finalize_session(&accept_payload, state, &priv_keys_own, &peer_pub_keys) {
                                            Ok(key) => {
                                                println!("🔒 Kuantum dirençli oturum başarıyla kuruldu!");
                                                // RAM'e kaydet
                                                active_sessions.lock().unwrap().insert(target_onion.clone(), key);
                                                session_key_opt = Some(key);
                                            }
                                            Err(e) => println!("❌ Oturum kurma hatası (Finalize): {}", e),
                                        }
                                    },
                                    _ => println!("❌ Handshake reddedildi veya karşı taraf yanıt vermedi."),
                                }
                            } else {
                                println!("❌ {} için açık anahtar bulunamadı! Lütfen önce ':getkeys {}' komutunu çalıştırın.", target_onion, target);
                                continue;
                            }
                        }

                        // 4. Session Key artık var. Mesajı şifrele ve yolla
                        if let Some(session_key) = session_key_opt {
                            println!("Gönderiliyor -> {}", target_onion);

                            match network::pack_encrypted_message(message, &session_key, &my_onion) {
                                Ok(payload_packet) => {
                                    // Şifreli paketi yolla ve OkResponse bekle
                                    match network::send_packet(&target_onion, payload_packet).await {
                                        Ok(network::TorquePacket::OkResponse) => {
                                            println!("✅ Mesaj başarıyla iletildi.");
                                                
                                            // Giden mesajı veritabanına 'sent' olarak kaydet
                                                let conn = shared_db.lock().unwrap();
                                            if let Ok(contact_id) = database::get_contact_info(&conn, &target_onion).map(|(id, _)| id) {
                                                // Not: DB şemanızda 'status' var varsayımıyla (Daha önce eklemiştik)
                                                let _ = conn.execute(
                                                    "INSERT INTO messages (sender_id, content, status) VALUES (?1, ?2, 'sent')",
                                                    rusqlite::params![contact_id, message],
                                                );
                                            }
                                        },
                                        _ => {
                                            println!("⚠ Mesaj Tor ağına iletildi ancak karşıdan 'OK' onayı alınamadı.");
                                            // DB'ye 'pending' veya 'failed' olarak kaydedilebilir
                                        },
                                    }
                                },
                                Err(e) => println!("❌ Şifreleme hatası: {}", e),
                            }
                        }
                    } else {
                        println!("Usage: :msg [address or name] [message]");
                    }
                },
                "getkeys" => {
                    if parts.len() >= 2 {
                        // Decrypt address
                        let target_onion = {
                            let conn = shared_db.lock().unwrap();
                            database::resolve_address(&conn, parts[1]).unwrap_or_else(|_| parts[1].to_string())
                        };

                        println!("Requesting public keys from {}...", target_onion);
        
                        match network::send_packet(&target_onion, network::TorquePacket::KeyRequest).await {
                            Ok(network::TorquePacket::KeyResponse { x25519_pub, kyber_pub }) => {
                                // Saev keys to db
                                let conn = shared_db.lock().unwrap();
                                match database::update_contact_keys(&conn, &target_onion, &x25519_pub, &kyber_pub) {
                                    Ok(_) => println!("Keys saved successfully"),
                                    Err(e) => println!("Could not write: {}", e),
                                }
                            },
                            _ => println!("Request failed."),
                        }
                    } else {
                        println!("Usage: :getkeys [name or address]");
                    }
                },
                "show" => {
                    println!("Gösterim mantığı (SQL aralık sorguları) bir sonraki adımda eklenecek.");
                },
                "retry" => {
                    println!("Pending mesajları tekrar deneme kuyruğu hazırlanıyor...");
                },
                _ => println!("Unknown command: {}", cmd),
            }
        } else {
            if let Some(ref target_onion) = active_dialogue {
                println!("Sending -> {}", target_onion);
                // TODO: Mesaj gönderme rutini
            } else {
                println!("Unknown command.");
            }
        }
    }


    Ok(())
}
