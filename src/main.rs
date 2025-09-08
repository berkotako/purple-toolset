use anyhow::{anyhow, Context, Result};
use argon2::{password_hash::SaltString, Argon2};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chacha20poly1305::aead::{Aead, KeyInit, OsRng};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce}; // 256-bit key, 96-bit nonce
use clap::{Parser, Subcommand};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;
use zeroize::Zeroize;

#[derive(Parser, Debug)]
#[command(name = "encsim", version, about = "Simple file encrypt/decrypt demo for lab testing")]
struct Cli {
    /// Subcommand to run; omit to run the demo (gen->encrypt->decrypt)
    #[command(subcommand)]
    command: Option<Cmd>,

    /// Directory to operate in (default: ./encsim_<timestamp>)
    #[arg(global = true, long)]
    dir: Option<PathBuf>,

    /// Passphrase to derive key (Argon2id). If omitted, a random key is generated and stored in manifest (lab-only).
    #[arg(global = true, long)]
    pass: Option<String>,

    /// Number of files to create for generate/demo (default 5)
    #[arg(global = true, long, default_value_t = 5)]
    count: usize,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Create N random files
    Gen,
    /// Encrypt all plaintext files in the directory and write manifest.json
    Encrypt,
    /// Decrypt files using manifest.json
    Decrypt {
        /// Path to manifest.json (default: <dir>/manifest.json)
        #[arg(long)]
        manifest: Option<PathBuf>,
    },
    /// One-shot demo: generate -> encrypt -> decrypt
    Demo,
}

#[derive(Serialize, Deserialize)]
struct Manifest {
    algo: String,                 // "chacha20poly1305"
    argon2_salt_b64: Option<String>,
    key_b64: Option<String>,      // only if no passphrase provided (lab-only)
    files: Vec<FileEntry>,
}

#[derive(Serialize, Deserialize)]
struct FileEntry {
    plain: String,     // original path
    cipher: String,    // cipher path
    nonce_b64: String, // 12-byte nonce
}

const RANSOM_NOTE: &str = "README_RECOVER_FILES.txt";

fn main() -> Result<()> {
    let cli = Cli::parse();

    let dir = cli
        .dir
        .clone()
        .unwrap_or_else(|| PathBuf::from(format!("encsim_{}", timestamp())));

    if let Some(cmd) = cli.command {
        match cmd {
            Cmd::Gen => {
                ensure_dir(&dir)?;
                generate_files(&dir, cli.count)?;
                println!("Generated {} files in {}", cli.count, dir.display());
            }
            Cmd::Encrypt => {
                ensure_dir(&dir)?;
                encrypt_dir(&dir, cli.pass.as_deref())?;
                println!("Encrypted. See manifest at {}", dir.join("manifest.json").display());
            }
            Cmd::Decrypt { manifest } => {
                let mpath = manifest.unwrap_or_else(|| dir.join("manifest.json"));
                decrypt_from_manifest(&mpath, cli.pass.as_deref())?;
                println!("Decrypted files listed in {}", mpath.display());
            }
            Cmd::Demo => demo(&dir, cli.count, cli.pass.as_deref())?,
        }
        return Ok(());
    }

    // Default: demo run
    demo(&dir, cli.count, cli.pass.as_deref())
}

fn demo(dir: &Path, count: usize, pass: Option<&str>) -> Result<()> {
    println!("[*] Using directory: {}", dir.display());
    ensure_dir(dir)?;
    generate_files(dir, count)?;
    println!("[*] Generated {count} files");
    encrypt_dir(dir, pass)?;
    println!("[*] Encrypted files. Manifest written.");
    let m = dir.join("manifest.json");
    decrypt_from_manifest(&m, pass)?;
    println!("[*] Decrypted files back to plaintext.");
    Ok(())
}

fn ensure_dir(dir: &Path) -> Result<()> {
    if !dir.exists() {
        fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    Ok(())
}

fn generate_files(dir: &Path, count: usize) -> Result<()> {
    let mut rng = rand::thread_rng();
    let exts = ["txt", "docx", "xlsx", "pdf", "jpg"];
    for i in 0..count {
        let ext = exts[i % exts.len()];
        let path = dir.join(format!("file_{i:04}.{ext}"));
        let mut buf = vec![0u8; 64 * 1024]; // 64 KiB dummy content
        rng.fill_bytes(&mut buf);
        let mut f = File::create(&path).with_context(|| format!("create {}", path.display()))?;
        f.write_all(&buf)?;
    }
    Ok(())
}

fn derive_or_generate_key(pass: Option<&str>) -> Result<(Key, Option<String>, Option<String>)> {
    // returns (key, argon2_salt_b64, key_b64_if_random)
    match pass {
        Some(pw) => {
            let salt = SaltString::generate(&mut OsRng);
            let argon2 = Argon2::default();
            let mut key_bytes = [0u8; 32];
            argon2
                .hash_password_into(
                    pw.as_bytes(),
                    salt.as_salt().as_str().as_bytes(),
                    &mut key_bytes,
                )
                .map_err(|e| anyhow!("argon2 derive failed: {e}"))?;
            let key = Key::from(key_bytes);
            key_bytes.zeroize();
            Ok((key, Some(salt.to_string()), None))
        }
        None => {
            let mut kb = [0u8; 32];
            OsRng.fill_bytes(&mut kb);
            let key_b64 = B64.encode(&kb);
            let key = Key::from(kb);
            kb.zeroize();
            Ok((key, None, Some(key_b64)))
        }
    }
}

fn key_from_manifest(m: &Manifest, pass: Option<&str>) -> Result<Key> {
    if let Some(ref salt_b64) = m.argon2_salt_b64 {
        // need passphrase
        let pass = pass.ok_or_else(|| anyhow!("manifest expects a passphrase (--pass)"))?;
        let salt = SaltString::from_b64(salt_b64).map_err(|_| anyhow!("bad salt in manifest"))?;
        let argon2 = Argon2::default();
        let mut kb = [0u8; 32];
        argon2
            .hash_password_into(
                pass.as_bytes(),
                salt.as_salt().as_str().as_bytes(),
                &mut kb,
            )
            .map_err(|e| anyhow!("argon2 derive failed: {e}"))?;
        let key = Key::from(kb);
        kb.zeroize();
        Ok(key)
    } else if let Some(ref key_b64) = m.key_b64 {
        let mut kb = [0u8; 32];
        let v = B64
            .decode(key_b64.as_bytes())
            .map_err(|_| anyhow!("invalid key_b64"))?;
        if v.len() != 32 {
            return Err(anyhow!("key_b64 is not 32 bytes"));
        }
        kb.copy_from_slice(&v);
        let key = Key::from(kb);
        kb.zeroize();
        Ok(key)
    } else {
        Err(anyhow!("manifest missing key info"))
    }
}

fn encrypt_dir(dir: &Path, pass: Option<&str>) -> Result<()> {
    // Gather plaintext files (skip .enc and manifest)
    let mut plains = vec![];
    for entry in WalkDir::new(dir).max_depth(1) {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() {
            if path.file_name().and_then(|s| s.to_str()) == Some("manifest.json") {
                continue;
            }
            if path.extension().and_then(|s| s.to_str()) == Some("enc") {
                continue;
            }
            plains.push(path.to_path_buf());
        }
    }

    if plains.is_empty() {
        return Err(anyhow!("no plaintext files to encrypt in {}", dir.display()));
    }

    // Prepare key
    let (key, salt_b64, key_b64) = derive_or_generate_key(pass)?;
    let cipher = ChaCha20Poly1305::new(&key);

    let mut manifest = Manifest {
        algo: "chacha20poly1305".into(),
        argon2_salt_b64: salt_b64,
        key_b64,
        files: Vec::new(),
    };

    for p in plains {
        let mut data = vec![];
        File::open(&p)
            .with_context(|| format!("open {}", p.display()))?
            .read_to_end(&mut data)?;
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ct = cipher
            .encrypt(nonce, data.as_ref())
            .with_context(|| format!("encrypt {}", p.display()))?;

        let cpath = match p.extension().and_then(|s| s.to_str()) {
            Some(orig_ext) if !orig_ext.is_empty() => p.with_extension(format!("{orig_ext}.enc")),
            _ => p.with_extension("enc"),
        };
        let mut f = File::create(&cpath)
            .with_context(|| format!("write {}", cpath.display()))?;
        f.write_all(&ct)?;
        drop(f);

        // remove plaintext to mimic impact (we'll restore on decrypt)
        fs::remove_file(&p).ok();

        manifest.files.push(FileEntry {
            plain: p.to_string_lossy().to_string(),
            cipher: cpath.to_string_lossy().to_string(),
            nonce_b64: B64.encode(&nonce_bytes),
        });
    }

    let mpath = dir.join("manifest.json");
    let mut mf = File::create(&mpath)?;
    mf.write_all(serde_json::to_string_pretty(&manifest)?.as_bytes())?;

    // Write ransom note after encrypting
    write_ransom_note(dir, &manifest)?;
    Ok(())
}

fn decrypt_from_manifest(manifest_path: &Path, pass: Option<&str>) -> Result<()> {
    let mut s = String::new();
    File::open(manifest_path)
        .with_context(|| format!("open {}", manifest_path.display()))?
        .read_to_string(&mut s)?;
    let manifest: Manifest = serde_json::from_str(&s).context("parse manifest")?;

    let key = key_from_manifest(&manifest, pass)?;
    let cipher = ChaCha20Poly1305::new(&key);

    for e in &manifest.files {
        let mut ct = vec![];
        File::open(&e.cipher)
            .with_context(|| format!("open {}", &e.cipher))?
            .read_to_end(&mut ct)?;

        let nonce_bytes =
            B64.decode(e.nonce_b64.as_bytes())
              .map_err(|_| anyhow!("bad nonce for {}", &e.cipher))?;
        if nonce_bytes.len() != 12 {
            return Err(anyhow!("nonce must be 12 bytes"));
        }
        let nonce = Nonce::from_slice(&nonce_bytes);

        let pt = cipher
            .decrypt(nonce, ct.as_ref())
            .with_context(|| format!("decrypt {}", &e.cipher))?;

        let mut f = File::create(&e.plain)?;
        f.write_all(&pt)?;

        // remove ciphertext to restore original state
        fs::remove_file(&e.cipher).ok();
    }

    // Cleanup ransom note after restoring files
    remove_ransom_note(Path::new(manifest_path).parent().unwrap_or_else(|| Path::new(".")));

    Ok(())
}

fn write_ransom_note(dir: &Path, manifest: &Manifest) -> Result<()> {
    let note_path = dir.join(RANSOM_NOTE);
    if note_path.exists() {
        return Ok(());
    }
    let mut f = File::create(&note_path)?;
    let msg = format!(
        concat!(
            "Your files have been encrypted with {algo}.\n\n",
            "This is a lab-only simulator. No data exfiltration occurred.\n",
            "To recover your files, run:\n",
            "  encsim decrypt --dir <DIR> [--pass <PASSPHRASE>]\n\n",
            "Manifest: manifest.json\n",
            "Files affected: {count}\n"
        ),
        algo = manifest.algo,
        count = manifest.files.len()
    );
    f.write_all(msg.as_bytes())?;
    Ok(())
}

fn remove_ransom_note(dir: &Path) {
    let note_path = dir.join(RANSOM_NOTE);
    fs::remove_file(note_path).ok();
}

fn timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    secs.to_string()
}
