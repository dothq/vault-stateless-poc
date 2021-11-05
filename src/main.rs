use std::env;
use std::process::exit;
use std::fmt::Write;
use sha2::Sha512;
use regex::Regex;
use hmac::{ Hmac, Mac, NewMac };

use clipboard::ClipboardProvider;
use clipboard::ClipboardContext;

type HmacSha512 = Hmac<Sha512>;

fn main() {
    let password_filter_regex: regex::Regex = Regex::new(r".").unwrap();

    let args: Vec<String> = env::args().collect();
    
    let password: String = env::var("VAULT_PASSWORD")
        .expect("Missing VAULT_PASSWORD env var.");

    if args.len() <= 2 {
        println!("❗ Missing site URL and username argument.");
        println!("\n📖 Examples:");
        println!("   cargo run google.com example@gmail.com");
        println!("   cargo run dothq.co foobar");
        println!("   cargo run github.com EnderDev");
        println!("");
        exit(1);
    }

    let site_url = &args[1];
    let username = &args[2];

    println!("🔐 Master key: {}\n", password_filter_regex.replace_all(&password, "•"));

    println!("🧮 Algorithm: SHA-512");
    println!("🌍 Site: {}", site_url);
    println!("👤 Username: {}", username);

    let mut hmac = HmacSha512::new_from_slice(password.as_bytes())
        .expect("HMAC can take key of any size");

    hmac.update(format!("{}:{}", site_url, username).as_bytes());

    let result = hmac.finalize();
    let code_bytes = result.into_bytes();

    let mut key = String::new();

    for byte in code_bytes {
        write!(&mut key, "{:x}", byte).expect("Unable to write");
    }

    println!("🔑 Password: {}", key);

    copy_to_clipboard(format!("{}", key));
}

fn copy_to_clipboard(key: String) {
    let mut ctx: ClipboardContext = ClipboardProvider::new().unwrap();

    ctx.set_contents(key.to_string().to_owned()).unwrap();

    // We need this because X11
    std::thread::sleep(std::time::Duration::from_millis(1));

    println!("\n📋 Copied to clipboard!")
}