mod processing; // On importe le module qu'on vient de créer

use clap::Parser;
use std::path::PathBuf;
use processing::{unpack_secure_package, RehaulConfig};

#[derive(Parser)]
#[command(name = "Rehaul")]
#[command(version = "1.0")]
#[command(about = "Réception sécurisée de paquets chiffrés et signés", long_about = None)]
struct Cli {
    /// Chemin vers le fichier chiffré (.tar.gz.age)
    #[arg(short, long, value_name = "FILE")]
    input: PathBuf,

    /// Chemin vers le fichier de signature (.minisig)
    /// Si non fourni, le programme cherchera input + ".minisig"
    #[arg(short, long, value_name = "SIG_FILE")]
    signature: Option<PathBuf>,

    /// Dossier de destination pour l'extraction
    #[arg(short, long, value_name = "DIR", default_value = "./output")]
    output: PathBuf,

    /// Clé publique Minisign (RW...) pour vérifier la signature
    /// Peut aussi être passée via la variable d'env REHAUL_PUBKEY
    #[arg(long, env = "REHAUL_PUBKEY")]
    pubkey: String,

    /// Chemin vers le fichier d'identité (clé privée) Age
    /// Peut aussi être passé via la variable d'env REHAUL_IDENTITY
    #[arg(long, env = "REHAUL_IDENTITY")]
    privkey: PathBuf,
}

fn main() {
    let cli = Cli::parse();

    // Gestion automatique du chemin de signature si non fourni
    let sig_path = match cli.signature {
        Some(p) => p,
        None => {
            let mut p = cli.input.clone();
            // Ajoute .minisig à la fin du nom de fichier existant
            if let Some(filename) = p.file_name() {
                let mut new_name = filename.to_os_string();
                new_name.push(".minisig");
                p.set_file_name(new_name);
            }
            p
        }
    };

    println!("🚀 Rehaul v1.0 - Démarrage...");
    println!("📁 Paquet: {:?}", cli.input);
    println!("📝 Signature: {:?}", sig_path);

    let config = RehaulConfig {
        encrypted_file_path: &cli.input,
        signature_file_path: &sig_path,
        output_dir: &cli.output,
        minisign_public_key: cli.pubkey,
        age_identity_path: &cli.privkey,
    };

    match unpack_secure_package(&config) {
        Ok(_) => {
            println!("✅ Opération terminée avec succès.");
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("❌ ERREUR: {}", e);
            std::process::exit(1);
        }
    }
}
