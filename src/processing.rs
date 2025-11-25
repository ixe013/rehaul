use std::fs::{self, File};
use std::io::BufReader;
use std::path::Path;
use minisign_verify::{PublicKey, Signature};
use age::Decryptor;
use flate2::read::GzDecoder;
use tar::Archive;

/// Erreur personnalisée pour simplifier le retour
type RehaulResult<T> = Result<T, Box<dyn std::error::Error>>;

/// Configuration nécessaire pour traiter un paquet
pub struct RehaulConfig<'a> {
    pub encrypted_file_path: &'a Path,
    pub signature_file_path: &'a Path,
    pub output_dir: &'a Path,
    pub minisign_public_key: String, // La clé publique "RW..."
    pub age_identity_path: &'a Path, // Le chemin vers le fichier clé privée age
}

pub fn unpack_secure_package(config: &RehaulConfig) -> RehaulResult<()> {
    println!("🔍 Étape 1 : Vérification de la signature (Minisign)...");
    
    // 1. Charger la clé publique Minisign
    let pub_key = PublicKey::from_base64(&config.minisign_public_key)
        .map_err(|_| "Clé publique Minisign invalide")?;

    // 2. Lire la signature
    let sig_content = fs::read_to_string(config.signature_file_path)?;
    let signature = Signature::decode(&sig_content)
        .map_err(|_| "Format de fichier de signature invalide")?;

    // 3. Lire le fichier chiffré (en bytes) pour vérifier l'intégrité
    // Note : Minisign doit lire tout le fichier pour vérifier le hash.
    let encrypted_bytes = fs::read(config.encrypted_file_path)?;

    // 4. VÉRIFICATION CRITIQUE
    // Si cette ligne échoue, on arrête tout. On ne tente même pas de déchiffrer.
    pub_key.verify(&encrypted_bytes, &signature, false)
        .map_err(|_| "⛔ ÉCHEC SIGNATURE : Le fichier est corrompu ou ne provient pas de l'auteur.")?;

    println!("✅ Signature valide. Provenance confirmée.");
    println!("🔓 Étape 2 : Déchiffrement (Age) et Décompression...");

    // 5. Préparer l'identité Age (Clé privée)
    // On suppose ici que la clé est dans un fichier texte (généré par age-keygen)
    let key_file_content = fs::read_to_string(config.age_identity_path)
        .map_err(|_| "Impossible de lire le fichier de clé privée Age")?;
    
    // On filtre les commentaires et les lignes vides pour trouver la clé
    let identity_str = key_file_content.lines()
        .find(|l| !l.starts_with('#') && !l.is_empty())
        .ok_or("Aucune clé trouvée dans le fichier d'identité")?;

    let identity = identity_str.parse::<age::x25519::Identity>()
        .map_err(|_| "Format de clé privée Age invalide")?;

    // 6. Ouvrir le fichier pour le déchiffrement (Streaming)
    let file = File::open(config.encrypted_file_path)?;
    let reader = BufReader::new(file);

    let decryptor = match Decryptor::new(reader)? {
        Decryptor::Recipients(d) => d,
        _ => return Err("Format de chiffrement non supporté (attendu: destinataires)".into()),
    };

    // Déchiffrement
    let decrypted_reader = decryptor.decrypt(std::iter::once(&identity as &dyn age::Identity))?;

    // 7. Décompression Gzip
    let decoded_reader = GzDecoder::new(decrypted_reader);

    // 8. Extraction Tar
    let mut archive = Archive::new(decoded_reader);
    
    // Création du dossier de sortie s'il n'existe pas
    fs::create_dir_all(config.output_dir)?;
    
    archive.unpack(config.output_dir)?;

    println!("🎉 Étape 3 : Succès ! Fichiers extraits dans {:?}", config.output_dir);

    Ok(())
}
