#!/bin/bash
set -e # Arrêter le script en cas d'erreur

# --- CONFIGURATION ---
FILES_TO_PACKAGE="mon_executable fichier_config.toml"
ARCHIVE_NAME="bundle.tar.gz"
ENCRYPTED_NAME="${ARCHIVE_NAME}.age"
# Pour la signature, Minisign crée automatiquement un fichier .minisig

# --- ÉTAPE 1 : GÉNÉRATION DES CLÉS ---
echo "🔑 Génération des clés..."

# A. Clés de chiffrement (Age)
# Note : Pour du symétrique pur (mot de passe), on sauterait cette étape.
# Ici, je génère une paire identité/clé publique pour une automatisation plus propre.
if [ ! -f "key_encryption.txt" ]; then
    age-keygen -o key_encryption.txt
    echo "   -> Clé de chiffrement (identité) générée dans 'key_encryption.txt'"
    # On extrait la clé publique pour chiffrer
    AGE_PUB_KEY=$(grep "public key" key_encryption.txt | awk '{print $4}')
else
    echo "   -> Clé de chiffrement existante trouvée."
    AGE_PUB_KEY=$(grep "public key" key_encryption.txt | awk '{print $4}')
fi

# B. Clés de signature (Minisign)
# Cela va créer minisign.pub (publique) et minisign.key (privée/secrète)
if [ ! -f "minisign.key" ]; then
    # -G génère la paire, -p et -s définissent les noms de fichiers, -f force sans password pour l'exemple (à éviter en prod)
    minisign -G -p minisign.pub -s minisign.key
    echo "   -> Paires de clés de signature générées (minisign.pub / minisign.key)"
else
    echo "   -> Clés de signature existantes trouvées."
fi

echo "--------------------------------------------------"

# --- ÉTAPE 2 : CRÉATION DE L'ARCHIVE ---
echo "📦 Création de l'archive tar.gz..."
tar -czf "$ARCHIVE_NAME" $FILES_TO_PACKAGE
echo "   -> $ARCHIVE_NAME créé."

# --- ÉTAPE 3 : CHIFFREMENT (Age) ---
echo "🔒 Chiffrement de l'archive..."

# OPTION A : Asymétrique (recommandé pour les scripts)
# On chiffre pour la clé publique extraite plus haut.
age -r "$AGE_PUB_KEY" -o "$ENCRYPTED_NAME" "$ARCHIVE_NAME"

# OPTION B : Symétrique (avec mot de passe)
# Si tu préfères un mot de passe simple, commente la ligne du dessus et utilise :
# age -p -o "$ENCRYPTED_NAME" "$ARCHIVE_NAME"

echo "   -> $ENCRYPTED_NAME généré."

# --- ÉTAPE 4 : SIGNATURE (Minisign) ---
echo "✍️  Signature de l'archive chiffrée..."

# -S : Signer
# -m : Le fichier à signer
# -s : La clé secrète (privée) utilisée pour signer
# -x : Nom du fichier de signature de sortie (optionnel, par défaut .minisig)
minisign -S -m "$ENCRYPTED_NAME" -s minisign.key

echo "   -> Signature créée : ${ENCRYPTED_NAME}.minisig"

echo "--------------------------------------------------"
echo "✅ TERMINÉ."
echo "Fichiers à distribuer :"
echo "  1. $ENCRYPTED_NAME (Le paquet chiffré)"
echo "  2. ${ENCRYPTED_NAME}.minisig (La signature)"
echo ""
echo "Informations pour le code Rust :"
echo "  - Clé publique de signature (pour vérifier) : $(cat minisign.pub)"
echo "  - Clé privée de déchiffrement (pour lire)   : Voir contenu de 'key_encryption.txt'"

# Nettoyage du fichier intermédiaire non sécurisé
rm "$ARCHIVE_NAME"
