#!/bin/bash

# Script de gestion d'environnement sécurisé chiffré
# Auteur: Expert Linux
# Version: 1.0

set -euo pipefail

# Configuration par défaut
DEFAULT_SIZE="5G"
DEFAULT_NAME="secure_vault"
DEFAULT_MOUNT_POINT="/mnt/secure_vault"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="$HOME/.secure_vault_config"

# Couleurs pour l'affichage
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Fonctions utilitaires
log() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

die() {
    error "$1"
    exit 1
}

check_root() {
    if [[ $EUID -eq 0 ]]; then
        die "Ce script ne doit pas être exécuté en tant que root pour des raisons de sécurité"
    fi
}

check_dependencies() {
    local deps=("cryptsetup" "gpg" "ssh" "losetup" "mkfs.ext4")
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            die "Dépendance manquante: $dep"
        fi
    done
}

load_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        source "$CONFIG_FILE"
    fi
    
    VAULT_FILE="${VAULT_FILE:-$HOME/$DEFAULT_NAME.img}"
    VAULT_NAME="${VAULT_NAME:-$DEFAULT_NAME}"
    MOUNT_POINT="${MOUNT_POINT:-$DEFAULT_MOUNT_POINT}"
    VAULT_SIZE="${VAULT_SIZE:-$DEFAULT_SIZE}"
}

save_config() {
    cat > "$CONFIG_FILE" << EOF
VAULT_FILE="$VAULT_FILE"
VAULT_NAME="$VAULT_NAME"
MOUNT_POINT="$MOUNT_POINT"
VAULT_SIZE="$VAULT_SIZE"
EOF
    chmod 600 "$CONFIG_FILE"
}

# Part I - Mise en place de l'environnement sécurisé
create_vault() {
    local size="$1"
    local vault_file="$2"
    
    log "Création du fichier conteneur de ${size}..."
    if [[ -f "$vault_file" ]]; then
        read -p "Le fichier $vault_file existe déjà. L'écraser ? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            return 1
        fi
    fi
    
    dd if=/dev/zero of="$vault_file" bs=1M count=0 seek=$(echo "$size" | sed 's/G$/000/;s/M$//') status=progress
    
    log "Configuration du chiffrement LUKS..."
    sudo cryptsetup luksFormat --type luks2 "$vault_file"
    
    log "Ouverture du conteneur chiffré..."
    sudo cryptsetup luksOpen "$vault_file" "$VAULT_NAME"
    
    log "Création du système de fichiers ext4..."
    sudo mkfs.ext4 "/dev/mapper/$VAULT_NAME"
    
    log "Fermeture du conteneur..."
    sudo cryptsetup luksClose "$VAULT_NAME"
    
    # Permissions sécurisées
    chmod 600 "$vault_file"
    
    log "Environnement sécurisé créé avec succès: $vault_file"
}

# Ouverture de l'environnement
open_vault() {
    if [[ ! -f "$VAULT_FILE" ]]; then
        die "Le fichier vault $VAULT_FILE n'existe pas"
    fi
    
    if sudo cryptsetup status "$VAULT_NAME" &>/dev/null; then
        warn "Le vault est déjà ouvert"
        return 0
    fi
    
    log "Ouverture du conteneur chiffré..."
    sudo cryptsetup luksOpen "$VAULT_FILE" "$VAULT_NAME"
    
    # Création du point de montage
    sudo mkdir -p "$MOUNT_POINT"
    
    log "Montage du système de fichiers..."
    sudo mount "/dev/mapper/$VAULT_NAME" "$MOUNT_POINT"
    
    # Changement du propriétaire
    sudo chown -R "$USER:$USER" "$MOUNT_POINT"
    
    # Création de la structure de répertoires
    mkdir -p "$MOUNT_POINT"/{ssh,gpg,config}
    chmod 700 "$MOUNT_POINT"/{ssh,gpg}
    chmod 755 "$MOUNT_POINT/config"
    
    log "Environnement sécurisé ouvert et monté sur $MOUNT_POINT"
}

# Fermeture de l'environnement
close_vault() {
    if ! sudo cryptsetup status "$VAULT_NAME" &>/dev/null; then
        warn "Le vault n'est pas ouvert"
        return 0
    fi
    
    log "Démontage du système de fichiers..."
    if mountpoint -q "$MOUNT_POINT"; then
        sudo umount "$MOUNT_POINT"
    fi
    
    log "Fermeture du conteneur chiffré..."
    sudo cryptsetup luksClose "$VAULT_NAME"
    
    log "Environnement sécurisé fermé"
}

# Part II - Cryptographie GPG
generate_gpg_key() {
    if [[ ! -d "$MOUNT_POINT" ]]; then
        die "L'environnement sécurisé n'est pas ouvert"
    fi
    
    local name email
    read -p "Nom complet: " name
    read -p "Adresse email: " email
    
    log "Génération de la paire de clés GPG..."
    
    # Configuration GPG pour le vault
    export GNUPGHOME="$MOUNT_POINT/gpg"
    chmod 700 "$GNUPGHOME"
    
    # Génération automatisée
    cat > "$GNUPGHOME/gen-key-batch" << EOF
%no-protection
Key-Type: RSA
Key-Length: 4096
Subkey-Type: RSA
Subkey-Length: 4096
Name-Real: $name
Name-Email: $email
Expire-Date: 2y
%commit
%echo done
EOF
    
    gpg --batch --generate-key "$GNUPGHOME/gen-key-batch"
    rm "$GNUPGHOME/gen-key-batch"
    
    # Export de la clé publique
    local key_id=$(gpg --list-keys --with-colons | grep '^pub' | head -n1 | cut -d: -f5)
    gpg --armor --export "$key_id" > "$MOUNT_POINT/gpg/public_key.asc"
    
    log "Clé GPG générée avec succès"
    log "ID de la clé: $key_id"
    log "Clé publique exportée vers: $MOUNT_POINT/gpg/public_key.asc"
    
    # Proposition d'export de la clé privée
    read -p "Exporter la clé privée ? (ATTENTION: stockage sensible) (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        gpg --armor --export-secret-keys "$key_id" > "$MOUNT_POINT/gpg/private_key.asc"
        chmod 600 "$MOUNT_POINT/gpg/private_key.asc"
        warn "Clé privée exportée vers: $MOUNT_POINT/gpg/private_key.asc"
        warn "ATTENTION: Protégez ce fichier et supprimez-le après usage !"
    fi
    
    unset GNUPGHOME
}

import_gpg_to_vault() {
    if [[ ! -d "$MOUNT_POINT" ]]; then
        die "L'environnement sécurisé n'est pas ouvert"
    fi
    
    export GNUPGHOME="$MOUNT_POINT/gpg"
    chmod 700 "$GNUPGHOME"
    
    log "Import des clés GPG du trousseau système vers le vault..."
    
    # Copie du trousseau principal
    if [[ -d "$HOME/.gnupg" ]]; then
        cp -r "$HOME/.gnupg"/* "$GNUPGHOME/" 2>/dev/null || true
        chmod -R 600 "$GNUPGHOME"/*
        log "Clés GPG importées dans le vault"
    else
        warn "Aucun trousseau GPG trouvé dans $HOME/.gnupg"
    fi
    
    unset GNUPGHOME
}

export_gpg_from_vault() {
    if [[ ! -d "$MOUNT_POINT/gpg" ]]; then
        die "Aucune configuration GPG trouvée dans le vault"
    fi
    
    log "Export des clés GPG du vault vers le trousseau système..."
    
    export GNUPGHOME="$MOUNT_POINT/gpg"
    
    # Liste des clés dans le vault
    local keys=$(gpg --list-keys --with-colons | grep '^pub' | cut -d: -f5)
    
    # Reset GNUPGHOME pour l'import système
    unset GNUPGHOME
    
    for key_id in $keys; do
        export GNUPGHOME="$MOUNT_POINT/gpg"
        gpg --armor --export "$key_id" | gpg --import
        unset GNUPGHOME
        log "Clé $key_id importée dans le trousseau système"
    done
}

# Part III - Configuration SSH
create_ssh_config_template() {
    if [[ ! -d "$MOUNT_POINT" ]]; then
        die "L'environnement sécurisé n'est pas ouvert"
    fi
    
    local config_file="$MOUNT_POINT/ssh/config"
    
    log "Création du template de configuration SSH..."
    
    cat > "$config_file" << 'EOF'
# Configuration SSH pour environnement sécurisé
# Utilisation: ssh -F chemin_vers_ce_fichier hostname

# Configuration par défaut
Host *
    StrictHostKeyChecking ask
    UserKnownHostsFile ~/.ssh/known_hosts
    PasswordAuthentication no
    PubkeyAuthentication yes
    IdentitiesOnly yes
    ServerAliveInterval 60
    ServerAliveCountMax 3
    Compression yes
    Protocol 2
    
# Exemple de configuration d'hôte
# Host exemple-serveur
#     HostName 192.168.1.100
#     User monuser
#     Port 22
#     IdentityFile chemin_vers_vault/ssh/exemple-serveur_rsa
#     LocalForward 8080 localhost:80

EOF
    
    chmod 600 "$config_file"
    log "Template SSH créé: $config_file"
}

create_aliases() {
    if [[ ! -d "$MOUNT_POINT" ]]; then
        die "L'environnement sécurisé n'est pas ouvert"
    fi
    
    local alias_file="$MOUNT_POINT/config/aliases"
    
    log "Création du fichier d'alias..."
    
    cat > "$alias_file" << EOF
# Alias pour environnement sécurisé
alias evsh="ssh -F $MOUNT_POINT/ssh/config"
alias evgpg="GNUPGHOME=$MOUNT_POINT/gpg gpg"
alias evls="ls -la $MOUNT_POINT"
alias evcd="cd $MOUNT_POINT"

# Fonctions utilitaires
vault_open() {
    $SCRIPT_DIR/$(basename "$0") open
}

vault_close() {
    $SCRIPT_DIR/$(basename "$0") close
}

vault_status() {
    if mountpoint -q "$MOUNT_POINT" 2>/dev/null; then
        echo "Vault: OUVERT (monté sur $MOUNT_POINT)"
    else
        echo "Vault: FERMÉ"
    fi
}
EOF
    
    chmod 644 "$alias_file"
    
    # Création du lien symbolique
    local link_target="$HOME/.secure_vault_aliases"
    if [[ -L "$link_target" ]] || [[ -f "$link_target" ]]; then
        rm "$link_target"
    fi
    ln -s "$alias_file" "$link_target"
    
    log "Fichier d'alias créé: $alias_file"
    log "Lien symbolique créé: $link_target"
    log "Pour charger les alias: source $link_target"
}

import_ssh_config() {
    if [[ ! -d "$MOUNT_POINT" ]]; then
        die "L'environnement sécurisé n'est pas ouvert"
    fi
    
    local ssh_config="$HOME/.ssh/config"
    if [[ ! -f "$ssh_config" ]]; then
        warn "Aucune configuration SSH trouvée dans $ssh_config"
        return 0
    fi
    
    log "Analyse de la configuration SSH existante..."
    
    # Parse des hosts
    local hosts=($(grep -E "^Host " "$ssh_config" | awk '{print $2}' | grep -v '\*'))
    
    if [[ ${#hosts[@]} -eq 0 ]]; then
        warn "Aucun host configuré trouvé"
        return 0
    fi
    
    echo "Hosts trouvés:"
    for i in "${!hosts[@]}"; do
        echo "$((i+1)). ${hosts[i]}"
    done
    
    read -p "Sélectionnez un host à importer (numéro): " selection
    
    if [[ ! "$selection" =~ ^[0-9]+$ ]] || [[ $selection -lt 1 ]] || [[ $selection -gt ${#hosts[@]} ]]; then
        error "Sélection invalide"
        return 1
    fi
    
    local selected_host="${hosts[$((selection-1))]}"
    log "Import de la configuration pour: $selected_host"
    
    # Extraction de la configuration du host
    local config_section=$(awk "/^Host $selected_host$/,/^Host |^$/" "$ssh_config" | head -n -1)
    
    # Recherche de l'IdentityFile
    local identity_file=$(echo "$config_section" | grep -E "^\s*IdentityFile" | awk '{print $2}' | head -n1)
    
    if [[ -n "$identity_file" ]]; then
        # Résolution du chemin
        identity_file=$(eval echo "$identity_file")
        
        if [[ -f "$identity_file" ]]; then
            log "Copie de la clé privée: $identity_file"
            cp "$identity_file" "$MOUNT_POINT/ssh/"
            local key_name=$(basename "$identity_file")
            chmod 600 "$MOUNT_POINT/ssh/$key_name"
            
            # Copie de la clé publique si elle existe
            if [[ -f "$identity_file.pub" ]]; then
                cp "$identity_file.pub" "$MOUNT_POINT/ssh/"
                chmod 644 "$MOUNT_POINT/ssh/$key_name.pub"
            fi
            
            # Mise à jour de la configuration
            config_section=$(echo "$config_section" | sed "s|IdentityFile.*|IdentityFile $MOUNT_POINT/ssh/$key_name|")
        fi
    fi
    
    # Ajout à la configuration du vault
    echo "" >> "$MOUNT_POINT/ssh/config"
    echo "$config_section" >> "$MOUNT_POINT/ssh/config"
    
    log "Configuration importée pour $selected_host"
}

# Part IV - Utilisation principale
install_environment() {
    check_dependencies
    load_config
    
    log "Installation de l'environnement sécurisé"
    
    read -p "Taille du vault [$DEFAULT_SIZE]: " size
    size=${size:-$DEFAULT_SIZE}
    
    read -p "Nom du fichier vault [$DEFAULT_NAME.img]: " name
    name=${name:-$DEFAULT_NAME.img}
    VAULT_FILE="$HOME/$name"
    
    read -p "Point de montage [$DEFAULT_MOUNT_POINT]: " mount_point
    MOUNT_POINT=${mount_point:-$DEFAULT_MOUNT_POINT}
    
    VAULT_SIZE="$size"
    save_config
    
    create_vault "$size" "$VAULT_FILE"
    
    # Ouverture pour configuration initiale
    open_vault
    create_ssh_config_template
    create_aliases
    
    log "Installation terminée avec succès !"
    log "Utilisez '$0 open' pour ouvrir l'environnement"
    log "Utilisez '$0 close' pour fermer l'environnement"
}

show_status() {
    load_config
    
    echo -e "${BLUE}=== État de l'environnement sécurisé ===${NC}"
    echo "Fichier vault: $VAULT_FILE"
    echo "Nom du device: $VAULT_NAME"
    echo "Point de montage: $MOUNT_POINT"
    
    if sudo cryptsetup status "$VAULT_NAME" &>/dev/null; then
        echo -e "État: ${GREEN}OUVERT${NC}"
        if mountpoint -q "$MOUNT_POINT" 2>/dev/null; then
            echo -e "Montage: ${GREEN}MONTÉ${NC}"
            echo "Utilisation:"
            df -h "$MOUNT_POINT" | tail -n1
        else
            echo -e "Montage: ${RED}NON MONTÉ${NC}"
        fi
    else
        echo -e "État: ${RED}FERMÉ${NC}"
    fi
}

show_help() {
    cat << EOF
Script de gestion d'environnement sécurisé chiffré

UTILISATION:
    $0 [COMMANDE] [OPTIONS]

COMMANDES:
    install             Installe un nouvel environnement sécurisé
    open                Ouvre l'environnement sécurisé
    close               Ferme l'environnement sécurisé
    status              Affiche l'état de l'environnement
    
    gpg-generate        Génère une nouvelle paire de clés GPG
    gpg-import          Importe les clés GPG du système vers le vault
    gpg-export          Exporte les clés GPG du vault vers le système
    
    ssh-import          Importe une configuration SSH existante
    ssh-config          Recrée le template de configuration SSH
    aliases             Recrée le fichier d'alias
    
    help                Affiche cette aide

EXEMPLES:
    $0 install          # Installation complète
    $0 open             # Ouverture de l'environnement
    $0 gpg-generate     # Génération de clés GPG
    $0 ssh-import       # Import de config SSH existante
    $0 close            # Fermeture de l'environnement

FICHIERS:
    ~/.secure_vault_config      Configuration du script
    ~/.secure_vault_aliases     Alias pour l'environnement

Pour charger les alias dans votre shell:
    source ~/.secure_vault_aliases

EOF
}

# Fonction principale
main() {
    check_root
    
    case "${1:-help}" in
        install)
            install_environment
            ;;
        open)
            load_config
            open_vault
            ;;
        close)
            load_config
            close_vault
            ;;
        status)
            show_status
            ;;
        gpg-generate)
            load_config
            generate_gpg_key
            ;;
        gpg-import)
            load_config
            import_gpg_to_vault
            ;;
        gpg-export)
            load_config
            export_gpg_from_vault
            ;;
        ssh-import)
            load_config
            import_ssh_config
            ;;
        ssh-config)
            load_config
            create_ssh_config_template
            ;;
        aliases)
            load_config
            create_aliases
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            error "Commande inconnue: $1"
            show_help
            exit 1
            ;;
    esac
}

# Piège pour nettoyage en cas d'interruption
trap 'echo -e "\n${YELLOW}Interruption détectée. Nettoyage...${NC}"; exit 130' INT TERM

# Exécution
main "$@"
