#!/usr/bin/env python3

import re
import os
import sys
import html
import argparse
import contextlib
import math
import json
import struct
import socket
import ssl
import requests
import tldextract
import whois
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from datetime import datetime, timezone
from collections import Counter

# ─────────────────────────────────────────
# COULEURS TERMINAL
# ─────────────────────────────────────────
class C:
    RESET = "\033[0m"
    ROUGE = "\033[91m"
    VERT  = "\033[92m"
    JAUNE = "\033[93m"
    BLEU  = "\033[94m"
    CYAN  = "\033[96m"
    GRAS  = "\033[1m"

def info(msg):   print(f"{C.BLEU}[*]{C.RESET} {msg}")
def succes(msg): print(f"{C.VERT}[+]{C.RESET} {msg}")
def erreur(msg): print(f"{C.ROUGE}[-]{C.RESET} {msg}")
def warn(msg):   print(f"{C.JAUNE}[!]{C.RESET} {msg}")


# ─────────────────────────────────────────
# CONSTANTES
# ─────────────────────────────────────────
MARQUES_CIBLES = [
    "paypal","apple","google","microsoft","amazon","netflix",
    "facebook","instagram","twitter","linkedin","dropbox",
    "bankofamerica","wellsfargo","chase","citibank","hsbc",
    "dhl","fedex","ups","orange","sfr","free","leboncoin"
]
MOTS_SUSPECTS_URL = [
    "login","signin","verify","secure","account","update",
    "confirm","banking","password","credential","submit",
    "wallet","suspend","unlock","validate","authenticate"
]
MOTS_SUSPECTS_CONTENU = [
    "verify your account","confirm your identity","suspended",
    "unusual activity","click here to verify","update your information",
    "your account has been","limited access","verify now",
    "enter your password","social security","credit card number"
]
HEADERS_SECURITE = [
    "Strict-Transport-Security","Content-Security-Policy",
    "X-Frame-Options","X-Content-Type-Options",
    "Referrer-Policy","Permissions-Policy"
]
TLDS_SUSPECTS = [".tk",".ml",".ga",".cf",".gq",".xyz",".top",".click",".loan"]

# Magic bytes pour identifier le vrai type de fichier
MAGIC_BYTES = {
    b"\x4d\x5a":                     "Windows Executable (EXE/DLL)",
    b"\x7f\x45\x4c\x46":             "Linux Executable (ELF)",
    b"\x50\x4b\x03\x04":             "ZIP / Office (DOCX/XLSX/PPTX)",
    b"\xd0\xcf\x11\xe0":             "Office Legacy (DOC/XLS/PPT)",
    b"\x25\x50\x44\x46":             "PDF",
    b"\xff\xd8\xff":                  "JPEG Image",
    b"\x89\x50\x4e\x47":             "PNG Image",
    b"\x47\x49\x46\x38":             "GIF Image",
    b"\x42\x4d":                      "BMP Image",
    b"\x52\x61\x72\x21":             "RAR Archive",
    b"\x1f\x8b":                      "GZIP Archive",
    b"\x4d\x5a\x90\x00":             "PE Executable",
    b"\xca\xfe\xba\xbe":             "Java Class",
    b"#!/":                           "Script Shell/Python",
    b"<script":                       "JavaScript/HTML",
}

# Extensions dangereuses
EXTENSIONS_DANGEREUSES = [
    ".exe",".bat",".cmd",".ps1",".vbs",".js",".jar",
    ".msi",".dll",".scr",".hta",".pif",".lnk",".reg",
    ".com",".wsf",".wsh"
]

# Strings suspects dans les fichiers
STRINGS_SUSPECTS = [
    "cmd.exe","powershell","wget","curl","base64",
    "invoke-expression","iex","downloadfile","shellexecute",
    "createobject","wscript","cscript","regsvr32",
    "mshta","certutil","bitsadmin","net user","net localgroup",
    "shadow copy","vssadmin","bcdedit","wmic","taskkill",
    "http://","https://","ftp://","\\\\","/etc/passwd",
    "eval(","exec(","os.system","subprocess"
]


# ═══════════════════════════════════════════
#   MODULE 1 — ANALYSE URL
# ═══════════════════════════════════════════
def marques_usurpees(url):
    """Marques citées dans l'URL alors que le domaine n'appartient pas à la marque.

    On compare des mots entiers (« free » ne matche plus « freedom », « ups » ne
    matche plus « groups ») et on ignore le site officiel (paypal.com n'usurpe pas PayPal).
    Les marques de 5 lettres ou plus sont aussi cherchées collées dans le domaine
    (paypalsecure.com).
    """
    parsed = urlparse(url)
    ext = tldextract.extract(url)
    domaine = ext.domain.lower()
    hote = parsed.netloc.lower().rsplit("@", 1)[-1].split(":")[0]
    jetons = set(re.split(r"[^a-z0-9]+", f"{hote} {parsed.path.lower()}")) - {""}
    trouvees = []
    for m in MARQUES_CIBLES:
        if domaine == m:
            continue
        if m in jetons or (len(m) >= 5 and m in domaine):
            trouvees.append(m)
    return trouvees


def analyser_url(url):
    resultats = {}
    score = 0
    parsed = urlparse(url)
    ext = tldextract.extract(url)

    longueur = len(url)
    resultats["longueur_url"] = longueur
    if longueur > 75:
        score += 10
        warn(f"URL longue ({longueur} chars) → +10 pts")

    if "@" in url:
        score += 20
        warn("Symbole '@' dans l'URL → +20 pts")
        resultats["arobase"] = True

    nb_tirets = ext.domain.count("-")
    resultats["tirets_domaine"] = nb_tirets
    if nb_tirets >= 3:
        score += 15
        warn(f"{nb_tirets} tirets dans le domaine → +15 pts")
    elif nb_tirets >= 1:
        score += 5

    sous_domaines = ext.subdomain.split(".") if ext.subdomain else []
    nb_sous = len([s for s in sous_domaines if s])
    resultats["nb_sous_domaines"] = nb_sous
    if nb_sous >= 4:
        score += 20
        warn(f"{nb_sous} sous-domaines → +20 pts")
    elif nb_sous >= 2:
        score += 10

    tld = f".{ext.suffix}"
    resultats["tld"] = tld
    if any(tld.endswith(t) for t in TLDS_SUSPECTS):
        score += 15
        warn(f"TLD suspect ({tld}) → +15 pts")

    marques = marques_usurpees(url)
    resultats["marques_trouvees"] = marques
    if marques:
        score += 20
        warn(f"Marque(s) usurpée(s) : {marques} → +20 pts")

    mots = [m for m in MOTS_SUSPECTS_URL if m in url.lower()]
    resultats["mots_suspects"] = mots
    if mots:
        score += min(len(mots) * 5, 20)

    if re.search(r"(\d{1,3}\.){3}\d{1,3}", parsed.netloc):
        score += 25
        warn("IP directe dans l'URL → +25 pts")
        resultats["ip_dans_url"] = True

    succes(f"Analyse URL — score partiel : {score}")
    return score, resultats


# ═══════════════════════════════════════════
#   MODULE 2 — SSL
# ═══════════════════════════════════════════
def verifier_ssl(url):
    resultats = {}
    score = 0
    parsed = urlparse(url)
    host = parsed.netloc.split(":")[0]

    if parsed.scheme != "https":
        score += 30
        warn("Pas de HTTPS → +30 pts")
        resultats["https"] = False
        return score, resultats

    resultats["https"] = True
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
            s.settimeout(5)
            s.connect((host, 443))
            cert = s.getpeercert()

        expire_str = cert.get("notAfter", "")
        if expire_str:
            expire = datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            jours = (expire - datetime.now(timezone.utc)).days
            resultats["ssl_expire_dans_jours"] = jours
            if jours < 0:
                score += 30
                warn("SSL expiré → +30 pts")
            elif jours < 30:
                score += 15
                warn(f"SSL expire bientôt ({jours}j) → +15 pts")
            else:
                succes(f"SSL valide ({jours} jours restants)")

        issuer = dict(x[0] for x in cert.get("issuer", []))
        resultats["ssl_issuer"] = issuer.get("organizationName", "Inconnu")

    except Exception as e:
        score += 20
        warn(f"Erreur SSL : {e} → +20 pts")
        resultats["ssl_erreur"] = str(e)

    return score, resultats


# ═══════════════════════════════════════════
#   MODULE 3 — HEADERS HTTP
# ═══════════════════════════════════════════
def analyser_headers(url):
    resultats = {}
    score = 0
    html = ""
    try:
        resp = requests.get(url, timeout=10, allow_redirects=True,
                            headers={"User-Agent": "Mozilla/5.0"})
        headers = resp.headers
        html = resp.text
        resultats["status_code"] = resp.status_code
        resultats["url_finale"] = resp.url

        if resp.url != url:
            d_init = tldextract.extract(url).registered_domain
            d_fin  = tldextract.extract(resp.url).registered_domain
            if d_init != d_fin:
                score += 20
                warn(f"Redirection vers domaine différent ({d_fin}) → +20 pts")
                resultats["redirection_suspecte"] = True

        manquants = [h for h in HEADERS_SECURITE if h not in headers]
        resultats["headers_securite_manquants"] = manquants
        if len(manquants) >= 4:
            score += 15
        elif len(manquants) >= 2:
            score += 8

        if "Server" in headers:
            resultats["server"] = headers["Server"]
        if "X-Powered-By" in headers:
            resultats["x_powered_by"] = headers["X-Powered-By"]
            warn(f"X-Powered-By exposé : {headers['X-Powered-By']}")

    except Exception as e:
        erreur(f"Connexion échouée : {e}")

    return score, resultats, html


# ═══════════════════════════════════════════
#   MODULE 4 — CONTENU HTML
# ═══════════════════════════════════════════
def analyser_contenu(html, url):
    resultats = {}
    score = 0
    if not html:
        return score, resultats

    soup = BeautifulSoup(html, "html.parser")
    texte = soup.get_text(separator=" ").lower()

    inputs_sensibles = []
    for form in soup.find_all("form"):
        for inp in form.find_all("input"):
            t = inp.get("type","").lower()
            n = inp.get("name","").lower()
            if t in ["password","tel"] or any(k in n for k in ["card","cvv","ssn","credit","pass"]):
                inputs_sensibles.append(n or t)

    resultats["formulaires"] = len(soup.find_all("form"))
    resultats["inputs_sensibles"] = inputs_sensibles
    if inputs_sensibles:
        score += 20
        warn(f"Inputs sensibles : {inputs_sensibles} → +20 pts")

    mots = [m for m in MOTS_SUSPECTS_CONTENU if m in texte]
    resultats["mots_phishing"] = mots
    if mots:
        ajout = min(len(mots) * 8, 30)
        score += ajout
        warn(f"{len(mots)} mot(s)-clé(s) phishing → +{ajout} pts")

    titre = soup.find("title")
    resultats["titre"] = titre.text.strip() if titre else "Aucun"

    succes(f"Analyse contenu — score partiel : {score}")
    return score, resultats


# ═══════════════════════════════════════════
#   MODULE 5 — WHOIS
# ═══════════════════════════════════════════
def analyser_whois(url):
    resultats = {}
    score = 0
    ext = tldextract.extract(url)
    domaine = f"{ext.domain}.{ext.suffix}"

    try:
        w = whois.whois(domaine)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation:
            if creation.tzinfo is None:
                creation = creation.replace(tzinfo=timezone.utc)
            age = (datetime.now(timezone.utc) - creation).days
            resultats["age_domaine_jours"] = age
            resultats["date_creation"] = str(creation.date())
            if age < 30:
                score += 30
                warn(f"Domaine très récent ({age}j) → +30 pts")
            elif age < 180:
                score += 15
                warn(f"Domaine récent ({age}j) → +15 pts")
            else:
                succes(f"Domaine existant depuis {age} jours")
        resultats["registrar"] = str(w.registrar or "Inconnu")
    except Exception as e:
        score += 10
        warn(f"WHOIS non dispo → +10 pts")
        resultats["whois_erreur"] = str(e)

    return score, resultats


# ═══════════════════════════════════════════
#   MODULE 6 — ANALYSE FICHIER SUSPECT
# ═══════════════════════════════════════════

def detecter_type_fichier(chemin):
    """Lit les magic bytes pour identifier le vrai type du fichier."""
    try:
        with open(chemin, "rb") as f:
            header = f.read(16)
        for magic, nom in MAGIC_BYTES.items():
            if header[:len(magic)] == magic:
                return nom
        return "Type inconnu"
    except Exception as e:
        return f"Erreur : {e}"

def calculer_entropie(chemin):
    """
    Calcule l'entropie de Shannon du fichier.
    Entropie > 7.0 → contenu probablement chiffré ou compressé (suspect).
    """
    try:
        with open(chemin, "rb") as f:
            data = f.read()
        if not data:
            return 0.0
        compteur = Counter(data)
        taille = len(data)
        entropie = -sum((c/taille) * math.log2(c/taille) for c in compteur.values())
        return round(entropie, 3)
    except Exception:
        return 0.0

def extraire_strings(chemin, min_len=6):
    """Extrait les chaînes ASCII lisibles du fichier (comme la commande 'strings')."""
    try:
        with open(chemin, "rb") as f:
            data = f.read()
        # Regex : bien plus rapide que la boucle octet par octet, et récupère
        # aussi la dernière chaîne quand le fichier se termine par du texte.
        return [m.decode("ascii") for m in re.findall(rb"[\x20-\x7e]{%d,}" % min_len, data)]
    except Exception:
        return []

def analyser_macros_office(chemin):
    """Détecte la présence de macros VBA dans les fichiers Office."""
    try:
        import olefile
        if not olefile.isOleFile(chemin):
            return False, "Pas un fichier OLE"
        ole = olefile.OleFileIO(chemin)
        macros = [e for e in ole.listdir() if "vba" in "/".join(e).lower()]
        ole.close()
        if macros:
            return True, f"{len(macros)} stream(s) VBA trouvé(s)"
        return False, "Aucune macro détectée"
    except ImportError:
        return False, "olefile non installé (pip install olefile)"
    except Exception as e:
        return False, str(e)

def lire_metadonnees_fichier(chemin):
    """Lit les métadonnées basiques du fichier (taille, dates, permissions)."""
    try:
        stat = os.stat(chemin)
        return {
            "taille": f"{stat.st_size} bytes ({stat.st_size/1024:.1f} KB)",
            "modifie_le": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
            "cree_le": datetime.fromtimestamp(stat.st_ctime).strftime("%Y-%m-%d %H:%M:%S"),
        }
    except Exception as e:
        return {"erreur": str(e)}

def analyser_fichier(chemin):
    """Analyse complète d'un fichier suspect."""
    resultats = {}
    score = 0

    info(f"Analyse du fichier : {chemin}")

    if not os.path.exists(chemin):
        erreur("Fichier introuvable.")
        return 0, {}

    nom = os.path.basename(chemin)
    ext = os.path.splitext(nom)[1].lower()

    # Extension
    resultats["nom_fichier"] = nom
    resultats["extension"] = ext
    if ext in EXTENSIONS_DANGEREUSES:
        score += 30
        warn(f"Extension dangereuse ({ext}) → +30 pts")

    # Double extension (ex: document.pdf.exe)
    if nom.count(".") >= 2:
        score += 20
        warn(f"Double extension détectée ({nom}) → +20 pts")
        resultats["double_extension"] = True

    # Type réel via magic bytes
    type_reel = detecter_type_fichier(chemin)
    resultats["type_reel"] = type_reel
    succes(f"Type réel : {type_reel}")

    # Discordance extension / type réel
    if ext == ".pdf" and "PDF" not in type_reel:
        score += 25
        warn(f"Extension .pdf mais type réel : {type_reel} → +25 pts")
    elif ext in [".jpg",".jpeg"] and "JPEG" not in type_reel:
        score += 25
        warn(f"Extension image mais type réel : {type_reel} → +25 pts")
    elif ext in [".docx",".xlsx"] and "ZIP" not in type_reel and "Office" not in type_reel:
        score += 20
        warn(f"Extension Office mais type réel : {type_reel} → +20 pts")

    # Métadonnées
    meta = lire_metadonnees_fichier(chemin)
    resultats.update(meta)

    # Entropie
    entropie = calculer_entropie(chemin)
    resultats["entropie_shannon"] = f"{entropie}/8.0"
    if entropie > 7.2:
        score += 20
        warn(f"Entropie très élevée ({entropie}) — contenu chiffré/obfusqué → +20 pts")
    elif entropie > 6.5:
        score += 10
        warn(f"Entropie élevée ({entropie}) → +10 pts")
    else:
        succes(f"Entropie normale ({entropie})")

    # Macros Office
    a_macro, msg_macro = analyser_macros_office(chemin)
    resultats["macros_vba"] = msg_macro
    if a_macro:
        score += 30
        warn(f"Macros VBA détectées → +30 pts")

    # Strings suspects
    all_strings = extraire_strings(chemin)
    strings_suspects_trouves = [
        s for s in all_strings
        if any(sus.lower() in s.lower() for sus in STRINGS_SUSPECTS)
    ]
    resultats["strings_suspects"] = strings_suspects_trouves[:15]  # Limite à 15
    resultats["total_strings_suspects"] = len(strings_suspects_trouves)

    if strings_suspects_trouves:
        ajout = min(len(strings_suspects_trouves) * 3, 25)
        score += ajout
        warn(f"{len(strings_suspects_trouves)} string(s) suspect(s) → +{ajout} pts")
        for s in strings_suspects_trouves[:5]:
            warn(f"  → {s[:80]}")

    # URLs extraites du fichier
    urls_trouvees = list(set(re.findall(r"https?://[^\s\"'<>]{10,}", " ".join(all_strings))))
    resultats["urls_dans_fichier"] = urls_trouvees[:10]
    if urls_trouvees:
        score += min(len(urls_trouvees) * 5, 20)
        warn(f"{len(urls_trouvees)} URL(s) trouvée(s) dans le fichier")
        for u in urls_trouvees[:3]:
            warn(f"  → {u}")

    score = min(score, 100)
    succes(f"Analyse fichier terminée — score : {score}/100")
    return score, resultats


# ═══════════════════════════════════════════
#   MODULE 7 — ANALYSE IMAGE SUSPECTE
# ═══════════════════════════════════════════

def analyser_exif(chemin):
    """Extrait les métadonnées EXIF d'une image."""
    try:
        import exifread
        with open(chemin, "rb") as f:
            tags = exifread.process_file(f, stop_tag="UNDEF", details=False)
        exif = {str(k): str(v) for k, v in tags.items()}
        return exif
    except ImportError:
        return {"erreur": "exifread non installé (pip install exifread)"}
    except Exception as e:
        return {"erreur": str(e)}

def extraire_gps(exif):
    """Extrait les coordonnées GPS depuis les données EXIF si présentes."""
    try:
        lat_ref = exif.get("GPS GPSLatitudeRef", "")
        lon_ref = exif.get("GPS GPSLongitudeRef", "")
        lat     = exif.get("GPS GPSLatitude", "")
        lon     = exif.get("GPS GPSLongitude", "")
        if lat and lon:
            return f"{lat} {lat_ref}, {lon} {lon_ref}"
    except:
        pass
    return None

def analyser_pixels_lsb(chemin):
    """
    Analyse basique de steganographie LSB (Least Significant Bit).
    Vérifie si les bits de poids faible des pixels sont anormalement non-aléatoires.
    """
    try:
        from PIL import Image
        import numpy as np
        img = Image.open(chemin).convert("RGB")
        pixels = list(img.getdata())
        # Extrait les LSB de chaque canal RGB
        lsb = [p & 1 for pixel in pixels for p in pixel]
        # Si trop uniforme → possible message caché
        ratio_uns = sum(lsb) / len(lsb)
        # Un ratio très loin de 0.5 peut indiquer une stéganographie
        ecart = abs(ratio_uns - 0.5)
        return round(ratio_uns, 4), round(ecart, 4)
    except ImportError:
        return None, None
    except Exception:
        return None, None

def analyser_image(chemin):
    """Analyse complète d'une image suspecte."""
    resultats = {}
    score = 0

    info(f"Analyse de l'image : {chemin}")

    if not os.path.exists(chemin):
        erreur("Fichier introuvable.")
        return 0, {}

    nom = os.path.basename(chemin)
    ext = os.path.splitext(nom)[1].lower()
    resultats["nom_fichier"] = nom
    resultats["extension"] = ext

    # Type réel
    type_reel = detecter_type_fichier(chemin)
    resultats["type_reel"] = type_reel
    succes(f"Type réel : {type_reel}")

    # Discordance extension/type
    extensions_images = [".jpg",".jpeg",".png",".gif",".bmp",".webp"]
    types_images = ["JPEG","PNG","GIF","BMP"]
    if ext in extensions_images and not any(t in type_reel for t in types_images):
        score += 30
        warn(f"Extension image mais contenu différent ({type_reel}) → +30 pts")

    # Métadonnées fichier
    meta = lire_metadonnees_fichier(chemin)
    resultats.update(meta)

    # Entropie
    entropie = calculer_entropie(chemin)
    resultats["entropie_shannon"] = f"{entropie}/8.0"
    if entropie > 7.5:
        score += 15
        warn(f"Entropie très élevée pour une image ({entropie}) → +15 pts")

    # EXIF
    info("Extraction des métadonnées EXIF...")
    exif = analyser_exif(chemin)
    if "erreur" not in exif:
        resultats["nb_tags_exif"] = len(exif)
        succes(f"{len(exif)} tag(s) EXIF trouvé(s)")

        # GPS
        gps = extraire_gps(exif)
        if gps:
            resultats["gps"] = gps
            warn(f"Coordonnées GPS dans l'image : {gps}")
            score += 10

        # Appareil photo / logiciel
        for tag in ["Image Make", "Image Model", "Image Software",
                    "EXIF DateTimeOriginal", "Image Artist", "Image Copyright"]:
            if tag in exif:
                resultats[tag] = exif[tag]
                succes(f"{tag} : {exif[tag]}")

        # Logiciel suspect dans EXIF
        soft = exif.get("Image Software", "").lower()
        if any(s in soft for s in ["python","script","wget","curl","exploit"]):
            score += 20
            warn(f"Logiciel suspect dans EXIF : {soft} → +20 pts")

        # URLs dans les métadonnées EXIF
        exif_str = " ".join(exif.values())
        urls_exif = re.findall(r"https?://[^\s\"']{10,}", exif_str)
        if urls_exif:
            resultats["urls_dans_exif"] = urls_exif
            score += 15
            warn(f"URL(s) dans les métadonnées EXIF : {urls_exif} → +15 pts")

    else:
        resultats["exif"] = exif.get("erreur", "Non disponible")

    # Strings cachés dans l'image
    all_strings = extraire_strings(chemin)
    strings_suspects = [
        s for s in all_strings
        if any(sus.lower() in s.lower() for sus in STRINGS_SUSPECTS)
    ]
    resultats["strings_suspects"] = strings_suspects[:10]
    if strings_suspects:
        score += min(len(strings_suspects) * 4, 20)
        warn(f"{len(strings_suspects)} string(s) suspect(s) dans l'image → +{min(len(strings_suspects)*4,20)} pts")

    # Analyse LSB (steganographie basique)
    info("Analyse LSB (steganographie basique)...")
    ratio_lsb, ecart_lsb = analyser_pixels_lsb(chemin)
    if ratio_lsb is not None:
        resultats["lsb_ratio"] = ratio_lsb
        resultats["lsb_ecart"] = ecart_lsb
        if ecart_lsb > 0.1:
            score += 20
            warn(f"Anomalie LSB détectée (ecart={ecart_lsb}) — possible stéganographie → +20 pts")
        else:
            succes(f"LSB normal (ecart={ecart_lsb})")
    else:
        resultats["lsb"] = "Analyse non disponible (pip install pillow numpy)"

    score = min(score, 100)
    succes(f"Analyse image terminée — score : {score}/100")
    return score, resultats


# ═══════════════════════════════════════════
#   SCORE & VERDICT
# ═══════════════════════════════════════════
def verdict(score):
    score = min(score, 100)
    if score >= 70:
        return score, "🔴 DANGEREUX / PHISHING TRÈS PROBABLE", "#e74c3c"
    elif score >= 45:
        return score, "🟠 SUSPECT — À ANALYSER AVEC PRÉCAUTION", "#e67e22"
    elif score >= 20:
        return score, "🟡 À SURVEILLER", "#f1c40f"
    else:
        return score, "🟢 PROBABLEMENT SÛR", "#2ecc71"


# ═══════════════════════════════════════════
#   RAPPORT HTML
# ═══════════════════════════════════════════
def generer_rapport(cible, score, verdict_txt, couleur, details, fichier="rapport.html"):
    date_scan = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def section(titre, data):
        if not data:
            return ""
        lignes = ""
        for k, v in data.items():
            # Tout ce qui vient de la cible (titre de page, strings d'un fichier, EXIF...)
            # est contrôlé par l'attaquant : on l'échappe pour éviter un XSS dans le rapport.
            if isinstance(v, list):
                v = "<br>".join(html.escape(str(x)) for x in v) if v else "Aucun"
            else:
                v = html.escape(str(v))
            lignes += f"<tr><td>{html.escape(str(k))}</td><td>{v}</td></tr>"
        return f"""
        <div class="section">
          <h3>{html.escape(titre)}</h3>
          <table><tbody>{lignes}</tbody></table>
        </div>"""

    sections_html = "".join(section(n, d) for n, d in details.items() if d)

    page = f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<title>Rapport — {html.escape(cible[:50])}</title>
<style>
  body {{ font-family:'Segoe UI',sans-serif; background:#0d1117; color:#c9d1d9; margin:0; padding:20px; }}
  h1 {{ color:#58a6ff; border-bottom:1px solid #30363d; padding-bottom:10px; }}
  h3 {{ color:#58a6ff; margin-bottom:8px; }}
  code {{ background:#161b22; padding:2px 6px; border-radius:4px; font-size:0.9em; }}
  .verdict {{ font-size:1.4em; font-weight:bold; color:{couleur};
              background:#161b22; border:2px solid {couleur};
              padding:20px; border-radius:10px; text-align:center; margin:20px 0; }}
  .score {{ font-size:3em; }}
  .section {{ background:#161b22; border:1px solid #30363d;
              border-radius:8px; padding:15px; margin:15px 0; }}
  table {{ width:100%; border-collapse:collapse; }}
  td {{ padding:6px 10px; border-bottom:1px solid #21262d; font-size:0.88em; vertical-align:top; }}
  td:first-child {{ color:#8b949e; width:38%; }}
  footer {{ margin-top:40px; color:#8b949e; font-size:0.85em; text-align:center; }}
</style>
</head>
<body>
<h1>🔍 Phishing & Threat Detector — Rapport</h1>
<p>Cible analysée : <code>{html.escape(cible)}</code></p>
<p>Date : <strong>{date_scan}</strong></p>
<div class="verdict">
  <div class="score">{score}/100</div>
  {verdict_txt}
</div>
{sections_html}
<footer>Phishing Page Detector v2.0 — Projet 3/12 Cybersecurity Portfolio</footer>
</body>
</html>"""

    with open(fichier, "w", encoding="utf-8") as f:
        f.write(page)
    succes(f"Rapport sauvegardé : {fichier}")


# ═══════════════════════════════════════════
#   ANALYSE + MENU / LIGNE DE COMMANDE
# ═══════════════════════════════════════════
def analyser(mode, cible):
    """Lance l'analyse adaptée. mode = 'url' | 'fichier' | 'image'."""
    details = {}
    if mode == "url":
        if not cible.startswith(("http://", "https://")):
            cible = "https://" + cible
        score = 0
        s, r = analyser_url(cible);           score += s; details["🔗 Analyse URL"] = r
        s, r = verifier_ssl(cible);           score += s; details["🔒 SSL"] = r
        s, r, page = analyser_headers(cible); score += s; details["📡 Headers HTTP"] = r
        s, r = analyser_contenu(page, cible); score += s; details["📄 Contenu HTML"] = r
        s, r = analyser_whois(cible);         score += s; details["🌍 WHOIS"] = r
    elif mode == "fichier":
        score, details["📁 Analyse Fichier"] = analyser_fichier(cible)
    else:
        score, details["🖼️ Analyse Image"] = analyser_image(cible)
    return cible, score, details


def menu_interactif():
    print(f"""{C.CYAN}{C.GRAS}
  ╔══════════════════════════════════════════╗
  ║   Phishing & Threat Detector  v2.1       ║
  ║                                          ║
  ╚══════════════════════════════════════════╝
{C.RESET}""")
    print("  1. Analyser une URL suspecte")
    print("  2. Analyser un fichier suspect")
    print("  3. Analyser une image suspecte")
    print("  4. Quitter")
    choix = input(f"\n{C.GRAS}>> Choix : {C.RESET}").strip()
    if choix == "1":
        return "url", input(">> URL à analyser : ").strip()
    if choix == "2":
        return "fichier", input(">> Chemin du fichier : ").strip()
    if choix == "3":
        return "image", input(">> Chemin de l'image : ").strip()
    if choix != "4":
        erreur("Choix invalide.")
    return None, None


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Phishing & Threat Detector — score de risque d'une URL, d'un fichier ou d'une image.",
        epilog="Sans argument, le menu interactif s'ouvre. Codes de sortie : 0 = sûr/à surveiller, 1 = suspect, 2 = dangereux.",
    )
    cible_grp = parser.add_mutually_exclusive_group()
    cible_grp.add_argument("-u", "--url", help="URL à analyser")
    cible_grp.add_argument("-f", "--file", help="fichier suspect à analyser")
    cible_grp.add_argument("-i", "--image", help="image suspecte à analyser")
    parser.add_argument("-o", "--output", help="chemin du rapport HTML (défaut : rapport_<date>.html)")
    parser.add_argument("--no-report", action="store_true", help="ne pas générer de rapport HTML")
    parser.add_argument("--json", action="store_true", help="résultat en JSON sur la sortie standard")
    args = parser.parse_args(argv)

    if args.url:
        mode, cible = "url", args.url
    elif args.file:
        mode, cible = "fichier", args.file
    elif args.image:
        mode, cible = "image", args.image
    else:
        mode, cible = menu_interactif()
        if not mode:
            return 0
    print()

    # En mode JSON, les logs colorés partent sur stderr pour garder un JSON propre.
    logs = sys.stderr if args.json else sys.stdout
    with contextlib.redirect_stdout(logs):
        cible, score_total, details = analyser(mode, cible)
        score_final, verdict_txt, couleur = verdict(score_total)
        print(f"\n{'═'*52}")
        print(f"{C.GRAS}  VERDICT FINAL{C.RESET}")
        print(f"  Score  : {score_final}/100")
        print(f"  Résultat : {verdict_txt}")
        print(f"{'═'*52}\n")
        if not args.no_report:
            nom = args.output or f"rapport_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
            generer_rapport(cible, score_final, verdict_txt, couleur, details, nom)

    if args.json:
        print(json.dumps({"cible": cible, "score": score_final, "verdict": verdict_txt,
                          "details": details}, ensure_ascii=False, indent=2, default=str))
    return 2 if score_final >= 70 else 1 if score_final >= 45 else 0


if __name__ == "__main__":
    sys.exit(main())
