# 🎣 Phishing & Threat Detector

> **Projet 3/12 — Cybersecurity Portfolio**  
> Un outil d'analyse défensive qui détecte les pages de phishing, fichiers suspects et images malveillantes via un système de score de risque 0-100.

---

## 📋 Fonctionnalités

### 🌐 Analyse d'URL
| Vérification | Description |
|---|---|
| Structure URL | Longueur, arobase, double slash, sous-domaines excessifs |
| Typosquatting | Détecte les marques usurpées (PayPal, Google, Apple...) |
| TLD suspect | Alerte sur les TLDs à risque (.tk, .ml, .xyz, .top...) |
| IP dans URL | Détecte l'usage d'une IP brute à la place d'un domaine |
| Mots-clés | Détecte les termes suspects (login, verify, secure...) |

### 🔒 Vérification SSL & Headers
| Vérification | Description |
|---|---|
| HTTPS | Vérifie la présence du chiffrement |
| Certificat SSL | Validité, date d'expiration, émetteur |
| Headers sécurité | Détecte les headers manquants (CSP, HSTS, X-Frame-Options...) |
| Redirections | Alerte si redirection vers un domaine différent |
| Stack exposée | Détecte Server et X-Powered-By exposés |

### 📄 Analyse de contenu HTML
| Vérification | Description |
|---|---|
| Formulaires | Détecte les inputs sensibles (password, carte, CVV, SSN) |
| Mots-clés phishing | "verify your account", "suspended", "unusual activity"... |
| Ressources externes | Images et scripts chargés depuis d'autres domaines |

### 🌍 WHOIS
| Vérification | Description |
|---|---|
| Âge du domaine | Alerte si domaine créé depuis moins de 30 ou 180 jours |
| Registrar | Identifie l'hébergeur du domaine |

### 📁 Analyse de fichier suspect
| Vérification | Description |
|---|---|
| Magic bytes | Identifie le vrai type du fichier (indépendamment de l'extension) |
| Double extension | Détecte les fichiers `document.pdf.exe` |
| Extensions dangereuses | .exe, .bat, .ps1, .vbs, .js, .lnk, .hta... |
| Entropie Shannon | Détecte le contenu chiffré ou obfusqué (> 7.0 = suspect) |
| Macros VBA | Détecte les macros dans les fichiers Office (.doc, .xls) |
| Strings suspects | Extrait les chaînes cachées (cmd.exe, powershell, base64...) |
| URLs embarquées | Trouve les URLs cachées dans le fichier |

### 🖼️ Analyse d'image suspecte
| Vérification | Description |
|---|---|
| EXIF complet | Appareil, logiciel, date, copyright, auteur |
| Coordonnées GPS | Extrait la localisation si présente dans les métadonnées |
| Logiciel suspect | Alerte si l'image a été générée par un script ou outil malveillant |
| URLs dans EXIF | Détecte les URLs cachées dans les métadonnées |
| Steganographie LSB | Analyse les bits de poids faible pour détecter des données cachées |
| Strings cachés | Extrait les chaînes lisibles dans le binaire de l'image |

### 📊 Rapport HTML
- Score de risque **0-100** avec verdict coloré
- Rapport standalone thème sombre style GitHub
- Détail complet de chaque vérification

---

## 🖥️ Prérequis

- Python 3.x
- Kali Linux recommandé

---

## 🚀 Installation

```bash
# Cloner le dépôt
git clone https://github.com/Jimo0x/Phishing-Page-Detector.git
cd Phishing-Page-Detector

# Installer les dépendances Python
pip install -r requirements.txt
```

---

## ▶️ Utilisation

```bash
python3 phishing_detector.py            # menu interactif
```

### En ligne de commande (scripts, CI, analyse en lot)

```bash
python3 phishing_detector.py --url https://exemple-suspect.tk/login
python3 phishing_detector.py --file facture.pdf.exe -o rapport_facture.html
python3 phishing_detector.py --image photo.jpg --no-report
python3 phishing_detector.py --url exemple.com --json > resultat.json
```

| Option | Rôle |
|---|---|
| `-u/--url`, `-f/--file`, `-i/--image` | cible à analyser |
| `-o/--output` | chemin du rapport HTML |
| `--no-report` | pas de rapport HTML |
| `--json` | résultat JSON sur stdout (les logs passent sur stderr) |

**Codes de sortie** : `0` = sûr ou à surveiller, `1` = suspect, `2` = dangereux.

### Menu principal

```
  ╔══════════════════════════════════════════╗
  ║   Phishing & Threat Detector  v2.0       ║
  ║   Projet 3 — Cyber Portfolio             ║
  ╚══════════════════════════════════════════╝

  1. Analyser une URL suspecte
  2. Analyser un fichier suspect
  3. Analyser une image suspecte
  4. Quitter
```

---

## 🧪 Exemples

### Analyse d'URL

```
>> Choix : 1
>> URL à analyser : http://paypa1-secure-login.tk/verify

[!] URL longue (42 chars) → +10 pts
[!] Marque usurpée : ['paypal'] → +20 pts
[!] TLD suspect (.tk) → +15 pts
[!] Mots suspects : ['secure', 'login', 'verify'] → +15 pts
[!] Pas de HTTPS → +30 pts
[!] Domaine très récent (3 jours) → +30 pts

══════════════════════════════════════════════════════
  VERDICT FINAL
  Score   : 100/100
  Résultat : 🔴 DANGEREUX / PHISHING TRÈS PROBABLE
══════════════════════════════════════════════════════
```

### Analyse de fichier

```
>> Choix : 2
>> Chemin du fichier : /home/user/invoice.pdf.exe

[!] Extension dangereuse (.exe) → +30 pts
[!] Double extension détectée (invoice.pdf.exe) → +20 pts
[+] Type réel : Windows Executable (EXE/DLL)
[!] Entropie très élevée (7.82) — contenu chiffré/obfusqué → +20 pts
[!] 3 string(s) suspect(s) → +9 pts
    → powershell -enc ...
    → cmd.exe /c ...

  Score : 79/100 — 🔴 DANGEREUX
```

### Analyse d'image

```
>> Choix : 3
>> Chemin de l'image : /home/user/photo.jpg

[+] Type réel : JPEG Image
[+] 12 tag(s) EXIF trouvé(s)
[!] Coordonnées GPS dans l'image : [48, 51, 29] N, [2, 21, 7] E → +10 pts
[!] Anomalie LSB détectée (ecart=0.14) — possible stéganographie → +20 pts

  Score : 30/100 — 🟡 À SURVEILLER
```

---

## 📁 Structure du projet

```
phishing-threat-detector/
│
├── phishing_detector.py    # Script principal
├── requirements.txt        # Dépendances
├── tests/                  # Tests (pytest)
└── README.md               # Documentation
```

### Résultat généré

```
rapport_20240125_160842.html    ← ouvrir dans le navigateur
```

---

## ⚙️ Système de score

| Score | Verdict |
|---|---|
| 0 — 19 | 🟢 Probablement sûr |
| 20 — 44 | 🟡 À surveiller |
| 45 — 69 | 🟠 Suspect |
| 70 — 100 | 🔴 Dangereux / Phishing très probable |

Chaque vérification contribue au score total (plafonné à 100). Plus le score est élevé, plus la cible présente de signaux d'alerte.

---

## 🧪 Tests

```bash
pip install pytest && pytest -q
```

Les tests couvrent la détection d'usurpation de marque (sans faux positifs sur
`freedom.org` ou le vrai `paypal.com`), l'analyse de fichiers, l'échappement du
rapport HTML et la ligne de commande. Ils tournent automatiquement sur GitHub Actions.

---

## 📦 Dépendances

| Librairie | Usage |
|---|---|
| `requests` | Requêtes HTTP |
| `beautifulsoup4` | Parsing HTML |
| `python-whois` | Requêtes WHOIS |
| `tldextract` | Analyse des domaines |
| `exifread` | Lecture des métadonnées EXIF |
| `pillow` | Analyse des pixels (stéganographie LSB) |
| `olefile` | Détection des macros VBA Office |
| `numpy` | Calculs LSB |

---

## ⚠️ Avertissement légal

> Ce projet est développé à des fins **éducatives et défensives** uniquement.  
> Il est conçu pour analyser des contenus **dont vous êtes propriétaire** ou pour lesquels vous avez une **autorisation explicite**.  
> N'utilisez pas cet outil pour analyser des systèmes ou fichiers tiers sans autorisation.  
> L'auteur décline toute responsabilité en cas d'utilisation malveillante.

---

## 🗺️ Roadmap — Cybersecurity Portfolio

- [x] **Projet 1** — Basic Network Recon Tool
- [x] **Projet 2** — SE Contact Scraper
- [x] **Projet 3** — Phishing & Threat Detector
- [ ] **Projet 4** — Vulnerability Scanner
- [ ] **Projet 5** — ...
- [ ] **Projet 6** — ...
- [ ] **Projet 7** — ...
- [ ] **Projet 8** — ...
- [ ] **Projet 9** — ...
- [ ] **Projet 10** — ...
- [ ] **Projet 11** — ...
- [ ] **Projet 12** — ...

---

## 👤 Auteur

**Ton Nom**  
[![GitHub](https://img.shields.io/badge/GitHub-000?style=flat&logo=github)](https://github.com/TON_USERNAME)

---

## 📄 Licence

Ce projet est sous licence [MIT](LICENSE).
