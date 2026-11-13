import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import phishing_detector as pd  # noqa: E402


# ── usurpation de marque ──
@pytest.mark.parametrize("url,attendu", [
    ("https://paypal-secure-login.com/verify", ["paypal"]),
    ("https://www.paypal.com.account-check.tk/", ["paypal"]),
    ("https://paypalsecure.com/", ["paypal"]),
    ("https://login.example.com/apple/id", ["apple"]),
])
def test_marque_usurpee(url, attendu):
    assert pd.marques_usurpees(url) == attendu


@pytest.mark.parametrize("url", [
    "https://www.paypal.com/signin",      # site officiel
    "https://freedom.org/",               # « free » n'est pas « freedom »
    "https://groups.example.com/",        # « ups » n'est pas « groups »
    "https://github.com/",
])
def test_pas_de_faux_positif(url):
    assert pd.marques_usurpees(url) == []


def test_score_url_suspecte_superieur_a_url_saine(capsys):
    s_mauvais, _ = pd.analyser_url("http://192.168.4.20/paypal/login/verify-account")
    s_sain, _ = pd.analyser_url("https://www.wikipedia.org/")
    assert s_mauvais >= 45 > s_sain


# ── analyse de fichier ──
def test_double_extension_et_strings(tmp_path):
    f = tmp_path / "facture.pdf.exe"
    f.write_bytes(b"MZ" + b"\x00" * 60 + b"powershell -enc AAAA http://evil.example/payload.bin")
    score, r = pd.analyser_fichier(str(f))
    assert r["double_extension"] is True
    assert "Windows Executable" in r["type_reel"]
    assert r["total_strings_suspects"] >= 1
    assert score >= 45


def test_entropie():
    import tempfile
    with tempfile.NamedTemporaryFile(delete=False) as t:
        t.write(bytes(range(256)) * 64)
    try:
        assert pd.calculer_entropie(t.name) == pytest.approx(8.0, abs=0.01)
    finally:
        os.unlink(t.name)


# ── rapport HTML : pas de XSS ──
def test_rapport_echappe_le_contenu_de_la_cible(tmp_path):
    out = tmp_path / "r.html"
    details = {"📄 Contenu HTML": {"titre": "<script>alert(document.cookie)</script>",
                                   "strings": ["<img src=x onerror=alert(1)>"]}}
    pd.generer_rapport("https://evil.tk/<svg/onload=alert(1)>", 80, "DANGER", "#e74c3c", details, str(out))
    page = out.read_text(encoding="utf-8")
    assert "<script>alert" not in page
    assert "<img src=x" not in page
    assert "<svg/onload" not in page
    assert "&lt;script&gt;" in page


# ── ligne de commande ──
def test_cli_fichier_json(tmp_path, capsys):
    f = tmp_path / "notes.txt"
    f.write_text("bonjour, rien de suspect ici")
    code = pd.main(["--file", str(f), "--json", "--no-report"])
    data = json.loads(capsys.readouterr().out)
    assert code == 0
    assert data["score"] < 20
