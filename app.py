import streamlit as st
import subprocess
import json
import os
import re
import tempfile
import datetime
import pandas as pd
from dotenv import load_dotenv
from mistralai.client import Mistral
from json_repair import repair_json

load_dotenv()
def get_api_key():
    key = os.getenv("MISTRAL_API_KEY")
    if key:
        return key
    try:
        return st.secrets["MISTRAL_API_KEY"]
    except Exception:
        return None

MISTRAL_API_KEY = get_api_key()
client = Mistral(api_key=MISTRAL_API_KEY)

st.set_page_config(
    page_title="Mini-SecureAudit",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
<style>
    .stApp {
        background-color: #f7f9fb;
    }
    .stButton>button {
        background-color: #2E86AB;
        color: white;
        border: none;
    }
    div[data-testid="stExpander"] {
        border: 1px solid #dfe3e8;
        border-radius: 6px;
        margin-bottom: 8px;
    }
</style>
""", unsafe_allow_html=True)

CRITICITE_ORDRE = ["Critique", "Elevee", "Moyenne", "Faible", "Inconnu"]
CRITICITE_COULEURS = {
    "Critique": "#E63946",
    "Elevee": "#F4A261",
    "Moyenne": "#E9C46A",
    "Faible": "#2A9D8F",
    "Inconnu": "#A0A0A0"
}
CRITICITE_EMOJI = {
    "Critique": "🔴",
    "Elevee": "🟠",
    "Moyenne": "🟡",
    "Faible": "🟢",
    "Inconnu": "⚪"
}


def run_bandit(file_path):
    result = subprocess.run(
        ["bandit", "-r", file_path, "-f", "json"],
        capture_output=True,
        text=True
    )
    return json.loads(result.stdout)


def get_code_snippet(filename, line_number, window=3):
    with open(filename, "r", encoding="utf-8") as f:
        lines = f.readlines()
    start = max(0, line_number - window - 1)
    end = min(len(lines), line_number + window)
    return "".join(lines[start:end])


def explain_vulnerability(vuln, file_path):
    line_number = vuln["line_number"]
    issue_text = vuln["issue_text"]
    code_snippet = get_code_snippet(file_path, line_number)

    prompt = (
        "Tu es un expert en securite informatique. Analyse cette vulnerabilite.\n\n"
        f"Ligne : {line_number}\n"
        f"Probleme : {issue_text}\n"
        f"Code :\n{code_snippet}\n\n"
        "Reponds UNIQUEMENT avec un objet JSON valide, sans texte avant ni apres, "
        "sans blocs de code markdown, sur ce format exact :\n"
        '{"explication": "...", "correctif": "...", "criticite": "Critique|Elevee|Moyenne|Faible"}\n'
    )

    response = client.chat.complete(
        model="mistral-tiny",
        messages=[{"role": "user", "content": prompt}]
    )
    raw = response.choices[0].message.content
    match = re.search(r'\{.*\}', raw, re.DOTALL)
    result = {"explication": "Non disponible", "correctif": "Non disponible", "criticite": "Inconnu"}
    if match:
        try:
            repaired = repair_json(match.group(0))
            parsed = json.loads(repaired)
            if isinstance(parsed, dict):
                result.update(parsed)
        except Exception:
            pass
    return result


if "history" not in st.session_state:
    st.session_state.history = []

# --- EN-TETE ---
col_logo, col_titre = st.columns([1, 8])
with col_logo:
    st.markdown("<h1 style='font-size:48px;'>🔒</h1>", unsafe_allow_html=True)
with col_titre:
    st.title("Mini-SecureAudit")
    st.caption("Audit de securite pour code Python — assiste par IA (Bandit + Mistral AI)")

st.divider()

# --- SIDEBAR ---
with st.sidebar:
    st.header("À propos")
    st.markdown(
        "**Mini-SecureAudit** combine une analyse statique (Bandit) "
        "avec un LLM (Mistral AI) pour detecter, expliquer et corriger "
        "les vulnerabilites de code Python."
    )
    st.markdown("---")
    st.markdown("**Auteur :** Edouard OUENA")
    st.markdown("**Projet :** Sujet 10 — Catalogue 2025-2026")
    st.markdown("---")
    if st.session_state.history:
        st.subheader("📜 Historique des audits")
        for i, item in enumerate(reversed(st.session_state.history[-5:]), 1):
            st.markdown(f"**{i}. {item['filename']}**")
            st.caption(f"{item['vulnerabilities']} vulnerabilite(s) — {item['date'][:19]}")
    else:
        st.caption("Aucun audit effectue pour le moment.")

# --- CORPS PRINCIPAL ---
uploaded_file = st.file_uploader("Choisis un fichier Python (.py) a auditer", type=["py"])

vulnerabilities = []
enriched_list = []

if uploaded_file is not None:
    with tempfile.NamedTemporaryFile(delete=False, suffix=".py", mode="wb") as tmp:
        tmp.write(uploaded_file.getbuffer())
        tmp_path = tmp.name

    debut = datetime.datetime.now()

    with st.spinner("Analyse statique avec Bandit..."):
        bandit_results = run_bandit(tmp_path)
        vulnerabilities = bandit_results.get("results", [])

    if not vulnerabilities:
        st.success("✅ Aucune vulnerabilite detectee par Bandit.")
    else:
        progress = st.progress(0, text="Analyse IA en cours...")
        for i, vuln in enumerate(vulnerabilities):
            enriched = explain_vulnerability(vuln, tmp_path)
            enriched.update(vuln)
            enriched_list.append(enriched)
            progress.progress((i + 1) / len(vulnerabilities), text=f"Explication {i+1}/{len(vulnerabilities)}...")
        progress.empty()

        duree = (datetime.datetime.now() - debut).total_seconds()

        # --- INDICATEURS CLES ---
        st.subheader("📊 Synthese de l'audit")
        compte_criticite = {c: 0 for c in CRITICITE_ORDRE}
        for e in enriched_list:
            c = e.get("criticite", "Inconnu")
            compte_criticite[c] = compte_criticite.get(c, 0) + 1

        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Vulnerabilites detectees", len(vulnerabilities))
        col2.metric("Critiques", compte_criticite.get("Critique", 0))
        col3.metric("Elevees", compte_criticite.get("Elevee", 0))
        col4.metric("Temps d'analyse", f"{duree:.1f}s")

        # --- GRAPHIQUE DE REPARTITION ---
        df = pd.DataFrame({
            "Criticite": list(compte_criticite.keys()),
            "Nombre": list(compte_criticite.values())
        })
        df = df[df["Nombre"] > 0]
        if not df.empty:
            st.bar_chart(df.set_index("Criticite"))

        st.divider()

        # --- FILTRES ---
        st.subheader("🔎 Filtrer les vulnerabilites")
        f1, f2 = st.columns([2, 2])
        with f1:
            criticites_choisies = st.multiselect(
                "Criticite a afficher", CRITICITE_ORDRE, default=CRITICITE_ORDRE
            )
        with f2:
            recherche = st.text_input("Rechercher dans la description")

        enriched_filtre = [
            e for e in enriched_list
            if e.get("criticite", "Inconnu") in criticites_choisies
            and (recherche.lower() in e.get("issue_text", "").lower() if recherche else True)
        ]

        # --- DETAIL DES VULNERABILITES ---
        st.subheader(f"🔍 Detail des vulnerabilites ({len(enriched_filtre)}/{len(enriched_list)} affichees)")
        if not enriched_filtre:
            st.info("Aucune vulnerabilite ne correspond aux filtres selectionnes.")
        for e in enriched_filtre:
            criticite = e.get("criticite", "Inconnu")
            emoji = CRITICITE_EMOJI.get(criticite, "⚪")
            with st.expander(f"{emoji}  Ligne {e['line_number']} — {e['issue_text']}"):
                badge_couleur = CRITICITE_COULEURS.get(criticite, "#A0A0A0")
                st.markdown(
                    f"<span style='background-color:{badge_couleur}; color:white; "
                    f"padding:3px 10px; border-radius:12px; font-size:13px;'>{criticite}</span>",
                    unsafe_allow_html=True
                )
                st.markdown("**Explication**")
                st.write(e.get("explication", "Non disponible"))
                st.markdown("**Correctif propose**")
                st.code(e.get("correctif", "Non disponible"), language="python")

        # --- EXPORT ---
        rapport_json = json.dumps({"vulnerabilities": enriched_list}, indent=2, ensure_ascii=False)
        st.download_button(
            label="📥 Telecharger le rapport complet (JSON)",
            data=rapport_json,
            file_name=f"audit_{uploaded_file.name}.json",
            mime="application/json"
        )

        st.session_state.history.append({
            "filename": uploaded_file.name,
            "vulnerabilities": len(vulnerabilities),
            "date": str(datetime.datetime.now())
        })

    os.unlink(tmp_path)
else:
    st.info("👆 Uploade un fichier Python pour lancer l'audit de securite.")
