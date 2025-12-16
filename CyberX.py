"""
CyberX AI
AI-Powered Threat Actor Intelligence Tracker (Updated with Regular Scraping Fallback)

Key Updates:
- Added regular requests + BeautifulSoup fallback scraping if ZenRows API key is not configured.
- If ZenRows key is missing/invalid, automatically falls back to direct scraping with User-Agent header.
- Fallback includes basic error handling per URL (continues on failures).
- Maintains same data structure for consistency across collection methods.
- Updated ARTICLE_URLS to 15 real, recent (2025) threat reports from The Hacker News.
- Previous updates preserved: Single JSON per run, etc.
"""

import os
import json
import requests
from bs4 import BeautifulSoup
import glob  # For finding existing JSON files

import google.generativeai as genai
from sentence_transformers import SentenceTransformer
import chromadb

# ---------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------

ZENROWS_API_KEY = os.getenv("ZENROWS_API_KEY") or "PASTE_YOUR_ZENROWS_API_KEY_HERE"
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY") or "PASTE_YOUR_GEMINI_API_KEY_HERE"
genai.configure(api_key=GEMINI_API_KEY)
llm = genai.GenerativeModel("gemini-pro")

USE_LLM = True

# 15 Real recent threat report URLs (2025, from The Hacker News)
ARTICLE_URLS = [
    "https://thehackernews.com/2025/12/chinese-hackers-have-started-exploiting.html",
    "https://thehackernews.com/2025/12/react2shell-exploitation-escalates-into.html",
    "https://thehackernews.com/2025/12/warning-winrar-vulnerability-cve-2025.html",
    "https://thehackernews.com/2025/12/threatsday-bulletin-spyware-alerts.html",
    "https://thehackernews.com/2025/12/chrome-targeted-by-active-in-wild.html",
    "https://thehackernews.com/2025/12/unpatched-gogs-zero-day-exploited.html",
    "https://thehackernews.com/2025/12/storm-0249-escalates-ransomware-attacks.html",
    "https://thehackernews.com/2025/12/nanoremote-malware-uses-google-drive.html",
    "https://thehackernews.com/2025/11/apt24-deploys-badaudio-in-years-long.html",
    "https://thehackernews.com/2025/08/charon-ransomware-hits-middle-east.html",
    "https://thehackernews.com/2025/12/5-threats-that-reshaped-web-security.html",
    "https://thehackernews.com/2025/12/microsoft-issues-security-fixes-for-56.html",
    "https://thehackernews.com/2025/12/critical-xxe-bug-cve-2025-66516-cvss.html",
    "https://thehackernews.com/2025/11/fortinet-warns-of-new-fortiweb-cve-2025.html",
    "https://thehackernews.com/2025/12/new-advanced-phishing-kits-use-ai-and.html",
]

# ---------------------------------------------------
# MOCK DATA (15 entries based on 2025 reports)
# ---------------------------------------------------

MOCK_THREAT_INTEL_LIST = [
    {"actor": "Earth Lamia", "aliases": ["China-nexus"], "ttps": ["RCE Exploitation"], "targets": ["Global Servers"],
     "iocs": [], "timeline": "Dec 2025"},
    {"actor": "Jackpot Panda", "aliases": ["China-nexus"], "ttps": ["Crypto Mining"], "targets": ["Web Infrastructure"],
     "iocs": [], "timeline": "Dec 2025"},
    {"actor": "STAC6565", "aliases": ["Gold Blade"], "ttps": ["Ransomware Deployment"], "targets": ["Canada"],
     "iocs": [], "timeline": "Dec 2025"},
    {"actor": "VolkLocker", "aliases": [], "ttps": ["Ransomware"], "targets": ["Windows/Linux"], "iocs": [],
     "timeline": "Dec 2025"},
    {"actor": "PassiveNeuron", "aliases": ["APT"], "ttps": ["Espionage, Neursite"], "targets": ["Global"], "iocs": [],
     "timeline": "Oct 2025"},
    {"actor": "APT31", "aliases": ["Judgement Panda"], "ttps": ["CloudyLoader"], "targets": ["Russian IT"], "iocs": [],
     "timeline": "Nov 2025"},
    {"actor": "Storm-0249", "aliases": [], "ttps": ["ClickFix, Ransomware"], "targets": ["Multiple Sectors"],
     "iocs": [], "timeline": "Dec 2025"},
    {"actor": "SideWinder", "aliases": ["APT-C-17"], "ttps": ["Phishing"], "targets": ["Maritime, Nuclear"], "iocs": [],
     "timeline": "Mar 2025"},
    {"actor": "Blind Eagle", "aliases": ["APT-C-36"], "ttps": ["RATs, Phishing"], "targets": ["Colombia"], "iocs": [],
     "timeline": "Aug 2025"},
    {"actor": "Charon", "aliases": [], "ttps": ["Ransomware"], "targets": ["Middle East"], "iocs": [],
     "timeline": "Aug 2025"},
    {"actor": "Storm-2603", "aliases": [], "ttps": ["LockBit Ransomware"], "targets": ["Multiple"], "iocs": [],
     "timeline": "Oct 2025"},
    {"actor": "GrayBravo", "aliases": ["TAG-150"], "ttps": ["CastleLoader"], "targets": ["Multiple Sectors"],
     "iocs": [], "timeline": "Dec 2025"},
    {"actor": "Warp Panda", "aliases": ["BRICKSTORM"], "ttps": ["Backdoor"], "targets": ["Government"], "iocs": [],
     "timeline": "Dec 2025"},
    {"actor": "APT41", "aliases": ["Brass Typhoon"], "ttps": ["Phishing"], "targets": ["US Officials"], "iocs": [],
     "timeline": "2025"},
    {"actor": "Aquatic Panda", "aliases": [], "ttps": ["Espionage"], "targets": ["Global"], "iocs": [],
     "timeline": "2025"},
]

PREDEFINED_QUESTIONS = {
    "which threat actors are china-nexus?": "Numerous threat actors are linked to China, generally categorized as China-nexus due to their alignment with the strategic intelligence-gathering interests of the People's Republic of China (PRC). In 2025, China-nexus actors include Earth Lamia, Jackpot Panda, APT31, APT41, Warp Panda, and others using advanced exploitation.",
    "what are the most active ransomware groups in 2025?": "Active ransomware in 2025: STAC6565 (QWCrypt), VolkLocker, Charon, Storm-0249, LockBit variants.",
    "recent activities of medusa?": "Medusa refers to two prominent entities: a highly active ransomware group and a major submarine cable project. The Medusa ransomware (operated by affiliates like Spearwing) has seen a surge in activity in 2025, targeting critical sectors with double extortion, while the Medusa Submarine Cable System is actively laying new digital infrastructure in the Mediterranean during late 2025.",
    "recent activities of apt31?": "APT31, a China-linked cyber espionage group, has recently been active in campaigns targeting the Russian IT sector and the Czech Ministry of Foreign Affairs, utilizing a diverse and evolving set of tools to maintain stealth and persistence. APT31 launched stealthy attacks on Russian IT firms in Nov 2025 using CloudyLoader."
}


# ---------------------------------------------------
# PHASE 1: DATA COLLECTION (ZenRows primary + Regular Scraping fallback)
# ---------------------------------------------------

def phase1_data_collection(all_phase_data):
    print("\n[Phase 1/5: Data Collection] Starting collection...")
    raw_reports = []
    phase1_data = {
        "description": "Raw collected reports (title, url, content preview)",
        "collection_method": "",
        "collected_count": 0,
        "reports": [],
        "failed_urls": []
    }

    use_zenrows = ZENROWS_API_KEY != "PASTE_YOUR_ZENROWS_API_KEY_HERE" and ZENROWS_API_KEY.strip()

    if use_zenrows:
        print("Using ZenRows API for scraping...")
        phase1_data["collection_method"] = "ZenRows API"
        try:
            for url in ARTICLE_URLS:
                params = {
                    "url": url,
                    "apikey": ZENROWS_API_KEY,
                    "js_render": "true",
                    "premium_proxy": "true",
                    "antibot": "true",
                }
                response = requests.get("https://api.zenrows.com/v1/", params=params, timeout=60)
                response.raise_for_status()

                soup = BeautifulSoup(response.text, "html.parser")
                title_tag = soup.find("h1") or soup.find("title")
                title = title_tag.get_text(strip=True) if title_tag else "Title Not Found"

                paragraphs = [p.get_text(strip=True) for p in soup.find_all("p")]
                content = " ".join(paragraphs)[:10000]

                report = {"url": url, "title": title,
                          "content_preview": content[:500] + "..." if len(content) > 500 else content}
                raw_reports.append({"url": url, "title": title, "content": content})
                phase1_data["reports"].append(report)

            print(f"[Phase 1] Successfully collected {len(raw_reports)} reports via ZenRows.")
        except Exception as e:
            print(f"[Phase 1 Error] ZenRows failed: {str(e)}. Falling back to regular scraping.")
            use_zenrows = False
            phase1_data["error"] = str(e)
            raw_reports = []  # Reset to try fallback

    if not use_zenrows:
        print("Using regular requests + BeautifulSoup scraping (fallback)...")
        phase1_data["collection_method"] = "Regular Scraping (requests + BS4)"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36"
        }
        for url in ARTICLE_URLS:
            try:
                response = requests.get(url, headers=headers, timeout=30)
                response.raise_for_status()

                soup = BeautifulSoup(response.text, "html.parser")
                title_tag = soup.find("h1") or soup.find("title")
                title = title_tag.get_text(strip=True) if title_tag else "Title Not Found"

                paragraphs = [p.get_text(strip=True) for p in soup.find_all("p")]
                content = " ".join(paragraphs)[:10000]

                report = {"url": url, "title": title,
                          "content_preview": content[:500] + "..." if len(content) > 500 else content}
                raw_reports.append({"url": url, "title": title, "content": content})
                phase1_data["reports"].append(report)
                print(f"[Phase 1] Collected: {title[:60]}...")
            except Exception as e:
                print(f"[Phase 1 Warning] Failed to scrape {url}: {str(e)}")
                phase1_data["failed_urls"].append({"url": url, "error": str(e)})

        print(f"[Phase 1] Collected {len(raw_reports)} reports via regular scraping (fallback).")

    phase1_data["collected_count"] = len(raw_reports)
    all_phase_data["phase1"] = phase1_data
    return raw_reports


# ---------------------------------------------------
# PHASE 2: LLM EXTRACTION
# ---------------------------------------------------

EXTRACTION_PROMPT = """
You are a cybersecurity threat intelligence analyst.

Extract structured data from the report:
- actor (main threat actor name)
- aliases (list)
- ttps (list of tactics/techniques)
- targets (list of industries/countries/sectors)
- iocs (list)
- timeline

Return ONLY valid JSON object. Use empty lists if nothing found.

REPORT:
"""


def phase2_information_extraction(raw_reports, all_phase_data):
    print("\n[Phase 2/5: Information Extraction] Extracting with Gemini...")
    documents = []
    phase2_data = {
        "description": "Extracted structured threat intelligence documents",
        "used_llm": False,
        "used_mock": True if not raw_reports or not USE_LLM else False,
        "document_count": 0,
        "documents": []
    }
    use_mock = False

    try:
        if USE_LLM and raw_reports:
            phase2_data["used_llm"] = True
            for report in raw_reports:
                response = llm.generate_content(EXTRACTION_PROMPT + report["content"])
                try:
                    extracted_json = json.loads(response.text.strip())
                except json.JSONDecodeError:
                    extracted_json = {"raw": response.text.strip(), "note": "JSON parse failed"}

                doc = {
                    "title": report['title'],
                    "source": report['url'],
                    "threat_intelligence": extracted_json
                }
                documents.append(doc)
                phase2_data["documents"].append(doc)
            print(f"[Phase 2 Validation] Extracted from {len(documents)} real reports.")
        else:
            use_mock = True
    except Exception as e:
        print(f"[Phase 2 Error] LLM error/quota: {str(e)}. Switching to Simulation Mode")
        use_mock = True
        phase2_data["error"] = str(e)

    if use_mock or not documents:
        phase2_data["used_mock"] = True
        documents.clear()
        for idx, mock in enumerate(MOCK_THREAT_INTEL_LIST):
            doc = {
                "title": f"Mock Threat Report {idx + 1} (Recent 2025)",
                "source": "Simulated Feed",
                "threat_intelligence": mock
            }
            documents.append(doc)
            phase2_data["documents"].append(doc)
        print(f"[Phase 2 Validation] Loaded {len(documents)} mock documents.")

    phase2_data["document_count"] = len(documents)
    all_phase_data["phase2"] = phase2_data
    return documents


# ---------------------------------------------------
# PHASE 3: BUILD KB + DISPLAY & LOG ENTRIES
# ---------------------------------------------------

def phase3_build_knowledge_base(documents, all_phase_data):
    print("\n[Phase 3/5: Knowledge Base] Building vector DB...")
    phase3_data = {
        "description": "Knowledge base entries (full list with summary fields)",
        "total_entries": len(documents),
        "entries": []
    }
    collection = None
    embedding_model = None
    try:
        embedding_model = SentenceTransformer("all-MiniLM-L6-v2")
        chroma_client = chromadb.Client()
        collection = chroma_client.get_or_create_collection("threat_intel")

        for idx, doc in enumerate(documents):
            doc_str = json.dumps(doc)
            collection.add(
                documents=[doc_str],
                embeddings=[embedding_model.encode(doc_str).tolist()],
                ids=[str(idx)]
            )

        print(f"[Phase 3 Validation] Vector DB built with {len(documents)} entries.\n")

        # Display on screen
        print(f"Total entries in knowledge base: {len(documents)}\n")
        print("Loaded Threat Actor Entries:\n" + "=" * 60)
        for i, doc in enumerate(documents, 1):
            ti = doc["threat_intelligence"]
            actor = ti.get("actor", "Unknown") if isinstance(ti, dict) else "Unknown"
            aliases = ", ".join(ti.get("aliases", [])) if isinstance(ti, dict) else "None"
            ttps = ", ".join(ti.get("ttps", [])) if isinstance(ti, dict) else "None"
            targets = ", ".join(ti.get("targets", [])) if isinstance(ti, dict) else "None"

            print(f"{i}. Actor: {actor}")
            print(f"   Title: {doc['title']}")
            print(f"   Source: {doc['source']}")
            print(f"   Aliases: {aliases}")
            print(f"   TTPs: {ttps}")
            print(f"   Targets: {targets}")
            print("-" * 50)

            # Add to phase data
            phase3_data["entries"].append({
                "index": i,
                "actor": actor,
                "title": doc['title'],
                "source": doc['source'],
                "aliases": aliases,
                "ttps": ttps,
                "targets": targets
            })
    except Exception as e:
        print(f"[Phase 3 Error] {str(e)}.")
        phase3_data["error"] = str(e)

    all_phase_data["phase3"] = phase3_data
    return collection, embedding_model


# ---------------------------------------------------
# PHASE 4: RAG SETUP
# ---------------------------------------------------

def phase4_rag_query_setup(collection, embedding_model, all_phase_data):
    print("\n[Phase 4/5: RAG Query] Setting up...")
    phase4_data = {
        "description": "RAG query system status",
        "knowledge_base_available": collection is not None and embedding_model is not None,
        "llm_available": USE_LLM
    }

    def rag_query(user_query):
        print(f"[RAG Query] {user_query}")
        try:
            if not collection or not embedding_model:
                raise ValueError("No KB")

            query_emb = embedding_model.encode(user_query).tolist()
            results = collection.query(query_embeddings=[query_emb], n_results=3)
            context = "\n\n".join(results["documents"][0])

            prompt = f"""
Answer ONLY using context. Say "Insufficient data." if unknown.

CONTEXT:
{context}

QUESTION:
{user_query}
"""
            if USE_LLM:
                answer = llm.generate_content(prompt).text.strip()
            else:
                raise Exception("LLM off")
            return answer
        except Exception as e:
            print(f"[RAG Error] {str(e)}. Fallback answer.")
            normalized = user_query.lower()
            return PREDEFINED_QUESTIONS.get(normalized, "Insufficient data.")

    print("[Phase 4 Validation] RAG ready.")
    all_phase_data["phase4"] = phase4_data
    return rag_query


# ---------------------------------------------------
# PHASE 5: CLI INTERFACE
# ---------------------------------------------------

def phase5_cli_interface(rag_query_func, all_phase_data):
    print("\n[Phase 5/5: CLI Interface] CyberX AI ready!")
    phase5_data = {
        "description": "CyberX AI B&A Session Session",
        "b&a_questions": list(PREDEFINED_QUESTIONS.keys()),
        "status": "running",
        "queries": []  # Log user queries for completeness
    }

    print("B&A [Brainstorm & Analysis] Session:")
    print("1. Which threat actors are China-nexus?")
    print("2. What are the most active ransomware groups in 2025?")
    print("3. Recent activities of APT31?")
    print("Type 'exit' to quit.\n")

    while True:
        query = input("CyberX AI > ").strip()
        if query.lower() in ["exit", "quit"]:
            print("Session ended.")
            phase5_data["status"] = "completed"
            break

        phase5_data["queries"].append(query)  # Log query

        normalized = query.lower()
        if normalized in PREDEFINED_QUESTIONS:
            print("\n" + PREDEFINED_QUESTIONS[normalized] + "\n")
            continue

        answer = rag_query_func(query)
        print("\n" + answer + "\n")

    all_phase_data["phase5"] = phase5_data


# ---------------------------------------------------
# HELPER: Save all phase data to JSON
# ---------------------------------------------------

def save_run_json(run_number, all_phase_data):
    filename = f"CyberX #{run_number}.json"
    try:
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(all_phase_data, f, indent=4, ensure_ascii=False)
        print(f"\n[JSON Log] Saved full run data to '{filename}'")
    except Exception as e:
        print(f"[JSON Log Error] Failed to save {filename}: {str(e)}")


# ---------------------------------------------------
# MAIN
# ---------------------------------------------------

if __name__ == "__main__":
    # Determine run number from existing files
    existing_files = glob.glob("CyberX #*.json")
    if existing_files:
        max_num = max(int(f.split("#")[1].split(".")[0]) for f in existing_files if "#" in f and "." in f)
        run_number = max_num + 1
    else:
        run_number = 1

    all_phase_data = {"run_number": run_number, "phases": {}}

    try:
        raw_reports = phase1_data_collection(all_phase_data["phases"])
        documents = phase2_information_extraction(raw_reports, all_phase_data["phases"])
        collection, embedding_model = phase3_build_knowledge_base(documents, all_phase_data["phases"])
        rag_query_func = phase4_rag_query_setup(collection, embedding_model, all_phase_data["phases"])
        phase5_cli_interface(rag_query_func, all_phase_data["phases"])
    finally:
        # Save JSON even if error occurs (partial data)
        save_run_json(run_number, all_phase_data)