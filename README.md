# CyberX AI

**AI-Powered Threat Actor Intelligence Tracker**

CyberX AI is a modular, end-to-end cybersecurity threat intelligence pipeline that collects, extracts, enriches, and queries threat-actor data from public security reports. It combines automated web scraping, large language model (LLM)–based information extraction, vector similarity search, and a Retrieval-Augmented Generation (RAG) query interface, with robust fallback mechanisms for API limits and offline simulation.

---

## Overview

CyberX AI is designed to demonstrate the complete lifecycle of modern threat intelligence processing, including:

* Collection of real-world threat reports
* Structured intelligence extraction
* Knowledge base construction using embeddings
* Context-aware querying via RAG
* CLI-based analyst interaction
* Deterministic fallback using mock intelligence when live services are unavailable

The system is well-suited for academic projects, security prototypes, demonstrations, and constrained environments where API quotas or scraping limitations exist.

---

## Key Capabilities

* **Hybrid Data Collection**

  * Primary: ZenRows API (anti-bot, JavaScript-rendered scraping)
  * Fallback: Direct `requests + BeautifulSoup` scraping

* **LLM-Based Intelligence Extraction**

  * Uses Google Gemini (`gemini-pro`) for structured threat intelligence extraction

* **Simulation-First Architecture**

  * Automatically switches to curated mock intelligence when LLM quota or network access is unavailable

* **Vector Knowledge Base**

  * SentenceTransformer-based embeddings
  * ChromaDB-backed vector similarity search

* **RAG-Based Analyst Querying**

  * Context-aware answers grounded in collected intelligence
  * Deterministic fallback answers for predefined analyst questions

* **Comprehensive Execution Logging**

  * Each run generates a versioned JSON audit log (`CyberX #N.json`)

---

## Architecture

```
Phase 1 ─ Data Collection
        ├─ ZenRows API (Primary)
        └─ Requests + BeautifulSoup (Fallback)

Phase 2 ─ Threat Intelligence Extraction
        ├─ Gemini LLM (Primary)
        └─ Mock Intelligence Dataset (Fallback)

Phase 3 ─ Knowledge Base Construction
        └─ SentenceTransformer + ChromaDB

Phase 4 ─ RAG Query System
        ├─ Vector Similarity Search
        └─ LLM Answer Generation / Static Fallback

Phase 5 ─ CLI Analyst Interface
```

---

## Installation

### Prerequisites

* Python 3.9 or higher
* pip package manager

### Dependency Installation

```bash
pip install requests beautifulsoup4 google-generativeai sentence-transformers chromadb
```

---

## Configuration

CyberX AI supports optional environment-based configuration for external services.

### Environment Variables

```bash
export ZENROWS_API_KEY="your_zenrows_api_key"
export GEMINI_API_KEY="your_gemini_api_key"
```

If these variables are not configured or exceed usage limits, the system automatically activates fallback and simulation modes without interrupting execution.

---

## Usage

Run the script directly:

```bash
python CyberX.py
```

On execution, CyberX AI will:

1. Collect threat reports from public sources
2. Extract structured threat intelligence
3. Build a vectorized knowledge base
4. Launch an interactive CLI analysis session
5. Persist all execution data into a versioned JSON log

---

## CLI Interaction

CyberX AI initiates a Brainstorm & Analysis (B&A) session with predefined analyst questions:

1. Which threat actors are China-nexus?
2. What are the most active ransomware groups in 2025?
3. Recent activities of APT31?

Users may also submit custom intelligence queries. If insufficient context is available, the system responds with:

```
Insufficient data.
```

Exit the session using:

```text
exit
```

---

## Fallback and Simulation Logic

CyberX AI is intentionally designed to be resilient and non-blocking.

| Component  | Primary Mode | Fallback Mode             |
| ---------- | ------------ | ------------------------- |
| Scraping   | ZenRows API  | Requests + BS4            |
| Extraction | Gemini LLM   | Curated Mock Dataset      |
| Querying   | RAG + LLM    | Static Predefined Answers |

This ensures consistent execution in free-tier, offline, or restricted environments.

---

## Output Artifacts

Each execution generates a uniquely versioned JSON file:

```
CyberX #1.json
CyberX #2.json
...
```

### JSON Contents

* Phase-wise execution metadata
* Collected report summaries
* Extracted threat intelligence
* Knowledge base entries
* Analyst queries and session status

These artifacts support auditing, evaluation, and academic submission requirements.

---

## Intended Use Cases

* Cyber threat intelligence demonstrations
* Security research prototypes
* Academic coursework and capstone projects
* Retrieval-Augmented Generation (RAG) system examples
* API-resilient AI pipeline design

---

## Limitations

* Not intended for production SOC deployment
* Intelligence quality depends on public reporting and LLM output
* Mock intelligence represents simulated data, not live feeds

---

## Ethical and Legal Notice

CyberX AI operates exclusively on publicly available security reporting and simulated datasets. It performs no exploitation activities and is intended strictly for educational, defensive, and research-oriented use.

Users are responsible for ensuring compliance with applicable laws and website terms of service when scraping content.

---

## Code of Conduct

CyberX AI is committed to fostering a respectful, inclusive, and professional environment for all users, contributors, and reviewers.

### Expected Behavior

* Use the project in a lawful, ethical, and responsible manner
* Respect differing viewpoints and constructive feedback
* Maintain professionalism in discussions, reviews, and collaborations
* Credit original sources and avoid misrepresentation of work

### Unacceptable Behavior

* Harassment, discrimination, or abusive conduct of any kind
* Misuse of the system for malicious, exploitative, or illegal activities
* Presenting simulated or mock intelligence as verified real-world data
* Attempting to bypass safeguards, rate limits, or ethical boundaries

Violations of this Code of Conduct may result in restriction of access or usage at the discretion of the project owner.

---

## Usage Policy

CyberX AI is intended strictly for **educational, research, and defensive cybersecurity purposes**.

### Permitted Use

* Academic coursework, capstone projects, and demonstrations
* Security research and threat intelligence learning
* Prototyping Retrieval-Augmented Generation (RAG) systems
* Controlled simulations and offline demonstrations

### Prohibited Use

* Offensive or malicious cyber operations
* Real-world exploitation, intrusion, or unauthorized surveillance
* Deployment as an operational threat intelligence feed without validation
* Misrepresentation of outputs as verified or real-time intelligence

### Data Integrity Notice

* Public reports are processed automatically and may contain inaccuracies
* LLM-generated outputs are probabilistic and must be independently validated
* Mock data is simulated and clearly marked for fallback or demonstration use

By using CyberX AI, you acknowledge and agree to comply with this Usage Policy and all applicable local and international laws.
