"""
agents/research_agent.py

AI Research Agent — AGENT-RS-01

Responsibilities:
  - Search and store CVE threat intelligence automatically
  - Use RAG pattern: retrieve relevant docs, then pass to LLM as context
  - Feed Sentinel with known threat patterns before detection happens
  - Run autonomously in background every 60 seconds

RAG flow:
  New threat query
      → search VectorStore for similar CVEs
      → pass retrieved CVEs as context to LLM
      → LLM gives grounded analysis (no hallucination)
      → result sent to Sentinel + broadcast to all agents
"""

import time
import json
from agents.base_agent import BaseAgent
from rag.vector_store import VectorStore
from rag.vectorless_store import VectorlessStore
from logger import log_info, log_threat, log_error, log_allowed


RESEARCH_PROMPT = """You are an AI Security Research Agent for NFTCipher.

Your job is to analyze threat intelligence based ONLY on provided CVE data.
Never speculate beyond the provided documents.
Always reference specific CVE IDs in your analysis.
Respond with JSON only."""


class AIResearchAgent(BaseAgent):

    # Seed CVE data loaded at startup
    # In production this would be pulled from NVD API or MITRE feeds
    SEED_CVES = [
        {
            "id":       "CVE-2024-3094",
            "desc":     "XZ Utils backdoor — malicious code injected into liblzma. Affects SSH on systemd Linux. CVSS 10.0. Supply chain attack.",
            "severity": "CRITICAL",
            "tags":     ["supply-chain", "backdoor", "linux", "ssh"],
        },
        {
            "id":       "CVE-2024-21762",
            "desc":     "Fortinet FortiOS out-of-bounds write allows remote code execution without authentication. Actively exploited in the wild. CVSS 9.8.",
            "severity": "CRITICAL",
            "tags":     ["rce", "fortinet", "network", "no-auth"],
        },
        {
            "id":       "CVE-2024-1709",
            "desc":     "ConnectWise ScreenConnect authentication bypass. Mass exploitation observed. CVSS 10.0. Remote takeover possible.",
            "severity": "CRITICAL",
            "tags":     ["auth-bypass", "remote-access", "mass-exploit"],
        },
        {
            "id":       "CVE-2023-44487",
            "desc":     "HTTP/2 Rapid Reset DDoS attack. Affects nginx, Apache, IIS, cloud providers. CVSS 7.5. Can crash servers with minimal traffic.",
            "severity": "HIGH",
            "tags":     ["ddos", "http2", "nginx", "apache", "denial-of-service"],
        },
        {
            "id":       "CVE-2023-20198",
            "desc":     "Cisco IOS XE web UI privilege escalation zero-day. Creates admin accounts without authentication. CVSS 10.0.",
            "severity": "CRITICAL",
            "tags":     ["privilege-escalation", "cisco", "zero-day", "network-device"],
        },
        {
            "id":       "CVE-2024-0519",
            "desc":     "Google Chrome V8 JavaScript engine heap corruption. Used in targeted attacks. Out-of-bounds memory access.",
            "severity": "HIGH",
            "tags":     ["browser", "chrome", "v8", "heap-corruption", "targeted"],
        },
        {
            "id":       "CVE-2024-4577",
            "desc":     "PHP CGI argument injection on Windows systems. Remote code execution without authentication. CVSS 9.8. Easy to exploit.",
            "severity": "CRITICAL",
            "tags":     ["php", "rce", "windows", "cgi", "no-auth"],
        },
        {
            "id":       "CVE-2024-38094",
            "desc":     "Microsoft SharePoint remote code execution. Authenticated attacker can execute arbitrary code on server. CVSS 8.8.",
            "severity": "HIGH",
            "tags":     ["microsoft", "sharepoint", "rce", "authenticated"],
        },
        {
            "id":       "CVE-2024-27198",
            "desc":     "JetBrains TeamCity authentication bypass. Full server takeover possible. Mass exploitation by APT groups. CVSS 9.8.",
            "severity": "CRITICAL",
            "tags":     ["auth-bypass", "teamcity", "cicd", "supply-chain", "apt"],
        },
        {
            "id":       "CVE-2024-6387",
            "desc":     "OpenSSH regreSSHion — race condition in signal handler allows unauthenticated RCE as root. Affects glibc Linux. CVSS 8.1.",
            "severity": "CRITICAL",
            "tags":     ["openssh", "rce", "race-condition", "linux", "root"],
        },
    ]

    def __init__(self):
        super().__init__(
            agent_id      = "AGENT-RS-01",
            role          = "AI Research",
            system_prompt = RESEARCH_PROMPT,
        )

        # Primary vector store — semantic CVE search
        self.vector_store = VectorStore(
            collection_name = "cve_database",
            db_path         = "./chroma_db",
        )

        # Fast cache — recently queried threats for instant lookup
        self.fast_cache = VectorlessStore()

        # Track research results in memory
        self._research_history: list = []
        self._intel_added_count: int = 0

        # Load initial CVE database
        self._seed_database()

        log_info(f"[Research] Agent ready | DB size: {self.vector_store.count()} CVEs")

    # ── BACKGROUND CYCLE ──────────────────────────────────
    def run_cycle(self):
        """
        Runs every 60 seconds automatically.
        Simulates pulling from a live threat feed.
        In production, replace simulation with real NVD or MITRE API calls.
        FIXED: Now also runs a background search so RAG Intelligence tab
               shows recent searches instead of 'No searches yet'.
        """
        log_info("[Research] Background cycle — checking for new threat intel")

        # Simulate receiving a new threat from an external feed
        # In production: call NVD API, MITRE ATT&CK API, or VirusTotal
        simulated_new = self._simulate_threat_feed()

        if simulated_new:
            self.vector_store.add(
                doc_id   = simulated_new["id"],
                content  = f"{simulated_new['id']} {simulated_new['desc']} {simulated_new['severity']}",
                metadata = simulated_new,
            )
            self._intel_added_count += 1

            # Cache in Redis for fast lookup
            self.fast_cache.set(
                key          = f"cve:latest:{simulated_new['id']}",
                value        = simulated_new,
                ttl_seconds  = 3600,
            )

            log_info(f"[Research] New intel added: {simulated_new['id']}")

        # ── FIXED: Run a background search so history tab shows activity ──
        # Rotate through common threat queries each cycle
        import random
        _AUTO_QUERIES = [
            "brute force authentication attack",
            "SQL injection vulnerability",
            "token hijacking replay attack",
            "API rate limiting flooding",
            "lateral movement privilege escalation",
            "data exfiltration large transfer",
            "quantum cryptography bypass",
            "agent anomaly detection pattern",
        ]
        bg_query = random.choice(_AUTO_QUERIES)
        try:
            bg_result = self.search_threats(bg_query, top_k=2)
            log_info(f"[Research] Background search: '{bg_query}' → {len(bg_result.get('relevant_cves', []))} CVEs")
        except Exception as e:
            # Fallback: just log to history without full search
            self._research_history.append({
                "query":         bg_query,
                "threat_level":  "UNKNOWN",
                "results_count": 0,
                "timestamp":     time.time(),
            })
            if len(self._research_history) > 50:
                self._research_history = self._research_history[-50:]
            log_error(f"[Research] Background search error: {e}")

        # Broadcast status to all agents
        self.broadcast("INFO", {
            "event":       "RESEARCH_CYCLE",
            "agent_id":    self.agent_id,
            "db_size":     self.vector_store.count(),
            "new_intel":   simulated_new["id"] if simulated_new else None,
            "total_added": self._intel_added_count,
            "timestamp":   time.time(),
        })

    def _simulate_threat_feed(self) -> dict | None:
        """
        Simulates a threat intel feed response.
        Replace this method with real API calls in production:
          - NVD: https://services.nvd.nist.gov/rest/json/cves/2.0
          - MITRE ATT&CK: https://attack.mitre.org/
          - AlienVault OTX: https://otx.alienvault.com/api/v1/pulses/subscribed
        """
        import random
        # Only add new intel 30% of the time to avoid flooding
        if random.random() > 0.30:
            return None

        fake_id = f"CVE-2024-{int(time.time()) % 99999:05d}"

        # Check if already exists
        if self.fast_cache.exists(f"cve:latest:{fake_id}"):
            return None

        return {
            "id":       fake_id,
            "desc":     f"Simulated threat intel from background feed at {int(time.time())}. New vulnerability pattern detected in authentication layer.",
            "severity": random.choice(["HIGH", "CRITICAL", "MEDIUM"]),
            "tags":     ["auto-detected", "feed"],
            "source":   "simulated_feed",
        }

    # ── SEEDING ────────────────────────────────────────────
    def _seed_database(self):
        """Load initial CVE data into the vector store at startup."""
        for cve in self.SEED_CVES:
            content = f"{cve['id']} {cve['desc']} severity:{cve['severity']} tags:{' '.join(cve['tags'])}"
            self.vector_store.add(
                doc_id   = cve["id"],
                content  = content,
                metadata = cve,
            )
        log_info(f"[Research] Database seeded with {len(self.SEED_CVES)} CVEs")

    # ── CORE RAG SEARCH ────────────────────────────────────
    def search_threats(self, query: str, top_k: int = 3) -> dict:
        """
        Main RAG function — retrieve + generate.

        Step 1: Retrieve relevant CVEs from VectorStore using semantic search
        Step 2: Build a grounded prompt with those CVEs as context
        Step 3: LLM analyzes using only the provided context — no hallucination
        Step 4: Return result + cache it for fast future lookup

        Called by Sentinel when it detects something suspicious.
        """
        log_info(f"[Research] Searching threat intel: {query[:60]}")

        # Check fast cache first — avoid duplicate searches
        cache_key = f"research:query:{hash(query) % 999999}"
        cached    = self.fast_cache.get(cache_key)
        if cached:
            log_info(f"[Research] Cache hit for query")
            return cached

        # Step 1 — Retrieve relevant CVEs
        relevant_docs = self.vector_store.search(query, top_k=top_k)

        if not relevant_docs:
            return {
                "query":         query,
                "retrieved":     [],
                "threat_level":  "UNKNOWN",
                "recommendation":"No matching CVEs found in database",
                "db_size":       self.vector_store.count(),
                "timestamp":     time.time(),
            }

        # Step 2 — Build grounded context from retrieved docs
        context_lines = []
        for doc in relevant_docs:
            meta  = doc.get("metadata", {})
            score = doc.get("score", 0)
            context_lines.append(
                f"- {meta.get('id', 'UNKNOWN')} [{meta.get('severity', '?')}] "
                f"(relevance={score:.2f}): {meta.get('desc', '')}"
            )
        context = "\n".join(context_lines)

        # Step 3 — Grounded LLM analysis
        prompt = f"""You are a cybersecurity researcher. Analyze ONLY using the CVEs listed below.
Do not reference any CVEs not in this list.
Do not speculate beyond what the CVE descriptions state.

RETRIEVED CVEs (most relevant to query):
{context}

QUERY: {query}

Respond with JSON only:
{{
  "relevant_cves":       ["CVE-ID-1", "CVE-ID-2"],
  "threat_level":        "CRITICAL" or "HIGH" or "MEDIUM" or "LOW" or "NONE",
  "applies_to_system":   true or false,
  "confidence":          <float 0.0-1.0>,
  "recommendation":      "specific one-line action based on CVE data",
  "cited_cve_count":     <int>
}}"""

        response = self._call_llm(prompt)

        # Build result
        result = {
            "query":        query,
            "retrieved":    [d.get("metadata", {}) for d in relevant_docs],
            "retrieved_count": len(relevant_docs),
            "db_size":      self.vector_store.count(),
            "timestamp":    time.time(),
        }

        if response:
            try:
                raw = response.replace("```json", "").replace("```", "").strip()
                if "{" in raw:
                    raw = raw[raw.index("{") : raw.rindex("}") + 1]
                parsed = json.loads(raw)
                result.update(parsed)
            except Exception as e:
                log_error(f"[Research] LLM parse error: {e}")
                result["threat_level"]   = "UNKNOWN"
                result["recommendation"] = "Parse error — check retrieved CVEs manually"
        else:
            # LLM unavailable — return raw retrieved data
            result["threat_level"]   = "UNKNOWN"
            result["recommendation"] = f"LLM unavailable — {len(relevant_docs)} CVEs retrieved, review manually"

        # Cache result for 10 minutes
        self.fast_cache.set(cache_key, result, ttl_seconds=600)

        # Save to history
        self._research_history.append({
            "query":         query,
            "threat_level":  result.get("threat_level", "UNKNOWN"),
            "results_count": len(relevant_docs),
            "timestamp":     time.time(),
        })
        if len(self._research_history) > 50:
            self._research_history = self._research_history[-50:]

        # Broadcast research result
        self.broadcast("INFO", {
            "event":        "RESEARCH_RESULT",
            "agent_id":     self.agent_id,
            "query":        query[:60],
            "threat_level": result.get("threat_level", "UNKNOWN"),
            "cves_found":   len(relevant_docs),
            "timestamp":    time.time(),
        })

        log_info(f"[Research] Result: threat_level={result.get('threat_level')} | cves={len(relevant_docs)}")
        return result

    # ── MANUAL INTEL ADDITION ──────────────────────────────
    def add_threat_intel(self, cve_id: str, description: str,
                         severity: str = "HIGH", tags: list = None) -> dict:
        """
        Manually add new threat intel to the database.
        Called from the API endpoint /research/add-intel
        """
        tags    = tags or []
        content = f"{cve_id} {description} severity:{severity} tags:{' '.join(tags)}"

        self.vector_store.add(
            doc_id   = cve_id,
            content  = content,
            metadata = {
                "id":       cve_id,
                "desc":     description,
                "severity": severity,
                "tags":     tags,
                "added_by": "api",
                "added_at": time.time(),
            },
        )

        # Also cache in fast store
        self.fast_cache.set(
            key         = f"cve:manual:{cve_id}",
            value       = {"id": cve_id, "desc": description, "severity": severity},
            ttl_seconds = 86400,
        )

        self._intel_added_count += 1
        log_allowed(f"[Research] Manual intel added: {cve_id} | severity={severity}")

        return {
            "added":    cve_id,
            "severity": severity,
            "db_size":  self.vector_store.count(),
        }

    # ── CONTEXT FOR OTHER AGENTS ───────────────────────────
    def get_context_for_threat(self, flags: list, evidence: dict) -> str:
        """
        Called by Sentinel or ThreatDetection to get research context.
        Converts flags + evidence into a search query automatically.
        Returns a formatted string ready to inject into an LLM prompt.
        """
        # Build a query from flags and evidence
        query_parts = []
        for flag in flags:
            query_parts.append(flag.replace("_", " ").lower())
        if evidence.get("rpm", 0) > 30:
            query_parts.append("high request rate flooding attack")
        if evidence.get("failed_attempts", 0) > 5:
            query_parts.append("brute force authentication attack")
        if evidence.get("data_mb", 0) > 50:
            query_parts.append("data exfiltration large transfer")

        query  = " ".join(query_parts) or "general security threat"
        result = self.search_threats(query, top_k=2)

        if result.get("relevant_cves"):
            return (
                f"Related CVEs: {result['relevant_cves']} | "
                f"Threat level: {result.get('threat_level')} | "
                f"Recommendation: {result.get('recommendation', 'N/A')}"
            )
        return "No matching CVEs found for this pattern"


    def handle_query(self, question: str, context: dict = None) -> dict:
        """
        Handle a direct question from another agent via ask_agent().

        Called by Suggestion Engine (through Sentinel's ask_agent()) when a
        confirmed threat needs CVE research. Routes to search_threats() with
        an enriched query that includes the detected flags and agent ID.

        Args:
            question : natural language question about the threat
            context  : dict may include — thread_id, flags, agent_id, threat_level

        Returns:
            dict — search_threats() result: relevant_cves, threat_level,
                   recommendation, retrieved CVE list
        """
        context = context or {}
        log_info(
            f"[Research] handle_query() | "
            f"thread={context.get('thread_id', '?')} | from=SuggestionEngine"
        )

        # Enrich the question with flags and agent_id from context
        # so search_threats() finds more specific CVE matches
        flags    = context.get("flags", [])
        agent_id = context.get("agent_id", "")

        enriched_query = question
        if flags:
            enriched_query += f" Observed flags: {', '.join(flags)}."
        if agent_id:
            enriched_query += f" Affected agent: {agent_id}."

        # search_threats() does RAG — retrieves CVEs then LLM analysis
        result = self.search_threats(enriched_query, top_k=3)

        log_info(
            f"[Research] handle_query() answered | "
            f"CVEs={result.get('relevant_cves', [])} | "
            f"level={result.get('threat_level', '?')}"
        )
        return result

    # ── STATUS ────────────────────────────────────────────
    def get_status(self) -> dict:
        base = super().get_status()
        base.update({
            "db_size":          self.vector_store.count(),
            "intel_added":      self._intel_added_count,
            "research_count":   len(self._research_history),
            "rag_enabled":      True,
            "vector_store":     self.vector_store.get_status(),
            "cache_status":     self.fast_cache.get_status(),
        })
        return base