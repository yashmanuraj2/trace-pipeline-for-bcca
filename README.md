# TRACE: Artifact & Code Repository (Anonymous Peer Review)

**Paper Title:** TRACE: A Continuous Big Data Pipeline for Asynchronous AI-Ready Audit Trails, Provenance, and Trust in Decentralized Compliance.
**Track:** Short Paper / Measurement Study

## 📌 Artifact Overview
This repository contains the core execution engine and aggregation pipelines for **TRACE**. 

**Note on Executability:** To comply with strict enterprise security policies and non-disclosure requirements regarding live compliance nodes, the database connection layer (`db.js`), proprietary environment configurations, and raw 10TB mainnet data dumps have been omitted. 

This artifact is provided for **methodological verification**. It allows the peer-review committee to directly audit our topological query formalizations, stream-processing logic, and the architectural design claims made in the manuscript.

## 📂 File Manifest & Architecture

| File | Primary Function | Relevance to Paper |
| :--- | :--- | :--- |
| `address_loader.js` | Asynchronous Ledger Ingestion | Demonstrates the $O(1)$ Redis deduplication and the strict finality trailing depth (chain-reorg protection). |
| `combined_fatf_rules.js` | Topology-Aware Formalizations | Contains the exact MongoDB aggregation pipelines that map FATF typologies to Account/UTXO structures. |
| `tagging_worker.js` | Stateful Audit Trail Generation | Contains the logic for the Historical State Merger, generating the deterministic `first_detected_at` bounds. |
| `cron_job.js` | Non-blocking Daemon execution | The continuous event loop that executes the telemetry logging for the 4.0x UTXO penalty benchmark. |

---

## 🔍 Mapping Code to the Manuscript's Claims

Reviewers are encouraged to cross-reference the following claims from the manuscript with the codebase:

### 1. Adversarial Robustness & Reorg Protection (Section III-A)
* **Claim:** TRACE enforces a strict finality trailing depth (e.g., lagging 6 blocks behind Bitcoin, 64 blocks behind Ethereum) to prevent the ingestion of transient/orphaned blocks.
* **Code Verification:** In `address_loader.js`, observe the `$match` aggregations utilizing the `$lte` operator to mathematically bound the ingestion window behind the chain tip.

### 2. O(1) In-Memory Deduplication (Section III-A)
* **Claim:** The pipeline relies on volatile in-memory queues with atomic set-add primitives.
* **Code Verification:** In `address_loader.js`, observe the use of `redis.multi()` and `pipeline.sAdd()` batched across 20,000 iterations to prevent memory pressure during mainnet spikes.

### 3. Formalized Typologies & The 23.4x Data Bloat Tax (Section III-B & IV-A)
* **Claim:** The system evaluates transactions against a dynamic matrix of national thresholds. Zero-threshold jurisdictions generate extensive extended liability. 
* **Code Verification:** In `combined_fatf_rules.js`, review the `JURISDICTION_CONFIG` constant. It defines the `$1,000` FATF Baseline alongside the `$0` EU TFR thresholds. The pipelines dynamically inject an `obligation_tier` marker based on these constants. 

### 4. The 4.0x UTXO Latency Penalty (Section IV-C)
* **Claim:** UTXO tracking imposes a fundamental graph-theoretic constraint, requiring structurally heavier queries than Account models.
* **Code Verification:** Compare `btc_large_deposit_followed_by_immediate_withdrawl` with `eth_large_deposit_followed_by_immediate_withdrawl` in `combined_fatf_rules.js`. Notice how the BTC (UTXO) pipeline must execute complex nested `$map`, `$filter`, and `$reduce` arrays over the `tx_details.inputs` and `outputs`, illustrating the bipartite mapping penalty compared to Ethereum's simple edge traversals. 

### 5. Historical State Merger (Section IV-B)
* **Claim:** The system actively merges historical risk scores to create dense provenance graphs.
* **Code Verification:** In `tagging_worker.js`, review the `processAddress()` function. Observe how it queries the persistent state, evaluates `getHighestRiskScore()`, and utilizes MongoDB's `$setOnInsert` and `$set` commands to accurately maintain the `first_detected_at` and `last_seen_at` temporal boundaries.
