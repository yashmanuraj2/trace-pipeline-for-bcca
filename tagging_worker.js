// tagging_worker.js
// FATF tagging with integrated Travel Rule (TR) detection
// Multi-Jurisdiction Engine with Historical State Merging + Parallel DB7 Replication

const pLimit = require("p-limit").default || require("p-limit");
const { redis, db1Connection, db3Connection, db4Connection, db7Connection } = require("./db");
const {
  JURISDICTION_CONFIG,
  USDT_CONTRACT,

  // ETH FATF
  eth_quick_succession_high_value_transaction, eth_large_deposit_followed_by_immediate_withdrawl, eth_fatf_low_value_transactions, eth_combined_rule_for_flagged_addresses, eth_fatf_whale_in, eth_fatf_whale_out,
  eth_tr_threshold_breach_known_vasp, eth_tr_unhosted_wallet_large_transfer, eth_tr_sanctions_hit, eth_tr_structuring_smurfing, eth_tr_low_confidence_vasp, eth_tr_cross_vasp_layering,
  
  // TRON FATF
  tron_quick_succession_high_value_transaction, tron_large_deposit_followed_by_immediate_withdrawl, tron_fatf_low_value_transactions, tron_combined_rule_for_flagged_addresses, tron_fatf_whale_in, tron_fatf_whale_out,
  tron_tr_threshold_breach_known_vasp, tron_tr_unhosted_wallet_large_transfer, tron_tr_sanctions_hit, tron_tr_structuring_smurfing, tron_tr_low_confidence_vasp, tron_tr_cross_vasp_layering,
  
  // BTC FATF
  btc_quick_succession_high_value_pass_transaction, btc_large_deposit_followed_by_immediate_withdrawl, btc_fatf_low_value_transactions, btc_combined_rule_for_flagged_addresses,
  btc_tr_threshold_breach_known_vasp, btc_tr_unhosted_wallet_large_transfer, btc_tr_sanctions_hit, btc_tr_structuring_smurfing, btc_tr_low_confidence_vasp, btc_tr_cross_vasp_layering,
  
  // ETH ERC-20 USDT
  eth_usdt_quick_succession_high_value_transaction, eth_usdt_large_deposit_followed_by_immediate_withdrawl, eth_usdt_fatf_low_value_transactions, eth_usdt_combined_rule_for_flagged_addresses, eth_usdt_whale_in, eth_usdt_whale_out,
  eth_usdt_tr_threshold_breach_known_vasp, eth_usdt_tr_unhosted_wallet_large_transfer, eth_usdt_tr_sanctions_hit, eth_usdt_tr_structuring_smurfing, eth_usdt_tr_low_confidence_vasp, eth_usdt_tr_cross_vasp_layering,
} = require("./combined_fatf_rules");

// Risk hierarchy for merging states (mild removed)
const RISK_HIERARCHY = { none: 0, low: 1, medium: 2, high: 3 };

function getHighestRiskScore(scores) {
  let highest = "none";
  for (const s of scores) {
    if (RISK_HIERARCHY[s] > RISK_HIERARCHY[highest]) {
      highest = s;
    }
  }
  return highest;
}

function extractEmbeddedTravelRules(fatfRuleResults) {
  const flags = [];
  for (const r of fatfRuleResults) {
    if (Array.isArray(r.result)) {
      for (const item of r.result) {
        if (Array.isArray(item.travel_rule_triggers)) {
          for (const t of item.travel_rule_triggers) {
            flags.push({ flag: t, risk_score: r.risk_score, source_rule: r.name });
          }
        }
        if (typeof item.travel_rule_trigger === "string") {
          flags.push({ flag: item.travel_rule_trigger, risk_score: r.risk_score, source_rule: r.name });
        }
      }
    }
  }
  return flags;
}

// Safely parse MongoDB Long object to JavaScript Number
async function getLatestEthBlock(usdtLogsCollection) {
  const doc = await usdtLogsCollection.find({ address: USDT_CONTRACT }).sort({ block_number: -1 }).limit(1).toArray();
  if (doc.length > 0) {
    const bn = doc[0].block_number;
    return typeof bn === 'object' && bn !== null ? Number(bn.toString()) : Number(bn);
  }
  return 0;
}

// Safely parse MongoDB Long object to JavaScript Number
async function getLatestBtcBlock(btcTxnsCollection) {
  const doc = await btcTxnsCollection.find().sort({ block: -1 }).limit(1).toArray();
  if (doc.length > 0) {
    const bn = doc[0].block;
    return typeof bn === 'object' && bn !== null ? Number(bn.toString()) : Number(bn);
  }
  return 0;
}

// 🚨 CRITICAL FIX: Strictly routes BTC to db3, ETH to db4, and all final replications to db7
function getFatfCollections(coin) {
  let collectionName = "fatf_results";
  let sourceDbConnection;
  
  if (coin === "ETH" || coin === "ETH_USDT") {
    collectionName = "fatf_results_ethereum";
    sourceDbConnection = db4Connection;
  } else if (coin === "BTC") {
    collectionName = "fatf_results_bitcoin";
    sourceDbConnection = db3Connection;
  } else if (coin === "TRX_USDT") {
    collectionName = "fatf_results_tron";
    sourceDbConnection = db1Connection;
  }

  return {
    fatfResults1: sourceDbConnection.db.collection(collectionName),
    fatfResults7: db7Connection.db.collection(collectionName)
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// MAIN AGGREGATION LOOP
// ─────────────────────────────────────────────────────────────────────────────
async function runAggregations() {
  const jurisdictions = Object.keys(JURISDICTION_CONFIG);
  const now = Math.floor(Date.now() / 1000);
  
  const ethTxnsCollection = db4Connection.db.collection("ethereum_transactions_all");
  const usdtLogsCollection = db4Connection.db.collection("ethereum_logs_all");
  const btcTxnsCollection = db3Connection.db.collection("bitcoin_addr_txn_map");
  const tronTxnsCollection = db1Connection.db.collection("tron_token_transfers");
  
  // 🚨 CRITICAL FIX: Alerts strictly routed to DB7 (test_db)
  const alertsCollection = db7Connection.db.collection("compliance_alerts");

  // ── 1. ETH NATIVE QUEUE ──────────────────────────────────────────────
  const _ethT0 = performance.now();
  while (true) {
    const addr = await redis.sPop("addresses:ETH:last24h");
    if (!addr) break;

    const { fatfResults1, fatfResults7 } = getFatfCollections("ETH");

    for (const j of jurisdictions) {
      const fatfRules = [
        { name: "eth_quick_succession", pipeline: eth_quick_succession_high_value_transaction(addr, 10, j) },
        { name: "eth_large_deposit_withdraw", pipeline: eth_large_deposit_followed_by_immediate_withdrawl(addr, j) },
        { name: "eth_fatf_low_value", pipeline: eth_fatf_low_value_transactions(addr, j) },
        { name: "eth_combined_rule_flagged", pipeline: eth_combined_rule_for_flagged_addresses(addr, j) },
        { name: "eth_whale_in", pipeline: eth_fatf_whale_in(addr, 100, j) }, 
        { name: "eth_whale_out", pipeline: eth_fatf_whale_out(addr, 100, j) }
      ];
      const travelRules = [
        { name: "eth_tr_vasp", pipeline: eth_tr_threshold_breach_known_vasp(addr, j) },
        { name: "eth_tr_unhosted", pipeline: eth_tr_unhosted_wallet_large_transfer(addr, j) },
        { name: "eth_tr_sanctions", pipeline: eth_tr_sanctions_hit(addr, j) },
        { name: "eth_tr_structuring", pipeline: eth_tr_structuring_smurfing(addr, j) },
        { name: "eth_tr_low_conf_vasp", pipeline: eth_tr_low_confidence_vasp(addr, j) },
        { name: "eth_tr_cross_vasp", pipeline: eth_tr_cross_vasp_layering(addr, j) }
      ];

      await processAddress({ addr, fatfRules, travelRules, txns: ethTxnsCollection, fatfResults1, fatfResults7, complianceAlerts: alertsCollection, coin: "ETH", now, jurisdiction: j });
    }
  }

  const _ethMs = performance.now() - _ethT0;
  console.log(`[TELEMETRY] ETH  (Account) : ${_ethMs.toFixed(0)}ms`);

  // ── 2. ETH USDT QUEUE ────────────────────────────────────────────────
  const currentEthBlock = await getLatestEthBlock(usdtLogsCollection);
  const _usdtT0 = performance.now();
  while (true) {
    const addr = await redis.sPop("addresses:ETH_USDT:last24h");
    if (!addr) break; 

    const { fatfResults1, fatfResults7 } = getFatfCollections("ETH_USDT");

    for (const j of jurisdictions) {
      const fatfRules = [
        { name: "eth_usdt_quick_succession", pipeline: eth_usdt_quick_succession_high_value_transaction(addr, currentEthBlock, j) },
        { name: "eth_usdt_large_deposit_withdraw", pipeline: eth_usdt_large_deposit_followed_by_immediate_withdrawl(addr, currentEthBlock, j) },
        { name: "eth_usdt_fatf_low_value", pipeline: eth_usdt_fatf_low_value_transactions(addr, currentEthBlock, j) },
        { name: "eth_usdt_combined_rule_flagged", pipeline: eth_usdt_combined_rule_for_flagged_addresses(addr, currentEthBlock, j) },
        { name: "eth_usdt_whale_in", pipeline: eth_usdt_whale_in(addr, 100000, currentEthBlock, j) },
        { name: "eth_usdt_whale_out", pipeline: eth_usdt_whale_out(addr, 100000, currentEthBlock, j) }
      ];
      const travelRules = [
        { name: "eth_usdt_tr_vasp", pipeline: eth_usdt_tr_threshold_breach_known_vasp(addr, currentEthBlock, j) },
        { name: "eth_usdt_tr_unhosted", pipeline: eth_usdt_tr_unhosted_wallet_large_transfer(addr, currentEthBlock, j) },
        { name: "eth_usdt_tr_sanctions", pipeline: eth_usdt_tr_sanctions_hit(addr, currentEthBlock, j) },
        { name: "eth_usdt_tr_structuring", pipeline: eth_usdt_tr_structuring_smurfing(addr, currentEthBlock, j) },
        { name: "eth_usdt_tr_low_conf_vasp", pipeline: eth_usdt_tr_low_confidence_vasp(addr, currentEthBlock, j) },
        { name: "eth_usdt_tr_cross_vasp", pipeline: eth_usdt_tr_cross_vasp_layering(addr, currentEthBlock, j) }
      ];

      await processAddress({ addr, fatfRules, travelRules, txns: usdtLogsCollection, fatfResults1, fatfResults7, complianceAlerts: alertsCollection, coin: "ETH_USDT", now, jurisdiction: j });
    }
  }

  const _usdtMs = performance.now() - _usdtT0;
  console.log(`[TELEMETRY] USDT (ERC-20)  : ${_usdtMs.toFixed(0)}ms`);

  // ── 3. TRON QUEUE — DISABLED ──────────────────────────────────────────
  const _tronMs = 0;
  console.log("[TAGGER] TRON skipped — disabled for this run");

  // ── 4. BTC NATIVE QUEUE ──────────────────────────────────────────────
  const _btcT0 = performance.now();
  const currentBtcBlock = await getLatestBtcBlock(btcTxnsCollection);
  while (true) {
    const addr = await redis.sPop("addresses:BTC:last24h");
    if (!addr) break;

    const { fatfResults1, fatfResults7 } = getFatfCollections("BTC");

    for (const j of jurisdictions) {
      const fatfRules = [
        { name: "btc_quick_succession", pipeline: btc_quick_succession_high_value_pass_transaction(addr, 10, currentBtcBlock, j) },
        { name: "btc_large_deposit_withdraw", pipeline: btc_large_deposit_followed_by_immediate_withdrawl(addr, j) },
        { name: "btc_fatf_low_value", pipeline: btc_fatf_low_value_transactions(addr, j) },
        { name: "btc_combined_rule_flagged", pipeline: btc_combined_rule_for_flagged_addresses(addr, j) }
      ];
      const travelRules = [
        { name: "btc_tr_vasp", pipeline: btc_tr_threshold_breach_known_vasp(addr, j) },
        { name: "btc_tr_unhosted", pipeline: btc_tr_unhosted_wallet_large_transfer(addr, j) },
        { name: "btc_tr_sanctions", pipeline: btc_tr_sanctions_hit(addr, j) },
        { name: "btc_tr_structuring", pipeline: btc_tr_structuring_smurfing(addr, currentBtcBlock, j) },
        { name: "btc_tr_low_conf_vasp", pipeline: btc_tr_low_confidence_vasp(addr, j) },
        { name: "btc_tr_cross_vasp", pipeline: btc_tr_cross_vasp_layering(addr, j) }
      ];

      await processAddress({ addr, fatfRules, travelRules, txns: btcTxnsCollection, fatfResults1, fatfResults7, complianceAlerts: alertsCollection, coin: "BTC", now, jurisdiction: j });
    }
  }

  const _btcMs = performance.now() - _btcT0;
  console.log(`[TELEMETRY] BTC  (UTXO)    : ${_btcMs.toFixed(0)}ms  ← UTXO model`);
  if (_ethMs > 0 && _btcMs > 0) {
    console.log(`[TELEMETRY] UTXO Penalty   : ${(_btcMs / _ethMs).toFixed(2)}x  ← RQ2`);
  }
  return { ethMs: _ethMs, ethUsdtMs: _usdtMs, tronMs: _tronMs, btcMs: _btcMs };
}

// ─────────────────────────────────────────────────────────────────────────────
// HISTORICAL STATE MERGER & DATABASE SAVER
// ─────────────────────────────────────────────────────────────────────────────
async function processAddress({
  addr, fatfRules, travelRules, txns, fatfResults1, fatfResults7, complianceAlerts, coin, now, jurisdiction
}) {
  const fatfRuleResults      = [];
  const standaloneTRResults  = [];

  await Promise.all([
    ...fatfRules.map(async ({ name, pipeline }) => {
      try {
        const result = await txns.aggregate(pipeline, { allowDiskUse: true }).toArray();
        if (result.length) {
          fatfRuleResults.push({ name, risk_score: result[0]?.risk_score || "none", result });
        }
      } catch (err) {
        console.error(`[TAGGER] FATF rule ${name} failed for ${coin}:${addr}`, err);
      }
    }),

    ...travelRules.map(async ({ name, pipeline }) => {
      try {
        const result = await txns.aggregate(pipeline, { allowDiskUse: true }).toArray();
        if (result.length) {
          standaloneTRResults.push({
            flag:         result[0]?.travel_rule_flag || name,
            risk_score:   result[0]?.risk_score || "medium",
            details:      result[0],
            sanctions_hit:result[0]?.sanctions_hit || false,
            jurisdiction: result[0]?.jurisdiction || jurisdiction,
            obligation_tier: result[0]?.obligation_tier || null,
          });
        }
      } catch (err) {
        console.error(`[TAGGER] Travel rule ${name} failed for ${coin}:${addr}`, err);
      }
    }),
  ]);

  const embeddedTR       = extractEmbeddedTravelRules(fatfRuleResults);
  const allTravelRuleFlags = [
    ...embeddedTR,
    ...standaloneTRResults.map((tr) => ({
      flag:         tr.flag,
      risk_score:   tr.risk_score,
      source_rule:  "standalone_tr",
      sanctions_hit:tr.sanctions_hit,
      jurisdiction: tr.jurisdiction,
      obligation_tier: tr.obligation_tier || null,
    })),
  ];

  const seenFlags = new Set();
  const dedupedTRFlags = allTravelRuleFlags.filter((tr) => {
    if (seenFlags.has(tr.flag)) return false;
    seenFlags.add(tr.flag);
    return true;
  });

  const hasTravelRuleFlags = dedupedTRFlags.length > 0;
  const sanctionsHit       = dedupedTRFlags.some((tr) => tr.sanctions_hit || tr.flag === "SANCTIONS_HIT");

  // NRT EXPOSER DEBUG LOGS
  if (coin === "BTC") {
    console.log(`\n[DEBUG BTC] Processing Address: ${addr} (Jurisdiction: ${jurisdiction})`);
    console.log(`   -> FATF Rule Hits  : ${fatfRuleResults.length}`);
    console.log(`   -> Travel Rule Hits: ${dedupedTRFlags.length}`);
    if (fatfRuleResults.length === 0 && !hasTravelRuleFlags) {
      console.log(`   -> ❌ SKIPPED DB SAVE: Queries returned 0 results.`);
    } else {
      console.log(`   -> ✅ SUCCESS: Saving risk score to DB3 (legacy) and DB7 (test_db)!`);
    }
  }

  if (fatfRuleResults.length > 0 || hasTravelRuleFlags) {
    const fatfScores = fatfRuleResults.map((r) => r.risk_score);
    if (sanctionsHit) fatfScores.push("high");
    const newHighestRisk = getHighestRiskScore(fatfScores);

    // Pull existing state from the specific chain's database
    const existingDoc      = await fatfResults1.findOne({ coin, address: addr, jurisdiction });
    const currentRiskScore = existingDoc?.risk_score || "none";
    const shouldUpdate     = RISK_HIERARCHY[newHighestRisk] >= RISK_HIERARCHY[currentRiskScore];
    const finalRiskScore   = shouldUpdate ? newHighestRisk : currentRiskScore;

    const sanitizedRuleDetails = fatfRuleResults.map((r) => {
      let truncatedResult = Array.isArray(r.result) ? r.result.slice(0, 10) : r.result;
      if (Array.isArray(truncatedResult)) {
        truncatedResult = truncatedResult.map(doc => {
          const safeDoc = { ...doc };
          if (Array.isArray(safeDoc.risky_pairs) && safeDoc.risky_pairs.length > 20) {
            safeDoc.risky_pairs = safeDoc.risky_pairs.slice(0, 20);
            safeDoc.truncated_risky_pairs = true;
          }
          if (Array.isArray(safeDoc.data) && safeDoc.data.length > 20) {
            safeDoc.data = safeDoc.data.slice(0, 20);
            safeDoc.truncated_data = true;
          }
          return safeDoc;
        });
      }
      return { rule: r.name, risk_score: r.risk_score, result: truncatedResult };
    });

    let mergedMatchingRules = fatfRuleResults.map((r) => ({ rule: r.name, risk_score: r.risk_score }));
    let mergedRuleDetails   = sanitizedRuleDetails;
    let mergedTRFlags       = dedupedTRFlags;

    if (existingDoc) {
      const rulesMap = new Map();
      (existingDoc.matching_rules || []).forEach(r => rulesMap.set(r.rule, r.risk_score));
      mergedMatchingRules.forEach(r => {
        const existingScore = rulesMap.get(r.rule);
        if (!existingScore || RISK_HIERARCHY[r.risk_score] >= RISK_HIERARCHY[existingScore]) {
          rulesMap.set(r.rule, r.risk_score);
        }
      });
      mergedMatchingRules = Array.from(rulesMap.entries()).map(([rule, risk_score]) => ({ rule, risk_score }));

      const detailsMap = new Map();
      (existingDoc.rule_details || []).forEach(d => detailsMap.set(d.rule, d));
      sanitizedRuleDetails.forEach(d => detailsMap.set(d.rule, d));
      mergedRuleDetails = Array.from(detailsMap.values());

      const trMap = new Map();
      (existingDoc.travel_rule_flags || []).forEach(f => trMap.set(f.flag, f));
      dedupedTRFlags.forEach(f => trMap.set(f.flag, f));
      mergedTRFlags = Array.from(trMap.values());
    }

    const finalTRStatus = mergedTRFlags.length > 0 ? "FLAGGED" : "CLEAR";
    const finalRequiresComplianceAction = mergedTRFlags.some(tr => 
      tr.sanctions_hit || 
      tr.flag === "SANCTIONS_HIT" || 
      ["CROSS_VASP_LAYERING", "STRUCTURING_SMURFING"].includes(tr.flag)
    );

    const updatePayload = {
      $setOnInsert: { coin, address: addr, jurisdiction, first_detected_at: now },
      $set: {
        last_seen_at:               now,
        risk_score:                 finalRiskScore,
        matching_rules:             mergedMatchingRules,
        rule_details:               mergedRuleDetails,
        travel_rule_flags:          mergedTRFlags,
        travel_rule_status:         finalTRStatus,
        sanctions_hit:              sanctionsHit,
        requires_compliance_action: finalRequiresComplianceAction,
      },
    };

    // Parallel upsert to BOTH native DB (fatfResults1) AND test_db (fatfResults7)
    await Promise.all([
      fatfResults1.updateOne(
        { coin, address: addr, jurisdiction },
        updatePayload,
        { upsert: true }
      ),
      fatfResults7.updateOne(
        { coin, address: addr, jurisdiction },
        updatePayload,
        { upsert: true }
      )
    ]);

    if (sanctionsHit && complianceAlerts) {
      await complianceAlerts.updateOne(
        { coin, address: addr, jurisdiction },
        {
          $setOnInsert: { coin, address: addr, jurisdiction, first_detected_at: now },
          $set: {
            last_seen_at:              now,
            alert_type:                "SANCTIONS_HIT",
            risk_score:                "high",
            travel_rule_flags:         mergedTRFlags.filter((tr) => tr.flag === "SANCTIONS_HIT"),
            requires_immediate_action: true,
          },
        },
        { upsert: true }
      );
    }
  }
}

module.exports = { runAggregations };