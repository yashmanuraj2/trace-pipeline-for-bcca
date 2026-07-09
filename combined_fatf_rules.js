// combined_fatf_rules.js
// FATF Rules + Travel Rule (TR) pipelines for ETH, TRON, BTC

const { db1Connection, db3Connection, db4Connection } = require("./db");

let tag_list_with_scores = [
  {
    mixer: "high", privacy_coin: "high", p2p: "high", forum: "high",
    darknet_marketplace: "high", illicit_group: "high", ATM: "high",
    criminal: "high", illicit: "high", ICO: "medium", NO_KYC: "high",
    Scam: "high", Terror: "high", Abuse: "high", gambling: "high",
    hack: "high", sanctioned: "high", ponzi: "high", "service-hack": "high", sextortion: "high",
    "Blackmail/Extortion": "high", "Bridge": "medium", "CEX": "low",
    "Darkweb": "high", "Hacker": "high", "Impersonation Scams": "high",
    "Investment Fraud": "high", "Phishing": "high", "Phishing/Scam": "high",
    "Pig Butching": "high", "Pool Mine": "low", "Ransomware": "high",
    "Rug Pull": "high", "Sanction": "high", "Suspicious": "medium",
    "Trojan": "high", "donation wallet": "low", "exchange_review": "low"
  },
];

const JURISDICTION_CONFIG = {
  FATF_BASELINE: {
    ETH: 0.4, BTC: 0.011, TRX_USDT: 1000,
    ETH_EXT: 0.4, BTC_EXT: 0.011, TRX_USDT_EXT: 1000,
    two_tier: false, below_threshold_obligation: false, unhosted_wallet_rule: "risk_based",
    legal_source: "FATF R.16 + INR.16 (2012/2019 update)"
  },
  EU: {
    ETH: 0, BTC: 0, TRX_USDT: 0,
    ETH_EXT: 0.4, BTC_EXT: 0.011, TRX_USDT_EXT: 1000,
    two_tier: true, below_threshold_obligation: true, unhosted_wallet_rule: "ownership_verification_above_1000_eur_once",
    legal_source: "Regulation (EU) 2023/1113 (TFR), OJ L150, 9.6.2023; EBA Travel Rule Guidelines Jul 2024"
  },
  US: {
    ETH: 1.2, BTC: 0.033, TRX_USDT: 3000,
    ETH_EXT: 1.2, BTC_EXT: 0.033, TRX_USDT_EXT: 3000,
    two_tier: false, below_threshold_obligation: false, unhosted_wallet_rule: "none",
    legal_source: "31 CFR 1010.410(f), BSA (1996); FinCEN FIN-2019-G001 (May 2019)"
  },
  UK: {
    ETH: 0, BTC: 0, TRX_USDT: 0,
    ETH_EXT: 0.4, BTC_EXT: 0.011, TRX_USDT_EXT: 1000,
    two_tier: true, below_threshold_obligation: true, unhosted_wallet_rule: "verification_required_above_1000_gbp",
    legal_source: "UK MLR 2017 (SI 2022/1166); FCA/JMLSG Travel Rule guidance, effective Sep 1 2023"
  },
  SG: {
    ETH: 0, BTC: 0, TRX_USDT: 0,
    ETH_EXT: 0.6, BTC_EXT: 0.017, TRX_USDT_EXT: 1500,
    two_tier: true, below_threshold_obligation: true, unhosted_wallet_rule: "exempt_but_elevated_risk",
    legal_source: "MAS Notice PSN02, s.13.4–13.6 (revised Jun 2025); Payment Services Act 2019"
  },
};

const DEFAULT_JURISDICTION = "FATF_BASELINE";

const TR_THRESHOLDS = {
  ETH: JURISDICTION_CONFIG.FATF_BASELINE.ETH,
  TRX_USDT: JURISDICTION_CONFIG.FATF_BASELINE.TRX_USDT,
  BTC: JURISDICTION_CONFIG.FATF_BASELINE.BTC,
};

const SAFE_CONTRACT_WHITELIST_ETH = [
  "0xdac17f958d2ee523a2206206994597c13d831ec7", 
  "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", 
  "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599", 
  "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2", 
];

const SAFE_CONTRACT_WHITELIST_TRON = [
  "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t", 
];

let hotAddresses = new Set();

async function ensureConnections() {
  try {
    if (!db1Connection || !db1Connection.client?.topology?.isConnected()) await db1Connection.client.connect();
    if (!db3Connection || !db3Connection.client?.topology?.isConnected()) await db3Connection.client.connect();
    if (!db4Connection || !db4Connection.client?.topology?.isConnected()) await db4Connection.client.connect();
  } catch (err) {
    console.error("Error ensuring database connections:", err);
  }
}

async function loadHotWallets() {
  try {
    await ensureConnections();
    const tronHot = await db1Connection.collection("test_hot_clustering").distinct("address");
    const ethHot  = await db4Connection.collection("test_hot_wallet2").distinct("_id");
    hotAddresses  = new Set([...tronHot, ...ethHot]);
    console.log(`[Hot Wallet Loader] Loaded ${hotAddresses.size} addresses`);
  } catch (err) {
    console.error("Error loading hot wallets:", err);
  }
}

const excludeHotWalletsStage = () => ({
  $match: {
    $and: [
      { from_address:   { $nin: Array.from(hotAddresses) } },
      { to_address:     { $nin: Array.from(hotAddresses) } },
      { transfer_from:  { $nin: Array.from(hotAddresses) } },
      { transfer_to:    { $nin: Array.from(hotAddresses) } },
    ],
  },
});

const _combined_tagpack_lookup = (chainPrefix, localField, asName) => {
  const tagpack     = `${chainPrefix}_tagpack`;
  const rootTagpack = `${chainPrefix}_root_tagpack`;
  return [
    { 
      $lookup: { 
        from: tagpack,     
        localField, 
        foreignField: "address", 
        pipeline: [
          { $sort: { confPercentage: -1, confidencePercentage: -1, confPercentge: -1, confidence: -1 } }
        ],
        as: `${asName}_1` 
      } 
    },
    { 
      $lookup: { 
        from: rootTagpack, 
        localField, 
        foreignField: "address", 
        pipeline: [
          { $sort: { confPercentage: -1, confidencePercentage: -1, confPercentge: -1, confidence: -1 } }
        ],
        as: `${asName}_2` 
      } 
    },
    {
      $addFields: {
        [asName]: {
          $map: {
            input: { $concatArrays: [`$${asName}_1`, `$${asName}_2`] },
            as: "item",
            in: {
              $mergeObjects: [
                "$$item",
                {
                  confidence: {
                    $let: {
                      vars: { 
                        c: "$$item.confidence", 
                        cp1: "$$item.confPercentge", 
                        cp2: "$$item.confidencePercentage",
                        cp3: "$$item.confPercentage" 
                      },
                      in: { $ifNull: [{ $cond: [{ $isNumber: "$$c" }, "$$c", null] }, "$$cp1", "$$cp2", "$$cp3", 100] }
                    }
                  }
                }
              ]
            }
          }
        }
      }
    },
    { $project: { [`${asName}_1`]: 0, [`${asName}_2`]: 0 } }
  ];
};

const _target_address_exchange_check = (chainPrefix, address, asName) => {
  const tagpack     = `${chainPrefix}_tagpack`;
  const rootTagpack = `${chainPrefix}_root_tagpack`;
  return [
    { $lookup: { from: tagpack,     pipeline: [{ $match: { address, tag: "exchange" } }], as: `${asName}_1` } },
    { $lookup: { from: rootTagpack, pipeline: [{ $match: { address, tag: "exchange" } }], as: `${asName}_2` } },
    { $match: { [`${asName}_1`]: { $size: 0 }, [`${asName}_2`]: { $size: 0 } } }
  ];
};

// ── ETH NATIVE ────────────────────────────────────────────────────────────
const eth_quick_succession_high_value_transaction = (address, amount, jurisdiction = DEFAULT_JURISDICTION) => {
  const jConfig = JURISDICTION_CONFIG[jurisdiction];
  const threshold = jConfig.ETH;
  return [
    excludeHotWalletsStage(),
    { $addFields: { ethValue: { $toDouble: "$value" }, currentTime: { $toLong: "$$NOW" } } },
    { $addFields: { currentUnixSeconds: { $floor: { $divide: ["$currentTime", 1000] } } } },
    {
      $match: {
        $or: [{ from_address: address }, { to_address: address }],
        $expr: { $gte: [{ $toLong: "$block_timestamp" }, { $subtract: ["$currentUnixSeconds", 86400] }] },
        ethValue: { $gte: parseInt(amount) },
      },
    },
    {
      $facet: {
        data: [{ $sort: { block_timestamp: -1 } }, { $project: { _id: 1, transaction_hash: "$_id", from_address: 1, to_address: 1, ethValue: 1, block_timestamp: 1 } }],
        exists: [{ $limit: 1 }],
        sub_threshold_txns: [
          { $match: { ethValue: { $gt: 0.0001, $lt: jConfig.ETH_EXT } } },
          { $group: { _id: null, count: { $sum: 1 }, total: { $sum: "$ethValue" }, triggering_txns: { $push: "$_id" } } },
        ],
      },
    },
    {
      $addFields: {
        malicious:      { $gt: [{ $size: "$exists" }, 0] },
        tr4_structuring: {
          $and: [
            { $gt: [{ $size: "$sub_threshold_txns" }, 0] },
            { $gte: [{ $arrayElemAt: ["$sub_threshold_txns.count", 0] }, 3] },
            { $gte: [{ $arrayElemAt: ["$sub_threshold_txns.total", 0] }, jConfig.ETH_EXT] },
          ],
        },
      },
    },
    { $unwind: { path: "$data", preserveNullAndEmptyArrays: true } },
    {
      $replaceRoot: {
        newRoot: {
          $mergeObjects: [
            "$data",
            {
              $cond: {
                if:   "$malicious",
                then: { risk_score: "mild", jurisdiction, travel_rule_trigger: { $cond: { if: "$tr4_structuring", then: "STRUCTURING_SMURFING", else: "$$REMOVE" } } },
                else: { risk_score: "low" },
              },
            },
          ],
        },
      },
    },
    { $limit: 1 },
    { $project: { risk_score: 1, travel_rule_trigger: 1, jurisdiction: 1 } },
  ];
};

const eth_large_deposit_followed_by_immediate_withdrawl = (address, jurisdiction = DEFAULT_JURISDICTION) => {
  const jConfig = JURISDICTION_CONFIG[jurisdiction];
  return [
    excludeHotWalletsStage(),
    { $match: { $or: [{ from_address: address }, { to_address: address }] } },
    ..._target_address_exchange_check("ethereum", address, "target_address_exchange_check"),
    ..._combined_tagpack_lookup("ethereum", "to_address", "to_tags"),
    {
      $addFields: {
        direction:   { $cond: [{ $eq: ["$from_address", address] }, "outgoing", "incoming"] },
        to_tag:      { $arrayElemAt: ["$to_tags.tag", 0] },
        counterparty:{ $cond: [{ $eq: ["$from_address", address] }, "$to_address", "$from_address"] },
        ethValue:    { $toDouble: "$value" },
      },
    },
    {
      $facet: {
        incoming: [{ $match: { direction: "incoming" } }, { $project: { _id: 1, transaction_hash: "$_id", value: { $toDouble: "$value" }, block_timestamp: { $toLong: "$block_timestamp" }, counterparty: 1 } }],
        outgoing: [{ $match: { direction: "outgoing" } }, { $project: { _id: 1, transaction_hash: "$_id", value: { $toDouble: "$value" }, block_timestamp: { $toLong: "$block_timestamp" }, to_tag: 1, counterparty: 1 } }],
        vasp_transfers:     [{ $match: { ethValue: { $gte: jConfig.ETH_EXT }, "to_tags.tag": "exchange" } }, { $limit: 1 }],
        unhosted_transfers: [{ $match: { ethValue: { $gte: jConfig.ETH_EXT }, to_tags: { $size: 0 } } }, { $limit: 1 }],
      },
    },
    {
      $project: {
        risky_pairs: {
          $map: {
            input: "$incoming", as: "inc",
            in: {
              incoming_transaction_hash: "$$inc.transaction_hash",
              outgoing_txn: {
                $first: {
                  $filter: {
                    input: "$outgoing", as: "out",
                    cond: {
                      $and: [
                        { $lte: [{ $abs: { $subtract: ["$$out.block_timestamp", "$$inc.block_timestamp"] } }, 3600] },
                        { $lte: [{ $abs: { $subtract: ["$$out.value", "$$inc.value"] } }, { $multiply: ["$$inc.value", 0.05] }] },
                        { $ne: ["$$out.to_tag", "exchange"] },
                      ],
                    },
                  },
                },
              },
            },
          },
        },
        vasp_transfers: 1, unhosted_transfers: 1, vasp_incoming: "$incoming", vasp_outgoing: "$outgoing",
      },
    },
    {
      $addFields: {
        risky_pairs:    { $filter: { input: "$risky_pairs", as: "p", cond: { $ifNull: ["$$p.outgoing_txn", false] } } },
        tr1_vasp_breach: { $gt: [{ $size: "$vasp_transfers" }, 0] },
        tr2_unhosted:    { $gt: [{ $size: "$unhosted_transfers" }, 0] },
      },
    },
    {
      $addFields: {
        risk_score: { $cond: [{ $gt: [{ $size: "$risky_pairs" }, 0] }, "high", "none"] },
        jurisdiction,
        travel_rule_triggers: {
          $filter: {
            input: [
              { $cond: ["$tr1_vasp_breach", "THRESHOLD_BREACH_KNOWN_VASP", "$$REMOVE"] },
              { $cond: [{ $and: ["$tr2_unhosted", { $ne: [jurisdiction, "SG"] }] }, "UNHOSTED_WALLET_LARGE_TRANSFER", "$$REMOVE"] },
              { $cond: [{ $and: ["$tr2_unhosted", { $eq: [jurisdiction, "SG"] }] }, "UNHOSTED_ELEVATED_RISK_SG", "$$REMOVE"] },
            ],
            as: "tr", cond: { $ne: ["$$tr", null] },
          },
        },
      },
    },
    { $project: { risky_pairs: 1, risk_score: 1, travel_rule_triggers: 1, jurisdiction: 1 } },
  ];
};

const eth_fatf_low_value_transactions = (address, jurisdiction = DEFAULT_JURISDICTION) => [
  excludeHotWalletsStage(),
  { $addFields: { numeric_value: { $toDouble: "$value" } } },
  { $match: { from_address: address, numeric_value: { $lt: 0.00001 } } },
  { $group: { _id: "$from_address", min_amount: { $min: "$numeric_value" }, dust_count: { $sum: 1 }, triggering_txns: { $push: "$_id" } } },
  { $project: { _id: 0, from_address: "$_id", amount: "$min_amount", triggering_txns: { $slice: ["$triggering_txns", 20] }, risk_score: { $literal: "mild" }, jurisdiction: { $literal: jurisdiction }, travel_rule_trigger: { $literal: "STRUCTURING_SMURFING" } } },
];

const eth_combined_rule_for_flagged_addresses = (address, jurisdiction = DEFAULT_JURISDICTION) => [
  excludeHotWalletsStage(),
  { $match: { $or: [{ from_address: address }, { to_address: address }] } },
  { $project: { transaction_hash: "$_id", original: { $cond: [{ $eq: ["$from_address", address] }, "$from_address", "$to_address"] }, counterparty:{ $cond: [{ $eq: ["$from_address", address] }, "$to_address", "$from_address"] } } },
  { $match: { counterparty: { $nin: SAFE_CONTRACT_WHITELIST_ETH } } },
  ..._combined_tagpack_lookup("ethereum", "counterparty", "counterparty_tags"),
  { $unwind: "$counterparty_tags" },
  {
    $addFields: {
      effective_risk_tag: { $cond: { if: { $and: [{ $ne: ["$counterparty_tags.subTag", null] }, { $ne: ["$counterparty_tags.subTag", ""] }] }, then: "$counterparty_tags.subTag", else: "$counterparty_tags.tag" } }
    }
  },
  { $match: { effective_risk_tag: { $in: Object.keys(tag_list_with_scores[0]) } } },
  {
    $addFields: {
      risk_score: { $switch: { branches: Object.entries(tag_list_with_scores[0]).map(([tag, score]) => ({ case: { $eq: ["$effective_risk_tag", tag] }, then: score })), default: "low" } },
      travel_rule_trigger: { $cond: { if: { $eq: ["$counterparty_tags.mal", true] }, then: "SANCTIONS_HIT", else: "$$REMOVE" } },
      sanctions_hit:       { $eq: ["$counterparty_tags.mal", true] },
    },
  },
  { $project: { _id: 0, transaction_hash: 1, original: 1, counterparty: 1, tag: "$effective_risk_tag", risk_score: 1, jurisdiction: { $literal: jurisdiction }, travel_rule_trigger: 1, sanctions_hit: 1 } },
];

const eth_fatf_whale_out = (address, amount, jurisdiction = DEFAULT_JURISDICTION) => [
excludeHotWalletsStage(),
  { $match: { from_address: address } },
  { $addFields: { numeric_value: { $toDouble: "$value" } } },
  { $match: { numeric_value: { $gte: parseInt(amount) } } },
  ..._combined_tagpack_lookup("ethereum", "to_address", "to_tags"),
  {
    $addFields: {
      is_known_vasp:          { $gt: [{ $size: { $filter: { input: "$to_tags", as: "t", cond: { $eq: ["$$t.tag", "exchange"] } } } }, 0] },
      is_low_confidence_vasp: { $gt: [{ $size: { $filter: { input: "$to_tags", as: "t", cond: { $and: [{ $eq: ["$$t.tag", "exchange"] }, { $lt: ["$$t.confidence", 50] }] } } } }, 0] },
      is_unhosted:            { $eq: [{ $size: "$to_tags" }, 0] },
    },
  },
  {
    $project: {
      _id: 0, transaction_hash: "$_id", address: "$from_address", risk_score: { $literal: "high" }, jurisdiction: { $literal: jurisdiction },
      travel_rule_triggers: {
        $filter: {
          input: [
            { $cond: ["$is_known_vasp", "THRESHOLD_BREACH_KNOWN_VASP", "$$REMOVE"] },
            { $cond: [{ $and: ["$is_unhosted", { $ne: [jurisdiction, "SG"] }] }, "UNHOSTED_WALLET_LARGE_TRANSFER", "$$REMOVE"] },
            { $cond: [{ $and: ["$is_unhosted", { $eq: [jurisdiction, "SG"] }] }, "UNHOSTED_ELEVATED_RISK_SG", "$$REMOVE"] },
            { $cond: ["$is_low_confidence_vasp", "LOW_CONFIDENCE_VASP", "$$REMOVE"] },
          ], as: "tr", cond: { $ne: ["$$tr", null] },
        },
      },
    },
  },
];

const eth_fatf_whale_in = (address, amount, jurisdiction = DEFAULT_JURISDICTION) => [
excludeHotWalletsStage(),
  { $match: { to_address: address } },
  { $addFields: { numeric_value: { $toDouble: "$value" } } },
  { $match: { numeric_value: { $gte: parseInt(amount) } } },
  ..._combined_tagpack_lookup("ethereum", "from_address", "from_tags"),
  {
    $addFields: {
      is_known_vasp:          { $gt: [{ $size: { $filter: { input: "$from_tags", as: "t", cond: { $eq: ["$$t.tag", "exchange"] } } } }, 0] },
      is_low_confidence_vasp: { $gt: [{ $size: { $filter: { input: "$from_tags", as: "t", cond: { $and: [{ $eq: ["$$t.tag", "exchange"] }, { $lt: ["$$t.confidence", 50] }] } } } }, 0] },
      is_unhosted:            { $eq: [{ $size: "$from_tags" }, 0] },
    },
  },
  {
    $project: {
      _id: 0, transaction_hash: "$_id", address: "$to_address", risk_score: { $literal: "high" }, jurisdiction: { $literal: jurisdiction },
      travel_rule_triggers: {
        $filter: {
          input: [
            { $cond: ["$is_known_vasp", "THRESHOLD_BREACH_KNOWN_VASP", "$$REMOVE"] },
            { $cond: [{ $and: ["$is_unhosted", { $ne: [jurisdiction, "SG"] }] }, "UNHOSTED_WALLET_LARGE_TRANSFER", "$$REMOVE"] },
            { $cond: [{ $and: ["$is_unhosted", { $eq: [jurisdiction, "SG"] }] }, "UNHOSTED_ELEVATED_RISK_SG", "$$REMOVE"] },
            { $cond: ["$is_low_confidence_vasp", "LOW_CONFIDENCE_VASP", "$$REMOVE"] },
          ], as: "tr", cond: { $ne: ["$$tr", null] },
        },
      },
    },
  },
];

const eth_tr_threshold_breach_known_vasp = (address, jurisdiction = DEFAULT_JURISDICTION) => {
  const jConfig   = JURISDICTION_CONFIG[jurisdiction];
  const threshold = jConfig.ETH;
  const extThresh = jConfig.ETH_EXT;
  return [
    excludeHotWalletsStage(),
    { $match: { $or: [{ from_address: address }, { to_address: address }] } },
    { $addFields: { ethValue: { $toDouble: "$value" }, counterparty: { $cond: [{ $eq: ["$from_address", address] }, "$to_address", "$from_address"] } } },
    ...(threshold > 0 ? [{ $match: { ethValue: { $gte: threshold } } }] : []),
    ..._combined_tagpack_lookup("ethereum", "counterparty", "cp_tags"),
    { $match: { cp_tags: { $elemMatch: { tag: "exchange" } } } },
    {
      $project: {
        _id: 0, transaction_hash: "$_id", address: { $literal: address }, counterparty: 1, ethValue: 1,
        obligation_tier: { $cond: [{ $gte: ["$ethValue", extThresh] }, "extended_pii", "basic_pii"] },
        jurisdiction: { $literal: jurisdiction }, travel_rule_flag: { $literal: "THRESHOLD_BREACH_KNOWN_VASP" },
        risk_score: { $cond: [{ $gte: ["$ethValue", extThresh] }, "medium", "mild"] },
      },
    },
    { $limit: 1 },
  ];
};

const eth_tr_unhosted_wallet_large_transfer = (address, jurisdiction = DEFAULT_JURISDICTION) => {
  const threshold = JURISDICTION_CONFIG[jurisdiction].ETH_EXT;
  const sgExempt  = jurisdiction === "SG";
  return [
    excludeHotWalletsStage(),
    { $match: { $or: [{ from_address: address }, { to_address: address }] } },
    { $addFields: { ethValue: { $toDouble: "$value" }, counterparty: { $cond: [{ $eq: ["$from_address", address] }, "$to_address", "$from_address"] } } },
    { $match: { ethValue: { $gte: threshold } } },
    ..._combined_tagpack_lookup("ethereum", "counterparty", "cp_tags"),
    { $match: { cp_tags: { $size: 0 } } },
    {
      $project: {
        _id: 0, transaction_hash: "$_id", address: { $literal: address }, counterparty: 1, ethValue: 1, jurisdiction: { $literal: jurisdiction },
        travel_rule_flag: { $literal: sgExempt ? "UNHOSTED_ELEVATED_RISK_SG" : "UNHOSTED_WALLET_LARGE_TRANSFER" },
        risk_score: { $literal: "medium" }, sg_exempt: { $literal: sgExempt },
      },
    },
    { $limit: 1 },
  ];
};

const eth_tr_sanctions_hit = (address, jurisdiction = DEFAULT_JURISDICTION) => [
  excludeHotWalletsStage(),
  { $match: { $or: [{ from_address: address }, { to_address: address }] } },
  { $addFields: { counterparty: { $cond: [{ $eq: ["$from_address", address] }, "$to_address", "$from_address"] } } },
  { $match: { counterparty: { $nin: SAFE_CONTRACT_WHITELIST_ETH } } },
  ..._combined_tagpack_lookup("ethereum", "counterparty", "cp_tags"),
  { $match: { cp_tags: { $elemMatch: { mal: true } } } },
  { $project: { _id: 0, transaction_hash: "$_id", address: { $literal: address }, counterparty: 1, jurisdiction: { $literal: jurisdiction }, travel_rule_flag: { $literal: "SANCTIONS_HIT" }, risk_score: { $literal: "high" }, sanctions_hit: { $literal: true } } },
  { $limit: 1 },
];

const eth_tr_structuring_smurfing = (address, jurisdiction = DEFAULT_JURISDICTION) => [
  excludeHotWalletsStage(),
  { $match: { $or: [{ from_address: address }, { to_address: address }] } },
  { $addFields: { ethValue: { $toDouble: "$value" } } },
  { $match: { ethValue: { $gt: 0.0001, $lt: JURISDICTION_CONFIG[jurisdiction].ETH_EXT } } },
  { $group: { _id: null, txn_count: { $sum: 1 }, total_value: { $sum: "$ethValue" }, triggering_txns: { $push: "$_id" } } },
  { $match: { txn_count: { $gte: 3 }, total_value: { $gte: JURISDICTION_CONFIG[jurisdiction].ETH_EXT } } },
  { $project: { _id: 0, address: { $literal: address }, txn_count: 1, total_value: 1, triggering_txns: { $slice: ["$triggering_txns", 20] }, jurisdiction: { $literal: jurisdiction }, travel_rule_flag: { $literal: "STRUCTURING_SMURFING" }, risk_score: { $literal: "high" } } },
];

const eth_tr_low_confidence_vasp = (address, jurisdiction = DEFAULT_JURISDICTION) => [
  excludeHotWalletsStage(),
  { $match: { $or: [{ from_address: address }, { to_address: address }] } },
  { $addFields: { counterparty: { $cond: [{ $eq: ["$from_address", address] }, "$to_address", "$from_address"] } } },
  ..._combined_tagpack_lookup("ethereum", "counterparty", "cp_tags"),
  { $match: { cp_tags: { $elemMatch: { tag: "exchange", confidence: { $lt: 50 } } } } },
  { $project: { _id: 0, transaction_hash: "$_id", address: { $literal: address }, counterparty: 1, jurisdiction: { $literal: jurisdiction }, travel_rule_flag: { $literal: "LOW_CONFIDENCE_VASP" }, risk_score: { $literal: "medium" } } },
  { $limit: 1 },
];

const eth_tr_cross_vasp_layering = (address, jurisdiction = DEFAULT_JURISDICTION) => [
  excludeHotWalletsStage(),
  { $match: { $or: [{ from_address: address }, { to_address: address }] } },
  { $addFields: { direction: { $cond: [{ $eq: ["$from_address", address] }, "outgoing", "incoming"] }, counterparty: { $cond: [{ $eq: ["$from_address", address] }, "$to_address", "$from_address"] } } },
  ..._combined_tagpack_lookup("ethereum", "counterparty", "cp_tags"),
  { $addFields: { is_vasp: { $gt: [{ $size: { $filter: { input: "$cp_tags", as: "t", cond: { $eq: ["$$t.tag", "exchange"] } } } }, 0] } } },
  {
    $facet: {
      vasp_incoming: [{ $match: { direction: "incoming", is_vasp: true } }, { $project: { transaction_hash: "$_id", block_timestamp: { $toLong: "$block_timestamp" } } }],
      vasp_outgoing: [{ $match: { direction: "outgoing", is_vasp: true } }, { $project: { transaction_hash: "$_id", block_timestamp: { $toLong: "$block_timestamp" } } }],
    },
  },
  {
    $addFields: {
      layering_detected: {
        $gt: [
          { $size: { $filter: { input: "$vasp_incoming", as: "inc", cond: { $gt: [{ $size: { $filter: { input: "$vasp_outgoing", as: "out", cond: { $and: [{ $gte: ["$$out.block_timestamp", "$$inc.block_timestamp"] }, { $lte: [{ $subtract: ["$$out.block_timestamp", "$$inc.block_timestamp"] }, 3600] }] } } } }, 0] } } } },
          0,
        ],
      },
    },
  },
  { $match: { layering_detected: true } },
  { $project: { _id: 0, address: { $literal: address }, incoming_txns: { $slice: ["$vasp_incoming.transaction_hash", 20] }, outgoing_txns: { $slice: ["$vasp_outgoing.transaction_hash", 20] }, jurisdiction: { $literal: jurisdiction }, travel_rule_flag: { $literal: "CROSS_VASP_LAYERING" }, risk_score: { $literal: "high" } } },
];

// ── BTC NATIVE ────────────────────────────────────────────────────────────

const btc_quick_succession_high_value_pass_transaction = (address, amount, currentBlockHeight, jurisdiction = DEFAULT_JURISDICTION) => {
  const jConfig = JURISDICTION_CONFIG[jurisdiction];
  return [
    { $match: { hash: address, block: { $gte: currentBlockHeight - 144 }, value: { $gte: Number(amount) } } },
    {
      $facet: {
        incomingExists: [{ $match: { received: true  } }, { $limit: 1 }],
        outgoingExists: [{ $match: { received: false } }, { $limit: 1 }],
        data: [{ $sort: { block: -1 } }, { $project: { _id: 1, hash: 1, txn: 1, transaction_hash: "$txn", value: 1, received: 1, block: 1 } }, { $limit: 1 }],
        sub_threshold: [{ $match: { value: { $gt: 0.0001, $lt: jConfig.BTC_EXT } } }, { $group: { _id: null, count: { $sum: 1 }, total: { $sum: "$value" } } }],
      },
    },
    {
      $project: {
        data: 1,
        malicious: { $cond: { if: { $and: [{ $gt: [{ $size: "$incomingExists" }, 0] }, { $gt: [{ $size: "$outgoingExists" }, 0] }] }, then: true, else: false } },
        tr4_structuring: { $and: [{ $gt: [{ $size: "$sub_threshold" }, 0] }, { $gte: [{ $arrayElemAt: ["$sub_threshold.count", 0] }, 3] }, { $gte: [{ $arrayElemAt: ["$sub_threshold.total", 0] }, jConfig.BTC_EXT] }] },
      },
    },
    { $unwind: { path: "$data", preserveNullAndEmptyArrays: true } },
    { $replaceRoot: { newRoot: { $mergeObjects: ["$data", { $cond: { if: "$malicious", then: { risk_score: "mild", jurisdiction, travel_rule_trigger: { $cond: { if: "$tr4_structuring", then: "STRUCTURING_SMURFING", else: "$$REMOVE" } } }, else: { risk_score: "low" } } }] } } },
    { $limit: 1 }, { $project: { risk_score: 1, travel_rule_trigger: 1, jurisdiction: 1 } },
  ];
};

const btc_large_deposit_followed_by_immediate_withdrawl = (address, jurisdiction = DEFAULT_JURISDICTION) => {
  const jConfig = JURISDICTION_CONFIG[jurisdiction];
  return [
    { $match: { hash: address } },
    ..._target_address_exchange_check("bitcoin", address, "target_address_exchange_check"),
    { $lookup: { from: "bitcoin_Transactions", localField: "txn", foreignField: "_id", as: "tx_details" } },
    { $unwind: { path: "$tx_details", preserveNullAndEmptyArrays: true } },
    { $addFields: { output_addresses: { $map: { input: { $objectToArray: "$tx_details.outputs" }, as: "out", in: { $arrayElemAt: ["$$out.v", 0] } } } } },
    ..._combined_tagpack_lookup("bitcoin", "output_addresses", "output_tags"),
    {
      $addFields: {
        direction: { $cond: ["$received", "incoming", "outgoing"] },
        sent_to_exchange: { $gt: [{ $size: { $filter: { input: "$output_tags", as: "tag", cond: { $eq: ["$$tag.tag", "exchange"] } } } }, 0] },
        sent_to_unhosted: { $eq: [{ $size: "$output_tags" }, 0] },
      },
    },
    {
      $facet: {
        incoming: [{ $match: { direction: "incoming" } }, { $sort: { "tx_details.block_timestamp": 1 } }, { $project: { _id: "$txn", transaction_hash: "$txn", value: 1, block_timestamp: "$tx_details.block_timestamp" } }],
        outgoing: [{ $match: { direction: "outgoing" } }, { $sort: { "tx_details.block_timestamp": 1 } }, { $project: { _id: "$txn", transaction_hash: "$txn", value: 1, block_timestamp: "$tx_details.block_timestamp", sent_to_exchange: 1, sent_to_unhosted: 1 } }],
        vasp_outgoing: [{ $match: { direction: "outgoing", sent_to_exchange: true, value: { $gte: jConfig.BTC_EXT } } }, { $limit: 1 }],
        unhosted_outgoing: [{ $match: { direction: "outgoing", sent_to_unhosted: true, value: { $gte: jConfig.BTC_EXT } } }, { $limit: 1 }],
      },
    },
    {
      $project: {
        rule1_pairs: {
          $filter: {
            input: {
              $map: {
                input: "$incoming", as: "inc",
                in: {
                  incoming_transaction_hash: "$$inc.transaction_hash",
                  matched_outgoing: {
                    $filter: {
                      input: "$outgoing", as: "out",
                      cond: { $and: [{ $gte: [{ $subtract: ["$$out.block_timestamp", "$$inc.block_timestamp"] }, 0] }, { $lte: [{ $subtract: ["$$out.block_timestamp", "$$inc.block_timestamp"] }, 3600] }, { $gte: ["$$out.value", { $multiply: ["$$inc.value", 0.95] }] }, { $lte: ["$$out.value", "$$inc.value"] }, { $eq: ["$$out.sent_to_exchange", false] }] },
                    },
                  },
                },
              },
            }, as: "p", cond: { $gt: [{ $size: "$$p.matched_outgoing" }, 0] },
          },
        },
        tr1_vasp_breach: { $gt: [{ $size: "$vasp_outgoing" }, 0] }, tr2_unhosted: { $gt: [{ $size: "$unhosted_outgoing" }, 0] },
      },
    },
    {
      $addFields: {
        rule1_triggered: { $gt: [{ $size: "$rule1_pairs" }, 0] }, risk_score: { $cond: [{ $gt: [{ $size: "$rule1_pairs" }, 0] }, "high", "none"] }, jurisdiction,
        travel_rule_triggers: { $filter: { input: [{ $cond: ["$tr1_vasp_breach", "THRESHOLD_BREACH_KNOWN_VASP", "$$REMOVE"] }, { $cond: ["$tr2_unhosted", "UNHOSTED_WALLET_LARGE_TRANSFER", "$$REMOVE"] }], as: "tr", cond: { $ne: ["$$tr", null] } } },
      },
    },
    { $project: { rule1_pairs: 1, risk_score: 1, travel_rule_triggers: 1, rule1_triggered: 1, jurisdiction: 1 } },
  ];
};

const btc_fatf_low_value_transactions = (address, jurisdiction = DEFAULT_JURISDICTION) => [
  ..._target_address_exchange_check("bitcoin", address, "exchange_check"),
  { $match: { hash: address, received: false, value: { $lt: 0.00001 } } },
  { $group: { _id: "$hash", min_amount: { $min: "$value" }, triggering_txns: { $push: "$txn" } } },
  { $project: { _id: 0, from_address: "$_id", amount: "$min_amount", triggering_txns: { $slice: ["$triggering_txns", 20] }, risk_score: { $literal: "mild" }, jurisdiction: { $literal: jurisdiction }, travel_rule_trigger: { $literal: "STRUCTURING_SMURFING" } } },
];

const btc_combined_rule_for_flagged_addresses = (address, jurisdiction = DEFAULT_JURISDICTION) => [
  excludeHotWalletsStage(),
  ..._target_address_exchange_check("bitcoin", address, "target_exchange_check"),
  { $match: { hash: address } },
  { $lookup: { from: "bitcoin_Transactions", localField: "txn", foreignField: "_id", as: "tx_details" } },
  { $unwind: { path: "$tx_details", preserveNullAndEmptyArrays: true } },
  {
    $addFields: {
      counterparty_addresses: {
        $filter: {
          input: { $concatArrays: [{ $map: { input: { $objectToArray: { $ifNull: ["$tx_details.inputs", {}] } }, as: "i", in: { $arrayElemAt: ["$$i.v", 0] } } }, { $map: { input: { $objectToArray: { $ifNull: ["$tx_details.outputs", {}] } }, as: "o", in: { $arrayElemAt: ["$$o.v", 0] } } }] },
          as: "cp", cond: { $and: [{ $ne: ["$$cp", address] }, { $ne: ["$$cp", null] }, { $ne: ["$$cp", ""] }] },
        },
      },
    },
  },
  ..._combined_tagpack_lookup("bitcoin", "counterparty_addresses", "counterparty_tags"),
  { $unwind: { path: "$counterparty_tags", preserveNullAndEmptyArrays: true } },
  { $addFields: { effective_risk_tag: { $cond: { if: { $and: [{ $ne: ["$counterparty_tags.subTag", null] }, { $ne: ["$counterparty_tags.subTag", ""] }] }, then: "$counterparty_tags.subTag", else: "$counterparty_tags.tag" } } } },
  { $match: { effective_risk_tag: { $in: Object.keys(tag_list_with_scores[0]) } } },
  {
    $addFields: {
      risk_score: { $switch: { branches: Object.entries(tag_list_with_scores[0]).map(([tag, score]) => ({ case: { $eq: ["$effective_risk_tag", tag] }, then: score })), default: "low" } },
      travel_rule_trigger: { $cond: { if: { $eq: ["$counterparty_tags.mal", true] }, then: "SANCTIONS_HIT", else: "$$REMOVE" } }, sanctions_hit: { $eq: ["$counterparty_tags.mal", true] },
    },
  },
  { $project: { _id: 0, original: address, transaction_hash: "$txn", counterparty: "$counterparty_tags.address", tag: "$effective_risk_tag", risk_score: 1, jurisdiction: { $literal: jurisdiction }, travel_rule_trigger: 1, sanctions_hit: 1 } },
];

const _btc_counterparty_stages = (address, jurisdiction = DEFAULT_JURISDICTION) => {
  const jConfig = JURISDICTION_CONFIG[jurisdiction];
  return [
    { $match: { hash: address } },
    { $lookup: { from: "bitcoin_Transactions", localField: "txn", foreignField: "_id", as: "tx_details" } },
    { $unwind: { path: "$tx_details", preserveNullAndEmptyArrays: true } },
    {
      $addFields: {
        transaction_hash: "$txn",
        counterparty_addresses: {
          $filter: {
            input: { $concatArrays: [{ $map: { input: { $objectToArray: { $ifNull: ["$tx_details.inputs", {}] } }, as: "i", in: { $arrayElemAt: ["$$i.v", 0] } } }, { $map: { input: { $objectToArray: { $ifNull: ["$tx_details.outputs", {}] } }, as: "o", in: { $arrayElemAt: ["$$o.v", 0] } } }] },
            as: "cp", cond: { $and: [{ $ne: ["$$cp", address] }, { $ne: ["$$cp", null] }, { $ne: ["$$cp", ""] }] },
          },
        },
        above_threshold: { $gte: ["$value", jConfig.BTC_EXT] },
        above_base_threshold: { $gte: ["$value", jConfig.BTC] },
      },
    },
  ];
};

const btc_tr_threshold_breach_known_vasp = (address, jurisdiction = DEFAULT_JURISDICTION) => {
  const jConfig = JURISDICTION_CONFIG[jurisdiction];
  return [
    ..._btc_counterparty_stages(address, jurisdiction),
    ...(jConfig.two_tier ? [] : [{ $match: { above_threshold: true } }]),
    ..._combined_tagpack_lookup("bitcoin", "counterparty_addresses", "cp_tags"),
    { $match: { cp_tags: { $elemMatch: { tag: "exchange" } } } },
    {
      $project: {
        _id: 0, address: { $literal: address }, transaction_hash: 1, value: 1, block: 1,
        obligation_tier: { $cond: [{ $gte: ["$value", jConfig.BTC_EXT] }, "extended_pii", "basic_pii"] },
        vasp_name: { $arrayElemAt: [{ $map: { input: { $filter: { input: "$cp_tags", as: "t", cond: { $eq: ["$$t.tag", "exchange"] } } }, as: "t", in: "$$t.name" } }, 0] },
        jurisdiction: { $literal: jurisdiction }, travel_rule_flag: { $literal: "THRESHOLD_BREACH_KNOWN_VASP" },
        risk_score: { $cond: [{ $gte: ["$value", jConfig.BTC_EXT] }, "medium", "mild"] },
      },
    },
    { $limit: 1 },
  ];
};

const btc_tr_unhosted_wallet_large_transfer = (address, jurisdiction = DEFAULT_JURISDICTION) => [
  ..._btc_counterparty_stages(address, jurisdiction),
  { $match: { above_threshold: true } },
  ..._combined_tagpack_lookup("bitcoin", "counterparty_addresses", "cp_tags"),
  { $match: { cp_tags: { $size: 0 } } },
  { $project: { _id: 0, address: { $literal: address }, transaction_hash: 1, value: 1, block: 1, jurisdiction: { $literal: jurisdiction }, travel_rule_flag: { $literal: jurisdiction === "SG" ? "UNHOSTED_ELEVATED_RISK_SG" : "UNHOSTED_WALLET_LARGE_TRANSFER" }, risk_score: { $literal: "medium" }, sg_exempt: { $literal: jurisdiction === "SG" } } },
  { $limit: 1 },
];

const btc_tr_sanctions_hit = (address, jurisdiction = DEFAULT_JURISDICTION) => [
  ..._btc_counterparty_stages(address, jurisdiction),
  ..._combined_tagpack_lookup("bitcoin", "counterparty_addresses", "cp_tags"),
  { $match: { cp_tags: { $elemMatch: { mal: true } } } },
  { $project: { _id: 0, address: { $literal: address }, transaction_hash: 1, block: 1, sanctioned_entity: { $arrayElemAt: [{ $map: { input: { $filter: { input: "$cp_tags", as: "t", cond: { $eq: ["$$t.mal", true] } } }, as: "t", in: "$$t.name" } }, 0] }, jurisdiction: { $literal: jurisdiction }, travel_rule_flag: { $literal: "SANCTIONS_HIT" }, risk_score: { $literal: "high" }, sanctions_hit: { $literal: true } } },
  { $limit: 1 },
];

const btc_tr_structuring_smurfing = (address, currentBlockHeight, jurisdiction = DEFAULT_JURISDICTION) => [
  { $match: { hash: address, block: { $gte: currentBlockHeight - 144 }, value: { $gt: 0.0001, $lt: JURISDICTION_CONFIG[jurisdiction].BTC_EXT } } },
  { $group: { _id: null, txn_count: { $sum: 1 }, total_value: { $sum: "$value" }, min_block: { $min: "$block" }, max_block: { $max: "$block" }, triggering_txns: { $push: "$txn" } } },
  { $match: { txn_count: { $gte: 3 }, total_value: { $gte: JURISDICTION_CONFIG[jurisdiction].BTC_EXT } } },
  { $project: { _id: 0, address: { $literal: address }, txn_count: 1, total_value: 1, triggering_txns: { $slice: ["$triggering_txns", 20] }, block_range: { min: "$min_block", max: "$max_block" }, jurisdiction: { $literal: jurisdiction }, travel_rule_flag: { $literal: "STRUCTURING_SMURFING" }, risk_score: { $literal: "high" } } },
];

const btc_tr_low_confidence_vasp = (address, jurisdiction = DEFAULT_JURISDICTION) => [
  ..._btc_counterparty_stages(address, jurisdiction),
  ..._combined_tagpack_lookup("bitcoin", "counterparty_addresses", "cp_tags"),
  { $match: { cp_tags: { $elemMatch: { tag: "exchange", confidence: { $lt: 50 } } } } },
  { $project: { _id: 0, address: { $literal: address }, transaction_hash: 1, block: 1, vasp_name: { $arrayElemAt: [{ $map: { input: { $filter: { input: "$cp_tags", as: "t", cond: { $and: [{ $eq: ["$$t.tag", "exchange"] }, { $lt: ["$$t.confidence", 50] }] } } }, as: "t", in: "$$t.name" } }, 0] }, jurisdiction: { $literal: jurisdiction }, travel_rule_flag: { $literal: "LOW_CONFIDENCE_VASP" }, risk_score: { $literal: "medium" } } },
  { $limit: 1 },
];

const btc_tr_cross_vasp_layering = (address, jurisdiction = DEFAULT_JURISDICTION) => [
  { $match: { hash: address } },
  { $lookup: { from: "bitcoin_addrs_cluster_mapping", pipeline: [{ $match: { _id: address } }], as: "self_cluster" } },
  { $addFields: { direction: { $cond: ["$received", "incoming", "outgoing"] } } },
  {
    $facet: {
      incoming_txns: [{ $match: { direction: "incoming" } }, { $sort: { block: 1 } }, { $project: { txn: 1, transaction_hash: "$txn", value: 1, block: 1 } }],
      outgoing_txns: [{ $match: { direction: "outgoing" } }, { $sort: { block: 1 } }, { $project: { txn: 1, transaction_hash: "$txn", value: 1, block: 1 } }],
    },
  },
  { $lookup: { from: "bitcoin_Transactions", localField: "incoming_txns.txn", foreignField: "_id", as: "incoming_tx_details" } },
  { $lookup: { from: "bitcoin_Transactions", localField: "outgoing_txns.txn", foreignField: "_id", as: "outgoing_tx_details" } },
  {
    $addFields: {
      incoming_sender_addresses: { $reduce: { input: "$incoming_tx_details", initialValue: [], in: { $concatArrays: ["$$value", { $filter: { input: { $map: { input: { $objectToArray: { $ifNull: ["$$this.inputs", {}] } }, as: "i", in: { $arrayElemAt: ["$$i.v", 0] } } }, as: "a", cond: { $and: [{ $ne: ["$$a", address] }, { $ne: ["$$a", null] }] } } }] } } },
      outgoing_receiver_addresses: { $reduce: { input: "$outgoing_tx_details", initialValue: [], in: { $concatArrays: ["$$value", { $filter: { input: { $map: { input: { $objectToArray: { $ifNull: ["$$this.outputs", {}] } }, as: "o", in: { $arrayElemAt: ["$$o.v", 0] } } }, as: "a", cond: { $and: [{ $ne: ["$$a", address] }, { $ne: ["$$a", null] }] } } }] } } },
    },
  },
  ..._combined_tagpack_lookup("bitcoin", "incoming_sender_addresses",  "incoming_vasp_tags"),
  ..._combined_tagpack_lookup("bitcoin", "outgoing_receiver_addresses", "outgoing_vasp_tags"),
  {
    $addFields: {
      has_vasp_sender:  { $gt: [{ $size: { $filter: { input: "$incoming_vasp_tags", as: "t", cond: { $eq: ["$$t.tag", "exchange"] } } } }, 0] },
      has_vasp_receiver:{ $gt: [{ $size: { $filter: { input: "$outgoing_vasp_tags", as: "t", cond: { $eq: ["$$t.tag", "exchange"] } } } }, 0] },
      incoming_block_min: { $min: "$incoming_txns.block" }, outgoing_block_min: { $min: "$outgoing_txns.block" },
    },
  },
  { $addFields: { layering_detected: { $and: ["$has_vasp_sender", "$has_vasp_receiver", { $lte: [{ $subtract: ["$outgoing_block_min", "$incoming_block_min"] }, 144] }, { $gte: ["$outgoing_block_min", "$incoming_block_min"] }] } } },
  { $match: { layering_detected: true } },
  { $project: { _id: 0, address: { $literal: address }, incoming_txns: { $slice: ["$incoming_txns.transaction_hash", 20] }, outgoing_txns: { $slice: ["$outgoing_txns.transaction_hash", 20] }, incoming_vasp: { $arrayElemAt: [{ $map: { input: { $filter: { input: "$incoming_vasp_tags", as: "t", cond: { $eq: ["$$t.tag", "exchange"] } } }, as: "t", in: "$$t.name" } }, 0] }, outgoing_vasp: { $arrayElemAt: [{ $map: { input: { $filter: { input: "$outgoing_vasp_tags", as: "t", cond: { $eq: ["$$t.tag", "exchange"] } } }, as: "t", in: "$$t.name" } }, 0] }, block_spread:  { $subtract: ["$outgoing_block_min", "$incoming_block_min"] }, jurisdiction:  { $literal: jurisdiction }, travel_rule_flag: { $literal: "CROSS_VASP_LAYERING" }, risk_score:    { $literal: "high" } } },
];

// ── USDT ERC-20 ───────────────────────────────────────────────────────────
const USDT_CONTRACT    = "0xdac17f958d2ee523a2206206994597c13d831ec7";
const USDT_PRECISION   = 1_000_000;
const ETH_BLOCKS_24H   = 6500;
const usdtRaw = (jurisdictionUSD) => jurisdictionUSD * USDT_PRECISION;

const excludeHotWalletsStageUSDT = () => ({ 
  $match: { 
    $and: [
      { token_transfer_from: { $nin: Array.from(hotAddresses) } }, 
      { token_transfer_to: { $nin: Array.from(hotAddresses) } },
      { _from: { $nin: Array.from(hotAddresses) } },
      { _to: { $nin: Array.from(hotAddresses) } }
    ] 
  } 
});

const _usdtBaseMatch = (address, currentEthBlock) => ({ 
  $match: { 
    address: USDT_CONTRACT, 
    token_transfer: true, 
    $or: [
      { token_transfer_from: address }, 
      { token_transfer_to: address },
      { _from: address },
      { _to: address }
    ], 
    block_number: { $gte: currentEthBlock - ETH_BLOCKS_24H } 
  } 
});

const eth_usdt_quick_succession_high_value_transaction = (address, currentEthBlock, jurisdiction = DEFAULT_JURISDICTION) => {
  const jConfig = JURISDICTION_CONFIG[jurisdiction];
  return [
    excludeHotWalletsStageUSDT(), _usdtBaseMatch(address, currentEthBlock),
    { 
      $addFields: { 
        safe_from: { $ifNull: ["$token_transfer_from", "$_from"] },
        safe_to: { $ifNull: ["$token_transfer_to", "$_to"] },
        usdtValueRaw: {
          $convert: {
            input: { $ifNull: ["$token_value", "$_value"] },
            to: "double",
            onError: 0,
            onNull: 0
          }
        }
      } 
    },
    {
      $facet: {
        data: [{ $sort: { block_number: -1 } }, { $project: { _id: 1, transaction_hash: 1, safe_from: 1, safe_to: 1, usdtValueRaw: 1, block_number: 1 } }],
        exists: [{ $match: { usdtValueRaw: { $gte: usdtRaw(jConfig.TRX_USDT) } } }, { $limit: 1 }],
        sub_threshold_txns: [{ $match: { usdtValueRaw: { $gt: USDT_PRECISION, $lt: usdtRaw(jConfig.TRX_USDT_EXT) } } }, { $group: { _id: null, count: { $sum: 1 }, total: { $sum: "$usdtValueRaw" }, triggering_txns: { $push: "$transaction_hash" } } }],
      },
    },
    { $addFields: { malicious: { $gt: [{ $size: "$exists" }, 0] }, tr4_structuring: { $and: [{ $gt: [{ $size: "$sub_threshold_txns" }, 0] }, { $gte: [{ $arrayElemAt: ["$sub_threshold_txns.count", 0] }, 3] }, { $gte: [{ $arrayElemAt: ["$sub_threshold_txns.total", 0] }, usdtRaw(jConfig.TRX_USDT_EXT)] }] } } },
    { $unwind: { path: "$data", preserveNullAndEmptyArrays: true } },
    { $replaceRoot: { newRoot: { $mergeObjects: ["$data", { $cond: { if: "$malicious", then: { risk_score: "mild", jurisdiction, travel_rule_trigger: { $cond: { if: "$tr4_structuring", then: "STRUCTURING_SMURFING", else: "$$REMOVE" } } }, else: { risk_score: "low" } } }] } } },
    { $limit: 1 }, { $project: { risk_score: 1, travel_rule_trigger: 1, jurisdiction: 1 } },
  ];
};

const eth_usdt_large_deposit_followed_by_immediate_withdrawl = (address, currentEthBlock, jurisdiction = DEFAULT_JURISDICTION) => [
  excludeHotWalletsStageUSDT(), _usdtBaseMatch(address, currentEthBlock),
  { 
    $addFields: { 
      safe_from: { $ifNull: ["$token_transfer_from", "$_from"] },
      safe_to: { $ifNull: ["$token_transfer_to", "$_to"] },
      usdtValueRaw: { $convert: { input: { $ifNull: ["$token_value", "$_value"] }, to: "double", onError: 0, onNull: 0 } }
    } 
  },
  ..._target_address_exchange_check("ethereum", address, "target_exchange_check"),
  ..._combined_tagpack_lookup("ethereum", "safe_to", "to_tags"),
  { $addFields: { direction: { $cond: [{ $eq: ["$safe_from", address] }, "outgoing", "incoming"] }, to_tag: { $arrayElemAt: ["$to_tags.tag", 0] }, counterparty:{ $cond: [{ $eq: ["$safe_from", address] }, "$safe_to", "$safe_from"] } } },
  {
    $facet: {
      incoming: [{ $match: { direction: "incoming" } }, { $project: { _id: 1, transaction_hash: 1, usdtValueRaw: 1, block_number: 1, counterparty: 1 } }],
      outgoing: [{ $match: { direction: "outgoing" } }, { $project: { _id: 1, transaction_hash: 1, usdtValueRaw: 1, block_number: 1, to_tag: 1, counterparty: 1 } }],
      vasp_transfers: [{ $match: { usdtValueRaw: { $gte: usdtRaw(JURISDICTION_CONFIG[jurisdiction].TRX_USDT_EXT) }, "to_tags.tag": "exchange" } }, { $limit: 1 }],
      unhosted_transfers: [{ $match: { usdtValueRaw: { $gte: usdtRaw(JURISDICTION_CONFIG[jurisdiction].TRX_USDT_EXT) }, to_tags: { $size: 0 } } }, { $limit: 1 }],
    },
  },
  {
    $project: {
      risky_pairs: { $map: { input: "$incoming", as: "inc", in: { incoming_transaction_hash: "$$inc.transaction_hash", outgoing_txn: { $first: { $filter: { input: "$outgoing", as: "out", cond: { $and: [{ $lte: [{ $abs: { $subtract: ["$$out.block_number", "$$inc.block_number"] } }, 450] }, { $lte: [{ $abs: { $subtract: ["$$out.usdtValueRaw", "$$inc.usdtValueRaw"] } }, { $multiply: ["$$inc.usdtValueRaw", 0.05] }] }, { $ne: ["$$out.to_tag", "exchange"] }] } } } } } } },
      vasp_transfers: 1, unhosted_transfers: 1,
    },
  },
  { $addFields: { risky_pairs: { $filter: { input: "$risky_pairs", as: "p", cond: { $ifNull: ["$$p.outgoing_txn", false] } } }, tr1_vasp_breach:{ $gt: [{ $size: "$vasp_transfers" }, 0] }, tr2_unhosted: { $gt: [{ $size: "$unhosted_transfers" }, 0] } } },
  { $addFields: { risk_score: { $cond: [{ $gt: [{ $size: "$risky_pairs" }, 0] }, "high", "none"] }, jurisdiction, travel_rule_triggers: { $filter: { input: [{ $cond: ["$tr1_vasp_breach", "THRESHOLD_BREACH_KNOWN_VASP", "$$REMOVE"] }, { $cond: [{ $and: ["$tr2_unhosted", { $ne: [jurisdiction, "SG"] }] }, "UNHOSTED_WALLET_LARGE_TRANSFER", "$$REMOVE"] }, { $cond: [{ $and: ["$tr2_unhosted", { $eq: [jurisdiction, "SG"] }] }, "UNHOSTED_ELEVATED_RISK_SG", "$$REMOVE"] }], as: "tr", cond: { $ne: ["$$tr", null] } } } } },
  { $project: { risky_pairs: 1, risk_score: 1, travel_rule_triggers: 1, jurisdiction: 1 } },
];

const eth_usdt_fatf_low_value_transactions = (address, currentEthBlock, jurisdiction = DEFAULT_JURISDICTION) => [
  excludeHotWalletsStageUSDT(), _usdtBaseMatch(address, currentEthBlock),
  { 
    $addFields: { 
      safe_from: { $ifNull: ["$token_transfer_from", "$_from"] },
      usdtValueRaw: { $convert: { input: { $ifNull: ["$token_value", "$_value"] }, to: "double", onError: 0, onNull: 0 } }
    } 
  },
  { $match: { safe_from: address } }, 
  { $match: { usdtValueRaw: { $lt: USDT_PRECISION } } }, 
  { $group: { _id: "$safe_from", min_amount: { $min: "$usdtValueRaw" }, dust_count: { $sum: 1 }, triggering_txns: { $push: "$transaction_hash" } } },
  { $project: { _id: 0, from_address: "$_id", amount_usdt: { $divide: ["$min_amount", USDT_PRECISION] }, triggering_txns: { $slice: ["$triggering_txns", 20] }, dust_count: 1, risk_score: { $literal: "mild" }, jurisdiction: { $literal: jurisdiction }, travel_rule_trigger: { $literal: "STRUCTURING_SMURFING" } } },
];

const eth_usdt_combined_rule_for_flagged_addresses = (address, currentEthBlock, jurisdiction = DEFAULT_JURISDICTION) => [
  excludeHotWalletsStageUSDT(), _usdtBaseMatch(address, currentEthBlock),
  { 
    $addFields: { 
      safe_from: { $ifNull: ["$token_transfer_from", "$_from"] },
      safe_to: { $ifNull: ["$token_transfer_to", "$_to"] },
      usdtValueRaw: { $convert: { input: { $ifNull: ["$token_value", "$_value"] }, to: "double", onError: 0, onNull: 0 } }
    } 
  },
  { $project: { transaction_hash: 1, original: { $cond: [{ $eq: ["$safe_from", address] }, "$safe_from", "$safe_to"] }, counterparty:{ $cond: [{ $eq: ["$safe_from", address] }, "$safe_to", "$safe_from"] }, usdtValue: { $divide: ["$usdtValueRaw", USDT_PRECISION] } } },
  { $match: { counterparty: { $nin: SAFE_CONTRACT_WHITELIST_ETH } } },
  ..._combined_tagpack_lookup("ethereum", "counterparty", "counterparty_tags"),
  { $unwind: "$counterparty_tags" },
  { $addFields: { effective_risk_tag: { $cond: { if: { $and: [{ $ne: ["$counterparty_tags.subTag", null] }, { $ne: ["$counterparty_tags.subTag", ""] }] }, then: "$counterparty_tags.subTag", else: "$counterparty_tags.tag" } } } },
  { $match: { effective_risk_tag: { $in: Object.keys(tag_list_with_scores[0]) } } },
  { $addFields: { risk_score: { $switch: { branches: Object.entries(tag_list_with_scores[0]).map(([tag, score]) => ({ case: { $eq: ["$effective_risk_tag", tag] }, then: score })), default: "low" } }, travel_rule_trigger: { $cond: { if: { $eq: ["$counterparty_tags.mal", true] }, then: "SANCTIONS_HIT", else: "$$REMOVE" } }, sanctions_hit: { $eq: ["$counterparty_tags.mal", true] } } },
  { $project: { _id: 0, transaction_hash: 1, original: 1, counterparty: 1, usdtValue: 1, tag: "$effective_risk_tag", risk_score: 1, jurisdiction: { $literal: jurisdiction }, travel_rule_trigger: 1, sanctions_hit: 1 } },
];

const eth_usdt_whale_out = (address, amountUSDT, currentEthBlock, jurisdiction = DEFAULT_JURISDICTION) => [
  excludeHotWalletsStageUSDT(), 
  _usdtBaseMatch(address, currentEthBlock),
  { 
    $addFields: { 
      safe_from: { $ifNull: ["$token_transfer_from", "$_from"] },
      safe_to: { $ifNull: ["$token_transfer_to", "$_to"] },
      usdtValueRaw: { $convert: { input: { $ifNull: ["$token_value", "$_value"] }, to: "double", onError: 0, onNull: 0 } }
    } 
  },
  { $match: { safe_from: address } },
  { $match: { usdtValueRaw: { $gte: amountUSDT * USDT_PRECISION } } },
  { $addFields: { usdtValue: { $divide: ["$usdtValueRaw", USDT_PRECISION] } } },
  ..._combined_tagpack_lookup("ethereum", "safe_to", "to_tags"),
  {
    $addFields: {
      is_known_vasp:          { $gt: [{ $size: { $filter: { input: "$to_tags", as: "t", cond: { $eq: ["$$t.tag", "exchange"] } } } }, 0] },
      is_low_confidence_vasp: { $gt: [{ $size: { $filter: { input: "$to_tags", as: "t", cond: { $and: [{ $eq: ["$$t.tag", "exchange"] }, { $lt: ["$$t.confidence", 50] }] } } } }, 0] },
      is_unhosted:            { $eq: [{ $size: "$to_tags" }, 0] },
    },
  },
  {
    $project: {
      _id: 0, transaction_hash: 1, address: "$safe_from", usdtValue: 1, risk_score: { $literal: "high" }, jurisdiction: { $literal: jurisdiction },
      travel_rule_triggers: {
        $filter: {
          input: [
            { $cond: ["$is_known_vasp", "THRESHOLD_BREACH_KNOWN_VASP", "$$REMOVE"] },
            { $cond: [{ $and: ["$is_unhosted", { $ne: [jurisdiction, "SG"] }] }, "UNHOSTED_WALLET_LARGE_TRANSFER", "$$REMOVE"] },
            { $cond: [{ $and: ["$is_unhosted", { $eq: [jurisdiction, "SG"] }] }, "UNHOSTED_ELEVATED_RISK_SG", "$$REMOVE"] },
            { $cond: ["$is_low_confidence_vasp", "LOW_CONFIDENCE_VASP", "$$REMOVE"] },
          ], as: "tr", cond: { $ne: ["$$tr", null] },
        },
      },
    },
  },
];

const eth_usdt_whale_in = (address, amountUSDT, currentEthBlock, jurisdiction = DEFAULT_JURISDICTION) => [
  excludeHotWalletsStageUSDT(), 
  _usdtBaseMatch(address, currentEthBlock),
  { 
    $addFields: { 
      safe_from: { $ifNull: ["$token_transfer_from", "$_from"] },
      safe_to: { $ifNull: ["$token_transfer_to", "$_to"] },
      usdtValueRaw: { $convert: { input: { $ifNull: ["$token_value", "$_value"] }, to: "double", onError: 0, onNull: 0 } }
    } 
  },
  { $match: { safe_to: address } },
  { $match: { usdtValueRaw: { $gte: amountUSDT * USDT_PRECISION } } },
  { $addFields: { usdtValue: { $divide: ["$usdtValueRaw", USDT_PRECISION] } } },
  ..._combined_tagpack_lookup("ethereum", "safe_from", "from_tags"),
  { 
    $addFields: { 
      is_known_vasp: { $gt: [{ $size: { $filter: { input: "$from_tags", as: "t", cond: { $eq: ["$$t.tag", "exchange"] } } } }, 0] }, 
      is_low_confidence_vasp: { $gt: [{ $size: { $filter: { input: "$from_tags", as: "t", cond: { $and: [{ $eq: ["$$t.tag", "exchange"] }, { $lt: ["$$t.confidence", 50] }] } } } }, 0] }, 
      is_unhosted: { $eq: [{ $size: "$from_tags" }, 0] } 
    } 
  },
  { 
    $project: { 
      _id: 0, transaction_hash: 1, address: "$safe_to", usdtValue: 1, risk_score: { $literal: "high" }, jurisdiction: { $literal: jurisdiction }, 
      travel_rule_triggers: { 
        $filter: { 
          input: [
            { $cond: ["$is_known_vasp", "THRESHOLD_BREACH_KNOWN_VASP", "$$REMOVE"] }, 
            { $cond: [{ $and: ["$is_unhosted", { $ne: [jurisdiction, "SG"] }] }, "UNHOSTED_WALLET_LARGE_TRANSFER", "$$REMOVE"] }, 
            { $cond: [{ $and: ["$is_unhosted", { $eq: [jurisdiction, "SG"] }] }, "UNHOSTED_ELEVATED_RISK_SG", "$$REMOVE"] }, 
            { $cond: ["$is_low_confidence_vasp", "LOW_CONFIDENCE_VASP", "$$REMOVE"] }
          ], 
          as: "tr", cond: { $ne: ["$$tr", null] } 
        } 
      } 
    } 
  },
];

const eth_usdt_tr_threshold_breach_known_vasp = (address, currentEthBlock, jurisdiction = DEFAULT_JURISDICTION) => {
  const jConfig = JURISDICTION_CONFIG[jurisdiction];
  return [
    excludeHotWalletsStageUSDT(), _usdtBaseMatch(address, currentEthBlock),
    { 
      $addFields: { 
        safe_from: { $ifNull: ["$token_transfer_from", "$_from"] },
        safe_to: { $ifNull: ["$token_transfer_to", "$_to"] },
        usdtValueRaw: { $convert: { input: { $ifNull: ["$token_value", "$_value"] }, to: "double", onError: 0, onNull: 0 } }
      } 
    },
    { $addFields: { counterparty: { $cond: [{ $eq: ["$safe_from", address] }, "$safe_to", "$safe_from"] } } },
    ...(jConfig.two_tier || usdtRaw(jConfig.TRX_USDT) === 0 ? [] : [{ $match: { usdtValueRaw: { $gte: usdtRaw(jConfig.TRX_USDT) } } }]),
    ..._combined_tagpack_lookup("ethereum", "counterparty", "cp_tags"),
    { $match: { cp_tags: { $elemMatch: { tag: "exchange" } } } },
    { $project: { _id: 0, transaction_hash: 1, address: { $literal: address }, counterparty: 1, usdt_amount: { $divide: ["$usdtValueRaw", USDT_PRECISION] }, obligation_tier: { $cond: [{ $gte: ["$usdtValueRaw", usdtRaw(jConfig.TRX_USDT_EXT)] }, "extended_pii", "basic_pii"] }, jurisdiction: { $literal: jurisdiction }, travel_rule_flag: { $literal: "THRESHOLD_BREACH_KNOWN_VASP" }, risk_score: { $cond: [{ $gte: ["$usdtValueRaw", usdtRaw(jConfig.TRX_USDT_EXT)] }, "medium", "mild"] } } },
    { $limit: 1 },
  ];
};

const eth_usdt_tr_unhosted_wallet_large_transfer = (address, currentEthBlock, jurisdiction = DEFAULT_JURISDICTION) => [
  excludeHotWalletsStageUSDT(), _usdtBaseMatch(address, currentEthBlock),
  { 
    $addFields: { 
      safe_from: { $ifNull: ["$token_transfer_from", "$_from"] },
      safe_to: { $ifNull: ["$token_transfer_to", "$_to"] },
      usdtValueRaw: { $convert: { input: { $ifNull: ["$token_value", "$_value"] }, to: "double", onError: 0, onNull: 0 } }
    } 
  },
  { $addFields: { counterparty: { $cond: [{ $eq: ["$safe_from", address] }, "$safe_to", "$safe_from"] } } },
  { $match: { usdtValueRaw: { $gte: usdtRaw(JURISDICTION_CONFIG[jurisdiction].TRX_USDT_EXT) } } },
  ..._combined_tagpack_lookup("ethereum", "counterparty", "cp_tags"),
  { $match: { cp_tags: { $size: 0 } } },
  { $project: { _id: 0, transaction_hash: 1, address: { $literal: address }, counterparty: 1, usdt_amount: { $divide: ["$usdtValueRaw", USDT_PRECISION] }, jurisdiction: { $literal: jurisdiction }, travel_rule_flag: { $literal: jurisdiction === "SG" ? "UNHOSTED_ELEVATED_RISK_SG" : "UNHOSTED_WALLET_LARGE_TRANSFER" }, risk_score: { $literal: "medium" }, sg_exempt: { $literal: jurisdiction === "SG" } } },
  { $limit: 1 },
];

const eth_usdt_tr_sanctions_hit = (address, currentEthBlock, jurisdiction = DEFAULT_JURISDICTION) => [
  excludeHotWalletsStageUSDT(), _usdtBaseMatch(address, currentEthBlock),
  { 
    $addFields: { 
      safe_from: { $ifNull: ["$token_transfer_from", "$_from"] },
      safe_to: { $ifNull: ["$token_transfer_to", "$_to"] },
    } 
  },
  { $addFields: { counterparty: { $cond: [{ $eq: ["$safe_from", address] }, "$safe_to", "$safe_from"] } } },
  { $match: { counterparty: { $nin: SAFE_CONTRACT_WHITELIST_ETH } } },
  ..._combined_tagpack_lookup("ethereum", "counterparty", "cp_tags"),
  { $match: { cp_tags: { $elemMatch: { mal: true } } } },
  { $project: { _id: 0, transaction_hash: 1, address: { $literal: address }, counterparty: 1, jurisdiction: { $literal: jurisdiction }, travel_rule_flag: { $literal: "SANCTIONS_HIT" }, risk_score: { $literal: "high" }, sanctions_hit: { $literal: true } } },
  { $limit: 1 },
];

const eth_usdt_tr_structuring_smurfing = (address, currentEthBlock, jurisdiction = DEFAULT_JURISDICTION) => [
  excludeHotWalletsStageUSDT(), _usdtBaseMatch(address, currentEthBlock),
  { 
    $addFields: { 
      usdtValueRaw: { $convert: { input: { $ifNull: ["$token_value", "$_value"] }, to: "double", onError: 0, onNull: 0 } }
    } 
  },
  { $match: { usdtValueRaw: { $gt: USDT_PRECISION, $lt: usdtRaw(JURISDICTION_CONFIG[jurisdiction].TRX_USDT_EXT) } } },
  { $group: { _id: null, txn_count: { $sum: 1 }, total_value: { $sum: "$usdtValueRaw" }, triggering_txns: { $push: "$transaction_hash" } } },
  { $match: { txn_count: { $gte: 3 }, total_value: { $gte: usdtRaw(JURISDICTION_CONFIG[jurisdiction].TRX_USDT_EXT) } } },
  { $project: { _id: 0, address: { $literal: address }, txn_count: 1, triggering_txns: { $slice: ["$triggering_txns", 20] }, total_usdt: { $divide: ["$total_value", USDT_PRECISION] }, jurisdiction: { $literal: jurisdiction }, travel_rule_flag: { $literal: "STRUCTURING_SMURFING" }, risk_score: { $literal: "high" } } },
];

const eth_usdt_tr_low_confidence_vasp = (address, currentEthBlock, jurisdiction = DEFAULT_JURISDICTION) => [
  excludeHotWalletsStageUSDT(), _usdtBaseMatch(address, currentEthBlock),
  { 
    $addFields: { 
      safe_from: { $ifNull: ["$token_transfer_from", "$_from"] },
      safe_to: { $ifNull: ["$token_transfer_to", "$_to"] },
    } 
  },
  { $addFields: { counterparty: { $cond: [{ $eq: ["$safe_from", address] }, "$safe_to", "$safe_from"] } } },
  ..._combined_tagpack_lookup("ethereum", "counterparty", "cp_tags"),
  { $match: { cp_tags: { $elemMatch: { tag: "exchange", confidence: { $lt: 50 } } } } },
  { $project: { _id: 0, transaction_hash: 1, address: { $literal: address }, counterparty: 1, jurisdiction: { $literal: jurisdiction }, travel_rule_flag: { $literal: "LOW_CONFIDENCE_VASP" }, risk_score: { $literal: "medium" } } },
  { $limit: 1 },
];

const eth_usdt_tr_cross_vasp_layering = (address, currentEthBlock, jurisdiction = DEFAULT_JURISDICTION) => [
  excludeHotWalletsStageUSDT(), _usdtBaseMatch(address, currentEthBlock),
  { 
    $addFields: { 
      safe_from: { $ifNull: ["$token_transfer_from", "$_from"] },
      safe_to: { $ifNull: ["$token_transfer_to", "$_to"] },
    } 
  },
  { $addFields: { direction: { $cond: [{ $eq: ["$safe_from", address] }, "outgoing", "incoming"] }, counterparty:{ $cond: [{ $eq: ["$safe_from", address] }, "$safe_to", "$safe_from"] } } },
  ..._combined_tagpack_lookup("ethereum", "counterparty", "cp_tags"),
  { $addFields: { is_vasp: { $gt: [{ $size: { $filter: { input: "$cp_tags", as: "t", cond: { $eq: ["$$t.tag", "exchange"] } } } }, 0] } } },
  { $facet: { vasp_incoming: [{ $match: { direction: "incoming", is_vasp: true } }, { $project: { transaction_hash: 1, block_number: 1 } }], vasp_outgoing: [{ $match: { direction: "outgoing", is_vasp: true } }, { $project: { transaction_hash: 1, block_number: 1 } }] } },
  { $addFields: { layering_detected: { $gt: [{ $size: { $filter: { input: "$vasp_incoming", as: "inc", cond: { $gt: [{ $size: { $filter: { input: "$vasp_outgoing", as: "out", cond: { $and: [{ $gte: ["$$out.block_number", "$$inc.block_number"] }, { $lte: [{ $subtract: ["$$out.block_number", "$$inc.block_number"] }, 450] }] } } } }, 0] } } } }, 0] } } },
  { $match: { layering_detected: true } },
  { $project: { _id: 0, address: { $literal: address }, incoming_txns: { $slice: ["$vasp_incoming.transaction_hash", 20] }, outgoing_txns: { $slice: ["$vasp_outgoing.transaction_hash", 20] }, jurisdiction: { $literal: jurisdiction }, travel_rule_flag: { $literal: "CROSS_VASP_LAYERING" }, risk_score: { $literal: "high" } } },
];

// ── TRON NATIVE ───────────────────────────────────────────────────────────

const tron_quick_succession_high_value_transaction = (address, amount, jurisdiction = DEFAULT_JURISDICTION) => [
  excludeHotWalletsStageUSDT(),
  { $addFields: { trxValue: { $divide: [{ $convert: { input: { $ifNull: ["$token_value", 0] }, to: "double", onError: 0, onNull: 0 } }, 1000000] }, currentTime: { $toLong: "$$NOW" } } },
  { $addFields: { currentUnixSeconds: { $floor: { $divide: ["$currentTime", 1000] } } } },
  {
    $match: {
      $or: [{ token_transfer_from: address }, { token_transfer_to: address }],
      token_name: "USDT",
      $expr: {
        $gte: [
          { $floor: { $divide: [{ $ifNull: ["$block_timestamp", "$block_timestamp"] }, 1000] } },
          { $subtract: ["$currentUnixSeconds", 86400] },
        ],
      },
    },
  },
  {
    $lookup: {
      from: "tron_tokens",
      let:  { token_name: "$tokenName" },
      pipeline: [
        { $match: { $expr: { $eq: ["$symbol", "$$token_name"] } } },
        { $project: { price: { $cond: [{ $eq: ["$price", ""] }, "0", "$price"] }, _id: 0 } },
      ],
      as: "token_info",
    },
  },
  { $unwind: { path: "$token_info", preserveNullAndEmptyArrays: true } },
  { $addFields: { trxValueUSD: { $multiply: ["$trxValue", { $toDouble: "$token_info.price" }] } } },
  {
    $facet: {
      data: [
        { $sort: { block_timestamp: -1 } },
        { $project: { _id: 1, transaction_hash: "$transaction_hash", token_transfer_from: 1, token_transfer_to: 1, trxValue: 1, trxValueUSD: 1, block_timestamp: 1 } },
      ],
      isMalicious: [
        { $match: { $expr: { $gt: ["$trxValueUSD", parseInt(amount)] } } },
        { $limit: 1 },
      ],
      sub_threshold: [
        { $match: { trxValue: { $gt: 1, $lt: TR_THRESHOLDS.TRX_USDT } } },
        { $group: { _id: null, count: { $sum: 1 }, total: { $sum: "$trxValue" }, triggering_txns: { $push: "$transaction_hash" } } },
      ],
    },
  },
  {
    $addFields: {
      malicious: { $gt: [{ $size: "$isMalicious" }, 0] },
      tr4_structuring: {
        $and: [
          { $gt: [{ $size: "$sub_threshold" }, 0] },
          { $gte: [{ $arrayElemAt: ["$sub_threshold.count", 0] }, 3] },
          { $gte: [{ $arrayElemAt: ["$sub_threshold.total", 0] }, TR_THRESHOLDS.TRX_USDT] },
        ],
      },
    },
  },
  { $addFields: { malicious: { $ifNull: ["$malicious", false] } } },
  { $unwind: { path: "$data", preserveNullAndEmptyArrays: true } },
  {
    $replaceRoot: {
      newRoot: {
        $mergeObjects: [
          { $ifNull: ["$data", {}] },
          {
            $cond: {
              if:   "$malicious",
              then: {
                risk_score: "mild",
                travel_rule_trigger: { $cond: { if: "$tr4_structuring", then: "STRUCTURING_SMURFING", else: "$$REMOVE" } },
              },
              else: { risk_score: "low" },
            },
          },
        ],
      },
    },
  },
  { $limit: 1 },
  { $project: { risk_score: 1, travel_rule_trigger: 1 } },
];

const tron_large_deposit_followed_by_immediate_withdrawl = (address, jurisdiction = DEFAULT_JURISDICTION) => [
  excludeHotWalletsStageUSDT(),
  ..._target_address_exchange_check("tron", address, "target_address_exchange_check"),
  { $match: { $or: [{ token_transfer_from: address }, { token_transfer_to: address }], token_name: "USDT" } },
  ..._combined_tagpack_lookup("tron", "token_transfer_to", "to_tags"),
  {
    $addFields: {
      direction: { $cond: [{ $eq: ["$token_transfer_from", address] }, "outgoing", "incoming"] },
      to_tag:    { $arrayElemAt: ["$to_tags.tag", 0] },
      trxValue:  { $divide: [{ $convert: { input: { $ifNull: ["$token_value", 0] }, to: "double", onError: 0, onNull: 0 } }, 1000000] },
    },
  },
  {
    $facet: {
      incoming: [
        { $match: { direction: "incoming" } },
        { $project: { transaction_hash: 1, transaction_hash: "$transaction_hash", amount: { $divide: [{ $convert: { input: { $ifNull: ["$token_value", 0] }, to: "double", onError: 0, onNull: 0 } }, 1000000] }, expiration: { $toLong: "$block_timestamp" } } },
      ],
      outgoing: [
        { $match: { direction: "outgoing" } },
        { $project: { transaction_hash: 1, transaction_hash: "$transaction_hash", amount: { $divide: [{ $convert: { input: { $ifNull: ["$token_value", 0] }, to: "double", onError: 0, onNull: 0 } }, 1000000] }, expiration: { $toLong: "$block_timestamp" }, to_tag: 1 } },
      ],
      vasp_transfers:     [{ $match: { trxValue: { $gte: TR_THRESHOLDS.TRX_USDT }, "to_tags.tag": "exchange" } }, { $limit: 1 }],
      unhosted_transfers: [{ $match: { trxValue: { $gte: TR_THRESHOLDS.TRX_USDT }, to_tags: { $size: 0 } } },   { $limit: 1 }],
    },
  },
  {
    $project: {
      risky_pairs: {
        $map: {
          input: "$incoming",
          as: "inc",
          in: {
            incoming_transaction_hash: "$$inc.transaction_hash",
            outgoing_txn: {
              $first: {
                $filter: {
                  input: "$outgoing",
                  as: "out",
                  cond: {
                    $and: [
                      { $gte: ["$$out.expiration", "$$inc.expiration"] },
                      { $lte: [{ $subtract: ["$$out.expiration", "$$inc.expiration"] }, 3600 * 1000] },
                      { $lte: [{ $abs: { $subtract: ["$$out.amount", "$$inc.amount"] } }, { $multiply: ["$$inc.amount", 0.05] }] },
                      { $ne: ["$$out.to_tag", "exchange"] },
                    ],
                  },
                },
              },
            },
          },
        },
      },
      vasp_transfers: 1, unhosted_transfers: 1,
    },
  },
  {
    $addFields: {
      risky_pairs:    { $filter: { input: "$risky_pairs", as: "p", cond: { $ifNull: ["$$p.outgoing_txn", false] } } },
      tr1_vasp_breach:{ $gt: [{ $size: "$vasp_transfers" }, 0] },
      tr2_unhosted:   { $gt: [{ $size: "$unhosted_transfers" }, 0] },
    },
  },
  {
    $addFields: {
      risk_score: { $cond: [{ $gt: [{ $size: "$risky_pairs" }, 0] }, "high", "none"] },
      travel_rule_triggers: {
        $filter: {
          input: [
            { $cond: ["$tr1_vasp_breach", "THRESHOLD_BREACH_KNOWN_VASP", "$$REMOVE"] },
            { $cond: ["$tr2_unhosted", "UNHOSTED_WALLET_LARGE_TRANSFER", "$$REMOVE"] },
          ],
          as: "tr", cond: { $ne: ["$$tr", null] },
        },
      },
    },
  },
  { $project: { risky_pairs: 1, risk_score: 1, travel_rule_triggers: 1 } },
];

const tron_fatf_low_value_transactions = (address, jurisdiction = DEFAULT_JURISDICTION) => [
  excludeHotWalletsStageUSDT(),
  { $match: { token_transfer_from: address, token_name: "USDT" } },
  { $addFields: { trxValue: { $divide: [{ $convert: { input: { $ifNull: ["$token_value", 0] }, to: "double", onError: 0, onNull: 0 } }, 1000000] } } },
  { $match: { trxValue: { $lt: 1 } } },
  { $group: { _id: "$token_transfer_from", min_amount: { $min: "$trxValue" }, dust_count: { $sum: 1 }, triggering_txns: { $push: "$transaction_hash" } } },
  { $project: { _id: 0, from_address: "$_id", amount: "$min_amount", triggering_txns: { $slice: ["$triggering_txns", 20] }, risk_score: { $literal: "mild" }, travel_rule_trigger: { $literal: "STRUCTURING_SMURFING" } } },
];

const tron_combined_rule_for_flagged_addresses = (address, jurisdiction = DEFAULT_JURISDICTION) => [
  excludeHotWalletsStageUSDT(),
  { $match: { $or: [{ token_transfer_from: address }, { token_transfer_to: address }] } },
  {
    $project: {
      transaction_hash: "$transaction_hash",
      original:    { $cond: [{ $eq: ["$token_transfer_from", address] }, "$token_transfer_from", "$token_transfer_to"] },
      counterparty:{ $cond: [{ $eq: ["$token_transfer_from", address] }, "$token_transfer_to", "$token_transfer_from"] },
    },
  },
  { $match: { counterparty: { $nin: SAFE_CONTRACT_WHITELIST_TRON } } },
  ..._combined_tagpack_lookup("tron", "counterparty", "counterparty_tags"),
  { $unwind: "$counterparty_tags" },
  {
    $addFields: {
      effective_risk_tag: {
        $cond: {
          if:   { $and: [{ $ne: ["$counterparty_tags.subTag", null] }, { $ne: ["$counterparty_tags.subTag", ""] }] },
          then: "$counterparty_tags.subTag",
          else: "$counterparty_tags.tag"
        }
      }
    }
  },
  { $match: { effective_risk_tag: { $in: Object.keys(tag_list_with_scores[0]) } } },
  {
    $addFields: {
      risk_score: {
        $switch: {
          branches: Object.entries(tag_list_with_scores[0]).map(([tag, score]) => ({
            case: { $eq: ["$effective_risk_tag", tag] }, then: score,
          })),
          default: "low",
        },
      },
      travel_rule_trigger: { $cond: { if: { $eq: ["$counterparty_tags.mal", true] }, then: "SANCTIONS_HIT", else: "$$REMOVE" } },
      sanctions_hit: { $eq: ["$counterparty_tags.mal", true] },
    },
  },
  {
    $project: {
      _id: 0, transaction_hash: 1, original: 1, counterparty: 1,
      tag: "$effective_risk_tag", risk_score: 1,
      travel_rule_trigger: 1, sanctions_hit: 1,
    },
  },
];

const tron_fatf_whale_out = (address, amount, jurisdiction = DEFAULT_JURISDICTION) => [
  excludeHotWalletsStageUSDT(),
  { $match: { token_transfer_from: address, token_name: "USDT" } },
  { $addFields: { trxValue: { $divide: [{ $convert: { input: { $ifNull: ["$token_value", 0] }, to: "double", onError: 0, onNull: 0 } }, 1000000] } } },
  { $match: { trxValue: { $gte: parseInt(amount) } } },
  ..._combined_tagpack_lookup("tron", "token_transfer_to", "to_tags"),
  {
    $addFields: {
      is_known_vasp:          { $gt: [{ $size: { $filter: { input: "$to_tags", as: "t", cond: { $eq: ["$$t.tag", "exchange"] } } } }, 0] },
      is_low_confidence_vasp: { $gt: [{ $size: { $filter: { input: "$to_tags", as: "t", cond: { $and: [{ $eq: ["$$t.tag", "exchange"] }, { $lt: ["$$t.confidence", 50] }] } } } }, 0] },
      is_unhosted: { $eq: [{ $size: "$to_tags" }, 0] },
    },
  },
  {
    $project: {
      _id: 0, transaction_hash: "$transaction_hash", address: "$token_transfer_from",
      risk_score: { $literal: "high" },
      travel_rule_triggers: {
        $filter: {
          input: [
            { $cond: ["$is_known_vasp", "THRESHOLD_BREACH_KNOWN_VASP", "$$REMOVE"] },
            { $cond: ["$is_unhosted", "UNHOSTED_WALLET_LARGE_TRANSFER", "$$REMOVE"] },
            { $cond: ["$is_low_confidence_vasp", "LOW_CONFIDENCE_VASP", "$$REMOVE"] },
          ],
          as: "tr", cond: { $ne: ["$$tr", null] },
        },
      },
    },
  },
];

const tron_fatf_whale_in = (address, amount, jurisdiction = DEFAULT_JURISDICTION) => [
  excludeHotWalletsStageUSDT(),
  { $match: { token_transfer_to: address, token_name: "USDT" } },
  { $addFields: { trxValue: { $divide: [{ $convert: { input: { $ifNull: ["$token_value", 0] }, to: "double", onError: 0, onNull: 0 } }, 1000000] } } },
  { $match: { trxValue: { $gte: parseInt(amount) } } },
  ..._combined_tagpack_lookup("tron", "token_transfer_from", "from_tags"),
  {
    $addFields: {
      is_known_vasp:          { $gt: [{ $size: { $filter: { input: "$from_tags", as: "t", cond: { $eq: ["$$t.tag", "exchange"] } } } }, 0] },
      is_low_confidence_vasp: { $gt: [{ $size: { $filter: { input: "$from_tags", as: "t", cond: { $and: [{ $eq: ["$$t.tag", "exchange"] }, { $lt: ["$$t.confidence", 50] }] } } } }, 0] },
      is_unhosted: { $eq: [{ $size: "$from_tags" }, 0] },
    },
  },
  {
    $project: {
      _id: 0, transaction_hash: "$transaction_hash", address: "$token_transfer_to",
      risk_score: { $literal: "high" },
      travel_rule_triggers: {
        $filter: {
          input: [
            { $cond: ["$is_known_vasp", "THRESHOLD_BREACH_KNOWN_VASP", "$$REMOVE"] },
            { $cond: ["$is_unhosted", "UNHOSTED_WALLET_LARGE_TRANSFER", "$$REMOVE"] },
            { $cond: ["$is_low_confidence_vasp", "LOW_CONFIDENCE_VASP", "$$REMOVE"] },
          ],
          as: "tr", cond: { $ne: ["$$tr", null] },
        },
      },
    },
  },
];

const tron_tr_threshold_breach_known_vasp = (address, jurisdiction = DEFAULT_JURISDICTION) => [
  excludeHotWalletsStageUSDT(),
  { $match: { $or: [{ token_transfer_from: address }, { token_transfer_to: address }], token_name: "USDT" } },
  { $addFields: { trxValue: { $divide: [{ $convert: { input: { $ifNull: ["$token_value", 0] }, to: "double", onError: 0, onNull: 0 } }, 1000000] }, counterparty: { $cond: [{ $eq: ["$token_transfer_from", address] }, "$token_transfer_to", "$token_transfer_from"] } } },
  { $match: { trxValue: { $gte: TR_THRESHOLDS.TRX_USDT } } },
  ..._combined_tagpack_lookup("tron", "counterparty", "cp_tags"),
  { $match: { cp_tags: { $elemMatch: { tag: "exchange" } } } },
  { $project: { _id: 0, transaction_hash: "$transaction_hash", address: { $literal: address }, counterparty: 1, trxValue: 1, travel_rule_flag: { $literal: "THRESHOLD_BREACH_KNOWN_VASP" }, risk_score: { $literal: "medium" } } },
  { $limit: 1 },
];

const tron_tr_unhosted_wallet_large_transfer = (address, jurisdiction = DEFAULT_JURISDICTION) => [
  excludeHotWalletsStageUSDT(),
  { $match: { $or: [{ token_transfer_from: address }, { token_transfer_to: address }], token_name: "USDT" } },
  { $addFields: { trxValue: { $divide: [{ $convert: { input: { $ifNull: ["$token_value", 0] }, to: "double", onError: 0, onNull: 0 } }, 1000000] }, counterparty: { $cond: [{ $eq: ["$token_transfer_from", address] }, "$token_transfer_to", "$token_transfer_from"] } } },
  { $match: { trxValue: { $gte: TR_THRESHOLDS.TRX_USDT } } },
  ..._combined_tagpack_lookup("tron", "counterparty", "cp_tags"),
  { $match: { cp_tags: { $size: 0 } } },
  { $project: { _id: 0, transaction_hash: "$transaction_hash", address: { $literal: address }, counterparty: 1, trxValue: 1, travel_rule_flag: { $literal: "UNHOSTED_WALLET_LARGE_TRANSFER" }, risk_score: { $literal: "medium" } } },
  { $limit: 1 },
];

const tron_tr_sanctions_hit = (address, jurisdiction = DEFAULT_JURISDICTION) => [
  excludeHotWalletsStageUSDT(),
  { $match: { $or: [{ token_transfer_from: address }, { token_transfer_to: address }] } },
  { $addFields: { counterparty: { $cond: [{ $eq: ["$token_transfer_from", address] }, "$token_transfer_to", "$token_transfer_from"] } } },
  { $match: { counterparty: { $nin: SAFE_CONTRACT_WHITELIST_TRON } } },
  ..._combined_tagpack_lookup("tron", "counterparty", "cp_tags"),
  { $match: { cp_tags: { $elemMatch: { mal: true } } } },
  { $project: { _id: 0, transaction_hash: "$transaction_hash", address: { $literal: address }, counterparty: 1, travel_rule_flag: { $literal: "SANCTIONS_HIT" }, risk_score: { $literal: "high" }, sanctions_hit: { $literal: true } } },
  { $limit: 1 },
];

const tron_tr_structuring_smurfing = (address, jurisdiction = DEFAULT_JURISDICTION) => [
  excludeHotWalletsStageUSDT(),
  { $match: { $or: [{ token_transfer_from: address }, { token_transfer_to: address }], token_name: "USDT" } },
  { $addFields: { trxValue: { $divide: [{ $convert: { input: { $ifNull: ["$token_value", 0] }, to: "double", onError: 0, onNull: 0 } }, 1000000] } } },
  { $match: { trxValue: { $gt: 1, $lt: TR_THRESHOLDS.TRX_USDT } } },
  { $group: { _id: null, txn_count: { $sum: 1 }, total_value: { $sum: "$trxValue" }, triggering_txns: { $push: "$transaction_hash" } } },
  { $match: { txn_count: { $gte: 3 }, total_value: { $gte: TR_THRESHOLDS.TRX_USDT } } },
  { $project: { _id: 0, address: { $literal: address }, txn_count: 1, total_value: 1, triggering_txns: { $slice: ["$triggering_txns", 20] }, travel_rule_flag: { $literal: "STRUCTURING_SMURFING" }, risk_score: { $literal: "high" } } },
];

const tron_tr_low_confidence_vasp = (address, jurisdiction = DEFAULT_JURISDICTION) => [
  excludeHotWalletsStageUSDT(),
  { $match: { $or: [{ token_transfer_from: address }, { token_transfer_to: address }] } },
  { $addFields: { counterparty: { $cond: [{ $eq: ["$token_transfer_from", address] }, "$token_transfer_to", "$token_transfer_from"] } } },
  ..._combined_tagpack_lookup("tron", "counterparty", "cp_tags"),
  { $match: { cp_tags: { $elemMatch: { tag: "exchange", confidence: { $lt: 50 } } } } },
  { $project: { _id: 0, transaction_hash: "$transaction_hash", address: { $literal: address }, counterparty: 1, travel_rule_flag: { $literal: "LOW_CONFIDENCE_VASP" }, risk_score: { $literal: "medium" } } },
  { $limit: 1 },
];

const tron_tr_cross_vasp_layering = (address, jurisdiction = DEFAULT_JURISDICTION) => [
  excludeHotWalletsStageUSDT(),
  { $match: { $or: [{ token_transfer_from: address }, { token_transfer_to: address }] } },
  {
    $addFields: {
      direction:   { $cond: [{ $eq: ["$token_transfer_from", address] }, "outgoing", "incoming"] },
      counterparty:{ $cond: [{ $eq: ["$token_transfer_from", address] }, "$token_transfer_to", "$token_transfer_from"] },
    },
  },
  ..._combined_tagpack_lookup("tron", "counterparty", "cp_tags"),
  { $addFields: { is_vasp: { $gt: [{ $size: { $filter: { input: "$cp_tags", as: "t", cond: { $eq: ["$$t.tag", "exchange"] } } } }, 0] } } },
  {
    $facet: {
      vasp_incoming: [{ $match: { direction: "incoming", is_vasp: true } }, { $project: { transaction_hash: "$transaction_hash", expiration: { $toLong: "$block_timestamp" } } }],
      vasp_outgoing: [{ $match: { direction: "outgoing", is_vasp: true } }, { $project: { transaction_hash: "$transaction_hash", expiration: { $toLong: "$block_timestamp" } } }],
    },
  },
  {
    $addFields: {
      layering_detected: {
        $gt: [
          {
            $size: {
              $filter: {
                input: "$vasp_incoming",
                as: "inc",
                cond: {
                  $gt: [
                    { $size: { $filter: { input: "$vasp_outgoing", as: "out", cond: { $and: [{ $gte: ["$$out.expiration", "$$inc.expiration"] }, { $lte: [{ $subtract: ["$$out.expiration", "$$inc.expiration"] }, 3600000] }] } } } },
                    0,
                  ],
                },
              },
            },
          },
          0,
        ],
      },
    },
  },
  { $match: { layering_detected: true } },
  { $project: { _id: 0, address: { $literal: address }, incoming_txns: { $slice: ["$vasp_incoming.transaction_hash", 20] }, outgoing_txns: { $slice: ["$vasp_outgoing.transaction_hash", 20] }, travel_rule_flag: { $literal: "CROSS_VASP_LAYERING" }, risk_score: { $literal: "high" } } },
];

module.exports = {
  JURISDICTION_CONFIG, DEFAULT_JURISDICTION, TR_THRESHOLDS, loadHotWallets, 
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
  USDT_CONTRACT, USDT_PRECISION, ETH_BLOCKS_24H,
  eth_usdt_quick_succession_high_value_transaction, eth_usdt_large_deposit_followed_by_immediate_withdrawl, eth_usdt_fatf_low_value_transactions, eth_usdt_combined_rule_for_flagged_addresses, eth_usdt_whale_in, eth_usdt_whale_out,
  eth_usdt_tr_threshold_breach_known_vasp, eth_usdt_tr_unhosted_wallet_large_transfer, eth_usdt_tr_sanctions_hit, eth_usdt_tr_structuring_smurfing, eth_usdt_tr_low_confidence_vasp, eth_usdt_tr_cross_vasp_layering,
};