// address_loader.js
// Pure address loader module (no cron, no side effects)
//
// Loads addresses from the last 24h into Redis for three chains + ETH USDT:
//   addresses:ETH:last24h      ← native ETH  (ethereum_transactions_all)
//   addresses:ETH_USDT:last24h ← ERC-20 USDT (ethereum_logs_all)
//   addresses:TRX:pending      ← TRC-20 USDT (tron_token_transfers)  [not consumed yet]
//   addresses:BTC:last24h      ← Bitcoin     (bitcoin_addr_txn_map)
//
// ETH USDT note:
//   ethereum_logs_all has no block_timestamp — time window approximated using
//   block_number: latest_block - 6500  ≈  24h  (ETH ~13s/block)
//   USDT contract: 0xdac17f958d2ee523a2206206994597c13d831ec7
//   token_value precision: divide by 1,000,000 to get USDT amount

const { db1Connection, db3Connection, db4Connection, redis } = require("./db");

const USDT_CONTRACT = "0xdac17f958d2ee523a2206206994597c13d831ec7";
const ETH_BLOCKS_24H = 6500; // ~24h at ~13s/block

async function loadAddresses() {
  const now       = Math.floor(Date.now() / 1000);
  const since24h  = now - 86400;
  const since24hrTron = since24h * 1000; // TRON uses ms timestamps

  console.log(`[ADDRESS_LOADER] Loading addresses since ${new Date(since24h * 1000).toISOString()}`);

  try {
    await Promise.all([

      // ── ETH NATIVE ────────────────────────────────────────────────────────
      (async () => {
        try {
          const ethTxns  = db4Connection.db.collection("ethereum_transactions_all");
          const ethCursor = ethTxns.aggregate(
            [
              // ARTIFACT FIX: Lagging 900 seconds (~15 mins or ~64 blocks) behind 'now' to prevent reorg ingestion
              { $match: { block_timestamp: { $gte: since24h, $lte: now - 900 } } },
              { $project: { addresses: ["$from_address", "$to_address"] } },
              { $unwind: "$addresses" },
              { $match: { addresses: { $ne: null, $ne: "" } } },
              { $group: { _id: "$addresses" } },
            ],
            { allowDiskUse: true },
          );

          let ethCount = 0;
          let ethPipeline = redis.multi();

          for await (const doc of ethCursor) {
            ethPipeline.sAdd("addresses:ETH:last24h", doc._id);
            ethCount++;

            // Batch flush every 20k to prevent memory pressure
            if (ethCount % 20000 === 0) {
              await ethPipeline.exec();
              ethPipeline = redis.multi();
            }
          }

          if (ethCount % 20000 !== 0) {
            await ethPipeline.exec();
          }

          console.log(`[ADDRESS_LOADER] ETH native addresses loaded: ${ethCount}`);
        } catch (err) {
          console.error("[ADDRESS_LOADER] Error loading ETH addresses:", err);
        }
      })(),

      // ── ETH ERC-20 USDT ───────────────────────────────────────────────────
      (async () => {
        try {
          const usdtLogs = db4Connection.db.collection("ethereum_logs_all");

          // Dynamically find the latest indexed block to compute the 24h window
          const latestBlockDoc = await usdtLogs
            .find({ address: USDT_CONTRACT })
            .sort({ block_number: -1 })
            .limit(1)
            .toArray();

          if (latestBlockDoc.length === 0) {
            console.warn("[ADDRESS_LOADER] No USDT logs found — skipping ETH USDT load");
            return;
          }

          // block_number may be a MongoDB Long — convert to plain JS number
          const latestBlock  = Number(latestBlockDoc[0].block_number);
          const sinceBlock   = latestBlock - ETH_BLOCKS_24H;

          console.log(`[ADDRESS_LOADER] ETH USDT window: blocks ${sinceBlock} → ${latestBlock - 64}`);

          const usdtCursor = usdtLogs.aggregate(
            [
              {
                $match: {
                  address:        USDT_CONTRACT,
                  token_transfer: true,
                  // ARTIFACT FIX: Trailing depth of 64 blocks to prevent reorg ingestion
                  block_number:   { $gte: sinceBlock, $lte: latestBlock - 64 },
                },
              },
              {
                $project: {
                  addresses: ["$token_transfer_from", "$token_transfer_to"],
                },
              },
              { $unwind: "$addresses" },
              {
                $match: {
                  addresses: { $type: "string", $ne: "", $ne: null },
                },
              },
              { $group: { _id: "$addresses" } },
            ],
            { allowDiskUse: true },
          );

          let usdtCount = 0;
          let pipeline  = redis.multi();

          for await (const doc of usdtCursor) {
            pipeline.sAdd("addresses:ETH_USDT:last24h", doc._id);
            usdtCount++;

            // Batch flush every 20k to prevent memory pressure
            if (usdtCount % 20000 === 0) {
              await pipeline.exec();
              pipeline = redis.multi();
            }
          }

          if (usdtCount % 20000 !== 0) {
            await pipeline.exec();
          }

          console.log(`[ADDRESS_LOADER] ETH USDT addresses loaded: ${usdtCount}`);
        } catch (err) {
          console.error("[ADDRESS_LOADER] Error loading ETH USDT addresses:", err);
        }
      })(),

      // ── TRON TRC-20 USDT ──────────────────────────────────────────────────
      (async () => {
        try {
          console.log("[ADDRESS_LOADER] TRON skipped — disabled for this run");
          return; // ← TRON DISABLED
          
          const tronTxns  = db1Connection.db.collection("tron_token_transfers");
          // TRON: 1 block per ~3s → 28,800 blocks ≈ 24h
          const TRON_BLOCKS_24H = 28800;

          const latestTronDoc = await tronTxns
            .find({ address: "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t" })
            .sort({ block_number: -1 })
            .limit(1)
            .toArray();

          if (latestTronDoc.length === 0) {
            console.warn("[ADDRESS_LOADER] No TRON USDT records found — skipping");
            return;
          }

          const latestTronBlock = latestTronDoc[0].block_number;
          const sinceTronBlock  = latestTronBlock - TRON_BLOCKS_24H;

          console.log(`[ADDRESS_LOADER] TRON USDT window: blocks ${sinceTronBlock} → ${latestTronBlock}`);

          const tronCursor = tronTxns.aggregate(
            [
              {
                $match: {
                  // USDT TRC-20 contract + last 24h block range
                  address:      "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t",
                  block_number: { $gte: sinceTronBlock },
                },
              },
              {
                $project: {
                  addresses: ["$token_transfer_from", "$token_transfer_to"],
                },
              },
              { $unwind: "$addresses" },
              { $match: { addresses: { $type: "string", $ne: "" } } },
              { $group: { _id: "$addresses" } },
            ],
            { allowDiskUse: true },
          );

          let tronCount = 0;
          let pipeline  = redis.multi();

          for await (const doc of tronCursor) {
            pipeline.sAdd("addresses:TRX:pending", String(doc._id));
            tronCount++;

            if (tronCount % 20000 === 0) {
              await pipeline.exec();
              pipeline = redis.multi();
            }
          }

          if (tronCount % 20000 !== 0) {
            await pipeline.exec();
          }

          console.log(`[ADDRESS_LOADER] TRON addresses loaded: ${tronCount}`);
        } catch (err) {
          console.error("[ADDRESS_LOADER] Error loading TRON addresses:", err);
        }
      })(),

      // ── BITCOIN ───────────────────────────────────────────────────────────
      (async () => {
        try {
          const btcTxns = db3Connection.db.collection("bitcoin_addr_txn_map");

          const latestBlockDoc = await btcTxns
            .find()
            .sort({ block: -1 })
            .limit(1)
            .toArray();

          let btcSinceBlock = 0;
          let btcLatestBlock = 0;
          if (latestBlockDoc.length > 0) {
            btcLatestBlock = latestBlockDoc[0].block;
            // 144 blocks ≈ 24h on Bitcoin (avg 10 min/block)
            btcSinceBlock = btcLatestBlock - 144;
          }

          const btcCursor = btcTxns.aggregate(
            [
              // ARTIFACT FIX: Trailing depth of 6 blocks to prevent reorg ingestion
              { $match: { block: { $gte: btcSinceBlock, $lte: btcLatestBlock - 6 } } },
              { $match: { hash:  { $ne: null, $ne: "" } } },
              { $group: { _id: "$hash" } },
            ],
            { allowDiskUse: true },
          );

          let btcCount = 0;
          let btcPipeline = redis.multi();

          for await (const doc of btcCursor) {
            btcPipeline.sAdd("addresses:BTC:last24h", doc._id);
            btcCount++;

            // Batch flush every 20k to prevent memory pressure
            if (btcCount % 20000 === 0) {
              await btcPipeline.exec();
              btcPipeline = redis.multi();
            }
          }

          if (btcCount % 20000 !== 0) {
            await btcPipeline.exec();
          }

          console.log(`[ADDRESS_LOADER] BTC addresses loaded: ${btcCount}`);
        } catch (err) {
          console.error("[ADDRESS_LOADER] Error loading BTC addresses:", err);
        }
      })(),

    ]);
  } catch (error) {
    console.error("[ADDRESS_LOADER] Critical error during parallel load:", error);
  }
}

module.exports = { loadAddresses };