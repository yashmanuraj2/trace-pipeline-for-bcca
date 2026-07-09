const { loadAddresses } = require("./address_loader");
const { runAggregations } = require("./tagging_worker");
const { performance } = require("perf_hooks");

let isTaggingRunning = false;
let isShuttingDown = false;

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function msUntilNextInterval(minutes) {
  const now = new Date();
  const next = new Date(now);

  next.setUTCSeconds(0, 0);
  next.setUTCMinutes(
    Math.floor(now.getUTCMinutes() / minutes) * minutes + minutes,
  );

  return Math.max(next.getTime() - now.getTime(), 0);
}

async function addressLoaderLoop() {
  while (!isShuttingDown) {
    // Modify this integer if you want to stretch the lookback cycle
    await sleep(msUntilNextInterval(5)); 
    console.log("[LOOP] Address loader started:", new Date().toISOString());
    
    try {
      await loadAddresses();
    } catch (err) {
      console.error("[LOOP ERROR] Address loader crashed. Will retry next interval:", err.message);
    }
  }
}

async function taggingWorkerLoop() {
  while (!isShuttingDown) {
    await sleep(msUntilNextInterval(1));

    if (isTaggingRunning) continue;
    isTaggingRunning = true;

    try {
      console.log("[LOOP] Tagging started:", new Date().toISOString());

      const startTime = performance.now();

      // runAggregations returns per-chain timing for paper telemetry
      const chainTelemetry = await runAggregations();

      const totalMs = performance.now() - startTime;

      // ── PAPER TELEMETRY — per-chain timing for UTXO vs Account disparity ──
      // These numbers go directly into Table II of the BCCA paper.
      // ETH (Account model) vs BTC (UTXO model) latency delta = RQ2 result.
      if (chainTelemetry) {
        const { ethMs, ethUsdtMs, btcMs, tronMs } = chainTelemetry;

        console.log("─────────────────────────────────────────────────");
        console.log("[PAPER TELEMETRY] Per-chain batch duration:");
        console.log(`  ETH  (Account model) : ${ethMs != null   ? ethMs.toFixed(0)     + "ms" : "skipped"}`);
        console.log(`  USDT (Account/ERC20) : ${ethUsdtMs != null ? ethUsdtMs.toFixed(0) + "ms" : "skipped"}`);
        console.log(`  BTC  (UTXO model)    : ${btcMs != null   ? btcMs.toFixed(0)     + "ms" : "skipped"}`);
        console.log(`  TRX  (Account/TRC20) : ${tronMs != null  ? tronMs.toFixed(0)    + "ms" : "skipped"}`);

        if (ethMs && btcMs) {
          const utxoPenalty = (btcMs / ethMs).toFixed(2);
          console.log(`  UTXO Penalty Ratio   : ${utxoPenalty}x  ← RQ2 result`);
        }
        console.log("─────────────────────────────────────────────────");
      }

      console.log(`[PERFORMANCE] Total batch completed in ${(totalMs / 1000).toFixed(2)}s`);

    } catch (err) {
      console.error("[LOOP ERROR] Tagging worker crashed. Will retry next interval:", err.message);
    } finally {
      isTaggingRunning = false;
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// GLOBAL ERROR HANDLERS
// ─────────────────────────────────────────────────────────────────────────────
process.on("uncaughtException", (err) => {
  console.error("[FATAL ERROR] Uncaught Exception:", err);
});

process.on("unhandledRejection", (reason, promise) => {
  console.error("[FATAL ERROR] Unhandled Promise Rejection:", reason);
});

process.on("SIGINT", () => {
  console.log("Shutting down gracefully...");
  isShuttingDown = true;
});
process.on("SIGTERM", () => {
  console.log("Shutting down gracefully...");
  isShuttingDown = true;
});

// Start the scheduler
(async () => {
  console.log("Loop scheduler started (NO CRON) - Crash Protection & Telemetry Enabled");
  addressLoaderLoop();
  taggingWorkerLoop();
})();