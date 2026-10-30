const https = require("https");
const host = process.argv[2];
https.get({ host, path: "/", headers: { "User-Agent": "emudhra-trust-store-check/1.0" }, timeout: 20000 }, (r) => {
  console.log(`ACCEPT HTTP ${r.statusCode}`); r.resume();
}).on("error", (e) => console.log(`reject ${e.code}: ${e.message}`));
