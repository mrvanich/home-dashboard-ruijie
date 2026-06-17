#!/usr/bin/env node
/**
 * Fetch Ruijie/Reyee EG105GW WAN upload/download rates via eWeb devSta API.
 * Uses module "flow" / func "interface_info" (same as eWeb Real-Time Flow).
 */
const https = require('https');
const fs = require('fs');
const path = require('path');

const CONFIG = path.join(__dirname, '../data/ruijie.json');
const GibberishAES = require(path.join(__dirname, 'gibberish-aes.js'));
const DEFAULT_AES_KEY = 'b68a1bc5614743c28ba5c7c457811022';

function readConfig() {
  try {
    return JSON.parse(fs.readFileSync(CONFIG, 'utf8'));
  } catch {
    return null;
  }
}

function request(url, body, extraHeaders = {}, method) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const data = body ? JSON.stringify(body) : null;
    const reqMethod = method || (data ? 'POST' : 'GET');
    const req = https.request(
      {
        hostname: u.hostname,
        port: u.port || 443,
        path: u.pathname + u.search,
        method: reqMethod,
        rejectUnauthorized: false,
        headers: {
          ...(data ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) } : {}),
          ...extraHeaders,
        },
        timeout: 12000,
      },
      (res) => {
        let raw = '';
        res.on('data', (c) => (raw += c));
        res.on('end', () => {
          let json = null;
          try {
            json = JSON.parse(raw);
          } catch {
            json = null;
          }
          resolve({ status: res.statusCode, json, raw, headers: res.headers });
        });
      }
    );
    req.on('error', reject);
    req.on('timeout', () => req.destroy(new Error('timeout')));
    if (data) req.write(data);
    req.end();
  });
}

async function fetchAesKey(host) {
  const res = await request(`https://${host}/cgi-bin/luci/?stamp=${Date.now()}`, null, {}, 'GET');
  const html = (res.raw || '').toString();
  const m = html.match(/GibberishAES\.enc\([^,]+,\s*"([0-9a-f]{32})"/i);
  return m ? m[1] : DEFAULT_AES_KEY;
}

async function login(cfg) {
  const host = cfg.host || '192.168.24.1';
  const aesKey = await fetchAesKey(host);
  const pwd = GibberishAES.enc(cfg.password, aesKey).replace(/\s+/g, '');
  const res = await request(`https://${host}/cgi-bin/luci/api/auth`, {
    method: 'login',
    params: {
      username: cfg.username || 'admin',
      time: Math.floor(Date.now() / 1000).toString(),
      encry: true,
      pwd,
    },
  });
  const data = res.json && res.json.data;
  if (data && data.reload) {
    throw new Error('Router auth key changed — retry');
  }
  if (!data || !data.sid) {
    const msg =
      (data && data.msg) ||
      (res.json && res.json.error && res.json.error.message) ||
      'Login failed — check password in ~/wol/data/ruijie.json';
    throw new Error(msg);
  }
  const cookie = ((res.headers && res.headers['set-cookie']) || [])
    .map((c) => c.split(';')[0])
    .join('; ');
  return { host, sid: data.sid, cookie };
}

async function cmdGet(session, module, data) {
  const url = `https://${session.host}/cgi-bin/luci/api/cmd?auth=${session.sid}`;
  const headers = session.cookie ? { Cookie: session.cookie } : {};
  const params = { module, device: 'pc' };
  if (data !== undefined) params.data = data;
  const res = await request(url, { method: 'devSta.get', params }, headers);
  if (res.status === 403) throw new Error('API auth expired');
  return res.json;
}

/** eWeb returns WAN rates as bytes/s strings; dashboard expects bps. */
function bytesPerSecToBps(value) {
  const n = Number(value);
  if (!Number.isFinite(n) || n < 0) return null;
  return Math.round(n * 8);
}

async function fetchWanRates(session) {
  const res = await cmdGet(session, 'flow', { func: 'interface_info' });
  if (!res || res.code !== 0) {
    const msg = (res && res.error && res.error.message) || 'flow API error';
    throw new Error(msg);
  }
  const payload = res.data && res.data.data;
  const wan = payload && payload.wan;
  if (!wan || (wan.up == null && wan.down == null)) {
    throw new Error('WAN rate data missing in flow response');
  }
  return {
    upload_bps: bytesPerSecToBps(wan.up),
    download_bps: bytesPerSecToBps(wan.down),
    raw: wan,
  };
}

function fmt(bps) {
  if (bps == null) return '—';
  if (bps >= 1048576) return (bps / 1048576).toFixed(2) + ' MB/s';
  if (bps >= 1024) return (bps / 1024).toFixed(1) + ' KB/s';
  return bps + ' B/s';
}

async function main() {
  const cfg = readConfig();
  if (!cfg || !cfg.password) {
    console.log(
      JSON.stringify({
        ok: false,
        error: 'Configure ~/wol/data/ruijie.json with router admin password',
        upload_bps: null,
        download_bps: null,
      })
    );
    process.exit(0);
  }
  try {
    const session = await login(cfg);
    const rates = await fetchWanRates(session);
    console.log(
      JSON.stringify({
        ok: true,
        host: cfg.host || '192.168.24.1',
        name: cfg.name || 'Ruijie EG105GW',
        upload_bps: rates.upload_bps,
        download_bps: rates.download_bps,
        upload_human: fmt(rates.upload_bps),
        download_human: fmt(rates.download_bps),
        api_method: 'devSta.get flow interface_info',
        timestamp: new Date().toISOString(),
      })
    );
  } catch (e) {
    console.log(
      JSON.stringify({
        ok: false,
        error: String(e.message || e),
        upload_bps: null,
        download_bps: null,
      })
    );
  }
}

main();
