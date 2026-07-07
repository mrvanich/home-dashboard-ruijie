#!/usr/bin/env node
/**
 * Fetch Ruijie/Reyee EG105GW WAN upload/download rates via eWeb devSta API.
 * Uses port_status + flow_status because those counters match the physical WAN port.
 */
const https = require('https');
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

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
    const client = u.protocol === 'http:' ? http : https;
    const req = client.request(
      {
        hostname: u.hostname,
        port: u.port || (u.protocol === 'http:' ? 80 : 443),
        path: u.pathname + u.search,
        method: reqMethod,
        rejectUnauthorized: u.protocol === 'http:' ? undefined : false,
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

function md5(value) {
  return crypto.createHash('md5').update(value).digest('hex');
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
  return { host, sid: data.sid, sn: data.sn, cookie };
}

async function cmdGet(session, module) {
  const url = `http://${session.host}/cgi-bin/luci/api/cmd?auth=${session.sid}`;
  const params = { module, device: 'pc' };
  const payload = { method: 'devSta.get', params };
  const text = JSON.stringify(payload);
  const headers = {
    'Content-Accept': md5(`Web@Rj$2020!${Buffer.byteLength(text)}`),
    'Contents-Accept': md5(`Web@Rj$2020!${text}`),
  };
  if (session.sn && session.sid) {
    headers.Cookie = `${session.sn}=${session.sid}`;
  } else if (session.cookie) {
    headers.Cookie = session.cookie;
  }
  const res = await request(url, payload, headers);
  if (res.status === 403) throw new Error('API auth expired');
  return res.json;
}

/** flow_status returns rates in kbps; dashboard stores/displays bytes per second. */
function kbpsToBytesPerSec(value) {
  const n = Number(value);
  if (!Number.isFinite(n) || n < 0) return null;
  return Math.round((n * 1000) / 8);
}

async function fetchWanRates(session) {
  const [portsRes, flowRes] = await Promise.all([cmdGet(session, 'port_status'), cmdGet(session, 'flow_status')]);
  if (!portsRes || portsRes.code !== 0 || !flowRes || flowRes.code !== 0) {
    const msg =
      (portsRes && portsRes.error && portsRes.error.message) ||
      (flowRes && flowRes.error && flowRes.error.message) ||
      'port flow API error';
    throw new Error(msg);
  }
  const wanPort = ((portsRes.data && portsRes.data.List) || []).find((p) => p.name === 'WAN' || p.panel_name === 'WAN');
  if (!wanPort) {
    throw new Error('WAN port not found in port_status');
  }
  const row = ((flowRes.data && flowRes.data.data) || []).find((p) => String(p.lpid) === String(wanPort.portId));
  if (!row) {
    throw new Error(`WAN lpid ${wanPort.portId} not found in flow_status`);
  }
  return {
    upload_bps: kbpsToBytesPerSec(row.output_rate),
    download_bps: kbpsToBytesPerSec(row.input_rate),
    raw: { port: wanPort, flow: row },
  };
}

function fmt(bps) {
  if (bps == null) return '—';
  const mbps = (bps * 8) / 1000000;
  if (mbps >= 100) return mbps.toFixed(0) + ' Mbps';
  if (mbps >= 10) return mbps.toFixed(1) + ' Mbps';
  return mbps.toFixed(2) + ' Mbps';
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
        api_method: 'devSta.get port_status + flow_status',
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
