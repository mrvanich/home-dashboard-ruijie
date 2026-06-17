#!/usr/bin/env node
/** Probe Ruijie eWeb WAN flow API — run: node ruijie_probe.js */
const https = require('https');
const fs = require('fs');
const path = require('path');
const GibberishAES = require(path.join(__dirname, 'gibberish-aes.js'));

const cfg = JSON.parse(fs.readFileSync(path.join(__dirname, '../data/ruijie.json'), 'utf8'));
if (!cfg.password) {
  console.error('Set password in ~/wol/data/ruijie.json first');
  process.exit(1);
}

function req(url, body, method = 'POST', headers = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const data = body ? JSON.stringify(body) : null;
    const r = https.request({
      hostname: u.hostname,
      path: u.pathname + u.search,
      method,
      rejectUnauthorized: false,
      headers: {
        ...(data ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) } : {}),
        ...headers,
      },
      timeout: 12000,
    }, (res) => {
      let raw = '';
      res.on('data', (c) => (raw += c));
      res.on('end', () => resolve({ status: res.statusCode, body: raw, headers: res.headers }));
    });
    r.on('error', reject);
    if (data) r.write(data);
    r.end();
  });
}

(async () => {
  const host = cfg.host || '192.168.24.1';
  const home = await req(`https://${host}/cgi-bin/luci/?stamp=${Date.now()}`, null, 'GET');
  const km = home.body.match(/GibberishAES\.enc\([^,]+,\s*"([0-9a-f]{32})"/i);
  const aesKey = km ? km[1] : 'b68a1bc5614743c28ba5c7c457811022';
  console.log('AES key:', aesKey);
  const pwd = GibberishAES.enc(cfg.password, aesKey).replace(/\s+/g, '');
  const login = await req(`https://${host}/cgi-bin/luci/api/auth`, {
    method: 'login',
    params: {
      username: cfg.username || 'admin',
      time: String(Math.floor(Date.now() / 1000)),
      encry: true,
      pwd,
    },
  });
  const loginJson = JSON.parse(login.body);
  const data = loginJson.data;
  if (!data || !data.sid) {
    console.error('Login failed:', login.body.slice(0, 300));
    process.exit(1);
  }
  const cookie = (login.headers['set-cookie'] || []).map((x) => x.split(';')[0]).join('; ');
  console.log('Logged in OK, sid:', data.sid.slice(0, 12) + '...\n');

  const flow = await req(
    `https://${host}/cgi-bin/luci/api/cmd?auth=${data.sid}`,
    {
      method: 'devSta.get',
      params: { module: 'flow', device: 'pc', data: { func: 'interface_info' } },
    },
    'POST',
    { Cookie: cookie }
  );
  console.log('flow interface_info:');
  console.log(flow.body);
})();
