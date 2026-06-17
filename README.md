# Home Dashboard Ruijie

Домашній моніторинг на **Raspberry Pi**: статистика Pi, скан LAN, Wake-on-LAN і **живі WAN upload/download** з роутера **Ruijie / Reyee EG105GW** — без SNMP і без SSH на роутері.

![Stack](https://img.shields.io/badge/Flask-3.x-green) ![Node](https://img.shields.io/badge/Node.js-18%2B-green) ![Router](https://img.shields.io/badge/Ruijie-EG105GW-blue)

---

## Можливості

| Блок | Опис |
|------|------|
| **Pi Monitor** | CPU temp, load, RAM, disk, uptime |
| **Ruijie WAN** | Download / Upload в реальному часі з EG105GW |
| **WAN графік** | Chart.js, оновлення кожні **30 с** (лише коли вкладка активна) |
| **LAN scan** | arp-scan + NetBIOS / reverse DNS |
| **Wake-on-LAN** | Увімкнення ПК з браузера |

---

## Архітектура

```
Браузер  →  nginx (/wol/)  →  Flask :5002  →  node ruijie_wan.js  →  HTTPS eWeb 192.168.24.1
                │                    │
                │                    └── /api/wan, /api/system, /api/scan
                └── dashboard.html (Chart.js, poll 30s)
```

- **Flask** (`app.py`) — API та HTML.
- **Node.js** (`scripts/ruijie_wan.js`) — логін у eWeb і запит WAN-швидкості.
- **Пароль роутера** зберігається локально в `data/ruijie.json` (не в git).

---

## Як вдалось підключитись до Ruijie (reverse engineering eWeb)

На **EG105GW** (ReyeeOS / EG_3.0) **немає SNMP** і **немає SSH**. Є лише веб-інтерфейс **eWeb** (`https://192.168.24.1/`).

### 1. Чому не спрацювали «очевидні» API

Спроби на кшталт:

```http
POST /cgi-bin/luci/api/overview
{"method":"getPortSpeed","params":{}}
```

повертали:

```json
{"error":{"message":"Method not found.","code":-32601}}
```

Функція `getPortSpeed` у JS роутера — **клієнтський хелпер**, а не RPC-метод бекенду.

### 2. Як eWeb насправді працює

У мініфікованому `app*.js` з `/luci-static/eweb-egw/static/js/` знайдено обгортку **`$apiArr`**. Вона:

1. Читає конфіг модулів (`apiConfig`, webpack-модуль `yKQW`).
2. Перетворює імена на shell-команди, наприклад `flow` → `dev_sta get -m flow`.
3. Викликає **`POST /cgi-bin/luci/api/cmd?auth={sid}`** з тілом:

```json
{
  "method": "devSta.get",
  "params": {
    "module": "flow",
    "device": "pc",
    "data": { "func": "interface_info" }
  }
}
```

У `apiConfig` запис:

```javascript
flow: {
  shell: "dev_sta get -m flow $data",
  data: { func: "interface_info" }
}
```

Саме цей модуль живить блок **Real-Time Flow** у веб-UI роутера.

### 3. Відповідь WAN

```json
{
  "code": 0,
  "data": {
    "count": 1,
    "data": {
      "wan": {
        "up": "115533",
        "down": "319260"
      }
    }
  }
}
```

- `up` / `down` — **байти за секунду** (рядки).
- Для dashboard: `bps = value × 8`.
- UI роутера ділить на 1000 для відображення KB/s — ми використовуємо ті самі сирі значення.

### 4. Логін (GibberishAES)

eWeb **не приймає plain-text пароль**:

1. `GET /cgi-bin/luci/?stamp=…` — з HTML витягується **динамічний AES-ключ** (32 hex):
   ```regex
   GibberishAES\.enc\([^,]+,\s*"([0-9a-f]{32})"
   ```
2. Пароль шифрується бібліотекою **`gibberish-aes.js`** (скопійована з `/luci-static/eweb-egw/static/aes.js` роутера).
3. `POST /cgi-bin/luci/api/auth`:
   ```json
   {
     "method": "login",
     "params": {
       "username": "admin",
       "time": "1718650000",
       "encry": true,
       "pwd": "<encrypted>"
     }
   }
   ```
4. У відповіді потрібен **`sid`** (не `token` у URL `;stok=` — це застарілий формат).
5. Далі всі запити: `?auth={sid}` + cookie з `Set-Cookie`.

> **Важливо:** ключ AES змінюється при кожному завантаженні сторінки логіну — його треба брати заново перед кожним login.

### 5. Перевірка вручну

```bash
cp data/ruijie.json.example data/ruijie.json   # вписати пароль admin eWeb
node scripts/ruijie_probe.js                   # логін + тест flow API
node scripts/ruijie_wan.js                     # JSON з upload_bps / download_bps
curl "http://127.0.0.1:5002/api/wan?refresh=1"
```

---

## Графік WAN у dashboard

У `templates/dashboard.html`:

1. **Chart.js** — два dataset (Download зелений, Upload блакитний), вісь Y у **MB/s**.
2. **Page Visibility API** — polling **кожні 30 с** лише коли `document.visibilityState === 'visible'`.
3. Кожен poll: `GET /wol/api/wan?refresh=1` (обходить 10-хв серверний кеш).
4. До **60 точок** (~30 хв історії при інтервалі 30 с).
5. Решта dashboard (Pi stats, LAN scan) — раз на **10 хв**.

---

## Швидкий старт (Raspberry Pi)

### Залежності

```bash
sudo apt install -y python3-venv nodejs arp-scan nmap
cd ~/wol   # або clone цього репо
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp data/ruijie.json.example data/ruijie.json
cp data/machines.json.example data/machines.json
nano data/ruijie.json   # пароль eWeb admin
```

### Запуск

```bash
source venv/bin/activate
python app.py    # слухає 127.0.0.1:5002
```

### systemd

```bash
sudo cp deploy/wol-dashboard.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now wol-dashboard
```

### nginx (приклад)

```nginx
location /wol/ {
    proxy_pass http://127.0.0.1:5002/;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
}
```

Окремий vhost на `:8081` → той самий backend для `/dashboard`.

---

## API

| Endpoint | Опис |
|----------|------|
| `GET /dashboard` | HTML dashboard |
| `GET /api/wan?refresh=1` | WAN rates (JSON) |
| `GET /api/system` | Pi stats |
| `GET /api/scan` | LAN devices |
| `GET /` | WoL UI |

---

## Структура проєкту

```
app.py                 Flask backend
templates/
  dashboard.html       Pi + WAN + графік
  index.html           Wake-on-LAN UI
scripts/
  ruijie_wan.js        WAN fetch (login + flow API)
  ruijie_probe.js      Debug: login + raw flow response
  gibberish-aes.js     AES з прошивки роутера
data/
  ruijie.json.example  конфіг роутера (скопіювати → ruijie.json)
deploy/
  wol-dashboard.service
```

---

## Обмеження

- Прошивка **Reyee / Ruijie EG** — API може відрізнятись на інших моделях.
- Пароль admin eWeb зберігається **локально** на Pi; не комітьте `data/ruijie.json`.
- Частий poll (30 с) створює навантаження на eWeb — приховування вкладки зупиняє polling.

---

## Ліцензія

MIT — використовуйте вільно для домашніх lab.

---

*Зроблено для домашньої мережі 192.168.24.0/24 — raspbserv + Ruijie EG105GW.*
