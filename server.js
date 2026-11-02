const http = require('http');
const crypto = require('crypto');
const { URL } = require('url');

const PORT = Number(process.env.PORT || 8080);
const PASSWORD = process.env.TAMASHA_PASSWORD || process.env.PASSWORD || '';
const LOGIN_URL = 'https://web.jazztv.pk/alpha/api_gateway/v6/auth/login';
const REFRESH_URL = 'https://web.jazztv.pk/alpha/api_gateway/v6/auth/refresh-token';
const CHANNEL_URL = 'https://web.jazztv.pk/alpha/api_gateway/v6/web/get-channel-url';
const ORIGIN = 'https://tamashaweb.com';
const REFERER = 'https://tamashaweb.com/';
const USER_AGENT = process.env.USER_AGENT || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36';

const tokenState = {
  token: null,
  refreshToken: null,
  expiresAt: 0
};

const DEBUG = process.env.DEBUG_RESTREAM === '1';

function logDebug(...args) {
  if (DEBUG) {
    console.log('[debug]', ...args);
  }
}

if (!PASSWORD) {
  throw new Error('Missing TAMASHA_PASSWORD environment variable');
}

function baseHeaders(extra = {}) {
  return {
    accept: 'application/json, text/plain, */*',
    'accept-language': 'en-US,en;q=0.9,ta;q=0.8',
    'cache-control': 'no-cache',
    pragma: 'no-cache',
    origin: ORIGIN,
    referer: REFERER,
    priority: 'u=1, i',
    'user-agent': USER_AGENT,
    ...extra
  };
}

function deriveKeyIv() {
  const parts = PASSWORD.split('-');
  const keyStr = (parts[0] || '').split('').filter((c) => /[a-z0-9]/.test(c)).join('');
  const ivStr = (parts[1] || '').split('').filter((c) => /[a-z0-9]/.test(c)).join('');
  const key = Buffer.from((keyStr + keyStr).slice(0, 32), 'utf8');
  const iv = Buffer.from((ivStr + ivStr).slice(0, 16), 'utf8');
  return { key, iv };
}

function maybeUnpadPkcs7(buf) {
  if (!buf || !buf.length) return buf;
  const pad = buf[buf.length - 1];
  if (pad <= 0 || pad > 16 || pad > buf.length) return buf;
  for (let i = 0; i < pad; i += 1) {
    if (buf[buf.length - 1 - i] !== pad) return buf;
  }
  return buf.slice(0, buf.length - pad);
}

function decryptEData(edataHex) {
  const { key, iv } = deriveKeyIv();
  const ciphertext = Buffer.from(String(edataHex || '').trim(), 'hex');
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
  decipher.setAutoPadding(false);
  const out = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  const unpadded = maybeUnpadPkcs7(out);
  const text = unpadded.toString('utf8');
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

async function fetchJson(url, options = {}) {
  const res = await fetch(url, options);
  const text = await res.text();
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    data = null;
  }
  if (!res.ok || !data) {
    throw new Error(`HTTP ${res.status} ${res.statusText}: ${text.slice(0, 400)}`);
  }
  return data;
}

async function login() {
  const body = {
    state: 'S29Pb3Q3eTl4dnUxRk5HME9sa0dXdVh0QjZmNXpoRDBAd2ViLmNvbQ==',
    city: 'S29Pb3Q3eTl4dnUxRk5HME9sa0dXdVh0QjZmNXpoRDA'
  };
  const data = await fetchJson(LOGIN_URL, {
    method: 'POST',
    headers: baseHeaders({ 'content-type': 'application/json' }),
    body: JSON.stringify(body)
  });
  if (!data.token) {
    throw new Error('Login response missing token');
  }
  tokenState.token = data.token;
  tokenState.refreshToken = data.refresh_token || tokenState.refreshToken;
  const ttl = Number(data.expires_in || 0);
  tokenState.expiresAt = Date.now() + Math.max(0, ttl - 60) * 1000;
  return tokenState.token;
}

async function refreshToken() {
  if (!tokenState.refreshToken) {
    throw new Error('No refresh token available');
  }
  const payload = {
    refresh_token: tokenState.refreshToken,
    platform: 'web'
  };
  const data = await fetchJson(REFRESH_URL, {
    method: 'POST',
    headers: baseHeaders({ 'content-type': 'application/json' }),
    body: JSON.stringify(payload)
  });
  if (!data.token) {
    throw new Error('Refresh response missing token');
  }
  tokenState.token = data.token;
  tokenState.refreshToken = data.refresh_token || tokenState.refreshToken;
  const ttl = Number(data.expires_in || 0);
  tokenState.expiresAt = Date.now() + Math.max(0, ttl - 60) * 1000;
  return tokenState.token;
}

async function getValidToken() {
  if (tokenState.token && Date.now() < tokenState.expiresAt) {
    return tokenState.token;
  }
  if (tokenState.refreshToken) {
    try {
      return await refreshToken();
    } catch {
      return login();
    }
  }
  return login();
}

function getCandidateUrls(decrypted) {
  const data = (decrypted && typeof decrypted === 'object' && decrypted.data && typeof decrypted.data === 'object') ? decrypted.data : {};
  const ordered = [
    data.ChannelStreamingUrls,
    data.BackupLiveStreamUrl,
    data.CastStreamingUrls
  ];

  const seen = new Set();
  const tokenized = [];

  for (const raw of ordered) {
    if (typeof raw !== 'string') continue;
    if (!/^https?:\/\//i.test(raw) || !raw.includes('.m3u8')) continue;
    let parsed;
    try {
      parsed = new URL(raw);
    } catch {
      continue;
    }
    const signed = parsed.searchParams.has('wmsAuthSign') || parsed.search.length > 1;
    if (!signed) continue;
    const normalized = parsed.toString();
    if (seen.has(normalized)) continue;
    seen.add(normalized);
    tokenized.push(normalized);
  }

  return tokenized;
}

async function fetchChannelPayload(slug) {
  const token = await getValidToken();
  const q = new URLSearchParams({
    slug,
    type: 'channel',
    phone_details: USER_AGENT,
    user_id: ''
  });
  const commonHeaders = baseHeaders({
    authorization: `Bearer ${token}`,
    platform: 'web'
  });
  const attempts = [];

  attempts.push(async () => {
    const url = `${CHANNEL_URL}?${q.toString()}`;
    return fetch(url, {
      method: 'POST',
      headers: {
        ...commonHeaders,
        'content-type': 'multipart/form-data; boundary=----WebKitFormBoundaryu9Zxwv0yy4VIRnBR'
      }
    });
  });

  attempts.push(async () => {
    const form = new FormData();
    form.append('slug', slug);
    form.append('type', 'channel');
    form.append('phone_details', USER_AGENT);
    form.append('user_id', '');
    return fetch(CHANNEL_URL, {
      method: 'POST',
      headers: commonHeaders,
      body: form
    });
  });

  attempts.push(async () => {
    return fetch(CHANNEL_URL, {
      method: 'POST',
      headers: {
        ...commonHeaders,
        'content-type': 'application/json'
      },
      body: JSON.stringify({
        slug,
        type: 'channel',
        phone_details: USER_AGENT,
        user_id: ''
      })
    });
  });

  let lastErr = null;
  let json = null;
  for (let i = 0; i < attempts.length; i += 1) {
    try {
      const res = await attempts[i]();
      const text = await res.text();
      logDebug('channel attempt', i + 1, 'status', res.status);
      if (!res.ok) {
        lastErr = new Error(`Channel API HTTP ${res.status}: ${text.slice(0, 400)}`);
        continue;
      }
      try {
        json = JSON.parse(text);
      } catch {
        lastErr = new Error(`Invalid JSON from channel API: ${text.slice(0, 400)}`);
        continue;
      }
      break;
    } catch (err) {
      lastErr = err;
    }
  }

  if (!json) {
    throw new Error(`Channel API failed across all request shapes: ${lastErr ? lastErr.message : 'unknown error'}`);
  }

  if (!json || !json.eData) {
    throw new Error('Channel API missing eData');
  }
  const decrypted = decryptEData(json.eData);
  if (!decrypted || typeof decrypted !== 'object') {
    throw new Error('Decrypted eData is not valid JSON object');
  }
  return decrypted;
}

function rewritePlaylist(content, playlistUrl, originHost) {
  const proto = (process.env.PUBLIC_BASE_URL && process.env.PUBLIC_BASE_URL.startsWith('https://'))
    ? 'https'
    : (process.env.FORCE_PROTO || 'http');
  const lines = content.split(/\r?\n/);
  const out = [];
  for (const line of lines) {
    const t = line.trim();
    if (!t || t.startsWith('#')) {
      out.push(line);
      continue;
    }
    let absolute;
    try {
      absolute = new URL(t, playlistUrl).toString();
    } catch {
      out.push(line);
      continue;
    }
    out.push(`${proto}://${originHost}/proxy?u=${encodeURIComponent(absolute)}`);
  }
  return out.join('\n');
}

async function streamFromUrl(targetUrl, req, res, options = {}) {
  const throwOnHttpError = Boolean(options.throwOnHttpError);
  const upstream = await fetch(targetUrl, {
    method: 'GET',
    headers: {
      'user-agent': USER_AGENT,
      accept: '*/*',
      referer: REFERER,
      origin: ORIGIN
    }
  });
  if (!upstream.ok) {
    if (throwOnHttpError) {
      throw new Error(`Upstream error ${upstream.status} for ${targetUrl}`);
    }
    res.statusCode = upstream.status;
    res.setHeader('content-type', 'text/plain; charset=utf-8');
    res.end(`Upstream error ${upstream.status}`);
    return;
  }
  const ct = upstream.headers.get('content-type') || '';
  const isM3u8 = /application\/(vnd\.apple\.mpegurl|x-mpegurl)|audio\/mpegurl|m3u8|mpegurl/i.test(ct) || /\.m3u8(\?|$)/i.test(targetUrl);

  res.setHeader('access-control-allow-origin', '*');
  res.setHeader('access-control-allow-methods', 'GET,HEAD,OPTIONS');
  res.setHeader('access-control-allow-headers', '*');
  res.setHeader('cache-control', 'no-cache');

  if (isM3u8) {
    const text = await upstream.text();
    const host = req.headers.host || `localhost:${PORT}`;
    const rewritten = rewritePlaylist(text, targetUrl, host);
    res.statusCode = 200;
    res.setHeader('content-type', 'application/vnd.apple.mpegurl; charset=utf-8');
    res.end(rewritten);
    return;
  }

  res.statusCode = 200;
  if (ct) res.setHeader('content-type', ct);
  const len = upstream.headers.get('content-length');
  if (len) res.setHeader('content-length', len);
  if (!upstream.body) {
    const buf = Buffer.from(await upstream.arrayBuffer());
    res.end(buf);
    return;
  }
  const stream = require('stream');
  stream.Readable.fromWeb(upstream.body).pipe(res);
}

function jsonError(res, status, message) {
  res.statusCode = status;
  res.setHeader('content-type', 'application/json; charset=utf-8');
  res.setHeader('access-control-allow-origin', '*');
  res.end(JSON.stringify({ ok: false, error: message }));
}

const server = http.createServer(async (req, res) => {
  try {
    const host = req.headers.host || `localhost:${PORT}`;
    const url = new URL(req.url || '/', `http://${host}`);

    if (req.method === 'OPTIONS') {
      res.statusCode = 204;
      res.setHeader('access-control-allow-origin', '*');
      res.setHeader('access-control-allow-methods', 'GET,HEAD,OPTIONS');
      res.setHeader('access-control-allow-headers', '*');
      res.end();
      return;
    }

    if (url.pathname === '/health') {
      res.statusCode = 200;
      res.setHeader('content-type', 'application/json; charset=utf-8');
      res.end(JSON.stringify({ ok: true, uptime: process.uptime() }));
      return;
    }

    if (url.pathname === '/proxy') {
      const target = url.searchParams.get('u');
      if (!target) {
        jsonError(res, 400, 'Missing query param u');
        return;
      }
      await streamFromUrl(target, req, res);
      return;
    }

    const match = url.pathname.match(/^\/([^/]+)\/(.+)$/);
    if (!match) {
      jsonError(res, 404, 'Use /:slug/index.m3u8 or /:slug/master.m3u8');
      return;
    }

    const slug = decodeURIComponent(match[1]);
    const reqTail = decodeURIComponent(match[2] || '');
    logDebug('request slug', slug, 'tail', reqTail);
    const decrypted = await fetchChannelPayload(slug);
    const candidates = getCandidateUrls(decrypted);
    logDebug('candidate urls', candidates);
    if (!candidates.length) {
      jsonError(res, 502, 'No playable m3u8 URL found in decrypted payload');
      return;
    }

    let lastErr = null;
    for (const candidate of candidates) {
      try {
        await streamFromUrl(candidate, req, res, { throwOnHttpError: true });
        return;
      } catch (err) {
        logDebug('candidate failed', candidate, err && err.message ? err.message : err);
        lastErr = err;
      }
    }

    jsonError(res, 502, `All upstream URLs failed: ${lastErr ? lastErr.message : 'unknown error'}`);
  } catch (err) {
    jsonError(res, 500, err && err.message ? err.message : 'Internal error');
  }
});

server.listen(PORT, () => {
  process.stdout.write(`Tamasha restream proxy listening on http://localhost:${PORT}\n`);
});
