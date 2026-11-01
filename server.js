/*
 * Vidsrc.to replica API server
 *
 * Endpoints:
 *   GET /                       -> simple HTML search page
 *   GET /api?id=<tmdb_id>       -> JSON with media info + HLS playlist URL(s)
 *
 * Replicates the vidsrc.to embed flow using plain HTTP (no browser):
 *   1. vs_src.php gate  -> player page #1 (playerUrl)
 *   2. player page #2   -> CONFIG.api + CONFIG.apiToken (single-use JWT)
 *   3. stream_urls API  -> encrypted stream_urls string + vs.wasm_url
 *   4. WASM ChaCha20 decrypt -> array of master.m3u8 host URLs
 *   5. per-host /generate.php token -> final playable master.m3u8?token=<jwt>
 */

const express = require('express');
const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.static('public'));
app.use(express.json());

const UA =
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36';
const GATE = 'https://vsembed.ru/vs_src.php';
const NEXUS = 'https://stellarconductornexus.com';

/* ---------- small helpers ---------- */
function fixEscaped(u) {
    return u.replace(/\\u0026/g, '&').replace(/\\u003d/g, '=');
}
function extract(html, key) {
    const m = html.match(new RegExp('"' + key + '"\\s*:\\s*"([^"]+)"'));
    return m ? fixEscaped(m[1]) : null;
}
function b64dec(s) {
    return new Uint8Array(Buffer.from(s, 'base64'));
}

/* ---------- step 4: ChaCha20 decrypt via WASM (mirrors vsdec.js) ---------- */
async function decryptStreamUrls(encB64, wasmUrl) {
    const wasmRes = await globalThis.fetch(wasmUrl, { credentials: 'omit' });
    if (!wasmRes.ok) throw new Error('wasm fetch failed: ' + wasmRes.status);
    const wasmBytes = await wasmRes.arrayBuffer();
    const mod = await WebAssembly.compile(wasmBytes);
    const inst = await WebAssembly.instantiate(mod, {});
    const ex = inst.exports;
    const enc = b64dec(encB64);
    const ptr = ex.alloc(enc.length);
    new Uint8Array(ex.memory.buffer, ptr, enc.length).set(enc);
    const outLen = ex.decrypt(ptr, enc.length);
    const txt = new TextDecoder().decode(new Uint8Array(ex.memory.buffer, ptr + 12, outLen));
    return txt.split('\n').filter((s) => s);
}

/* ---------- step 5: per-host /generate.php token ---------- */
function parseToken(text) {
    if (text == null) return '';
    const t = String(text).trim();
    if (t && (t.charAt(0) === '{' || t.charAt(0) === '[')) {
        try {
            const j = JSON.parse(t);
            if (typeof j === 'string') return j;
            if (j && typeof j === 'object') return j.token || j.data || j.string || j.result || '';
        } catch (e) {}
    }
    return t;
}
function applyToken(url, token) {
    if (!token) return url;
    if (url.indexOf('__TOKEN__') > -1) return url.split('__TOKEN__').join(token);
    return url + (url.indexOf('?') > -1 ? '&' : '?') + 'token=' + encodeURIComponent(token);
}
async function stampStreamUrl(raw) {
    let origin = '';
    try {
        const x = new URL(raw);
        origin = x.protocol + '//' + x.host;
    } catch (e) {}
    let token = '';
    if (origin) {
        try {
            const tres = await globalThis.fetch(origin + '/generate.php', {
                credentials: 'omit',
                headers: { 'User-Agent': UA, 'Referer': NEXUS },
            });
            token = tres.ok ? await tres.text() : '';
            token = parseToken(token);
        } catch (e) {}
    }
    return applyToken(raw, token);
}

/* ---------- steps 1-3: gate -> player page -> stream_urls API ---------- */
async function fetchJson(url, headers) {
    const res = await globalThis.fetch(url, {
        headers: { 'User-Agent': UA, ...headers },
        redirect: 'follow',
    });
    return res.json();
}
async function fetchText(url, headers) {
    const res = await globalThis.fetch(url, {
        headers: { 'User-Agent': UA, ...headers },
        redirect: 'follow',
    });
    return res.text();
}

/* ---------- core replica logic ---------- */
async function getPlaylist(tmdb) {
    // Step 1: gate
    const gateJson = await fetchJson(`${GATE}?type=movie&id=${tmdb}`, {
        'Accept': 'application/json',
        'Referer': 'https://vidsrc.to/',
    });
    if (!gateJson || !gateJson.src) {
        throw new Error('gate returned no src: ' + JSON.stringify(gateJson));
    }
    const page1Url = gateJson.src;

    // Step 2: page #1 -> playerUrl (page #2)
    const html1 = await fetchText(page1Url, { 'Referer': 'https://vsembed.ru/' });
    const playerUrlPath = extract(html1, 'playerUrl');
    if (!playerUrlPath) throw new Error('page1 has no playerUrl');
    const page2Url = NEXUS + playerUrlPath;

    // Step 3: page #2 -> CONFIG.api + CONFIG.apiToken
    const html2 = await fetchText(page2Url, { 'Referer': NEXUS });
    const api = extract(html2, 'api');
    const token = extract(html2, 'apiToken');
    if (!api) throw new Error('page2 has no CONFIG.api');
    if (!token) throw new Error('page2 has no CONFIG.apiToken');

    // Step 4: stream_urls API with single-use token
    const streamUrl = api + '&api_token=' + encodeURIComponent(token);
    const json = await fetchJson(streamUrl, {
        'Accept': 'application/json',
        'Referer': NEXUS,
    });
    if (json.status_code && String(json.status_code) !== '200') {
        throw new Error('stream_urls API error: ' + (json.error || json.status_code));
    }

    // Step 5: decrypt stream_urls if it's an encrypted string
    let wasmUrl = json.vs && json.vs.wasm_url ? json.vs.wasm_url : null;
    let streamUrls = json.data && json.data.stream_urls;
    if (typeof streamUrls === 'string') {
        if (!wasmUrl) throw new Error('encrypted stream_urls but no wasm_url');
        streamUrls = await decryptStreamUrls(streamUrls, wasmUrl);
        json.data.stream_urls = streamUrls;
    }
    if (!Array.isArray(streamUrls) || streamUrls.length === 0) {
        throw new Error('no stream_urls returned');
    }

    // Step 6: stamp each stream URL with its per-host generate.php token
    const streams = [];
    for (const raw of streamUrls) {
        const finalUrl = await stampStreamUrl(raw);
        let origin = '';
        try {
            origin = new URL(raw).protocol + '//' + new URL(raw).host;
        } catch (e) {}
        streams.push({ url: finalUrl, origin, raw });
    }

    return {
        success: true,
        tmdb,
        title: json.data && json.data.title,
        imdb: json.data && json.data.imdb_id,
        file_name: json.data && json.data.file_name,
        backdrop: json.data && json.data.backdrop,
        default_subs: json.data && json.data.default_subs,
        thumbnails_url: json.data && json.data.thumbnails_url,
        streams,
        raw: json,
    };
}

/* ---------- routes ---------- */
app.get('/', (_req, res) => {
    res.sendFile('index.html', { root: __dirname + '/public' });
});

app.get('/api', async (req, res) => {
    const tmdb = req.query.id;
    if (!tmdb) {
        return res.status(400).json({ success: false, error: 'missing ?id=tmdb_id' });
    }
    try {
        const result = await getPlaylist(String(tmdb));
        res.json(result);
    } catch (e) {
        res.status(502).json({ success: false, error: e.message, tmdb });
    }
});

app.listen(PORT, () => {
    console.log(`vidsrc-replica API listening on http://localhost:${PORT}`);
    console.log(`  GET /          -> HTML search page`);
    console.log(`  GET /api?id=1339713 -> JSON playlist`);
});
