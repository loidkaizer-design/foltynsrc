/*
 * foltynsrc — Optimized vidsrc.to HLS playlist replica
 *
 * Endpoints:
 *   GET /                       -> HTML search page
 *   GET /api?id=<tmdb_id>       -> JSON with media info + HLS playlist URL(s)
 *   GET /proxy?url=<absolute>   -> server-side HLS relay (playlist and video bytes only)
 *   GET /health                 -> health check
 *
 * Query params:
 *   id        -> TMDB movie id (required)
 *   naming    -> "sequential" (Server 1, Server 2...) or "universe" (Milkyway, Andromeda...)
 *
 * Replicates the vidsrc.to embed flow using plain HTTP (no browser):
 *   1. vs_src.php gate          -> player page #1 (playerUrl)
 *   2. player page #2           -> CONFIG.api + CONFIG.apiToken (single-use JWT)
 *   3. stream_urls API          -> encrypted stream_urls string + vs.wasm_url
 *   4. WASM ChaCha20 decrypt    -> array of master.m3u8 host URLs
 *   5. Per-host /generate.php   -> JWT token stamped onto each master.m3u8
 *
 * Token model (upstream JWTs embed an ip_cidr claim):
 *   - Every client gets the same server-side relay. The proxy mints a fresh
 *     token from its own egress IP, then rewrites playlists so all video
 *     segments and keys stay inside /proxy.
 *
 * Other fixes:
 *   - Segments are streamed through instead of buffered, so responses
 *     larger than the serverless body limit still play
 *   - Upstream requests no longer carry the browser's foreign Referer/Origin
 */

const express = require('express');
const { Readable } = require('stream');
const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.static('public'));
app.use(express.json());

// CORS so the API can be called from anywhere
app.use((_req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization, Range');
    res.header('Access-Control-Expose-Headers', 'Accept-Ranges, Content-Length, Content-Range, Content-Type');
    next();
});
app.options('*', (_req, res) => res.sendStatus(204));

const UA =
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36';
const GATE = 'https://vsembed.ru/vs_src.php';
const NEXUS = 'https://stellarconductornexus.com';

// Universe names for the "universe" naming mode
const UNIVERSE_NAMES = [
    'Milkyway', 'Andromeda', 'Orion', 'Sombrero', 'Whirlpool', 'Triangulum',
    'Cigar', 'Pinwheel', 'Tadpole', 'Cartwheel', 'Black Eye', 'Sunflower',
    'Southern Pinwheel', 'Comet', 'Hoags Object', 'Antennae', 'Ring Nebula',
    'Helix', 'Crab', 'Eagle', 'Omega', 'Lobster', 'Tarantula', 'Ghost Head',
    'Magic Eye', 'Bear Claw', 'Cosmic Reef'
];

function universeName(index) {
    return UNIVERSE_NAMES[index % UNIVERSE_NAMES.length];
}

function serverName(index, mode) {
    if (mode === 'universe') return universeName(index);
    return `Server ${index + 1}`;
}

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

/* ---------- per-host token minting (IP-bound JWTs) ---------- */
// generate.php tokens embed the requesting IP range (ip_cidr claim).
// A token minted by the /api call (or a different serverless instance) is
// rejected when the proxy fetches from a different egress IP. The server-side
// relay therefore mints its own fresh token, cached briefly per origin.
const TOKEN_CACHE_MS = 4 * 60 * 1000;
const tokenCache = new Map();

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

async function mintToken(origin, force) {
    const now = Date.now();
    const hit = tokenCache.get(origin);
    if (!force && hit && hit.expires > now) return hit.token;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 10000);
    try {
        const res = await globalThis.fetch(origin + '/generate.php', {
            credentials: 'omit',
            signal: controller.signal,
            headers: { 'User-Agent': UA, 'Referer': NEXUS },
        });
        const token = res.ok ? parseToken(await res.text()) : '';
        if (token) tokenCache.set(origin, { token: token, expires: now + TOKEN_CACHE_MS });
        return token;
    } finally {
        clearTimeout(timer);
    }
}

function withTokenUrl(url, token) {
    const u = new URL(url);
    u.searchParams.set('token', token);
    return u.toString();
}

/* ---------- server-side HLS relay ---------- */
const PROXY_TIMEOUT_MS = 20000;
const RESPONSE_HEADERS = [
    'accept-ranges', 'cache-control', 'content-disposition', 'content-encoding',
    'content-language', 'content-range', 'content-type', 'etag', 'expires',
    'last-modified', 'vary',
];

function proxyRequestHeaders(req, targetUrl) {
    // Upstream hosts reject requests that carry a foreign Referer/Origin
    // (e.g. foltynsrc.vercel.app), so send a minimal, same-origin-looking
    // header set instead of forwarding the browser's headers. Range is
    // forwarded so seeking keeps working.
    const headers = {
        'accept': '*/*',
        'accept-encoding': 'identity',
        'user-agent': req.get('user-agent') || UA,
        'referer': targetUrl.origin,
    };
    const range = req.get('range');
    if (range) headers.range = range;
    return headers;
}

function isPlaylistUrl(finalUrl) {
    return /\.m3u8(?:$|[?#])/i.test(finalUrl);
}

function proxyUrlFor(_req, absoluteUrl) {
    // Relative URLs work both locally and on Vercel without trusting Host headers.
    return '/proxy?url=' + encodeURIComponent(absoluteUrl);
}

function rewritePlaylist(playlist, baseUrl, req) {
    const rewrite = (value) => {
        const uri = value.trim();
        if (!uri || /^(?:data|blob|about):/i.test(uri)) return value;
        try {
            return proxyUrlFor(req, new URL(uri, baseUrl).toString());
        } catch (e) {
            return value;
        }
    };

    return playlist.split(/(\r?\n)/).map((part) => {
        if (/^\r?\n$/.test(part)) return part;
        // Handles EXT-X-KEY, EXT-X-MAP, audio/subtitle renditions, and variants.
        let line = part.replace(/(URI\s*=\s*")([^"]*)(")/gi,
            (_match, prefix, uri, suffix) => prefix + rewrite(uri) + suffix);
        // Bare media or variant playlist references are non-comment lines.
        if (line.trim() && !line.trim().startsWith('#') &&
            !/^(?:\/\/|[a-z][a-z\d+.-]*:)/i.test(line.trim())) {
            line = rewrite(line);
        }
        return line;
    }).join('');
}

function sendPlaylist(res, upstream, playlist, finalUrl, req) {
    const rewritten = rewritePlaylist(playlist, finalUrl, req);
    res.set('Content-Type', upstream.headers.get('content-type') || 'application/vnd.apple.mpegurl');
    res.set('Cache-Control', 'no-store');
    return res.send(rewritten);
}

async function proxyHls(req, res) {
    const target = Array.isArray(req.query.url) ? req.query.url[0] : req.query.url;
    if (!target || typeof target !== 'string') {
        return res.status(400).json({ success: false, error: 'missing ?url=<m3u8-or-segment-url>' });
    }

    let targetUrl;
    try {
        targetUrl = new URL(target);
        if (!['http:', 'https:'].includes(targetUrl.protocol)) throw new Error('unsupported protocol');
    } catch (e) {
        return res.status(400).json({ success: false, error: 'url must be an absolute HTTP(S) URL' });
    }

    // Always relay the media itself. Do not return an HTML player page here:
    // browsers request HLS manifests with Accept: text/html in some contexts,
    // and returning HTML prevents the video element from ever receiving HLS.
    const origin = targetUrl.protocol + '//' + targetUrl.host;
    const hasToken = targetUrl.searchParams.has('token');

    // Mint a fresh token from THIS instance before the first fetch: the token
    // embedded in the URL was minted elsewhere and is IP-bound upstream.
    let effectiveUrl = targetUrl.toString();
    if (hasToken) {
        try {
            const fresh = await mintToken(origin, false);
            if (fresh) effectiveUrl = withTokenUrl(effectiveUrl, fresh);
        } catch (e) { /* fall back to the embedded token */ }
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), PROXY_TIMEOUT_MS);
    try {
        const doFetch = (url) => globalThis.fetch(url, {
            method: 'GET',
            headers: proxyRequestHeaders(req, targetUrl),
            redirect: 'follow',
            signal: controller.signal,
        });

        let upstream = await doFetch(effectiveUrl);

        if (!upstream.ok && hasToken) {
            const errText = await upstream.text().catch(() => '');
            const retryable = upstream.status === 403 || upstream.status === 401 ||
                /not in range|expired|invalid/i.test(errText);
            if (retryable) {
                try {
                    const fresh = await mintToken(origin, true);
                    if (fresh) upstream = await doFetch(withTokenUrl(targetUrl.toString(), fresh));
                } catch (e) { /* fall through to the error response */ }
            }
            if (!upstream.ok) {
                const finalErr = await upstream.text().catch(() => '');
                return res.status(upstream.status)
                    .type(upstream.headers.get('content-type') || 'text/plain')
                    .send(finalErr || errText || ('upstream returned ' + upstream.status));
            }
        } else if (!upstream.ok) {
            const errorBody = await upstream.text();
            return res.status(upstream.status)
                .type(upstream.headers.get('content-type') || 'text/plain')
                .send(errorBody);
        }

        const finalUrl = upstream.url || effectiveUrl;
        const contentType = upstream.headers.get('content-type') || '';

        // Playlists must be rewritten; fetch them as text.
        if (contentType.toLowerCase().includes('mpegurl') || isPlaylistUrl(finalUrl)) {
            const playlist = await upstream.text();
            return sendPlaylist(res, upstream, playlist, finalUrl, req);
        }

        // Small non-playlist bodies may still be mislabelled playlists; sniff them.
        const contentLength = parseInt(upstream.headers.get('content-length') || '', 10);
        if (!Number.isNaN(contentLength) && contentLength > 0 && contentLength <= 512 * 1024) {
            const body = Buffer.from(await upstream.arrayBuffer());
            const head = body.slice(0, 1024).toString('utf8');
            if (/^\s*#EXTM3U/m.test(head)) {
                return sendPlaylist(res, upstream, body.toString('utf8'), finalUrl, req);
            }
            for (const header of RESPONSE_HEADERS) {
                const value = upstream.headers.get(header);
                if (value && header !== 'content-length' && header !== 'cache-control') res.set(header, value);
            }
            res.set('Cache-Control', 'no-store');
            return res.send(body);
        }

        // Binary media (segments/keys): stream through instead of buffering so
        // responses larger than the serverless body limit still play. Clearing
        // the abort timer lets long segment downloads finish.
        clearTimeout(timer);
        res.status(upstream.status);
        for (const header of RESPONSE_HEADERS) {
            const value = upstream.headers.get(header);
            if (value && header !== 'content-length' && header !== 'cache-control') res.set(header, value);
        }
        res.set('Cache-Control', 'no-store');
        if (!upstream.body) return res.end();
        const nodeStream = Readable.fromWeb(upstream.body);
        nodeStream.on('error', () => res.end());
        return nodeStream.pipe(res);
    } catch (e) {
        const message = e.name === 'AbortError' ? 'upstream request timed out' : e.message;
        return res.status(502).json({ success: false, error: 'proxy request failed: ' + message });
    } finally {
        clearTimeout(timer);
    }
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
    let tokenError = null;
    if (origin) {
        try {
            token = await mintToken(origin, false);
            if (!token) tokenError = 'generate.php returned no token';
        } catch (e) {
            tokenError = e.message;
        }
    }
    return { finalUrl: applyToken(raw, token), origin, token, tokenError };
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
async function getPlaylist(tmdb, namingMode) {
    // Step 1: gate
    let gateJson;
    try {
        gateJson = await fetchJson(`${GATE}?type=movie&id=${tmdb}`, {
            'Accept': 'application/json',
            'Referer': 'https://vidsrc.to/',
        });
    } catch (e) {
        throw new Error('gate request failed: ' + e.message);
    }
    if (!gateJson || !gateJson.src) {
        throw new Error('gate returned no src: ' + JSON.stringify(gateJson));
    }
    const page1Url = gateJson.src;

    // Step 2: page #1 -> playerUrl (page #2)
    let html1;
    try {
        html1 = await fetchText(page1Url, { 'Referer': 'https://vsembed.ru/' });
    } catch (e) {
        throw new Error('page1 request failed: ' + e.message);
    }
    const playerUrlPath = extract(html1, 'playerUrl');
    if (!playerUrlPath) throw new Error('page1 has no playerUrl (gate token may be expired)');
    const page2Url = NEXUS + playerUrlPath;

    // Step 3: page #2 -> CONFIG.api + CONFIG.apiToken
    let html2;
    try {
        html2 = await fetchText(page2Url, { 'Referer': NEXUS });
    } catch (e) {
        throw new Error('page2 request failed: ' + e.message);
    }
    const api = extract(html2, 'api');
    const token = extract(html2, 'apiToken');
    if (!api) throw new Error('page2 has no CONFIG.api');
    if (!token) throw new Error('page2 has no CONFIG.apiToken');

    // Step 4: stream_urls API with single-use token
    const streamUrl = api + '&api_token=' + encodeURIComponent(token);
    let json;
    try {
        json = await fetchJson(streamUrl, {
            'Accept': 'application/json',
            'Referer': NEXUS,
        });
    } catch (e) {
        throw new Error('stream_urls API request failed: ' + e.message);
    }
    if (json.status_code && String(json.status_code) !== '200') {
        throw new Error('stream_urls API error: ' + (json.error || json.status_code));
    }

    // Step 5: decrypt stream_urls if encrypted string
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

    // Step 6: stamp each stream URL with its per-host generate.php token (PARALLEL)
    const stamped = await Promise.allSettled(
        streamUrls.map(async (raw, i) => {
            const stamped = await stampStreamUrl(raw);
            return {
                id: i + 1,
                name: serverName(i, namingMode),
                origin: stamped.origin,
                url: stamped.finalUrl,
                raw,
                token: stamped.token,
                tokenError: stamped.tokenError,
                status: stamped.token ? 'ready' : 'token-failed',
            };
        })
    );

    const servers = stamped.map((r, i) =>
        r.status === 'fulfilled' ? r.value : {
            id: i + 1,
            name: serverName(i, namingMode),
            origin: '',
            url: streamUrls[i] || '',
            raw: streamUrls[i] || '',
            token: '',
            tokenError: r.reason ? r.reason.message : 'unknown',
            status: 'error',
        }
    );

    return {
        success: true,
        project: 'foltynsrc',
        naming_mode: namingMode,
        tmdb,
        title: json.data && json.data.title,
        imdb: json.data && json.data.imdb_id,
        file_name: json.data && json.data.file_name,
        backdrop: json.data && json.data.backdrop,
        default_subs: json.data && json.data.default_subs,
        thumbnails_url: json.data && json.data.thumbnails_url,
        servers,
        raw: json,
    };
}

/* ---------- routes ---------- */
app.get('/health', (_req, res) => {
    res.json({ ok: true, project: 'foltynsrc', time: new Date().toISOString() });
});

app.get('/', (_req, res) => {
    res.sendFile('index.html', { root: __dirname + '/public' });
});

app.get('/proxy', proxyHls);

app.get('/api', async (req, res) => {
    const tmdb = req.query.id;
    // Universe naming is the single supported presentation mode.
    const namingMode = 'universe';
    if (!tmdb) {
        return res.status(400).json({
            success: false,
            error: 'missing ?id=tmdb_id',
            example: '/api?id=1339713&naming=universe',
        });
    }
    try {
        const result = await getPlaylist(String(tmdb), namingMode);
        res.json(result);
    } catch (e) {
        res.status(502).json({ success: false, error: e.message, tmdb, naming_mode: namingMode });
    }
});

// Export for Vercel serverless (also runnable locally with `node server.js`)
if (require.main === module) {
    app.listen(PORT, () => {
        console.log(`foltynsrc API listening on http://localhost:${PORT}`);
        console.log(`  GET /          -> HTML search page`);
        console.log(`  GET /proxy?url=<master.m3u8> -> HLS playlist and media relay`);
        console.log(`  GET /api?id=1339713&naming=universe -> JSON playlist`);
        console.log(`  GET /health    -> health check`);
    });
}

module.exports = app;
