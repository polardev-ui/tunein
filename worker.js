// Enhanced Cloudflare Worker with API Key Authentication
// Supports both ?API=key and Authorization: Bearer key

const ALLOWED_ORIGINS = null; // e.g. "https://yourdomain.com,https://www.yourdomain.com"

// In-memory listener map for tune in stats (per Worker instance).
// Keyed by IP, value: { station: string, updatedAt: number }
const LISTENERS = new Map();

function buildCorsHeaders(request) {
  const origin = request.headers.get('Origin') || '*';
  if (ALLOWED_ORIGINS) {
    const allowed = ALLOWED_ORIGINS.split(',').map(s => s.trim());
    if (!allowed.includes(origin)) {
      return {
        'Access-Control-Allow-Origin': 'null',
        'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization'
      };
    }
    return {
      'Access-Control-Allow-Origin': origin,
      'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization'
    };
  }
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization'
  };
}

function jsonResponse(obj, status = 200, corsHeaders = {}) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: Object.assign({ 'Content-Type': 'application/json' }, corsHeaders)
  });
}

function textResponse(text, status = 200, corsHeaders = {}) {
  return new Response(text, { status, headers: Object.assign({ 'Content-Type': 'text/plain' }, corsHeaders) });
}

function isSafeHttpUrl(u) {
  try {
    const url = new URL(u);
    if (!/^https?:$/.test(url.protocol)) return false;
    const host = url.hostname.toLowerCase();
    const blockedHosts = ['localhost', '127.0.0.1', '::1', '0.0.0.0'];
    if (blockedHosts.includes(host)) return false;
    if (/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[0-1])\.|169\.254\.)/.test(host)) return false;
    return true;
  } catch {
    return false;
  }
}

function parseMeta(html) {
  const pick = (re) => {
    const m = html.match(re);
    return m ? (m[1] || '').trim() : '';
  };
  const title = pick(/<meta[^>]+property=["']og:title["'][^>]+content=["']([^"']+)["']/i) ||
                pick(/<meta[^>]+name=["']twitter:title["'][^>]+content=["']([^"']+)["']/i) ||
                pick(/<title[^>]*>([^<]*)<\/title>/i);
  const description = pick(/<meta[^>]+property=["']og:description["'][^>]+content=["']([^"']+)["']/i) ||
                      pick(/<meta[^>]+name=["']twitter:description["'][^>]+content=["']([^"']+)["']/i);
  const image = pick(/<meta[^>]+property=["']og:image["'][^>]+content=["']([^"']+)["']/i) ||
                pick(/<meta[^>]+name=["']twitter:image["'][^>]+content=["']([^"']+)["']/i);
  const site = pick(/<meta[^>]+property=["']og:site_name["'][^>]+content=["']([^"']+)["']/i) ||
               pick(/<meta[^>]+name=["']twitter:site["'][^>]+content=["']([^"']+)["']/i);
  return { title, description, image, site };
}

function validateApiKey(request, url, env) {
  // Check query parameter first: ?API=key
  const queryKey = url.searchParams.get('API');
  if (queryKey) {
    return queryKey;
  }
  
  // Check Authorization header: Bearer key
  const authHeader = request.headers.get('Authorization');
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.substring(7);
  }
  
  return null;
}

function requiresAuth(pathname) {
  const publicEndpoints = [
    '/v1/images',
    '/v1/giphy',
    '/v1/link/preview',
    '/v1/polls',
    '/api/stats',
    '/api/tune'
  ];
  
  return !publicEndpoints.some(ep => pathname.startsWith(ep));
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const pathname = url.pathname || '/';
    const method = request.method.toUpperCase();
    const CORS_HEADERS = buildCorsHeaders(request);

    if (method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }

    if (requiresAuth(pathname)) {
      const apiKey = validateApiKey(request, url, env);
      
      if (!apiKey) {
        return jsonResponse({ error: 'API key required. Use ?API=key or Authorization: Bearer key' }, 401, CORS_HEADERS);
      }
      
      // Validate against KV store if available
      if (env.API_KEYS) {
        try {
          const isValid = await env.API_KEYS.get(apiKey);
          if (!isValid) {
            return jsonResponse({ error: 'Invalid API key' }, 403, CORS_HEADERS);
          }
        } catch (err) {
          // If KV fails, allow through but log error
          console.error('KV validation error:', err);
        }
      }
    }

    // --- tune in stats (public, no API key) ---
    if (pathname === '/api/tune' && method === 'POST') {
      return handleTune(request, CORS_HEADERS);
    }

    if (pathname === '/api/stats' && method === 'GET') {
      return handleStats(CORS_HEADERS);
    }

    // R2 binding is required for images and polls
    if (!env.IMAGES && (pathname.startsWith('/v1/images') || pathname.startsWith('/v1/polls'))) {
      return textResponse('R2 binding IMAGES is not configured', 501, CORS_HEADERS);
    }

    // --- Images ---
    if ((pathname === '/v1/images' || pathname === '/v1/images/') && method === 'POST') {
      return handleUpload(request, env, CORS_HEADERS);
    }
    if (pathname.startsWith('/v1/images/') && method === 'GET') {
      const key = pathname.slice('/v1/images/'.length);
      return handleGet(key, env, CORS_HEADERS);
    }

    // --- Giphy ---
    if (pathname === '/v1/giphy/search' && method === 'GET') {
      return handleGiphySearch(url, env, CORS_HEADERS);
    }

    // --- Link preview ---
    if (pathname === '/v1/link/preview' && method === 'GET') {
      return handleLinkPreview(url, CORS_HEADERS);
    }

    // --- Polls (R2) ---
    if (pathname === '/v1/polls' && method === 'POST') {
      return handlePollCreate(request, env, CORS_HEADERS);
    }
    if (pathname.startsWith('/v1/polls/') && method === 'GET') {
      const id = pathname.split('/')[3];
      return handlePollGet(id, env, CORS_HEADERS);
    }
    if (pathname.startsWith('/v1/polls/') && method === 'POST' && pathname.endsWith('/vote')) {
      const id = pathname.split('/')[3];
      return handlePollVote(id, request, env, CORS_HEADERS);
    }
    
    // --- VPN provisioning (requires auth) ---
    if (pathname === '/v1/vpn' && method === 'GET') {
      return handleVpnGet(request, env, CORS_HEADERS);
    }
    if (pathname === '/v1/vpn/list' && method === 'GET') {
      return handleVpnList(request, env, CORS_HEADERS);
    }
    if (pathname === '/v1/vpn/geo' && method === 'GET') {
      return handleVpnGeo(request, CORS_HEADERS);
    }

    // --- Network Tools (requires auth) ---
    if (pathname === '/v1/network/ip' && method === 'GET') {
      const ip = request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || '0.0.0.0';
      return jsonResponse({ ip }, 200, CORS_HEADERS);
    }
    if (pathname === '/v1/network/headers' && method === 'GET') {
      const headers = {};
      request.headers.forEach((value, key) => { headers[key] = value; });
      return jsonResponse({ headers }, 200, CORS_HEADERS);
    }
    if (pathname === '/v1/network/ping' && method === 'GET') {
      const target = url.searchParams.get('url');
      if (!target || !isSafeHttpUrl(target)) return textResponse('Invalid URL', 400, CORS_HEADERS);
      const start = Date.now();
      try {
        await fetch(target, { method: 'HEAD', signal: AbortSignal.timeout(5000) });
        return jsonResponse({ url: target, responseTime: Date.now() - start, status: 'success' }, 200, CORS_HEADERS);
      } catch {
        return jsonResponse({ url: target, responseTime: Date.now() - start, status: 'failed' }, 200, CORS_HEADERS);
      }
    }
    if (pathname === '/v1/network/dns' && method === 'GET') {
      const domain = url.searchParams.get('domain');
      if (!domain) return textResponse('Missing domain parameter', 400, CORS_HEADERS);
      try {
        const result = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=A`, {
          headers: { 'Accept': 'application/dns-json' }
        });
        const data = await result.json();
        return jsonResponse(data, 200, CORS_HEADERS);
      } catch (err) {
        return textResponse(`DNS lookup failed: ${err}`, 500, CORS_HEADERS);
      }
    }

    // --- Text Operations (requires auth) ---
    if (pathname === '/v1/text/hash' && method === 'GET') {
      const text = url.searchParams.get('text');
      const algo = url.searchParams.get('algo') || 'SHA-256';
      if (!text) return textResponse('Missing text parameter', 400, CORS_HEADERS);
      try {
        const encoder = new TextEncoder();
        const data = encoder.encode(text);
        const hashBuffer = await crypto.subtle.digest(algo, data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hash = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        return jsonResponse({ text, algorithm: algo, hash }, 200, CORS_HEADERS);
      } catch (err) {
        return textResponse(`Hash failed: ${err}`, 500, CORS_HEADERS);
      }
    }
    if (pathname === '/v1/text/wordcount' && method === 'GET') {
      const text = url.searchParams.get('text') || '';
      const words = text.trim().split(/\s+/).filter(Boolean).length;
      const chars = text.length;
      return jsonResponse({ text, words, characters: chars }, 200, CORS_HEADERS);
    }
    if (pathname === '/v1/text/case' && method === 'GET') {
      const text = url.searchParams.get('text') || '';
      const caseType = url.searchParams.get('type') || 'upper';
      let result = text;
      if (caseType === 'upper') result = text.toUpperCase();
      else if (caseType === 'lower') result = text.toLowerCase();
      else if (caseType === 'title') result = text.replace(/\w\S*/g, txt => txt.charAt(0).toUpperCase() + txt.substr(1).toLowerCase());
      return jsonResponse({ original: text, type: caseType, result }, 200, CORS_HEADERS);
    }

    // --- Math Operations (requires auth) ---
    if (pathname === '/v1/math/fibonacci' && method === 'GET') {
      const n = parseInt(url.searchParams.get('n') || '10', 10);
      if (n < 0 || n > 50) return textResponse('n must be between 0 and 50', 400, CORS_HEADERS);
      const fib = [0, 1];
      for (let i = 2; i <= n; i++) fib[i] = fib[i-1] + fib[i-2];
      return jsonResponse({ n, sequence: fib.slice(0, n+1) }, 200, CORS_HEADERS);
    }
    if (pathname === '/v1/math/prime' && method === 'GET') {
      const num = parseInt(url.searchParams.get('num') || '2', 10);
      const isPrime = (n) => {
        if (n < 2) return false;
        for (let i = 2; i <= Math.sqrt(n); i++) {
          if (n % i === 0) return false;
        }
        return true;
      };
      return jsonResponse({ number: num, isPrime: isPrime(num) }, 200, CORS_HEADERS);
    }

    // --- Generators (requires auth) ---
    if (pathname === '/v1/generate/username' && method === 'GET') {
      const adjectives = ['Cool', 'Swift', 'Brave', 'Clever', 'Mighty'];
      const nouns = ['Tiger', 'Eagle', 'Dragon', 'Phoenix', 'Wolf'];
      const username = adjectives[Math.floor(Math.random() * adjectives.length)] + 
                      nouns[Math.floor(Math.random() * nouns.length)] + 
                      Math.floor(Math.random() * 1000);
      return jsonResponse({ username }, 200, CORS_HEADERS);
    }
    if (pathname === '/v1/generate/company' && method === 'GET') {
      const prefixes = ['Tech', 'Cyber', 'Digital', 'Smart', 'Cloud'];
      const suffixes = ['Labs', 'Systems', 'Solutions', 'Innovations', 'Technologies'];
      const name = prefixes[Math.floor(Math.random() * prefixes.length)] + 
                  suffixes[Math.floor(Math.random() * suffixes.length)];
      return jsonResponse({ company: name }, 200, CORS_HEADERS);
    }

    // --- Validation (requires auth) ---
    if (pathname === '/v1/validate/email' && method === 'GET') {
      const email = url.searchParams.get('email') || '';
      const isValid = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
      return jsonResponse({ email, isValid }, 200, CORS_HEADERS);
    }
    if (pathname === '/v1/validate/url' && method === 'GET') {
      const testUrl = url.searchParams.get('url') || '';
      let isValid = false;
      try {
        new URL(testUrl);
        isValid = true;
      } catch {}
      return jsonResponse({ url: testUrl, isValid }, 200, CORS_HEADERS);
    }
    if (pathname === '/v1/validate/json' && method === 'POST') {
      try {
        const text = await request.text();
        JSON.parse(text);
        return jsonResponse({ isValid: true }, 200, CORS_HEADERS);
      } catch (err) {
        return jsonResponse({ isValid: false, error: err.message }, 200, CORS_HEADERS);
      }
    }

    // --- Time Utilities (requires auth) ---
    if (pathname === '/v1/time/unix' && method === 'GET') {
      return jsonResponse({ timestamp: Math.floor(Date.now() / 1000) }, 200, CORS_HEADERS);
    }
    if (pathname === '/v1/time/format' && method === 'GET') {
      const timestamp = url.searchParams.get('timestamp');
      const format = url.searchParams.get('format') || 'iso';
      const date = timestamp ? new Date(parseInt(timestamp) * 1000) : new Date();
      let formatted = date.toISOString();
      if (format === 'locale') formatted = date.toLocaleString();
      else if (format === 'date') formatted = date.toLocaleDateString();
      else if (format === 'time') formatted = date.toLocaleTimeString();
      return jsonResponse({ timestamp: Math.floor(date.getTime() / 1000), formatted }, 200, CORS_HEADERS);
    }

    // --- Converters (requires auth) ---
    if (pathname === '/v1/convert/currency' && method === 'GET') {
      const amount = parseFloat(url.searchParams.get('amount') || '1');
      const from = url.searchParams.get('from') || 'USD';
      const to = url.searchParams.get('to') || 'EUR';
      // Mock conversion rates
      const rates = { USD: 1, EUR: 0.92, GBP: 0.79, JPY: 149.50 };
      const result = (amount * (rates[to] || 1)) / (rates[from] || 1);
      return jsonResponse({ amount, from, to, result: result.toFixed(2) }, 200, CORS_HEADERS);
    }
    if (pathname === '/v1/convert/units' && method === 'GET') {
      const value = parseFloat(url.searchParams.get('value') || '1');
      const from = url.searchParams.get('from') || 'km';
      const to = url.searchParams.get('to') || 'miles';
      const conversions = {
        'km-miles': 0.621371,
        'miles-km': 1.60934,
        'kg-lbs': 2.20462,
        'lbs-kg': 0.453592
      };
      const key = `${from}-${to}`;
      const result = conversions[key] ? value * conversions[key] : value;
      return jsonResponse({ value, from, to, result: result.toFixed(2) }, 200, CORS_HEADERS);
    }

    // --- Fun Endpoints (requires auth) ---
    if (pathname === '/v1/fun/joke' && method === 'GET') {
      const jokes = [
        "Why don't scientists trust atoms? Because they make up everything!",
        "Why did the scarecrow win an award? He was outstanding in his field!",
        "Why don't eggs tell jokes? They'd crack each other up!"
      ];
      return jsonResponse({ joke: jokes[Math.floor(Math.random() * jokes.length)] }, 200, CORS_HEADERS);
    }
    if (pathname === '/v1/fun/8ball' && method === 'GET') {
      const answers = ['Yes', 'No', 'Maybe', 'Ask again later', 'Definitely', 'Unlikely', 'Absolutely not', 'Without a doubt'];
      return jsonResponse({ answer: answers[Math.floor(Math.random() * answers.length)] }, 200, CORS_HEADERS);
    }
    if (pathname === '/v1/fun/fortune' && method === 'GET') {
      const fortunes = [
        'A pleasant surprise is waiting for you.',
        'Your hard work will soon pay off.',
        'Good things come to those who wait.',
        'Adventure awaits you around the corner.'
      ];
      return jsonResponse({ fortune: fortunes[Math.floor(Math.random() * fortunes.length)] }, 200, CORS_HEADERS);
    }

    // --- QR Code (requires auth) ---
    if (pathname === '/v1/qr' && method === 'GET') {
      const data = url.searchParams.get('data');
      if (!data) return textResponse('Missing data parameter', 400, CORS_HEADERS);
      const qrUrl = `https://api.qrserver.com/v1/create-qr-code/?size=300x300&data=${encodeURIComponent(data)}`;
      return jsonResponse({ data, qrUrl }, 200, CORS_HEADERS);
    }

    // --- Utilities (all require auth except already handled) ---
    if (pathname === '/v1/utility/echo' && method === 'GET') {
      const msg = url.searchParams.get('msg') || '';
      return jsonResponse({ original: msg, reversed: msg.split('').reverse().join('') }, 200, CORS_HEADERS);
    }
    if (pathname === '/v1/utility/dice' && method === 'GET') {
      const roll = url.searchParams.get('roll') || '1d6';
      return jsonResponse({ roll, result: rollDice(roll) }, 200, CORS_HEADERS);
    }
    if (pathname.startsWith('/v1/utility/base64-') && method === 'GET') {
      const action = pathname.split('/').pop();
      const text = url.searchParams.get('text') || '';
      if (!text) return textResponse("Missing 'text' query param", 400, CORS_HEADERS);
      let result;
      if (action === 'base64-encode' || action === 'encode') result = btoa(text);
      else if (action === 'base64-decode' || action === 'decode') result = atob(text);
      else return textResponse('Invalid base64 action', 400, CORS_HEADERS);
      return jsonResponse({ action, input: text, result }, 200, CORS_HEADERS);
    }
    if (pathname === '/v1/utility/random-user' && method === 'GET') {
      return jsonResponse(generateRandomUser(), 200, CORS_HEADERS);
    }
    if (pathname === '/v1/utility/palindrome' && method === 'GET') {
      const text = url.searchParams.get('text') || '';
      if (!text) return textResponse("Missing 'text' query param", 400, CORS_HEADERS);
      const clean = text.replace(/[^a-zA-Z0-9]/g, '').toLowerCase();
      const isPalindrome = clean === clean.split('').reverse().join('');
      return jsonResponse({ text, isPalindrome }, 200, CORS_HEADERS);
    }
    if (pathname === '/v1/utility/countdown' && method === 'GET') {
      const untilStr = url.searchParams.get('until');
      if (!untilStr) return textResponse("Missing 'until' param", 400, CORS_HEADERS);
      const until = new Date(untilStr);
      if (isNaN(until.getTime())) return textResponse('Invalid date', 400, CORS_HEADERS);
      const secondsRemaining = Math.max(0, Math.floor((until.getTime() - Date.now()) / 1000));
      return jsonResponse({ until: until.toISOString(), secondsRemaining }, 200, CORS_HEADERS);
    }
    if (pathname === '/v1/utility/random-color' && method === 'GET') {
      return jsonResponse({ color: '#' + Math.floor(Math.random() * 0xffffff).toString(16).padStart(6, '0') }, 200, CORS_HEADERS);
    }
    if (pathname === '/v1/utility/advice' && method === 'GET') {
      const advices = ["Don't compare yourself to others.","Stay hydrated.","Consistency is key.","Take breaks when needed.","Keep learning every day."];
      return jsonResponse({ advice: advices[Math.floor(Math.random() * advices.length)] }, 200, CORS_HEADERS);
    }
    if (pathname === '/v1/utility/number-fact' && method === 'GET') {
      const num = parseInt(url.searchParams.get('num') || '0', 10);
      return jsonResponse({ number: num, fact: `${num} is just a number, but cool nonetheless!` }, 200, CORS_HEADERS);
    }
    if (pathname === '/v1/utility/uuid' && method === 'GET') {
      return jsonResponse({ uuid: crypto.randomUUID() }, 200, CORS_HEADERS);
    }
    if (pathname === '/v1/utility/password' && method === 'GET') {
      const length = parseInt(url.searchParams.get('length') || '12', 10);
      const strength = url.searchParams.get('strength') || 'medium';
      return jsonResponse({ password: generatePassword(length, strength) }, 200, CORS_HEADERS);
    }
    if (pathname === '/v1/utility/quote' && method === 'GET') {
      const quotes = [
        'The best way to get started is to quit talking and begin doing. – Walt Disney',
        "Don't let yesterday take up too much of today. – Will Rogers",
        "It always seems impossible until it's done. – Nelson Mandela"
      ];
      return jsonResponse({ quote: quotes[Math.floor(Math.random() * quotes.length)] }, 200, CORS_HEADERS);
    }
    if (pathname === '/v1/utility/time' && method === 'GET') {
      const tz = url.searchParams.get('tz') || 'UTC';
      try {
        const time = new Date().toLocaleString('en-US', { timeZone: tz });
        return jsonResponse({ timezone: tz, time }, 200, CORS_HEADERS);
      } catch {
        return textResponse('Invalid timezone', 400, CORS_HEADERS);
      }
    }
    if (pathname === '/v1/utility/math' && method === 'GET') {
      const expr = url.searchParams.get('expr');
      if (!expr) return textResponse("Missing 'expr' param", 400, CORS_HEADERS);
      try {
        if (!/^[0-9+\-*/().\s]+$/.test(expr)) throw new Error('Invalid characters');
        const result = new Function('return ' + expr)();
        return jsonResponse({ expr, result }, 200, CORS_HEADERS);
      } catch {
        return textResponse('Invalid expression', 400, CORS_HEADERS);
      }
    }
    if (pathname === '/v1/utility/emoji' && method === 'GET') {
      const emojis = ['🚀','🎉','🔥','😎','💡','🎨','🍕','🐱'];
      return jsonResponse({ emoji: emojis[Math.floor(Math.random() * emojis.length)] }, 200, CORS_HEADERS);
    }
    if (pathname === '/v1/utility/slugify' && method === 'GET') {
      const text = url.searchParams.get('text') || '';
      if (!text) return textResponse("Missing 'text' param", 400, CORS_HEADERS);
      const slug = text.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '');
      return jsonResponse({ slug }, 200, CORS_HEADERS);
    }
    if (pathname === '/v1/utility/random-hex' && method === 'GET') {
      const length = parseInt(url.searchParams.get('length') || '8', 10);
      const hex = Array.from({ length }).map(() => Math.floor(Math.random() * 16).toString(16)).join('');
      return jsonResponse({ hex }, 200, CORS_HEADERS);
    }
    if (pathname === '/v1/utility/lorem' && method === 'GET') {
      const words = parseInt(url.searchParams.get('words') || '10', 10);
      const lorem = 'Lorem ipsum dolor sit amet consectetur adipiscing elit'.split(' ');
      const text = Array.from({ length: words }).map(() => lorem[Math.floor(Math.random() * lorem.length)]).join(' ');
      return jsonResponse({ text }, 200, CORS_HEADERS);
    }
    if (pathname === '/v1/utility/cat-fact' && method === 'GET') {
      const facts = ['Cats sleep 70% of their lives.','A group of cats is called a clowder.','Cats have over 20 muscles in their ears.'];
      return jsonResponse({ fact: facts[Math.floor(Math.random() * facts.length)] }, 200, CORS_HEADERS);
    }
    if (pathname === '/v1/utility/temp' && method === 'GET') {
      const c = url.searchParams.get('c');
      const f = url.searchParams.get('f');
      if (c !== null) return jsonResponse({ c: parseFloat(c), f: parseFloat(c) * 9/5 + 32 }, 200, CORS_HEADERS);
      if (f !== null) return jsonResponse({ f: parseFloat(f), c: (parseFloat(f) - 32) * 5/9 }, 200, CORS_HEADERS);
      return textResponse('Provide ?c= or ?f=', 400, CORS_HEADERS);
    }

    return new Response('Not Found', { status: 404, headers: CORS_HEADERS });
  }
};

// ----- tune in stats (in-memory, per-Worker instance) -----
async function handleTune(request, CORS_HEADERS) {
  try {
    const body = await request.json();
    const station = body && typeof body.station === 'string' ? body.station.trim() : '';
    if (!station) {
      return jsonResponse({ error: 'station is required' }, 400, CORS_HEADERS);
    }

    const ip = request.headers.get('CF-Connecting-IP') ||
               request.headers.get('X-Forwarded-For') ||
               '0.0.0.0';

    LISTENERS.set(ip, { station, updatedAt: Date.now() });

    return jsonResponse({ ok: true }, 200, CORS_HEADERS);
  } catch (err) {
    return jsonResponse({ error: 'invalid json body' }, 400, CORS_HEADERS);
  }
}

function handleStats(CORS_HEADERS) {
  const now = Date.now();
  const cutoff = now - 5 * 60 * 1000; // 5 minutes inactivity window

  // Drop stale listeners
  for (const [ip, info] of LISTENERS.entries()) {
    if (!info || info.updatedAt < cutoff) {
      LISTENERS.delete(ip);
    }
  }

  const stations = {};
  for (const info of LISTENERS.values()) {
    if (!info || !info.station) continue;
    stations[info.station] = (stations[info.station] || 0) + 1;
  }

  let total = 0;
  for (const key of Object.keys(stations)) {
    total += stations[key];
  }

  return jsonResponse({ total, stations }, 200, CORS_HEADERS);
}

// ----- Images -----
async function handleUpload(request, env, CORS_HEADERS) {
  try {
    const contentType = (request.headers.get('content-type') || '').toLowerCase();
    let bodyBuf, finalContentType;
    if (contentType.startsWith('multipart/form-data')) {
      const form = await request.formData();
      const f = form.get('file');
      if (!f) return textResponse("Missing 'file' field", 400, CORS_HEADERS);
      bodyBuf = await f.arrayBuffer();
      finalContentType = f.type || 'application/octet-stream';
    } else if (contentType.startsWith('image/')) {
      bodyBuf = await request.arrayBuffer();
      finalContentType = contentType;
    } else {
      return textResponse("Only image uploads or multipart form with 'file' allowed", 400, CORS_HEADERS);
    }
    const ext = (finalContentType.split('/')[1] || 'bin').replace(/[^a-z0-9]/gi, '');
    const key = crypto.randomUUID() + '.' + ext;
    await env.IMAGES.put(key, bodyBuf, { httpMetadata: { contentType: finalContentType } });
    return jsonResponse({ success: true, url: `https://api.wsgpolar.me/v1/images/${key}` }, 200, CORS_HEADERS);
  } catch (err) {
    return textResponse(`Upload failed: ${err}`, 500, CORS_HEADERS);
  }
}

async function handleGet(key, env, CORS_HEADERS) {
  try {
    const obj = await env.IMAGES.get(key);
    if (!obj) return textResponse('Image not found', 404, CORS_HEADERS);
    const headers = Object.assign({ 'Content-Type': obj.httpMetadata?.contentType || 'application/octet-stream' }, CORS_HEADERS);
    return new Response(obj.body, { headers });
  } catch (err) {
    return textResponse(`Get failed: ${err}`, 500, CORS_HEADERS);
  }
}

// ----- Giphy -----
async function handleGiphySearch(url, env, CORS_HEADERS) {
  try {
    const q = (url.searchParams.get('q') || '').trim();
    const limit = Math.min(parseInt(url.searchParams.get('limit') || '35', 10), 50);
    const offset = parseInt(url.searchParams.get('offset') || '0', 10);
    const key = env.GIPHY_API_KEY;
    if (!key) return jsonResponse({ error: 'GIPHY_API_KEY is not set' }, 501, CORS_HEADERS);

    const base = 'https://api.giphy.com/v1/gifs';
    const endpoint = (!q || q.toLowerCase() === 'trending')
      ? `${base}/trending?api_key=${encodeURIComponent(key)}&limit=${limit}&offset=${offset}`
      : `${base}/search?api_key=${encodeURIComponent(key)}&q=${encodeURIComponent(q)}&limit=${limit}&offset=${offset}`;

    const r = await fetch(endpoint, { cf: { cacheTtl: 300, cacheEverything: true } });
    if (!r.ok) return jsonResponse({ error: 'Giphy fetch failed' }, 502, CORS_HEADERS);
    const data = await r.json();

    const results = (data.data || []).map(d => {
      const images = d.images || {};
      const best = images.downsized_medium || images.downsized || images.original || images.fixed_width || {};
      const preview = (images.fixed_width_small_still && images.fixed_width_small_still.url) ||
                      (images.fixed_width_small && images.fixed_width_small.url) ||
                      best.url || d.url;
      const url = best.url || d.url;
      const width = parseInt(best.width || '0', 10) || null;
      const height = parseInt(best.height || '0', 10) || null;
      return { id: d.id, title: d.title || '', url, preview, width, height };
    });

    return jsonResponse({ results, nextOffset: offset + results.length }, 200, CORS_HEADERS);
  } catch (err) {
    return jsonResponse({ error: `Giphy error: ${err}` }, 500, CORS_HEADERS);
  }
}

// ----- Link preview -----
async function handleLinkPreview(url, CORS_HEADERS) {
  try {
    const target = url.searchParams.get('url');
    if (!target || !isSafeHttpUrl(target)) return textResponse('Invalid or unsafe URL', 400, CORS_HEADERS);
    const r = await fetch(target, {
      cf: { cacheTtl: 3600, cacheEverything: true },
      headers: { 'User-Agent': 'Mozilla/5.0 (compatible; PreviewBot/1.0; +https://wsgpolar.me)' }
    });
    if (!r.ok) return textResponse('Fetch failed', 502, CORS_HEADERS);
    const html = await r.text();
    const meta = parseMeta(html);
    try { meta.site = meta.site || (new URL(target)).hostname; } catch {}
    return jsonResponse(meta, 200, CORS_HEADERS);
  } catch (err) {
    return textResponse(`Preview error: ${err}`, 500, CORS_HEADERS);
  }
}

// ----- Polls in R2 (IMAGES) -----
function pollStore(env) {
  const bucket = env.IMAGES;
  return {
    async get(id) {
      const obj = await bucket.get(`polls/${id}.json`);
      if (!obj) return null;
      try { return await obj.json(); } catch { return JSON.parse(await obj.text()); }
    },
    async set(id, poll) {
      return bucket.put(`polls/${id}.json`, JSON.stringify(poll), {
        httpMetadata: { contentType: 'application/json' }
      });
    },
    async voted(id, ip) {
      const obj = await bucket.get(`poll_votes/${id}/${ip}.lock`);
      return !!obj;
    },
    async markVoted(id, ip) {
      return bucket.put(`poll_votes/${id}/${ip}.lock`, '1', {
        httpMetadata: { contentType: 'text/plain' }
      });
    }
  };
}

async function handlePollCreate(request, env, CORS_HEADERS) {
  try {
    const body = await request.json();
    const question = (body.question || '').toString().trim();
    const options = Array.isArray(body.options) ? body.options.map(o => (o || '').toString().trim()).filter(Boolean) : [];
    if (!question || options.length < 2 || options.length > 10) {
      return textResponse('Provide question and 2-10 non-empty options', 400, CORS_HEADERS);
    }
    const id = crypto.randomUUID();
    const poll = { id, question, options, counts: options.map(() => 0), closed: false, createdAt: Date.now() };
    await pollStore(env).set(id, poll);
    return jsonResponse({ id, question, options, counts: poll.counts, closed: false }, 200, CORS_HEADERS);
  } catch (err) {
    return textResponse(`Poll create failed: ${err}`, 500, CORS_HEADERS);
  }
}

async function handlePollGet(id, env, CORS_HEADERS) {
  try {
    if (!id) return textResponse('Missing id', 400, CORS_HEADERS);
    const poll = await pollStore(env).get(id);
    if (!poll) return textResponse('Not found', 404, CORS_HEADERS);
    return jsonResponse(poll, 200, CORS_HEADERS);
  } catch (err) {
    return textResponse(`Poll get failed: ${err}`, 500, CORS_HEADERS);
  }
}

async function handlePollVote(id, request, env, CORS_HEADERS) {
  try {
    if (!id) return textResponse('Missing id', 400, CORS_HEADERS);
    const body = await request.json();
    const option = parseInt(body.option, 10);
    const store = pollStore(env);
    const poll = await store.get(id);
    if (!poll) return textResponse('Not found', 404, CORS_HEADERS);
    if (poll.closed) return jsonResponse(poll, 409, CORS_HEADERS);
    if (isNaN(option) || option < 0 || option >= (poll.options || []).length) {
      return textResponse('Invalid option', 400, CORS_HEADERS);
    }
    const ip = request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || '0.0.0.0';
    if (await store.voted(id, ip)) return jsonResponse(poll, 409, CORS_HEADERS);
    poll.counts[option] = (poll.counts[option] || 0) + 1;
    await store.set(id, poll);
    await store.markVoted(id, ip);
    return jsonResponse(poll, 200, CORS_HEADERS);
  } catch (err) {
    return textResponse(`Vote failed: ${err}`, 500, CORS_HEADERS);
  }
}

// ===== VPN provisioning helpers =====
function validateServerShape(srv) {
  if (!srv) return null;
  const type = String(srv.type || '').toLowerCase();
  if (!['http', 'https', 'socks4', 'socks5'].includes(type)) return null;
  const host = String(srv.host || '').trim();
  const port = Number(srv.port || 0);
  if (!host || !port) return null;

  return {
    id: srv.id || crypto.randomUUID(),
    name: srv.name || `${type.toUpperCase()} ${host}:${port}`,
    type,
    host,
    port,
    username: srv.username || undefined,
    password: srv.password || undefined,
    bypass: (srv.bypass || 'localhost, 127.0.0.1, ::1'),
    countries: Array.isArray(srv.countries) ? srv.countries.map(String) : undefined,
    region: srv.region || undefined
  };
}

function parseServersFromEnv(env) {
  if (env.VPN_SERVERS) {
    try {
      const parsed = JSON.parse(env.VPN_SERVERS);
      const arr = Array.isArray(parsed) ? parsed : [parsed];
      const validated = arr.map(validateServerShape).filter(Boolean);
      if (validated.length) return validated;
    } catch (e) {}
  }
  if (env.PROXY_HOST && env.PROXY_PORT && env.PROXY_TYPE) {
    const single = validateServerShape({
      id: env.PROXY_ID || 'default',
      name: env.PROXY_NAME || 'Default Server',
      type: env.PROXY_TYPE,
      host: env.PROXY_HOST,
      port: Number(env.PROXY_PORT),
      username: env.PROXY_USERNAME,
      password: env.PROXY_PASSWORD,
      bypass: env.PROXY_BYPASS
    });
    return single ? [single] : [];
  }
  return [];
}

function pickServer(servers, request, url) {
  if (!servers.length) return null;
  const qRegion = (url.searchParams.get('region') || '').trim().toUpperCase();
  const qCountry = (url.searchParams.get('country') || '').trim().toUpperCase();
  const cf = (request.cf || {});
  const cfCountry = (cf.country || request.headers.get('CF-IPCountry') || '').trim().toUpperCase();

  const wantId = (url.searchParams.get('id') || '').trim();
  if (wantId) {
    const m = servers.find(s => s.id === wantId);
    if (m) return m;
  }

  if (qRegion) {
    const byRegion = servers.find(s => (s.region || '').toUpperCase() === qRegion);
    if (byRegion) return byRegion;
  }

  const desiredCountry = qCountry || cfCountry;
  if (desiredCountry) {
    const byCountry = servers.find(s => Array.isArray(s.countries) && s.countries.map(String).map(c => c.toUpperCase()).includes(desiredCountry));
    if (byCountry) return byCountry;
  }

  return servers[0];
}

function stripSecrets(server) {
  const { username, password, ...rest } = server || {};
  return rest;
}

// ===== VPN provisioning handlers =====
async function handleVpnGet(request, env, CORS_HEADERS) {
  try {
    const url = new URL(request.url);
    const servers = parseServersFromEnv(env);
    if (!servers.length) {
      return jsonResponse({ error: 'No VPN servers configured' }, 501, CORS_HEADERS);
    }
    const chosen = pickServer(servers, request, url);
    if (!chosen) {
      return jsonResponse({ error: 'No matching server' }, 404, CORS_HEADERS);
    }

    const payload = {
      id: chosen.id,
      name: chosen.name,
      type: chosen.type,
      host: chosen.host,
      port: chosen.port,
      username: chosen.username,
      password: chosen.password,
      bypass: chosen.bypass
    };
    return jsonResponse(payload, 200, CORS_HEADERS);
  } catch (err) {
    return textResponse(`VPN error: ${err}`, 500, CORS_HEADERS);
  }
}

async function handleVpnList(request, env, CORS_HEADERS) {
  try {
    const url = new URL(request.url);
    const includeSecrets = url.searchParams.get('includeSecrets') === '1';
    const adminKey = request.headers.get('Authorization') || '';
    const ok = env.ADMIN_API_KEY && adminKey === `Bearer ${env.ADMIN_API_KEY}`;

    const servers = parseServersFromEnv(env);
    if (!servers.length) {
      return jsonResponse({ servers: [] }, 200, CORS_HEADERS);
    }

    const list = (includeSecrets && ok) ? servers : servers.map(stripSecrets);
    return jsonResponse({ servers: list }, 200, CORS_HEADERS);
  } catch (err) {
    return textResponse(`List error: ${err}`, 500, CORS_HEADERS);
  }
}

async function handleVpnGeo(request, CORS_HEADERS) {
  try {
    const ip = request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || '';
    const country = (request.cf && request.cf.country) || request.headers.get('CF-IPCountry') || 'XX';
    const colo = (request.cf && request.cf.colo) || '';
    return jsonResponse({ ip, country, colo }, 200, CORS_HEADERS);
  } catch (err) {
    return textResponse(`Geo error: ${err}`, 500, CORS_HEADERS);
  }
}

async function handleEmailSend(request, env, CORS_HEADERS) {
  try {
    const body = await request.json();
    const id = crypto.randomUUID();
    const timestamp = Date.now();

    const record = {
      id,
      timestamp,
      ...body,
      status: "queued"
    };

    // store record in KV
    await env.EMAIL_LOGS.put(id, JSON.stringify(record));

    // forward to email worker
    const res = await fetch(env.EMAIL_WORKER_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(record)
    });

    const result = await res.json().catch(() => null);

    // update status
    await env.EMAIL_LOGS.put(id, JSON.stringify({
      ...record,
      status: res.ok ? "sent" : "failed",
      providerResponse: result
    }));

    return new Response(JSON.stringify({
      ok: true,
      id,
      status: res.ok ? "sent" : "failed"
    }), {
      status: 200,
      headers: { "Content-Type": "application/json", ...CORS_HEADERS }
    });

  } catch (err) {
    return new Response(JSON.stringify({ error: err.message }), {
      status: 500,
      headers: CORS_HEADERS
    });
  }
}

async function handleEmailList(env, CORS_HEADERS) {
  const list = await env.EMAIL_LOGS.list();
  return new Response(JSON.stringify(list.keys), {
    status: 200,
    headers: { "Content-Type": "application/json", ...CORS_HEADERS }
  });
}

async function handleEmailGet(id, env, CORS_HEADERS) {
  const data = await env.EMAIL_LOGS.get(id);
  if (!data) {
    return new Response(JSON.stringify({ error: "Email not found" }), {
      status: 404,
      headers: CORS_HEADERS
    });
  }
  return new Response(data, {
    status: 200,
    headers: { "Content-Type": "application/json", ...CORS_HEADERS }
  });
}

// ----- Helpers -----
function rollDice(roll) {
  const match = roll.match(/(\d+)d(\d+)/);
  if (!match) return null;
  const count = Number(match[1]);
  const sides = Number(match[2]);
  return Array.from({ length: count }, () => Math.floor(Math.random() * sides) + 1);
}

function generateRandomUser() {
  const names = ['Alice','Bob','Charlie','Dana','Eve'];
  const domains = ['example.com','mail.com','test.org'];
  const name = names[Math.floor(Math.random() * names.length)];
  const email = `${name.toLowerCase()}@${domains[Math.floor(Math.random() * domains.length)]}`;
  return { id: crypto.randomUUID(), name, email };
}

function generatePassword(length = 12, strength = 'medium') {
  let chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  if (strength === 'strong') chars += '!@#$%^&*()-_=+[]{}|;:,.<>?';
  if (strength === 'weak') chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
  return Array.from({ length }).map(() => chars[Math.floor(Math.random() * chars.length)]).join('');
}