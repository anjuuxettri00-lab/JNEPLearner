/*
  JNEP Learner server
  - serves the static SPA
  - keeps translation-provider configuration server-side
  - proxies same-origin /api/translate requests to a real online provider
*/
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ROOT = __dirname;
const PORT = Number(process.env.PORT || 8080);
const PROVIDER = process.env.TRANSLATION_PROVIDER || 'google-chrome';
const MAX_TEXT_LENGTH = 2000;
const RATE_WINDOW_MS = 5 * 60 * 1000;
const RATE_MAX = Number(process.env.TRANSLATION_RATE_LIMIT || 40);
const SUBSCRIPTIONS_FILE = path.join(ROOT, '.jnep-payment-subscriptions.json');
const PAYMENT_ORDERS_FILE = path.join(ROOT, '.jnep-payment-orders.json');
const PUBLIC_APP_URL = String(process.env.PUBLIC_APP_URL || '').replace(/\/$/, '');
const HAS_SECURE_PUBLIC_APP_URL = !!PUBLIC_APP_URL && (process.env.NODE_ENV !== 'production' || PUBLIC_APP_URL.startsWith('https://'));
const rateBuckets = new Map();
let subscriptions = loadJsonStore(SUBSCRIPTIONS_FILE);
let paymentOrders = loadJsonStore(PAYMENT_ORDERS_FILE);

const MIME = {
  '.html': 'text/html; charset=utf-8', '.js': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png',
  '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.webp': 'image/webp', '.ico': 'image/x-icon'
};
const ALLOWED_DIRECTIONS = new Set(['en:ja', 'ne:ja', 'ja:en', 'ja:ne']);

function send(res, status, body, type = 'application/json; charset=utf-8') {
  res.writeHead(status, {
    'Content-Type': type,
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'same-origin'
  });
  res.end(body);
}
function json(res, status, value) { send(res, status, JSON.stringify(value)); }
function clientIp(req) { return String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim(); }
function withinRateLimit(req) {
  const ip = clientIp(req), now = Date.now();
  const active = (rateBuckets.get(ip) || []).filter(time => now - time < RATE_WINDOW_MS);
  if (active.length >= RATE_MAX) { rateBuckets.set(ip, active); return false; }
  active.push(now); rateBuckets.set(ip, active); return true;
}
function readJson(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk;
      if (body.length > 16000) { reject(new Error('Request body too large')); req.destroy(); }
    });
    req.on('end', () => { try { resolve(JSON.parse(body || '{}')); } catch { reject(new Error('Invalid JSON')); } });
    req.on('error', reject);
  });
}
function loadJsonStore(file) { try { return JSON.parse(fs.readFileSync(file, 'utf8')) || {}; } catch { return {}; } }
function saveJsonStore(file, value) { fs.writeFileSync(file, JSON.stringify(value, null, 2), { mode: 0o600 }); }
function addCalendarMonths(date, months) { const d = new Date(date), day = d.getDate(); d.setDate(1); d.setMonth(d.getMonth() + months); d.setDate(Math.min(day, new Date(d.getFullYear(), d.getMonth() + 1, 0).getDate())); return d; }
function planDetails(plan) { return plan === 'premium-3months' ? { plan, amount: 99, months: 3 } : plan === 'premium' ? { plan, amount: 49, months: 1 } : null; }
function subscriptionFor(email) {
  const subscription = subscriptions[String(email || '').toLowerCase()];
  if (!subscription) return null;
  if (subscription.status === 'active' && new Date(subscription.expiresAt).getTime() <= Date.now()) { subscription.status = 'expired'; saveJsonStore(SUBSCRIPTIONS_FILE, subscriptions); }
  return subscription;
}
function providerList() {
  const providers = [];
  if (process.env.ESEWA_PRODUCT_CODE && process.env.ESEWA_SECRET_KEY && HAS_SECURE_PUBLIC_APP_URL) providers.push({ id: 'esewa', name: 'eSewa', description: 'Secure payment through the official eSewa checkout.', logo: 'eSewa' });
  if (process.env.KHALTI_SECRET_KEY && HAS_SECURE_PUBLIC_APP_URL) providers.push({ id: 'khalti', name: 'Khalti', description: 'Secure payment through the official Khalti checkout.', logo: 'Khalti' });
  return providers;
}
function publicOrder(order) { if (!order) return null; const { id, email, plan, amount, durationMonths, provider, status, createdAt, activatedAt, expiresAt } = order; return { id, email, plan, amount, durationMonths, provider, status, createdAt, activatedAt, expiresAt }; }
function createOrder(email, plan, provider) {
  const details = planDetails(plan); if (!details) return null;
  const id = `pay_${crypto.randomUUID()}`;
  const order = { id, email: email.toLowerCase(), plan, amount: details.amount, durationMonths: details.months, provider, status: 'pending', createdAt: new Date().toISOString(), providerTransactionId: null };
  paymentOrders[id] = order; saveJsonStore(PAYMENT_ORDERS_FILE, paymentOrders); return order;
}
function activateVerifiedOrder(order, providerTransactionId) {
  if (!order || order.status === 'paid') return order;
  const now = new Date();
  order.status = 'paid'; order.providerTransactionId = providerTransactionId; order.activatedAt = now.toISOString(); order.expiresAt = addCalendarMonths(now, order.durationMonths).toISOString();
  subscriptions[order.email] = { plan: order.plan, status: 'active', amount: order.amount, durationMonths: order.durationMonths, purchasedAt: order.activatedAt, expiresAt: order.expiresAt, source: order.provider };
  saveJsonStore(PAYMENT_ORDERS_FILE, paymentOrders); saveJsonStore(SUBSCRIPTIONS_FILE, subscriptions); return order;
}
function verifyEsewaSignature(payload) {
  const secret = process.env.ESEWA_SECRET_KEY; if (!secret || !payload?.signature || !payload?.signed_field_names) return false;
  const message = String(payload.signed_field_names).split(',').map(field => `${field}=${payload[field] ?? ''}`).join(',');
  const expected = crypto.createHmac('sha256', secret).update(message).digest('base64');
  return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(String(payload.signature)));
}
async function verifyKhaltiOrder(order) {
  const endpoint = process.env.KHALTI_LOOKUP_URL || 'https://a.khalti.com/api/v2/epayment/lookup/';
  const response = await fetch(endpoint, { method: 'POST', headers: { Authorization: `Key ${process.env.KHALTI_SECRET_KEY}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ pidx: order.providerTransactionId }), signal: AbortSignal.timeout(15000) });
  if (!response.ok) throw new Error(`Khalti lookup returned HTTP ${response.status}`);
  const result = await response.json();
  if (result.status === 'Completed' && Number(result.total_amount) === order.amount * 100) return activateVerifiedOrder(order, result.transaction_id || order.providerTransactionId);
  if (['User canceled', 'Expired', 'Refunded'].includes(result.status)) { order.status = 'cancelled'; saveJsonStore(PAYMENT_ORDERS_FILE, paymentOrders); }
  return order;
}
async function createEsewaCheckout(order) {
  const productCode = process.env.ESEWA_PRODUCT_CODE, secret = process.env.ESEWA_SECRET_KEY;
  const fields = { amount: String(order.amount), tax_amount: '0', total_amount: String(order.amount), transaction_uuid: order.id, product_code: productCode, product_service_charge: '0', product_delivery_charge: '0', success_url: `${PUBLIC_APP_URL}/api/payments/esewa/return`, failure_url: `${PUBLIC_APP_URL}/#payment-failed?order=${encodeURIComponent(order.id)}` };
  const signed_field_names = 'total_amount,transaction_uuid,product_code';
  const message = signed_field_names.split(',').map(field => `${field}=${fields[field]}`).join(',');
  fields.signed_field_names = signed_field_names; fields.signature = crypto.createHmac('sha256', secret).update(message).digest('base64');
  return { type: 'form', action: process.env.ESEWA_PAYMENT_URL || 'https://epay.esewa.com.np/api/epay/main/v2/form', fields };
}
async function createKhaltiCheckout(order) {
  const endpoint = process.env.KHALTI_INITIATE_URL || 'https://a.khalti.com/api/v2/epayment/initiate/';
  const response = await fetch(endpoint, { method: 'POST', headers: { Authorization: `Key ${process.env.KHALTI_SECRET_KEY}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ return_url: `${PUBLIC_APP_URL}/#payment-pending?order=${encodeURIComponent(order.id)}`, website_url: PUBLIC_APP_URL, amount: order.amount * 100, purchase_order_id: order.id, purchase_order_name: order.plan }), signal: AbortSignal.timeout(15000) });
  if (!response.ok) throw new Error(`Khalti initiate returned HTTP ${response.status}`);
  const result = await response.json(); if (!result.payment_url || !result.pidx) throw new Error('Khalti did not return a payment URL');
  order.providerTransactionId = result.pidx; saveJsonStore(PAYMENT_ORDERS_FILE, paymentOrders); return { type: 'redirect', url: result.payment_url };
}
async function handleCreatePayment(req, res) {
  let payload; try { payload = await readJson(req); } catch { return json(res, 400, { error: 'invalid_request' }); }
  const email = String(payload.email || '').toLowerCase().trim(), plan = String(payload.plan || ''), provider = String(payload.provider || '');
  if (!/^\S+@\S+\.\S+$/.test(email) || !planDetails(plan) || !providerList().some(item => item.id === provider)) return json(res, 400, { error: 'invalid_request' });
  const order = createOrder(email, plan, provider);
  try {
    if (provider === 'esewa') return json(res, 200, { order: publicOrder(order), checkout: await createEsewaCheckout(order) });
    if (provider === 'khalti') return json(res, 200, { order: publicOrder(order), checkout: await createKhaltiCheckout(order) });
    throw new Error('Unknown provider');
  } catch (error) { order.status = 'failed'; saveJsonStore(PAYMENT_ORDERS_FILE, paymentOrders); console.error(`[payment] checkout create failed: ${error.message}`); return json(res, 503, { error: 'payment_unavailable' }); }
}
async function handlePaymentStatus(req, res, orderId) {
  const order = paymentOrders[orderId]; if (!order) return json(res, 404, { error: 'order_not_found' });
  if (order.provider === 'khalti' && order.status === 'pending' && order.providerTransactionId) { try { await verifyKhaltiOrder(order); } catch (error) { console.error(`[payment] Khalti verification failed: ${error.message}`); } }
  return json(res, 200, { order: publicOrder(order) });
}
function handleEsewaReturn(req, res) {
  try {
    const encoded = new URL(req.url, 'http://localhost').searchParams.get('data');
    const payload = JSON.parse(Buffer.from(String(encoded || ''), 'base64').toString('utf8'));
    const order = paymentOrders[payload.transaction_uuid];
    if (!order || order.provider !== 'esewa' || payload.status !== 'COMPLETE' || Number(payload.total_amount) !== order.amount || payload.product_code !== process.env.ESEWA_PRODUCT_CODE || !verifyEsewaSignature(payload)) throw new Error('invalid eSewa confirmation');
    activateVerifiedOrder(order, payload.transaction_code || payload.transaction_uuid);
    res.writeHead(302, { Location: `/#payment-success?order=${encodeURIComponent(order.id)}` }); res.end();
  } catch (error) { console.error(`[payment] eSewa verification failed: ${error.message}`); res.writeHead(302, { Location: '/#payment-failed' }); res.end(); }
}
function handleSubscriptionStatus(req, res) {
  const email = new URL(req.url, 'http://localhost').searchParams.get('email') || '';
  const subscription = subscriptionFor(email); return json(res, 200, { subscription: subscription || null, verified: !!subscription });
}
function decodeHtml(value) {
  return String(value || '').replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>');
}
async function translateWithGoogleChrome(text, source, target) {
  // Keyless Google Translate endpoint used by the Chrome translation client. The browser never calls it directly.
  const url = new URL('https://clients5.google.com/translate_a/t');
  url.searchParams.set('client', 'dict-chrome-ex');
  url.searchParams.set('sl', source);
  url.searchParams.set('tl', target);
  url.searchParams.set('q', text);
  const response = await fetch(url, { signal: AbortSignal.timeout(15000), headers: { 'Accept': 'application/json', 'User-Agent': 'JNEP-Learner/1.0' } });
  if (!response.ok) throw new Error(`Google translation returned HTTP ${response.status}`);
  const data = await response.json();
  const translated = String(Array.isArray(data) ? data[0] : '').trim();
  if (!translated) throw new Error('Google translation did not return a translation');
  return translated;
}
async function translateWithMyMemory(text, source, target) {
  const endpoint = process.env.MYMEMORY_API_URL || 'https://api.mymemory.translated.net/get';
  const url = new URL(endpoint);
  url.searchParams.set('q', text);
  url.searchParams.set('langpair', `${source}|${target}`);
  const response = await fetch(url, { signal: AbortSignal.timeout(15000), headers: { 'Accept': 'application/json' } });
  if (!response.ok) throw new Error(`MyMemory returned HTTP ${response.status}`);
  const data = await response.json();
  const translated = decodeHtml(data?.responseData?.translatedText);
  if (Number(data?.responseStatus) !== 200 || !translated) throw new Error('MyMemory did not return a translation');
  return translated;
}
async function translateWithLibreTranslate(text, source, target) {
  const endpoint = process.env.TRANSLATION_API_URL;
  if (!endpoint) throw new Error('TRANSLATION_API_URL is not configured for LibreTranslate');
  const payload = { q: text, source, target, format: 'text' };
  // API keys, if required by the selected provider, remain on the server only.
  if (process.env.TRANSLATION_API_KEY) payload.api_key = process.env.TRANSLATION_API_KEY;
  const response = await fetch(endpoint, {
    method: 'POST', signal: AbortSignal.timeout(15000),
    headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
    body: JSON.stringify(payload)
  });
  if (!response.ok) throw new Error(`LibreTranslate returned HTTP ${response.status}`);
  const data = await response.json();
  const translated = String(data?.translatedText || '').trim();
  if (!translated) throw new Error('LibreTranslate did not return a translation');
  return translated;
}
function looksLikeRequestedLanguage(text, target) {
  if (target === 'ja') return /[\u3040-\u30ff\u3400-\u9fff]/.test(text);
  if (target === 'ne') return /[\u0900-\u097f]/.test(text);
  return /[A-Za-z]/.test(text);
}
async function translateOnline(text, source, target) {
  if (PROVIDER === 'libretranslate') return translateWithLibreTranslate(text, source, target);
  if (PROVIDER === 'mymemory') return translateWithMyMemory(text, source, target);
  // Both providers are real online services. MyMemory is used only as an online resilience fallback,
  // never as a client-side phrase dictionary and never when its response is clearly in the wrong script.
  try { return await translateWithGoogleChrome(text, source, target); }
  catch (googleError) {
    const fallback = await translateWithMyMemory(text, source, target);
    if (!looksLikeRequestedLanguage(fallback, target)) throw googleError;
    return fallback;
  }
}
async function handleTranslation(req, res) {
  if (!withinRateLimit(req)) return json(res, 429, { error: 'rate_limited' });
  let payload;
  try { payload = await readJson(req); } catch { return json(res, 400, { error: 'invalid_request' }); }
  const text = String(payload.text || '').trim();
  const source = String(payload.source || '');
  const target = String(payload.target || '');
  if (!text || text.length > MAX_TEXT_LENGTH || !ALLOWED_DIRECTIONS.has(`${source}:${target}`)) return json(res, 400, { error: 'invalid_request' });
  try {
    const translation = await translateOnline(text, source, target);
    return json(res, 200, { translation });
  } catch (error) {
    // Do not expose provider endpoints, credentials, or internal errors to the browser.
    console.error(`[translation] ${PROVIDER} unavailable: ${error.message}`);
    return json(res, 503, { error: 'translation_unavailable' });
  }
}
function handleRuntimeConfig(req, res) { return json(res, 200, { production: process.env.NODE_ENV === 'production', paymentProviders: providerList() }); }
function serveStatic(req, res) {
  const requestPath = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
  const relative = requestPath === '/' ? 'index.html' : requestPath.replace(/^\/+/, '');
  const filePath = path.resolve(ROOT, relative);
  if (relative.startsWith('.') || relative.includes('/.') || (!filePath.startsWith(ROOT + path.sep) && filePath !== path.join(ROOT, 'index.html'))) return send(res, 403, 'Forbidden', 'text/plain; charset=utf-8');
  fs.readFile(filePath, (error, content) => {
    if (error) return send(res, error.code === 'ENOENT' ? 404 : 500, 'Not found', 'text/plain; charset=utf-8');
    const extension = path.extname(filePath).toLowerCase();
    send(res, 200, content, MIME[extension] || 'application/octet-stream');
  });
}
const server = http.createServer((req, res) => {
  const pathname = req.url.split('?')[0];
  if (req.method === 'GET' && pathname === '/api/runtime-config') return handleRuntimeConfig(req, res);
  if (req.method === 'GET' && pathname === '/api/subscription/status') return handleSubscriptionStatus(req, res);
  if (req.method === 'POST' && pathname === '/api/payments/orders') return handleCreatePayment(req, res);
  if (req.method === 'GET' && /^\/api\/payments\/orders\/[^/]+$/.test(pathname)) return handlePaymentStatus(req, res, pathname.split('/')[4]);
  if (req.method === 'GET' && pathname === '/api/payments/esewa/return') return handleEsewaReturn(req, res);
  if (req.method === 'POST' && pathname === '/api/translate') return handleTranslation(req, res);
  if (req.method === 'GET' || req.method === 'HEAD') return serveStatic(req, res);
  return send(res, 405, 'Method not allowed', 'text/plain; charset=utf-8');
});
server.listen(PORT, '0.0.0.0', () => console.log(`JNEP Learner running at http://0.0.0.0:${PORT} (translation provider: ${PROVIDER})`));
