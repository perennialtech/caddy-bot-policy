import crypto from 'crypto';

// Match the default cookie name, HMAC inputs and TTL in turnstile.go.
const cookiePrefix = 'turnstile_clearance';
const cookieLabel = 'caddy-turnstile/turnstile/cookie/v3\0';
const version = '3';
const ttlSeconds = 30 * 24 * 60 * 60;

function field(s) {
    return Buffer.byteLength(s) + ':' + s;
}

function sameBytes(a, b) {
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
    return diff === 0;
}

function valid(r) {
    const key = process.env.TURNSTILE_CLEARANCE_KEY;
    const siteKey = process.env.TURNSTILE_SITE_KEY;
    if (!key || !siteKey) return '0';

    const identity = field(siteKey) + field(cookiePrefix);
    const suffix = crypto.createHmac('sha256', key)
        .update(cookieLabel).update(identity).digest().subarray(0, 16)
        .toString('base64url');
    const name = cookiePrefix + '_' + suffix;
    const cookies = String(r.headersIn.Cookie || '').split(';');
    const entry = cookies.find(c => c.trim().startsWith(name + '='));
    if (!entry) return '0';

    const value = entry.trim().slice(name.length + 1);
    const parts = value.split('.');
    if (parts.length !== 3 || parts[0] !== version ||
        !/^[0-9]+$/.test(parts[1])) return '0';

    const host = String(r.variables.host).toLowerCase().replace(/\.$/, '');
    const expected = crypto.createHmac('sha256', key)
        .update(version + '\0').update(identity)
        .update(parts[1] + '\0' + host + '\0').digest();
    if (!sameBytes(Buffer.from(parts[2], 'base64url'), expected)) return '0';

    const age = Date.now() / 1000 - Number(parts[1]);
    return age > -60 && age < ttlSeconds ? '1' : '0';
}

export default { valid };
