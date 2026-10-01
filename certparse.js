// Minimal DER / X.509 parser. Runs in browser and Node. No dependencies.
(function (root) {
  const OIDS = {
    '2.5.4.3': 'CN', '2.5.4.6': 'C', '2.5.4.7': 'L', '2.5.4.8': 'ST', '2.5.4.10': 'O', '2.5.4.11': 'OU',
    '2.5.4.5': 'serialNumber', '1.2.840.113549.1.9.1': 'emailAddress', '2.5.4.9': 'street', '2.5.4.17': 'postalCode',
    '1.2.840.113549.1.1.1': 'RSA', '1.2.840.10045.2.1': 'EC', '1.3.101.112': 'Ed25519', '1.3.101.113': 'Ed448',
    '1.2.840.113549.1.1.5': 'sha1WithRSAEncryption', '1.2.840.113549.1.1.11': 'sha256WithRSAEncryption',
    '1.2.840.113549.1.1.12': 'sha384WithRSAEncryption', '1.2.840.113549.1.1.13': 'sha512WithRSAEncryption',
    '1.2.840.113549.1.1.10': 'RSASSA-PSS', '1.2.840.10045.4.3.2': 'ecdsa-with-SHA256',
    '1.2.840.10045.4.3.3': 'ecdsa-with-SHA384', '1.2.840.10045.4.3.4': 'ecdsa-with-SHA512',
    '1.2.840.10045.3.1.7': 'P-256', '1.3.132.0.34': 'P-384', '1.3.132.0.35': 'P-521',
    '2.5.29.14': 'subjectKeyIdentifier', '2.5.29.15': 'keyUsage', '2.5.29.17': 'subjectAltName',
    '2.5.29.19': 'basicConstraints', '2.5.29.31': 'cRLDistributionPoints', '2.5.29.32': 'certificatePolicies',
    '2.5.29.35': 'authorityKeyIdentifier', '2.5.29.37': 'extendedKeyUsage', '1.3.6.1.5.5.7.1.1': 'authorityInfoAccess',
    '1.3.6.1.5.5.7.3.1': 'serverAuth', '1.3.6.1.5.5.7.3.2': 'clientAuth', '1.3.6.1.5.5.7.3.3': 'codeSigning',
    '1.3.6.1.5.5.7.3.4': 'emailProtection', '1.3.6.1.5.5.7.3.8': 'timeStamping', '1.3.6.1.5.5.7.3.9': 'OCSPSigning',
    '1.3.6.1.5.5.7.48.1': 'OCSP', '1.3.6.1.5.5.7.48.2': 'caIssuers', '1.2.840.113549.1.9.14': 'extensionRequest',
  };
  const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
  const colon = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0').toUpperCase()).join(':');

  function read(buf, pos) {
    if (pos + 2 > buf.length) throw new Error('Truncated DER');
    const tag = buf[pos];
    let len = buf[pos + 1], p = pos + 2;
    if (len & 0x80) {
      const n = len & 0x7f;
      if (n === 0 || n > 4) throw new Error('Unsupported DER length');
      len = 0;
      for (let i = 0; i < n; i++) len = len * 256 + buf[p++];
    }
    if (p + len > buf.length) throw new Error('Truncated DER');
    return { tag, start: pos, body: p, end: p + len, buf };
  }
  function children(n) {
    const out = [];
    for (let p = n.body; p < n.end;) { const c = read(n.buf, p); out.push(c); p = c.end; }
    return out;
  }
  const bytes = (n) => n.buf.subarray(n.body, n.end);
  const raw = (n) => n.buf.subarray(n.start, n.end);
  function oid(n) {
    const b = bytes(n); const parts = [];
    let v = 0;
    for (let i = 0; i < b.length; i++) {
      v = v * 128 + (b[i] & 0x7f);
      if (!(b[i] & 0x80)) {
        if (!parts.length) { const f = v < 80 ? Math.floor(v / 40) : 2; parts.push(f, v - f * 40); } else parts.push(v);
        v = 0;
      }
    }
    return parts.join('.');
  }
  const name = (o) => OIDS[o] || o;
  function str(n) {
    const b = bytes(n);
    if (n.tag === 0x1e) { let s = ''; for (let i = 0; i + 1 < b.length; i += 2) s += String.fromCharCode(b[i] * 256 + b[i + 1]); return s; }
    return n.tag === 0x0c ? new TextDecoder().decode(b) : String.fromCharCode(...b);
  }
  function time(n) {
    const s = str(n);
    let m;
    if (n.tag === 0x17) { m = /^(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)?Z$/.exec(s); if (m) m[1] = (+m[1] >= 50 ? '19' : '20') + m[1]; }
    else m = /^(\d{4})(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)?/.exec(s);
    if (!m) throw new Error('Bad time ' + s);
    return new Date(Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +(m[6] || 0)));
  }
  function dn(n) {
    return children(n).map((rdn) => children(rdn).map((atv) => {
      const [k, v] = children(atv); return [name(oid(k)), str(v)];
    })).flat();
  }
  const dnString = (d) => d.map(([k, v]) => k + '=' + v).join(', ');
  function bigHex(b) { let s = hex(b).replace(/^(00)+(?=.)/, ''); return s; }
  function ip(b) {
    if (b.length === 4) return Array.from(b).join('.');
    const g = []; for (let i = 0; i < 16; i += 2) g.push((b[i] * 256 + b[i + 1]).toString(16));
    return g.join(':');
  }
  function generalName(n) {
    const b = bytes(n);
    switch (n.tag) {
      case 0x81: return 'email:' + String.fromCharCode(...b);
      case 0x82: return 'DNS:' + String.fromCharCode(...b);
      case 0x86: return 'URI:' + String.fromCharCode(...b);
      case 0x87: return 'IP:' + ip(b);
      case 0xa4: return 'DirName:' + dnString(dn(children(n)[0]));
      default: return 'other:' + hex(b);
    }
  }
  const KU = ['digitalSignature', 'contentCommitment', 'keyEncipherment', 'dataEncipherment', 'keyAgreement', 'keyCertSign', 'cRLSign', 'encipherOnly', 'decipherOnly'];
  function extension(e) {
    const c = children(e); const id = oid(c[0]);
    const critical = c.length === 3 && bytes(c[1])[0] !== 0;
    const inner = read(bytes(c[c.length - 1]), 0);
    let value;
    try {
      if (id === '2.5.29.17') value = children(inner).map(generalName);
      else if (id === '2.5.29.19') {
        const k = children(inner); let ca = false, path;
        k.forEach((x) => { if (x.tag === 0x01) ca = bytes(x)[0] !== 0; else if (x.tag === 0x02) path = bytes(x)[0]; });
        value = 'CA:' + (ca ? 'TRUE' : 'FALSE') + (path !== undefined ? ', pathlen:' + path : '');
      } else if (id === '2.5.29.15') {
        const b = bytes(inner); const bits = [];
        for (let i = 0; i < KU.length; i++) { const byte = b[1 + (i >> 3)]; if (byte !== undefined && byte & (0x80 >> (i & 7))) bits.push(KU[i]); }
        value = bits;
      } else if (id === '2.5.29.37') value = children(inner).map((x) => name(oid(x)));
      else if (id === '2.5.29.14') value = colon(bytes(inner));
      else if (id === '2.5.29.35') { const k = children(inner).find((x) => x.tag === 0x80); value = k ? colon(bytes(k)) : ''; }
      else if (id === '1.3.6.1.5.5.7.1.1') value = children(inner).map((x) => { const [m, l] = children(x); return name(oid(m)) + ' - ' + generalName(l); });
      else if (id === '2.5.29.31') {
        const out = []; (function walk(n) { if (n.tag === 0x86) out.push('URI:' + String.fromCharCode(...bytes(n))); else if (n.tag & 0x20) children(n).forEach(walk); })(inner);
        value = out;
      } else value = 'hex:' + hex(bytes(inner)).slice(0, 120);
    } catch (err) { value = 'unparsed'; }
    return { oid: id, name: name(id), critical, value };
  }
  function pubkey(spki) {
    const [alg, bits] = children(spki); const ac = children(alg); const a = oid(ac[0]);
    const kb = bytes(bits).subarray(1);
    const r = { algorithm: name(a) };
    if (a === '1.2.840.113549.1.1.1') {
      const m = children(read(kb, 0))[0]; let b = bytes(m); while (b.length > 1 && b[0] === 0) b = b.subarray(1);
      r.size = b.length * 8 - Math.clz32(b[0]) + 24; // exact bit length of modulus
    } else if (a === '1.2.840.10045.2.1') { r.curve = ac[1] ? name(oid(ac[1])) : '?'; }
    return r;
  }
  function parseTbs(tbs) {
    const k = children(tbs); let i = 0;
    const r = {};
    if (k[0].tag === 0xa0) { r.version = bytes(children(k[0])[0])[0] + 1; i = 1; } else r.version = 1;
    r.serial = bigHex(bytes(k[i++]));
    i++; // inner signature alg
    r.issuer = dn(k[i++]);
    const [nb, na] = children(k[i++]); r.notBefore = time(nb); r.notAfter = time(na);
    r.subject = dn(k[i++]);
    r.publicKey = pubkey(k[i++]);
    r.extensions = [];
    for (; i < k.length; i++) if (k[i].tag === 0xa3) children(children(k[i])[0]).forEach((e) => r.extensions.push(extension(e)));
    return r;
  }
  function parseCsrInfo(info) {
    const k = children(info); const r = { version: bytes(k[0])[0] + 1, subject: dn(k[1]), publicKey: pubkey(k[2]), extensions: [] };
    const attrs = k[3];
    if (attrs) children(attrs).forEach((a) => { const [t, vs] = children(a); if (oid(t) === '1.2.840.113549.1.9.14') children(children(vs)[0]).forEach((e) => r.extensions.push(extension(e))); });
    return r;
  }
  function parseDer(der) {
    const top = read(der, 0); const k = children(top);
    const sigAlg = name(oid(children(k[1])[0]));
    const r = { signatureAlgorithm: sigAlg };
    const first = children(k[0]);
    // CSR: INTEGER version then subject (a SEQUENCE of SETs); certificate: [0] version or serial then sigAlg (a SEQUENCE starting with an OID)
    const isCsr = first[0].tag === 0x02 && first[1] && first[1].tag === 0x30 && (children(first[1])[0] || {}).tag === 0x31;
    if (isCsr) return Object.assign(r, { type: 'CSR' }, parseCsrInfo(k[0]));
    return Object.assign(r, { type: 'Certificate' }, parseTbs(k[0]));
  }
  async function fingerprints(der) {
    const out = {};
    for (const [label, algo] of [['SHA-1', 'SHA-1'], ['SHA-256', 'SHA-256']]) {
      out[label] = colon(new Uint8Array(await (root.crypto || require('crypto').webcrypto).subtle.digest(algo, der)));
    }
    return out;
  }
  function b64decode(s) {
    if (typeof atob === 'function') return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
    return new Uint8Array(Buffer.from(s, 'base64'));
  }
  function b64encode(b) {
    if (typeof btoa === 'function') { let s = ''; b.forEach((x) => { s += String.fromCharCode(x); }); return btoa(s); }
    return Buffer.from(b).toString('base64');
  }
  // Returns array of {label, der} from PEM text (possibly several blocks) or a bare base64 / hex blob.
  function extractBlocks(text) {
    const out = [];
    const re = /-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----/g; let m;
    while ((m = re.exec(text))) out.push({ label: m[1], der: b64decode(m[2].replace(/[^A-Za-z0-9+/=]/g, '')) });
    if (!out.length) {
      const t = text.replace(/\s+/g, '');
      if (/^[0-9a-fA-F]+$/.test(t) && t.length % 2 === 0 && t.length > 20) out.push({ label: 'CERTIFICATE', der: Uint8Array.from(t.match(/../g), (h) => parseInt(h, 16)) });
      else if (/^[A-Za-z0-9+/=]+$/.test(t) && t.length > 20) out.push({ label: 'CERTIFICATE', der: b64decode(t) });
    }
    return out;
  }
  function toPem(der, label) {
    return '-----BEGIN ' + label + '-----\n' + b64encode(der).replace(/(.{64})/g, '$1\n').replace(/\n$/, '') + '\n-----END ' + label + '-----\n';
  }
  const api = { parseDer, fingerprints, extractBlocks, toPem, dnString, colon };
  if (typeof module !== 'undefined' && module.exports) module.exports = api; else root.CertParse = api;
})(typeof window !== 'undefined' ? window : globalThis);
