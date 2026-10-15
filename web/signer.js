// APK signing that runs entirely in the browser. Nothing is uploaded anywhere.
//
// The output is what Google's apksigner produces with v1 and v2 enabled: a JAR signature
// (META-INF/MANIFEST.MF, CERT.SF and CERT.RSA, which Android 6 and older check) plus an APK
// Signature Scheme v2 block (Android 7 and newer), zip-aligned. Everything else in the APK stays
// exactly as it was, META-INF included; only old signature files are replaced. The one exception
// is a separate copy (see below), which also changes AndroidManifest.xml and resources.arsc.
//
// It needs nothing beyond what browsers ship: WebCrypto for SHA-256 and RSA, and
// DecompressionStream / CompressionStream for the zip entries.

import { CERTIFICATE, PRIVATE_KEY_PKCS8 } from './debug-key.js';

export class ApkError extends Error {}

const NOT_AN_APK = 'That file is not a valid APK.';
const RSA = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };
const RSA_PKCS1_SHA256 = 0x0103;    // signature algorithm id used in the v2 block
const V2_BLOCK_ID = 0x7109871a;
const ALIGNMENT_EXTRA_ID = 0xd935;  // the zip extra field apksigner pads with to align data
const DOS_TIME = 0x0821;            // 01:01:02 on 1981-01-01, the fixed timestamp apksigner
const DOS_DATE = 0x0221;            // gives the META-INF files it adds
const EMPTY = new Uint8Array(0);
const CRLF = Uint8Array.of(13, 10);
const SPACE = Uint8Array.of(0x20);
const encoder = new TextEncoder();
const MAGIC = encoder.encode('APK Sig Block 42');
const CERT_BYTES = fromBase64(CERTIFICATE);
const CERT_FIELDS = certificateFields(CERT_BYTES);

// ---------------------------------------------------------------------------------------------
// Bytes

function fromBase64(text) {
  return Uint8Array.from(atob(text), (c) => c.charCodeAt(0));
}

function toBase64(bytes) {
  let text = '';
  for (let i = 0; i < bytes.length; i += 0x8000) text += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(text);
}

function concat(parts) {
  let length = 0;
  for (const part of parts) length += part.length;
  const out = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function equal(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

function u16(b, p) { return b[p] | (b[p + 1] << 8); }
function u32(b, p) { return (b[p] | (b[p + 1] << 8) | (b[p + 2] << 16) | (b[p + 3] << 24)) >>> 0; }
function u64(b, p) { return u32(b, p) + u32(b, p + 4) * 0x100000000; }
function put16(b, p, v) { b[p] = v & 0xff; b[p + 1] = (v >>> 8) & 0xff; }
function put32(b, p, v) { put16(b, p, v & 0xffff); put16(b, p + 2, (v >>> 16) & 0xffff); }
function put64(b, p, v) { put32(b, p, v >>> 0); put32(b, p + 4, Math.floor(v / 0x100000000)); }

function le32(v) {
  const b = new Uint8Array(4);
  put32(b, 0, v);
  return b;
}

// A uint32 length followed by the parts: how everything in the v2 block is nested.
function prefixed(...parts) {
  const body = concat(parts);
  return concat([le32(body.length), body]);
}

const CRC_TABLE = new Uint32Array(256).map((_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c;
});

function crc32(bytes) {
  let c = 0xffffffff;
  for (let i = 0; i < bytes.length; i++) c = CRC_TABLE[(c ^ bytes[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

// ---------------------------------------------------------------------------------------------
// Crypto and compression

async function sha256(data) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', data));
}

async function rsaSign(key, data) {
  return new Uint8Array(await crypto.subtle.sign(RSA, key, data));
}

async function run(stream, data) {
  const writer = stream.writable.getWriter();
  writer.write(data).catch(() => {});  // a failure surfaces on the readable side
  writer.close().catch(() => {});
  return new Uint8Array(await new Response(stream.readable).arrayBuffer());
}

const inflate = (data) => run(new DecompressionStream('deflate-raw'), data);
const deflate = (data) => run(new CompressionStream('deflate-raw'), data);

// Runs fn over items with at most `limit` in flight, keeping results in order.
async function mapLimit(items, limit, fn, onEach) {
  const results = new Array(items.length);
  let next = 0;
  let done = 0;
  const worker = async () => {
    while (next < items.length) {
      const i = next++;
      results[i] = await fn(items[i]);
      if (onEach) onEach(++done, items.length);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return results;
}

// ---------------------------------------------------------------------------------------------
// DER, just enough to read the certificate and write a PKCS #7 signature

function tlv(b, p) {
  let length = b[p + 1];
  let start = p + 2;
  if (length & 0x80) {
    const count = length & 0x7f;
    length = 0;
    for (let i = 0; i < count; i++) length = length * 256 + b[start++];
  }
  return { tag: b[p], start, end: start + length, bytes: b.subarray(p, start + length) };
}

function certificateFields(cert) {
  const tbs = tlv(cert, tlv(cert, 0).start);
  let serial = tlv(cert, tbs.start);
  if (serial.tag === 0xa0) serial = tlv(cert, serial.end);  // skip the explicit version
  const algorithm = tlv(cert, serial.end);
  const issuer = tlv(cert, algorithm.end);
  const validity = tlv(cert, issuer.end);
  const subject = tlv(cert, validity.end);
  const publicKey = tlv(cert, subject.end);
  return { serial: serial.bytes, issuer: issuer.bytes, publicKey: publicKey.bytes };
}

function der(tag, ...parts) {
  const body = concat(parts);
  const n = body.length;
  const head = n < 0x80 ? [tag, n]
    : n < 0x100 ? [tag, 0x81, n]
    : n < 0x10000 ? [tag, 0x82, n >> 8, n & 0xff]
    : [tag, 0x83, n >> 16, (n >> 8) & 0xff, n & 0xff];
  return concat([Uint8Array.from(head), body]);
}

const OID_SIGNED_DATA = Uint8Array.of(0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02);
const OID_DATA = Uint8Array.of(0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01);
const OID_SHA256 = Uint8Array.of(0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01);
const OID_RSA = Uint8Array.of(0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01);
const DER_NULL = Uint8Array.of(0x05, 0x00);
const DER_ONE = Uint8Array.of(0x02, 0x01, 0x01);

// CERT.RSA: a detached PKCS #7 SignedData over CERT.SF, laid out the way apksigner writes it.
function signatureBlock(signature) {
  const sha256Algorithm = der(0x30, OID_SHA256, DER_NULL);
  const signerInfo = der(0x30,
    DER_ONE,
    der(0x30, CERT_FIELDS.issuer, CERT_FIELDS.serial),
    sha256Algorithm,
    der(0x30, OID_RSA, DER_NULL),
    der(0x04, signature));
  const signedData = der(0x30,
    DER_ONE,
    der(0x31, sha256Algorithm),
    der(0x30, OID_DATA),
    der(0xa0, CERT_BYTES),
    der(0x31, signerInfo));
  return der(0x30, OID_SIGNED_DATA, der(0xa0, signedData));
}

// ---------------------------------------------------------------------------------------------
// Reading the zip (APKs never use ZIP64)

// b holds the last bytes of a file of fileSize bytes, starting at offset `base` in it.
function findEnd(b, fileSize, base = 0) {
  const lowest = Math.max(0, b.length - 22 - 0xffff);
  for (let p = b.length - 22; p >= lowest; p--) {
    if (u32(b, p) !== 0x06054b50 || base + p + 22 + u16(b, p + 20) !== fileSize) continue;
    const count = u16(b, p + 10);
    const cdSize = u32(b, p + 12);
    const cdOffset = u32(b, p + 16);
    if (count === 0xffff || cdSize === 0xffffffff || cdOffset === 0xffffffff) throw new ApkError('ZIP64 APKs are not supported.');
    if (cdOffset + cdSize !== base + p) throw new ApkError(NOT_AN_APK);
    return { eocd: base + p, cdOffset, cdSize, comment: b.slice(p + 22) };
  }
  throw new ApkError(NOT_AN_APK);
}

function readEntries(cd) {
  const decoder = new TextDecoder();
  const entries = [];
  for (let p = 0; p < cd.length;) {
    if (cd.length - p < 46 || u32(cd, p) !== 0x02014b50) throw new ApkError('That APK is damaged.');
    const nameLength = u16(cd, p + 28);
    const extraEnd = p + 46 + nameLength + u16(cd, p + 30);
    const end = extraEnd + u16(cd, p + 32);
    if (end > cd.length) throw new ApkError('That APK is damaged.');
    const nameBytes = cd.slice(p + 46, p + 46 + nameLength);
    entries.push({
      name: decoder.decode(nameBytes),
      nameBytes,
      madeBy: u16(cd, p + 4),
      versionNeeded: u16(cd, p + 6),
      flags: u16(cd, p + 8),
      method: u16(cd, p + 10),
      time: u16(cd, p + 12),
      date: u16(cd, p + 14),
      crc: u32(cd, p + 16),
      compressedSize: u32(cd, p + 20),
      size: u32(cd, p + 24),
      extra: cd.slice(p + 46 + nameLength, extraEnd),
      comment: cd.slice(extraEnd, end),
      internalAttributes: u16(cd, p + 36),
      externalAttributes: u32(cd, p + 38),
      localOffset: u32(cd, p + 42),
    });
    p = end;
  }
  return entries;
}

function checkEntries(entries) {
  const names = new Set();
  for (const e of entries) {
    if (names.has(e.name)) throw new ApkError(`That APK lists ${e.name} twice, so Android would reject it.`);
    names.add(e.name);
    if (e.flags & 1) throw new ApkError('That APK has encrypted entries, which cannot be signed.');
  }
  if (!names.has('AndroidManifest.xml')) throw new ApkError('That file has no AndroidManifest.xml, so it is not an APK.');
  if (entries.length >= 0xffff) throw new ApkError('That APK has too many files to sign here.');
}

// The old signature's files, which a new signature replaces. The rest of META-INF stays.
function isSignatureFile(name) {
  if (!name.startsWith('META-INF/') || name.indexOf('/', 9) !== -1) return false;
  const file = name.slice(9).toUpperCase();
  return file === 'MANIFEST.MF' || /\.(SF|RSA|DSA|EC)$/.test(file) || file.startsWith('SIG-');
}

function localEntry(b, e) {
  const p = e.localOffset;
  if (p + 30 > b.length || u32(b, p) !== 0x04034b50) throw new ApkError(`${e.name} in that APK is damaged.`);
  const extraStart = p + 30 + u16(b, p + 26);
  const dataStart = extraStart + u16(b, p + 28);
  if (dataStart + e.compressedSize > b.length) throw new ApkError(`${e.name} in that APK is damaged.`);
  return {
    versionNeeded: u16(b, p + 4),
    extra: b.subarray(extraStart, dataStart),
    data: b.subarray(dataStart, dataStart + e.compressedSize),
  };
}

// ---------------------------------------------------------------------------------------------
// v1: the JAR signature

// An entry's uncompressed content: rewritten content if there is any, else read from the APK.
async function plainContent(b, e) {
  if (e.plain) return e.plain;
  const { data } = localEntry(b, e);
  let content = data;
  if (e.method === 8) {
    try {
      content = await inflate(data);
    } catch {
      throw new ApkError(`${e.name} in that APK cannot be decompressed.`);
    }
  } else if (e.method !== 0) {
    throw new ApkError(`${e.name} uses a compression method this signer does not support.`);
  }
  if (content.length !== e.size) throw new ApkError(`${e.name} in that APK is damaged.`);
  return content;
}

async function contentDigest(b, e) {
  return sha256(await plainContent(b, e));
}

// One "Name: value" line in manifest form: at most 72 bytes a line including the CRLF, with
// continuation lines starting with a space.
function attribute(name, value) {
  const line = concat([encoder.encode(`${name}: `), typeof value === 'string' ? encoder.encode(value) : value]);
  const parts = [line.subarray(0, 70)];
  for (let p = 70; p < line.length; p += 69) parts.push(CRLF, SPACE, line.subarray(p, p + 69));
  parts.push(CRLF);
  return concat(parts);
}

async function jarSignature(b, entries, key, onProgress) {
  const files = entries
    .filter((e) => !e.name.endsWith('/'))
    .sort((x, y) => (x.name < y.name ? -1 : x.name > y.name ? 1 : 0));
  const digests = await mapLimit(files, 8, (e) => contentDigest(b, e), (done, total) => onProgress(done / total));
  const sections = files.map((e, i) =>
    concat([attribute('Name', e.nameBytes), attribute('SHA-256-Digest', toBase64(digests[i])), CRLF]));
  const manifest = concat([attribute('Manifest-Version', '1.0'), attribute('Created-By', '1.0 (Android)'), CRLF, ...sections]);
  const sectionDigests = await Promise.all(sections.map((section) => sha256(section)));
  const signatureFile = concat([
    attribute('Signature-Version', '1.0'),
    attribute('Created-By', '1.0 (Android)'),
    attribute('SHA-256-Digest-Manifest', toBase64(await sha256(manifest))),
    attribute('X-Android-APK-Signed', '2'),
    CRLF,
    ...files.map((e, i) =>
      concat([attribute('Name', e.nameBytes), attribute('SHA-256-Digest', toBase64(sectionDigests[i])), CRLF])),
  ]);
  return [
    ['META-INF/MANIFEST.MF', manifest],
    ['META-INF/CERT.SF', signatureFile],
    ['META-INF/CERT.RSA', signatureBlock(await rsaSign(key, signatureFile))],
  ];
}

async function newEntry(name, data) {
  const compressed = await deflate(data);
  return {
    name,
    nameBytes: encoder.encode(name),
    madeBy: 20,
    versionNeeded: 20,
    flags: 0,
    method: 8,
    time: DOS_TIME,
    date: DOS_DATE,
    crc: crc32(data),
    compressedSize: compressed.length,
    size: data.length,
    extra: EMPTY,
    comment: EMPTY,
    internalAttributes: 0,
    externalAttributes: 0,
    local: { versionNeeded: 20, extra: EMPTY, data: compressed },
  };
}

// ---------------------------------------------------------------------------------------------
// Writing the zip

// The local extra field with apksigner's alignment padding, sized so the entry's data starts on
// an `alignment` boundary. Old padding (0xd935 fields, or zipalign's bare zeros) is dropped first.
function alignedExtra(original, extraStart, alignment) {
  const kept = [];
  for (let p = 0; original.length - p >= 4;) {
    const id = u16(original, p);
    const size = u16(original, p + 2);
    if (size > original.length - p - 4) break;
    if (!(id === ALIGNMENT_EXTRA_ID || (id === 0 && size === 0))) kept.push(original.subarray(p, p + 4 + size));
    p += 4 + size;
  }
  const fields = concat(kept);
  const padding = (alignment - ((extraStart + fields.length + 6) % alignment)) % alignment;
  const field = new Uint8Array(6 + padding);
  put16(field, 0, ALIGNMENT_EXTRA_ID);
  put16(field, 2, 2 + padding);
  put16(field, 4, alignment);
  return concat([fields, field]);
}

function localHeader(e, versionNeeded, extra) {
  const h = new Uint8Array(30 + e.nameBytes.length + extra.length);
  put32(h, 0, 0x04034b50);
  put16(h, 4, versionNeeded);
  put16(h, 6, e.flags & ~0x08);  // sizes go in the header, so no trailing data descriptor
  put16(h, 8, e.method);
  put16(h, 10, e.time);
  put16(h, 12, e.date);
  put32(h, 14, e.crc);
  put32(h, 18, e.compressedSize);
  put32(h, 22, e.size);
  put16(h, 26, e.nameBytes.length);
  put16(h, 28, extra.length);
  h.set(e.nameBytes, 30);
  h.set(extra, 30 + e.nameBytes.length);
  return h;
}

function centralHeader(e, offset) {
  const n = e.nameBytes.length;
  const x = e.extra.length;
  const h = new Uint8Array(46 + n + x + e.comment.length);
  put32(h, 0, 0x02014b50);
  put16(h, 4, e.madeBy);
  put16(h, 6, e.versionNeeded);
  put16(h, 8, e.flags & ~0x08);
  put16(h, 10, e.method);
  put16(h, 12, e.time);
  put16(h, 14, e.date);
  put32(h, 16, e.crc);
  put32(h, 20, e.compressedSize);
  put32(h, 24, e.size);
  put16(h, 28, n);
  put16(h, 30, x);
  put16(h, 32, e.comment.length);
  put16(h, 36, e.internalAttributes);
  put32(h, 38, e.externalAttributes);
  put32(h, 42, offset);
  h.set(e.nameBytes, 46);
  h.set(e.extra, 46 + n);
  h.set(e.comment, 46 + n + x);
  return h;
}

function endRecord(count, cdSize, cdOffset, comment) {
  const h = new Uint8Array(22 + comment.length);
  put32(h, 0, 0x06054b50);
  put16(h, 8, count);
  put16(h, 10, count);
  put32(h, 12, cdSize);
  put32(h, 16, cdOffset);
  put16(h, 20, comment.length);
  h.set(comment, 22);
  return h;
}

function layOut(b, entries) {
  const parts = [];
  const central = [];
  let offset = 0;
  for (const e of entries) {
    const local = e.local ?? localEntry(b, e);
    // Uncompressed data has to be aligned for Android to use it in place: 4 bytes, and 16 KB for
    // native libraries (which also covers devices with 4 KB pages).
    const extra = e.method === 0
      ? alignedExtra(local.extra, offset + 30 + e.nameBytes.length, e.name.endsWith('.so') ? 16384 : 4)
      : local.extra;
    const header = localHeader(e, local.versionNeeded, extra);
    central.push(centralHeader(e, offset));
    parts.push(header, local.data);
    offset += header.length + local.data.length;
  }
  if (offset > 0xffff0000) throw new ApkError('APKs over 4 GB are not supported.');
  return { body: concat(parts), centralDirectory: concat(central) };
}

// ---------------------------------------------------------------------------------------------
// v2: the APK Signature Scheme v2 block
// https://source.android.com/docs/security/features/apksigning/v2

// The digest v2 signs: SHA-256 over 1 MB chunks of the entries, the central directory and the end
// record, each chunk hashed on its own first.
async function chunkedDigest(sections) {
  const chunks = [];
  for (const s of sections) for (let p = 0; p < s.length; p += 1 << 20) chunks.push(s.subarray(p, p + (1 << 20)));
  const digests = await mapLimit(chunks, 8, (chunk) => {
    const input = new Uint8Array(5 + chunk.length);
    input[0] = 0xa5;
    put32(input, 1, chunk.length);
    input.set(chunk, 5);
    return sha256(input);
  });
  const top = new Uint8Array(5 + 32 * digests.length);
  top[0] = 0x5a;
  put32(top, 1, digests.length);
  digests.forEach((d, i) => top.set(d, 5 + 32 * i));
  return sha256(top);
}

async function signingBlock(digest, key) {
  const signedData = concat([
    prefixed(prefixed(le32(RSA_PKCS1_SHA256), prefixed(digest))),  // digests
    prefixed(prefixed(CERT_BYTES)),                                  // certificates
    prefixed(),                                                      // additional attributes
  ]);
  const signature = await rsaSign(key, signedData);
  const signer = concat([
    prefixed(signedData),
    prefixed(prefixed(le32(RSA_PKCS1_SHA256), prefixed(signature))),
    prefixed(CERT_FIELDS.publicKey),
  ]);
  const value = prefixed(prefixed(signer));
  const block = new Uint8Array(44 + value.length);
  put64(block, 0, block.length - 8);
  put64(block, 8, 4 + value.length);
  put32(block, 16, V2_BLOCK_ID);
  block.set(value, 20);
  put64(block, 20 + value.length, block.length - 8);
  block.set(MAGIC, 28 + value.length);
  return block;
}

// ---------------------------------------------------------------------------------------------
// Separate copies
//
// Android tells apps apart by package name, not by signature, so a copy needs its own package
// name to install alongside the original. The manifest's package changes, along with what has to
// be unique per app (provider authorities and the app's own permissions); class names stay put, so
// the code runs unchanged. The label gets the time, so the copies can be told apart on the
// launcher, and resources.arsc takes the new package name too, so lookups by name keep working.

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
const PERMISSION_ELEMENTS = new Set(['permission', 'permission-group', 'permission-tree', 'uses-permission', 'uses-permission-sdk-23']);
const PERMISSION_ATTRIBUTES = new Set(['permission', 'readPermission', 'writePermission', 'taskAffinity']);
const pad2 = (n) => String(n).padStart(2, '0');

function readStringPool(b, start) {
  const headerSize = u16(b, start + 2);
  const count = u32(b, start + 8);
  const flags = u32(b, start + 16);
  const stringsStart = u32(b, start + 20);
  const utf8 = (flags & 0x100) !== 0;
  const decoder = new TextDecoder(utf8 ? 'utf-8' : 'utf-16le');
  const strings = [];
  for (let i = 0; i < count; i++) {
    let p = start + stringsStart + u32(b, start + headerSize + i * 4);
    let n;
    if (utf8) {
      p += b[p] & 0x80 ? 2 : 1;  // the length in UTF-16 units, not needed here
      n = b[p];
      if (n & 0x80) {
        n = ((n & 0x7f) << 8) | b[p + 1];
        p += 2;
      } else {
        p += 1;
      }
    } else {
      n = u16(b, p) * 2;
      p += 2;
      if (n & 0x10000) {
        n = (((u16(b, p - 2) & 0x7fff) << 16) | u16(b, p)) * 2;
        p += 2;
      }
    }
    strings.push(decoder.decode(b.subarray(p, p + n)));
  }
  return {
    start, headerSize, count, flags, stringsStart, utf8, strings,
    size: u32(b, start + 4),
    styleCount: u32(b, start + 12),
    stylesStart: u32(b, start + 24),
  };
}

function encodePoolString(s, utf8) {
  if (utf8) {
    const bytes = encoder.encode(s);
    const length = (n) => (n > 0x7f ? [0x80 | (n >> 8), n & 0xff] : [n]);
    return concat([Uint8Array.from(length(s.length)), Uint8Array.from(length(bytes.length)), bytes, Uint8Array.of(0)]);
  }
  const out = new Uint8Array(2 + s.length * 2 + 2);
  put16(out, 0, s.length);
  for (let i = 0; i < s.length; i++) put16(out, 2 + i * 2, s.charCodeAt(i));
  return out;
}

// The string pool with `added` appended. Existing indexes stay as they are.
function appendToPool(b, pool, added) {
  const offsetsEnd = pool.start + pool.headerSize + pool.count * 4;
  const styleOffsets = b.subarray(offsetsEnd, offsetsEnd + pool.styleCount * 4);
  const oldData = b.subarray(pool.start + pool.stringsStart, pool.start + (pool.stylesStart || pool.size));
  const styleData = pool.styleCount ? b.subarray(pool.start + pool.stylesStart, pool.start + pool.size) : EMPTY;
  const encoded = added.map((s) => encodePoolString(s, pool.utf8));
  const offsets = new Uint8Array((pool.count + added.length) * 4);
  offsets.set(b.subarray(pool.start + pool.headerSize, offsetsEnd));
  let at = oldData.length;
  encoded.forEach((e, i) => {
    put32(offsets, (pool.count + i) * 4, at);
    at += e.length;
  });
  let stringData = concat([oldData, ...encoded]);
  stringData = concat([stringData, new Uint8Array((4 - (stringData.length % 4)) % 4)]);
  const header = b.slice(pool.start, pool.start + pool.headerSize);
  const stringsStart = pool.headerSize + offsets.length + styleOffsets.length;
  put32(header, 4, stringsStart + stringData.length + styleData.length);
  put32(header, 8, pool.count + added.length);
  put32(header, 16, pool.flags & ~1);  // appended strings are not in sorted order
  put32(header, 20, stringsStart);
  put32(header, 24, pool.styleCount ? stringsStart + stringData.length : 0);
  return concat([header, offsets, styleOffsets, stringData, styleData]);
}

function readAttributes(axml, p, strings) {
  const start = u16(axml, p + 24);
  const size = u16(axml, p + 26);
  const list = [];
  for (let k = 0; k < u16(axml, p + 28); k++) {
    const at = p + 16 + start + k * size;
    const type = axml[at + 15];
    const data = u32(axml, at + 16);
    list.push({ at, name: strings[u32(axml, at + 4)], type, data, value: type === 0x03 ? strings[data] : null });
  }
  return list;
}

// The string value of resource `id` in its default configuration, or null.
function resolveString(arsc, id) {
  if (arsc.length < 12 || u16(arsc, 0) !== 0x0002) return null;
  let values = null;
  for (let p = u16(arsc, 2); p + 8 <= arsc.length;) {
    const size = u32(arsc, p + 4);
    if (size < 8) return null;
    if (u16(arsc, p) === 0x0001 && !values) values = readStringPool(arsc, p).strings;
    if (u16(arsc, p) === 0x0200 && u32(arsc, p + 8) === id >>> 24) {
      for (let q = p + u16(arsc, p + 2); q + 8 <= p + size;) {
        const chunkSize = u32(arsc, q + 4);
        if (chunkSize < 8) return null;
        if (u16(arsc, q) === 0x0201 && arsc[q + 8] === ((id >>> 16) & 0xff)) {
          const value = defaultEntryString(arsc, q, id & 0xffff, values);
          if (value !== undefined) return value;
        }
        q += chunkSize;
      }
    }
    p += size;
  }
  return null;
}

// undefined when this type chunk is not the default configuration or lacks the entry.
function defaultEntryString(arsc, q, index, values) {
  const headerSize = u16(arsc, q + 2);
  const flags = arsc[q + 9];
  const count = u32(arsc, q + 12);
  const configSize = u32(arsc, q + 20);
  for (let i = 4; i < configSize; i++) if (arsc[q + 20 + i]) return undefined;
  let offset = null;
  if (flags & 0x01) {  // sparse: (index, offset / 4) pairs
    for (let i = 0; i < count; i++) if (u16(arsc, q + headerSize + i * 4) === index) offset = u16(arsc, q + headerSize + i * 4 + 2) * 4;
  } else if (flags & 0x02) {  // 16-bit offsets, in units of 4
    if (index < count && u16(arsc, q + headerSize + index * 2) !== 0xffff) offset = u16(arsc, q + headerSize + index * 2) * 4;
  } else if (index < count && u32(arsc, q + headerSize + index * 4) !== 0xffffffff) {
    offset = u32(arsc, q + headerSize + index * 4);
  }
  if (offset === null) return undefined;
  const entry = q + u32(arsc, q + 16) + offset;
  const entryFlags = u16(arsc, entry + 2);
  let type;
  let data;
  if (entryFlags & 0x0008) {  // compact: the value's type is in the flags' high byte, its data inline
    type = entryFlags >> 8;
    data = u32(arsc, entry + 4);
  } else if (entryFlags & 0x0001) {
    return null;  // a map (style, array)
  } else {
    const value = entry + u16(arsc, entry);
    type = arsc[value + 3];
    data = u32(arsc, value + 4);
  }
  return type === 0x03 && values ? values[data] ?? null : null;
}

// Rewrites the binary AndroidManifest.xml for a copy. Returns the new manifest, the old and new
// package names, and the app's new label.
function rewriteManifest(axml, arsc, newPackageFor, newLabelFor) {
  const broken = () => new ApkError('Its AndroidManifest.xml is not in the expected binary format.');
  if (axml.length < 8 || u16(axml, 0) !== 0x0003) throw broken();
  const poolStart = u16(axml, 2);
  if (u16(axml, poolStart) !== 0x0001) throw broken();
  const pool = readStringPool(axml, poolStart);
  const s = pool.strings;

  // Every start tag in order, noting the activities that appear on the launcher.
  const elements = [];
  const open = [];
  const launchers = new Set();
  for (let p = poolStart + pool.size; p + 8 <= axml.length;) {
    const size = u32(axml, p + 4);
    if (size < 8) throw broken();
    if (u16(axml, p) === 0x0102) {
      const element = { name: s[u32(axml, p + 20)], attributes: readAttributes(axml, p, s) };
      elements.push(element);
      open.push(element);
      const name = element.attributes.find((a) => a.name === 'name');
      if (element.name === 'category' && name?.value === 'android.intent.category.LAUNCHER' && open.length >= 3)
        launchers.add(open[open.length - 3]);  // category, inside intent-filter, inside the activity
    } else if (u16(axml, p) === 0x0103) {
      open.pop();
    }
    p += size;
  }

  const manifest = elements.find((e) => e.name === 'manifest');
  const from = manifest?.attributes.find((a) => a.name === 'package')?.value;
  if (!from) throw broken();
  const to = newPackageFor(from);
  if (to.length > 127) throw new ApkError('That package name is too long to make a copy of.');
  const rename = (v) => (v === from ? to : v.startsWith(`${from}.`) ? to + v.slice(from.length) : v);

  const out = axml.slice();
  const added = [];
  const set = (a, text) => {
    let index = s.indexOf(text);
    if (index < 0) {
      index = added.indexOf(text);
      if (index < 0) index = added.push(text) - 1;
      index += s.length;
    }
    put32(out, a.at + 8, index);  // raw value
    put16(out, a.at + 12, 8);     // typed value: a string
    out[a.at + 14] = 0;
    out[a.at + 15] = 0x03;
    put32(out, a.at + 16, index);
  };

  let label = null;
  for (const element of elements) {
    for (const a of element.attributes) {
      if (element === manifest && a.name === 'package') {
        set(a, to);
      } else if (a.name === 'label' && (element.name === 'application' || launchers.has(element))) {
        const text = a.value ?? (a.type === 0x01 && arsc ? resolveString(arsc, a.data) : null) ?? from;
        const next = newLabelFor(text);
        set(a, next);
        if (element.name === 'application' || !label) label = next;
      } else if (a.value !== null) {
        const renamed = a.name === 'authorities' ? a.value.split(';').map(rename).join(';')
          : (a.name === 'name' && PERMISSION_ELEMENTS.has(element.name)) || PERMISSION_ATTRIBUTES.has(a.name) ? rename(a.value)
            : a.value;
        if (renamed !== a.value) set(a, renamed);
      }
    }
  }

  if (added.some((text) => text.length > 0x7fff || encoder.encode(text).length > 0x7fff))
    throw new ApkError('That APK has text too long to make a copy of.');
  const result = concat([out.subarray(0, poolStart), appendToPool(out, pool, added), out.subarray(poolStart + pool.size)]);
  put32(result, 4, result.length);
  return { manifest: result, from, to, label };
}

// resources.arsc names its package; the name sits in a fixed 128-character field.
function renameResourcePackage(arsc, from, to) {
  const out = arsc.slice();
  if (arsc.length < 12 || u16(arsc, 0) !== 0x0002) return out;
  const decoder = new TextDecoder('utf-16le');
  for (let p = u16(arsc, 2); p + 8 <= arsc.length;) {
    const size = u32(arsc, p + 4);
    if (size < 8) break;
    if (u16(arsc, p) === 0x0200 && decoder.decode(arsc.subarray(p + 12, p + 12 + 256)).split('\0')[0] === from) {
      out.fill(0, p + 12, p + 12 + 256);
      for (let i = 0; i < to.length; i++) put16(out, p + 12 + i * 2, to.charCodeAt(i));
    }
    p += size;
  }
  return out;
}

// Gives an entry new content, compressed the way it was.
async function replaceContent(b, e, plain) {
  const original = localEntry(b, e);
  const data = e.method === 8 ? await deflate(plain) : plain;
  e.local = { versionNeeded: original.versionNeeded, extra: original.extra, data };
  e.plain = plain;
  e.crc = crc32(plain);
  e.size = plain.length;
  e.compressedSize = data.length;
}

async function makeSeparateCopy(b, entries, when) {
  const stamp = `${when.getFullYear()}${pad2(when.getMonth() + 1)}${pad2(when.getDate())}`
    + `${pad2(when.getHours())}${pad2(when.getMinutes())}${pad2(when.getSeconds())}`;
  // The time goes before the date: launchers cut long labels at the end, and the time is what
  // tells copies made on the same day apart.
  const shown = `${pad2(when.getHours())}:${pad2(when.getMinutes())}:${pad2(when.getSeconds())} ${when.getDate()} ${MONTHS[when.getMonth()]}`;
  const manifestEntry = entries.find((e) => e.name === 'AndroidManifest.xml');
  const arscEntry = entries.find((e) => e.name === 'resources.arsc');
  const arsc = arscEntry ? await plainContent(b, arscEntry) : null;
  const rewritten = rewriteManifest(await plainContent(b, manifestEntry), arsc,
    (name) => `${name}.c${stamp}`, (label) => `${label} ${shown}`);
  await replaceContent(b, manifestEntry, rewritten.manifest);
  if (arsc) await replaceContent(b, arscEntry, renameResourcePackage(arsc, rewritten.from, rewritten.to));
  return { packageName: rewritten.to, label: rewritten.label };
}

// ---------------------------------------------------------------------------------------------
// The public part

// Quick check made when a file is picked. It reads only the zip's directory, so it is instant
// even for a large APK.
export async function inspectApk(file) {
  if (file.size < 22) throw new ApkError(NOT_AN_APK);
  const base = Math.max(0, file.size - 22 - 0xffff);
  const end = findEnd(new Uint8Array(await file.slice(base).arrayBuffer()), file.size, base);
  checkEntries(readEntries(new Uint8Array(await file.slice(end.cdOffset, end.eocd).arrayBuffer())));
}

// Signs an APK (ArrayBuffer or Uint8Array). onProgress receives a fraction between 0 and 1.
// With copyAt (a Date), the APK is also turned into a separate copy made at that time.
// Returns { apk: the signed APK as a Uint8Array, copy: null or { packageName, label } }.
export async function signApk(input, onProgress = () => {}, { copyAt = null } = {}) {
  const b = input instanceof Uint8Array ? input : new Uint8Array(input);
  const end = findEnd(b, b.length);
  const entries = readEntries(b.subarray(end.cdOffset, end.eocd));
  checkEntries(entries);
  const copy = copyAt ? await makeSeparateCopy(b, entries, copyAt) : null;
  const kept = entries.filter((e) => !isSignatureFile(e.name));
  const key = await crypto.subtle.importKey('pkcs8', fromBase64(PRIVATE_KEY_PKCS8), RSA, false, ['sign']);

  const jarFiles = await jarSignature(b, kept, key, (fraction) => onProgress(0.8 * fraction));
  const all = [...kept, ...(await Promise.all(jarFiles.map(([name, data]) => newEntry(name, data))))];
  const { body, centralDirectory } = layOut(b, all);

  onProgress(0.85);
  const unsignedEnd = endRecord(all.length, centralDirectory.length, body.length, end.comment);
  const block = await signingBlock(await chunkedDigest([body, centralDirectory, unsignedEnd]), key);
  const output = concat([
    body,
    block,
    centralDirectory,
    endRecord(all.length, centralDirectory.length, body.length + block.length, end.comment),
  ]);

  onProgress(0.92);
  const problem = await verifyApk(output);
  if (problem) throw new ApkError(`The signed APK failed its own check: ${problem}.`);
  onProgress(1);
  return { apk: output, copy };
}

// Checks a signed APK the way Android 7+ does: a valid v2 signature by this signer's certificate
// over exactly these bytes. Also checks zip alignment. Returns '' when all is well, else the
// problem.
export async function verifyApk(input) {
  const b = input instanceof Uint8Array ? input : new Uint8Array(input);
  let end;
  let entries;
  try {
    end = findEnd(b, b.length);
    entries = readEntries(b.subarray(end.cdOffset, end.eocd));
  } catch {
    return 'it is not a valid zip file';
  }

  const cd = end.cdOffset;
  if (cd < 32 || !equal(b.subarray(cd - 16, cd), MAGIC)) return 'it has no APK Signature Scheme v2 signature';
  const size = u64(b, cd - 24);
  const start = cd - size - 8;
  if (size < 24 || start < 0 || u64(b, start) !== size) return 'its signing block is damaged';
  let v2 = null;
  for (let p = start + 8; p < cd - 24;) {
    const length = u64(b, p);
    if (length < 4 || p + 8 + length > cd - 24) return 'its signing block is damaged';
    if (u32(b, p + 8) === V2_BLOCK_ID) v2 = b.subarray(p + 12, p + 8 + length);
    p += 8 + length;
  }
  if (!v2) return 'it has no APK Signature Scheme v2 signature';

  let signedData;
  let expected;
  let signature;
  let cert;
  let publicKey;
  try {
    const signers = new Reader(new Reader(v2).prefixed());
    const signer = new Reader(signers.prefixed());
    if (!signers.done) return 'it has more than one signer';
    signedData = signer.prefixed();
    const signatures = signer.prefixed();
    publicKey = signer.prefixed();
    const fields = new Reader(signedData);
    const digests = fields.prefixed();
    cert = new Reader(fields.prefixed()).prefixed();
    expected = pick(digests);
    signature = pick(signatures);
  } catch {
    return 'its v2 signature is malformed';
  }
  if (!expected || expected.length !== 32 || !signature) return 'its v2 signature has no RSA/SHA-256 record';
  if (!equal(cert, CERT_BYTES)) return 'it was signed with a different certificate';
  if (!equal(publicKey, CERT_FIELDS.publicKey)) return 'its public key does not match its certificate';
  const verifyKey = await crypto.subtle.importKey('spki', publicKey, RSA, false, ['verify']);
  if (!(await crypto.subtle.verify(RSA, verifyKey, signature, signedData))) return 'its signature does not verify';

  const endRecordCopy = b.slice(end.eocd);
  put32(endRecordCopy, 16, start);  // as signed: the central directory right after the entries
  const actual = await chunkedDigest([b.subarray(0, start), b.subarray(cd, end.eocd), endRecordCopy]);
  if (!equal(actual, expected)) return 'its contents do not match its signature';

  for (const e of entries) {
    if (e.method !== 0) continue;
    const p = e.localOffset;
    if (u32(b, p) !== 0x04034b50) return `${e.name} is damaged`;
    const data = p + 30 + u16(b, p + 26) + u16(b, p + 28);
    if (data % (e.name.endsWith('.so') ? 4096 : 4) !== 0) return `it is not zip-aligned (${e.name})`;
  }
  return '';
}

class Reader {
  constructor(bytes) {
    this.bytes = bytes;
    this.p = 0;
  }

  get done() {
    return this.p === this.bytes.length;
  }

  u32() {
    if (this.bytes.length - this.p < 4) throw new Error('truncated');
    const v = u32(this.bytes, this.p);
    this.p += 4;
    return v;
  }

  prefixed() {
    const length = this.u32();
    if (length > this.bytes.length - this.p) throw new Error('truncated');
    const v = this.bytes.subarray(this.p, this.p + length);
    this.p += length;
    return v;
  }
}

// The RSA/SHA-256 value from a v2 list of (algorithm id, value) records.
function pick(list) {
  const records = new Reader(list);
  let found = null;
  while (!records.done) {
    const record = new Reader(records.prefixed());
    const algorithm = record.u32();
    const value = record.prefixed();
    if (algorithm === RSA_PKCS1_SHA256) found = value;
  }
  return found;
}
