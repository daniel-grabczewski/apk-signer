// APK Signer (Windows)
//
// Drop an APK on the window (or click the box to pick one), press Sign, choose where to save.
// It signs with the Android debug key that uber-apk-signer bundles and writes what Google's
// apksigner writes with v1 and v2 enabled: a JAR signature (META-INF/MANIFEST.MF, CERT.SF and
// CERT.RSA, which Android 6 and older check) plus an APK Signature Scheme v2 block (Android 7 and
// newer), zip-aligned. Everything else in the APK stays exactly as it was, META-INF included;
// only old signature files are replaced. web/signer.js is the same signer for the browser.
//
// Nothing is saved until the result has been checked: its v2 signature must verify with the
// expected certificate, it must be zip-aligned, and every entry must match what was written.

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <shellapi.h>
#include <shlobj.h>
#include <shobjidl.h>
#include <commctrl.h>
#include <bcrypt.h>
#include <wincrypt.h>

#include <algorithm>
#include <climits>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <initializer_list>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "resource.h"
#include "third_party/miniz/miniz.h"

namespace {

constexpr UINT WM_APP_DONE = WM_APP + 1;
constexpr uint32_t kV2BlockId = 0x7109871A;
constexpr uint32_t kRsaPkcs1Sha256 = 0x0103;    // RSASSA-PKCS1-v1_5 with SHA-256, chunked SHA-256 digest
constexpr uint16_t kAlignmentExtraId = 0xD935;  // the zip extra field apksigner pads with to align data
constexpr uint16_t kDosTime = 0x0821;           // 01:01:02 on 1981-01-01, the fixed timestamp apksigner
constexpr uint16_t kDosDate = 0x0221;           // gives the META-INF files it adds

using ByteVec = std::vector<uint8_t>;

// ---------------------------------------------------------------------------------------------
// Small helpers

std::wstring Widen(const std::string& s, UINT codePage = CP_UTF8) {
    if (s.empty()) return {};
    const int n = MultiByteToWideChar(codePage, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    std::wstring w(static_cast<size_t>(n), L'\0');
    MultiByteToWideChar(codePage, 0, s.data(), static_cast<int>(s.size()), w.data(), n);
    return w;
}

std::wstring Trim(std::wstring s) {
    auto blank = [](wchar_t c) { return c == L' ' || c == L'\t' || c == L'\r' || c == L'\n'; };
    while (!s.empty() && blank(s.back())) s.pop_back();
    size_t start = 0;
    while (start < s.size() && blank(s[start])) ++start;
    return s.substr(start);
}

std::wstring ErrorText(DWORD code) {
    wchar_t* buffer = nullptr;
    FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                   nullptr, code, 0, reinterpret_cast<wchar_t*>(&buffer), 0, nullptr);
    std::wstring text = buffer ? Trim(buffer) : L"Windows error " + std::to_wstring(code);
    LocalFree(buffer);
    return text;
}

std::wstring FileName(const std::wstring& path) {
    const size_t slash = path.find_last_of(L"\\/");
    return slash == std::wstring::npos ? path : path.substr(slash + 1);
}

std::wstring Folder(const std::wstring& path) {
    const size_t slash = path.find_last_of(L"\\/");
    if (slash == std::wstring::npos) return {};
    if (slash == 2 && path[1] == L':') return path.substr(0, 3);  // keep "C:\" a root
    return path.substr(0, slash);
}

// "app.apk" -> "app-SIGNED.apk"
std::wstring SignedName(const std::wstring& path) {
    std::wstring name = FileName(path);
    const size_t dot = name.find_last_of(L'.');
    if (dot != std::wstring::npos && dot > 0) name.resize(dot);
    return name + L"-SIGNED.apk";
}

bool HasApkExtension(const std::wstring& path) {
    return path.size() > 4 && _wcsicmp(path.c_str() + path.size() - 4, L".apk") == 0;
}

std::wstring FormatSize(uint64_t bytes) {
    wchar_t text[32];
    if (bytes >= 1024 * 1024)
        swprintf_s(text, L"%.1f MB", static_cast<double>(bytes) / (1024.0 * 1024.0));
    else
        swprintf_s(text, L"%llu KB", (bytes + 1023) / 1024);
    return text;
}

bool EndsWith(std::string_view s, std::string_view suffix) {
    return s.size() >= suffix.size() && s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

uint16_t Le16(const uint8_t* p) { return static_cast<uint16_t>(p[0] | (p[1] << 8)); }
uint32_t Le32(const uint8_t* p) { uint32_t v; std::memcpy(&v, p, 4); return v; }
uint64_t Le64(const uint8_t* p) { uint64_t v; std::memcpy(&v, p, 8); return v; }
void Put16(uint8_t* p, uint32_t v) { p[0] = static_cast<uint8_t>(v); p[1] = static_cast<uint8_t>(v >> 8); }
void Put32(uint8_t* p, uint32_t v) { std::memcpy(p, &v, 4); }
void Put64(uint8_t* p, uint64_t v) { std::memcpy(p, &v, 8); }

// A view of some bytes: in a mapped file, a resource or a vector.
struct Bytes {
    const uint8_t* p = nullptr;
    size_t n = 0;
    Bytes() = default;
    Bytes(const uint8_t* data, size_t size) : p(data), n(size) {}
    Bytes(const ByteVec& v) : p(v.data()), n(v.size()) {}  // implicit on purpose
};

Bytes Text(std::string_view s) { return {reinterpret_cast<const uint8_t*>(s.data()), s.size()}; }

bool Same(Bytes a, Bytes b) { return a.n == b.n && (a.n == 0 || std::memcmp(a.p, b.p, a.n) == 0); }

ByteVec Concat(std::initializer_list<Bytes> parts) {
    size_t length = 0;
    for (const Bytes& part : parts) length += part.n;
    ByteVec out;
    out.reserve(length);
    for (const Bytes& part : parts) out.insert(out.end(), part.p, part.p + part.n);
    return out;
}

ByteVec Le32Bytes(uint32_t v) {
    ByteVec b(4);
    Put32(b.data(), v);
    return b;
}

// A uint32 length followed by the parts: how everything in the v2 block is nested.
ByteVec Prefixed(std::initializer_list<Bytes> parts) {
    ByteVec body = Concat(parts);
    ByteVec out = Le32Bytes(static_cast<uint32_t>(body.size()));
    out.insert(out.end(), body.begin(), body.end());
    return out;
}

std::string Base64(Bytes data) {
    const DWORD flags = CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF;
    DWORD length = 0;
    CryptBinaryToStringA(data.p, static_cast<DWORD>(data.n), flags, nullptr, &length);
    std::string text(length, '\0');
    CryptBinaryToStringA(data.p, static_cast<DWORD>(data.n), flags, text.data(), &length);
    text.resize(length);
    return text;
}

Bytes ResourceBytes(int id) {
    HRSRC resource = FindResourceW(nullptr, MAKEINTRESOURCEW(id), RT_RCDATA);
    HGLOBAL loaded = resource ? LoadResource(nullptr, resource) : nullptr;
    const void* data = loaded ? LockResource(loaded) : nullptr;
    if (!data) return {};
    return {static_cast<const uint8_t*>(data), SizeofResource(nullptr, resource)};
}

// ---------------------------------------------------------------------------------------------
// Read-only view of a whole file

class MappedFile {
public:
    MappedFile() = default;
    MappedFile(const MappedFile&) = delete;
    MappedFile& operator=(const MappedFile&) = delete;
    ~MappedFile() { Close(); }

    bool Open(const std::wstring& path) {
        file_ = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        LARGE_INTEGER size{};
        if (file_ == INVALID_HANDLE_VALUE || !GetFileSizeEx(file_, &size) || size.QuadPart == 0) return false;
        mapping_ = CreateFileMappingW(file_, nullptr, PAGE_READONLY, 0, 0, nullptr);
        if (!mapping_) return false;
        view_ = MapViewOfFile(mapping_, FILE_MAP_READ, 0, 0, 0);
        if (!view_) return false;
        size_ = static_cast<uint64_t>(size.QuadPart);
        return true;
    }

    void Close() {
        if (view_) UnmapViewOfFile(view_);
        if (mapping_) CloseHandle(mapping_);
        if (file_ != INVALID_HANDLE_VALUE) CloseHandle(file_);
        view_ = nullptr;
        mapping_ = nullptr;
        file_ = INVALID_HANDLE_VALUE;
        size_ = 0;
    }

    const uint8_t* data() const { return static_cast<const uint8_t*>(view_); }
    uint64_t size() const { return size_; }

private:
    HANDLE file_ = INVALID_HANDLE_VALUE;
    HANDLE mapping_ = nullptr;
    void* view_ = nullptr;
    uint64_t size_ = 0;
};

// ---------------------------------------------------------------------------------------------
// SHA-256 and RSA through CNG

class Sha256 {
public:
    Sha256() {
        if (BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&alg_, BCRYPT_SHA256_ALGORITHM, nullptr, 0)))
            BCryptCreateHash(alg_, &hash_, nullptr, 0, nullptr, 0, BCRYPT_HASH_REUSABLE_FLAG);
    }
    ~Sha256() {
        if (hash_) BCryptDestroyHash(hash_);
        if (alg_) BCryptCloseAlgorithmProvider(alg_, 0);
    }
    Sha256(const Sha256&) = delete;
    Sha256& operator=(const Sha256&) = delete;

    bool ok() const { return hash_ != nullptr; }
    void Update(const void* p, size_t n) {
        BCryptHashData(hash_, static_cast<PUCHAR>(const_cast<void*>(p)), static_cast<ULONG>(n), 0);
    }
    // Writes the digest and resets, ready for the next one.
    void Finish(uint8_t out[32]) { BCryptFinishHash(hash_, out, 32, 0); }

private:
    BCRYPT_ALG_HANDLE alg_ = nullptr;
    BCRYPT_HASH_HANDLE hash_ = nullptr;
};

// The signing key, from res/debug.pk8 (PKCS #8, written by tools/ExtractKey.java).
class RsaKey {
public:
    RsaKey() = default;
    RsaKey(const RsaKey&) = delete;
    RsaKey& operator=(const RsaKey&) = delete;
    ~RsaKey() {
        if (key_) BCryptDestroyKey(key_);
        if (alg_) BCryptCloseAlgorithmProvider(alg_, 0);
    }

    bool Load(Bytes pkcs8) {
        CRYPT_PRIVATE_KEY_INFO* info = nullptr;
        BYTE* blob = nullptr;
        DWORD size = 0;
        const bool ok =
            CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, PKCS_PRIVATE_KEY_INFO, pkcs8.p,
                                static_cast<DWORD>(pkcs8.n), CRYPT_DECODE_ALLOC_FLAG, nullptr, &info, &size) &&
            CryptDecodeObjectEx(X509_ASN_ENCODING, CNG_RSA_PRIVATE_KEY_BLOB, info->PrivateKey.pbData,
                                info->PrivateKey.cbData, CRYPT_DECODE_ALLOC_FLAG, nullptr, &blob, &size) &&
            BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&alg_, BCRYPT_RSA_ALGORITHM, nullptr, 0)) &&
            BCRYPT_SUCCESS(BCryptImportKeyPair(alg_, nullptr, BCRYPT_RSAPRIVATE_BLOB, &key_, blob, size, 0));
        if (blob) LocalFree(blob);
        if (info) LocalFree(info);
        return ok;
    }

    // RSASSA-PKCS1-v1_5 with SHA-256. Empty if signing fails.
    ByteVec Sign(Bytes data) const {
        Sha256 sha;
        uint8_t hash[32];
        sha.Update(data.p, data.n);
        sha.Finish(hash);
        BCRYPT_PKCS1_PADDING_INFO padding{BCRYPT_SHA256_ALGORITHM};
        ULONG size = 0;
        if (!BCRYPT_SUCCESS(BCryptSignHash(key_, &padding, hash, 32, nullptr, 0, &size, BCRYPT_PAD_PKCS1))) return {};
        ByteVec signature(size);
        if (!BCRYPT_SUCCESS(BCryptSignHash(key_, &padding, hash, 32, signature.data(), size, &size, BCRYPT_PAD_PKCS1)))
            return {};
        signature.resize(size);
        return signature;
    }

private:
    BCRYPT_ALG_HANDLE alg_ = nullptr;
    BCRYPT_KEY_HANDLE key_ = nullptr;
};

// ---------------------------------------------------------------------------------------------
// DER, just enough to read the certificate and write a PKCS #7 signature

struct Tlv {
    uint8_t tag;
    size_t header, start, end;
};

Tlv ReadTlv(Bytes b, size_t p) {
    size_t length = b.p[p + 1];
    size_t start = p + 2;
    if (length & 0x80) {
        const size_t count = length & 0x7f;
        length = 0;
        for (size_t i = 0; i < count; ++i) length = length * 256 + b.p[start++];
    }
    return {b.p[p], p, start, start + length};
}

struct CertificateFields {
    Bytes serial, issuer, publicKey;
};

CertificateFields ReadCertificate(Bytes cert) {
    const Tlv tbs = ReadTlv(cert, ReadTlv(cert, 0).start);
    Tlv serial = ReadTlv(cert, tbs.start);
    if (serial.tag == 0xa0) serial = ReadTlv(cert, serial.end);  // skip the explicit version
    const Tlv algorithm = ReadTlv(cert, serial.end);
    const Tlv issuer = ReadTlv(cert, algorithm.end);
    const Tlv validity = ReadTlv(cert, issuer.end);
    const Tlv subject = ReadTlv(cert, validity.end);
    const Tlv publicKey = ReadTlv(cert, subject.end);
    auto whole = [&](const Tlv& t) { return Bytes(cert.p + t.header, t.end - t.header); };
    return {whole(serial), whole(issuer), whole(publicKey)};
}

ByteVec Der(uint8_t tag, std::initializer_list<Bytes> parts) {
    const ByteVec body = Concat(parts);
    const size_t n = body.size();
    ByteVec out{tag};
    if (n >= 0x10000) out.insert(out.end(), {0x83, static_cast<uint8_t>(n >> 16), static_cast<uint8_t>(n >> 8)});
    else if (n >= 0x100) out.insert(out.end(), {0x82, static_cast<uint8_t>(n >> 8)});
    else if (n >= 0x80) out.push_back(0x81);
    out.push_back(static_cast<uint8_t>(n));
    out.insert(out.end(), body.begin(), body.end());
    return out;
}

const uint8_t kOidSignedData[] = {0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02};
const uint8_t kOidData[] = {0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01};
const uint8_t kOidSha256[] = {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01};
const uint8_t kOidRsa[] = {0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01};
const uint8_t kDerNull[] = {0x05, 0x00};
const uint8_t kDerOne[] = {0x02, 0x01, 0x01};

template <size_t N>
Bytes BytesOf(const uint8_t (&array)[N]) { return {array, N}; }

// CERT.RSA: a detached PKCS #7 SignedData over CERT.SF, laid out the way apksigner writes it.
ByteVec SignatureBlock(Bytes cert, const CertificateFields& fields, Bytes signature) {
    const ByteVec sha256 = Der(0x30, {BytesOf(kOidSha256), BytesOf(kDerNull)});
    const ByteVec signerInfo = Der(0x30, {BytesOf(kDerOne), Der(0x30, {fields.issuer, fields.serial}), sha256,
                                          Der(0x30, {BytesOf(kOidRsa), BytesOf(kDerNull)}), Der(0x04, {signature})});
    const ByteVec signedData = Der(0x30, {BytesOf(kDerOne), Der(0x31, {sha256}), Der(0x30, {BytesOf(kOidData)}),
                                          Der(0xa0, {cert}), Der(0x31, {signerInfo})});
    return Der(0x30, {BytesOf(kOidSignedData), Der(0xa0, {signedData})});
}

// ---------------------------------------------------------------------------------------------
// ZIP structure (APKs never use ZIP64)

struct ZipLayout {
    uint64_t eocd = 0;      // End of Central Directory record
    uint64_t cdOffset = 0;  // start of the central directory
    uint64_t cdSize = 0;
    Bytes comment;          // the archive comment, kept as it was
};

struct ZipEntry {
    std::string name;  // raw bytes, as stored
    uint16_t madeBy = 20;
    uint16_t versionNeeded = 20;
    uint16_t flags = 0;
    uint16_t method = 0;
    uint16_t time = kDosTime;
    uint16_t date = kDosDate;
    uint32_t crc = 0;
    uint32_t compressedSize = 0;
    uint32_t size = 0;
    ByteVec extra;    // central directory extra field
    ByteVec comment;  // entry comment
    uint16_t internalAttributes = 0;
    uint32_t externalAttributes = 0;
    uint32_t localOffset = 0;
    bool added = false;  // a signature file this signer wrote
    ByteVec data;        // its compressed data
};

bool FindZipLayout(const uint8_t* d, uint64_t size, ZipLayout& z) {
    if (size < 22) return false;
    const uint64_t lowest = size > 22 + 0xFFFF ? size - 22 - 0xFFFF : 0;
    for (uint64_t pos = size - 22;; --pos) {
        if (Le32(d + pos) == 0x06054b50 && pos + 22 + Le16(d + pos + 20) == size) {
            z.eocd = pos;
            z.cdSize = Le32(d + pos + 12);
            z.cdOffset = Le32(d + pos + 16);
            z.comment = {d + pos + 22, static_cast<size_t>(size - pos - 22)};
            if (Le16(d + pos + 10) == 0xFFFF || z.cdOffset == 0xFFFFFFFF || z.cdSize == 0xFFFFFFFF) return false;  // ZIP64
            return z.cdOffset + z.cdSize == z.eocd;
        }
        if (pos == lowest) return false;
    }
}

bool ReadEntries(const uint8_t* d, const ZipLayout& z, std::vector<ZipEntry>& out) {
    uint64_t pos = z.cdOffset;
    const uint64_t end = z.cdOffset + z.cdSize;
    while (pos < end) {
        if (end - pos < 46 || Le32(d + pos) != 0x02014b50) return false;
        const uint16_t nameLength = Le16(d + pos + 28);
        const uint16_t extraLength = Le16(d + pos + 30);
        const uint16_t commentLength = Le16(d + pos + 32);
        const uint64_t next = pos + 46 + nameLength + extraLength + commentLength;
        if (next > end) return false;
        const uint8_t* name = d + pos + 46;
        ZipEntry e;
        e.name.assign(reinterpret_cast<const char*>(name), nameLength);
        e.madeBy = Le16(d + pos + 4);
        e.versionNeeded = Le16(d + pos + 6);
        e.flags = Le16(d + pos + 8);
        e.method = Le16(d + pos + 10);
        e.time = Le16(d + pos + 12);
        e.date = Le16(d + pos + 14);
        e.crc = Le32(d + pos + 16);
        e.compressedSize = Le32(d + pos + 20);
        e.size = Le32(d + pos + 24);
        e.extra.assign(name + nameLength, name + nameLength + extraLength);
        e.comment.assign(name + nameLength + extraLength, name + nameLength + extraLength + commentLength);
        e.internalAttributes = Le16(d + pos + 36);
        e.externalAttributes = Le32(d + pos + 38);
        e.localOffset = Le32(d + pos + 42);
        out.push_back(std::move(e));
        pos = next;
    }
    return true;
}

struct LocalParts {
    uint16_t versionNeeded = 20;
    Bytes extra;
    Bytes data;  // as stored, usually compressed
};

// An entry's local header fields and data. False when they are not where the central directory
// says, or run past `limit`.
bool ReadLocal(const uint8_t* d, uint64_t limit, const ZipEntry& e, LocalParts& local) {
    const uint64_t header = e.localOffset;
    if (header + 30 > limit || Le32(d + header) != 0x04034b50) return false;
    const uint64_t extraStart = header + 30 + Le16(d + header + 26);
    const uint64_t dataStart = extraStart + Le16(d + header + 28);
    if (dataStart + e.compressedSize > limit) return false;
    local.versionNeeded = Le16(d + header + 4);
    local.extra = {d + extraStart, static_cast<size_t>(dataStart - extraStart)};
    local.data = {d + dataStart, e.compressedSize};
    return true;
}

// The old signature's files, which a new signature replaces. The rest of META-INF stays.
bool IsSignatureFile(const std::string& name) {
    if (name.rfind("META-INF/", 0) != 0 || name.find('/', 9) != std::string::npos) return false;
    std::string file = name.substr(9);
    for (char& c : file) c = static_cast<char>(toupper(static_cast<unsigned char>(c)));
    return file == "MANIFEST.MF" || EndsWith(file, ".SF") || EndsWith(file, ".RSA") || EndsWith(file, ".DSA") ||
           EndsWith(file, ".EC") || file.rfind("SIG-", 0) == 0;
}

std::wstring CheckEntries(const std::vector<ZipEntry>& entries) {
    std::unordered_set<std::string> names;
    for (const ZipEntry& e : entries) {
        if (!names.insert(e.name).second)
            return L"That APK lists " + Widen(e.name) + L" twice, so Android would reject it.";
        if (e.flags & 1) return L"That APK has encrypted entries, which cannot be signed.";
    }
    if (!names.count("AndroidManifest.xml")) return L"That file has no AndroidManifest.xml, so it is not an APK.";
    if (entries.size() >= 0xFFFF) return L"That APK has too many files to sign here.";
    return L"";
}

// ---------------------------------------------------------------------------------------------
// v1: the JAR signature

// One "Name: value" line in manifest form: at most 72 bytes a line including the CRLF, with
// continuation lines starting with a space.
ByteVec Attribute(std::string_view name, Bytes value) {
    const ByteVec line = Concat({Text(name), Text(": "), value});
    ByteVec out(line.begin(), line.begin() + static_cast<ptrdiff_t>(std::min<size_t>(70, line.size())));
    for (size_t p = 70; p < line.size(); p += 69) {
        out.insert(out.end(), {'\r', '\n', ' '});
        out.insert(out.end(), line.begin() + static_cast<ptrdiff_t>(p),
                   line.begin() + static_cast<ptrdiff_t>(std::min(p + 69, line.size())));
    }
    out.insert(out.end(), {'\r', '\n'});
    return out;
}

ByteVec Attribute(std::string_view name, std::string_view value) { return Attribute(name, Text(value)); }

const ByteVec kCrlf{'\r', '\n'};

using JarFile = std::pair<std::string, ByteVec>;

bool JarSignature(const MappedFile& input, const ZipLayout& zip, const std::vector<ZipEntry>& entries,
                  const RsaKey& key, Bytes cert, const CertificateFields& fields, std::vector<JarFile>& files,
                  std::wstring& problem) {
    std::vector<const ZipEntry*> listed;
    for (const ZipEntry& e : entries)
        if (!e.name.empty() && e.name.back() != '/') listed.push_back(&e);
    std::sort(listed.begin(), listed.end(), [](const ZipEntry* a, const ZipEntry* b) { return a->name < b->name; });

    Sha256 sha;
    if (!sha.ok()) {
        problem = L"SHA-256 is not available on this PC.";
        return false;
    }
    uint8_t digest[32];
    ByteVec plain;
    ByteVec manifest = Concat({Attribute("Manifest-Version", "1.0"), Attribute("Created-By", "1.0 (Android)"), kCrlf});
    std::vector<ByteVec> sections;
    sections.reserve(listed.size());
    for (const ZipEntry* e : listed) {
        LocalParts local;
        if (!ReadLocal(input.data(), zip.cdOffset, *e, local)) {
            problem = Widen(e->name) + L" in that APK is damaged.";
            return false;
        }
        Bytes content = local.data;
        if (e->method == 8) {
            plain.resize(e->size);
            if (e->size && tinfl_decompress_mem_to_mem(plain.data(), plain.size(), local.data.p, local.data.n, 0) != e->size) {
                problem = Widen(e->name) + L" in that APK cannot be decompressed.";
                return false;
            }
            content = plain;
        } else if (e->method != 0) {
            problem = Widen(e->name) + L" uses a compression method this signer does not support.";
            return false;
        }
        if (content.n != e->size) {
            problem = Widen(e->name) + L" in that APK is damaged.";
            return false;
        }
        sha.Update(content.p, content.n);
        sha.Finish(digest);
        sections.push_back(Concat({Attribute("Name", Text(e->name)), Attribute("SHA-256-Digest", Base64({digest, 32})), kCrlf}));
        manifest.insert(manifest.end(), sections.back().begin(), sections.back().end());
    }

    sha.Update(manifest.data(), manifest.size());
    sha.Finish(digest);
    ByteVec signatureFile = Concat({Attribute("Signature-Version", "1.0"), Attribute("Created-By", "1.0 (Android)"),
                                    Attribute("SHA-256-Digest-Manifest", Base64({digest, 32})),
                                    Attribute("X-Android-APK-Signed", "2"), kCrlf});
    for (size_t i = 0; i < listed.size(); ++i) {
        sha.Update(sections[i].data(), sections[i].size());
        sha.Finish(digest);
        const ByteVec section =
            Concat({Attribute("Name", Text(listed[i]->name)), Attribute("SHA-256-Digest", Base64({digest, 32})), kCrlf});
        signatureFile.insert(signatureFile.end(), section.begin(), section.end());
    }

    const ByteVec signature = key.Sign(signatureFile);
    if (signature.empty()) {
        problem = L"Could not sign the APK.";
        return false;
    }
    ByteVec signatureBlock = SignatureBlock(cert, fields, signature);
    files.emplace_back("META-INF/MANIFEST.MF", std::move(manifest));
    files.emplace_back("META-INF/CERT.SF", std::move(signatureFile));
    files.emplace_back("META-INF/CERT.RSA", std::move(signatureBlock));
    return true;
}

bool NewEntry(const std::string& name, const ByteVec& plain, ZipEntry& e) {
    size_t length = 0;
    void* compressed = tdefl_compress_mem_to_heap(plain.data(), plain.size(), &length,
                                                  static_cast<int>(tdefl_create_comp_flags_from_zip_params(9, -15, 0)));
    if (!compressed) return false;
    e.data.assign(static_cast<const uint8_t*>(compressed), static_cast<const uint8_t*>(compressed) + length);
    mz_free(compressed);
    e.name = name;
    e.method = 8;
    e.crc = static_cast<uint32_t>(mz_crc32(MZ_CRC32_INIT, plain.data(), plain.size()));
    e.compressedSize = static_cast<uint32_t>(e.data.size());
    e.size = static_cast<uint32_t>(plain.size());
    e.added = true;
    return true;
}

// ---------------------------------------------------------------------------------------------
// Writing the zip

// The local extra field with apksigner's alignment padding, sized so the entry's data starts on an
// `alignment` boundary. Old padding (0xd935 fields, or zipalign's bare zeros) is dropped first.
ByteVec AlignedExtra(Bytes original, uint64_t extraStart, uint32_t alignment) {
    ByteVec out;
    for (size_t p = 0; original.n - p >= 4;) {
        const uint16_t id = Le16(original.p + p);
        const uint16_t size = Le16(original.p + p + 2);
        if (size > original.n - p - 4) break;
        if (!(id == kAlignmentExtraId || (id == 0 && size == 0))) out.insert(out.end(), original.p + p, original.p + p + 4 + size);
        p += 4 + static_cast<size_t>(size);
    }
    const size_t padding = static_cast<size_t>((alignment - (extraStart + out.size() + 6) % alignment) % alignment);
    const size_t at = out.size();
    out.resize(at + 6 + padding);
    Put16(out.data() + at, kAlignmentExtraId);
    Put16(out.data() + at + 2, static_cast<uint32_t>(2 + padding));
    Put16(out.data() + at + 4, alignment);
    return out;
}

ByteVec LocalHeader(const ZipEntry& e, uint16_t versionNeeded, const ByteVec& extra) {
    ByteVec h(30);
    Put32(h.data(), 0x04034b50);
    Put16(h.data() + 4, versionNeeded);
    Put16(h.data() + 6, e.flags & ~0x08u);  // sizes go in the header, so no trailing data descriptor
    Put16(h.data() + 8, e.method);
    Put16(h.data() + 10, e.time);
    Put16(h.data() + 12, e.date);
    Put32(h.data() + 14, e.crc);
    Put32(h.data() + 18, e.compressedSize);
    Put32(h.data() + 22, e.size);
    Put16(h.data() + 26, static_cast<uint32_t>(e.name.size()));
    Put16(h.data() + 28, static_cast<uint32_t>(extra.size()));
    h.insert(h.end(), e.name.begin(), e.name.end());
    h.insert(h.end(), extra.begin(), extra.end());
    return h;
}

ByteVec CentralHeader(const ZipEntry& e, uint32_t offset) {
    ByteVec h(46);
    Put32(h.data(), 0x02014b50);
    Put16(h.data() + 4, e.madeBy);
    Put16(h.data() + 6, e.versionNeeded);
    Put16(h.data() + 8, e.flags & ~0x08u);
    Put16(h.data() + 10, e.method);
    Put16(h.data() + 12, e.time);
    Put16(h.data() + 14, e.date);
    Put32(h.data() + 16, e.crc);
    Put32(h.data() + 20, e.compressedSize);
    Put32(h.data() + 24, e.size);
    Put16(h.data() + 28, static_cast<uint32_t>(e.name.size()));
    Put16(h.data() + 30, static_cast<uint32_t>(e.extra.size()));
    Put16(h.data() + 32, static_cast<uint32_t>(e.comment.size()));
    Put16(h.data() + 36, e.internalAttributes);
    Put32(h.data() + 38, e.externalAttributes);
    Put32(h.data() + 42, offset);
    h.insert(h.end(), e.name.begin(), e.name.end());
    h.insert(h.end(), e.extra.begin(), e.extra.end());
    h.insert(h.end(), e.comment.begin(), e.comment.end());
    return h;
}

ByteVec EndRecord(uint32_t count, uint32_t cdSize, uint32_t cdOffset, Bytes comment) {
    ByteVec h(22);
    Put32(h.data(), 0x06054b50);
    Put16(h.data() + 8, count);
    Put16(h.data() + 10, count);
    Put32(h.data() + 12, cdSize);
    Put32(h.data() + 16, cdOffset);
    Put16(h.data() + 20, static_cast<uint32_t>(comment.n));
    h.insert(h.end(), comment.p, comment.p + comment.n);
    return h;
}

bool LayOut(const MappedFile& input, const ZipLayout& zip, const std::vector<ZipEntry>& entries, ByteVec& body,
            ByteVec& central, std::wstring& problem) {
    body.reserve(static_cast<size_t>(input.size()) + (1 << 20));
    for (const ZipEntry& e : entries) {
        LocalParts local;
        if (e.added) {
            local.data = e.data;
        } else if (!ReadLocal(input.data(), zip.cdOffset, e, local)) {
            problem = Widen(e.name) + L" in that APK is damaged.";
            return false;
        }
        const uint64_t offset = body.size();
        // Uncompressed data has to be aligned for Android to use it in place: 4 bytes, and 16 KB for
        // native libraries (which also covers devices with 4 KB pages).
        const ByteVec extra = e.method == 0
            ? AlignedExtra(local.extra, offset + 30 + e.name.size(), EndsWith(e.name, ".so") ? 16384 : 4)
            : ByteVec(local.extra.p, local.extra.p + local.extra.n);
        const ByteVec header = LocalHeader(e, local.versionNeeded, extra);
        body.insert(body.end(), header.begin(), header.end());
        body.insert(body.end(), local.data.p, local.data.p + local.data.n);
        const ByteVec record = CentralHeader(e, static_cast<uint32_t>(offset));
        central.insert(central.end(), record.begin(), record.end());
    }
    if (body.size() + central.size() > 0xFFFF0000) {
        problem = L"APKs over 4 GB are not supported.";
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------------------------
// v2: the APK Signature Scheme v2 block
// https://source.android.com/docs/security/features/apksigning/v2

// The digest v2 signs: SHA-256 over 1 MB chunks of the entries, the central directory and the end
// record, each chunk hashed on its own first.
void ChunkedDigest(std::initializer_list<Bytes> sections, Sha256& sha, uint8_t out[32]) {
    constexpr size_t kChunk = 1 << 20;
    uint32_t chunks = 0;
    for (const Bytes& s : sections) chunks += static_cast<uint32_t>((s.n + kChunk - 1) / kChunk);
    ByteVec top(5);
    top[0] = 0x5a;
    Put32(top.data() + 1, chunks);
    for (const Bytes& s : sections) {
        for (size_t offset = 0; offset < s.n; offset += kChunk) {
            const uint32_t length = static_cast<uint32_t>(std::min(kChunk, s.n - offset));
            uint8_t prefix[5] = {0xa5};
            Put32(prefix + 1, length);
            sha.Update(prefix, sizeof(prefix));
            sha.Update(s.p + offset, length);
            uint8_t digest[32];
            sha.Finish(digest);
            top.insert(top.end(), digest, digest + 32);
        }
    }
    sha.Update(top.data(), top.size());
    sha.Finish(out);
}

bool SigningBlock(const uint8_t digest[32], const RsaKey& key, Bytes cert, const CertificateFields& fields, ByteVec& block) {
    const ByteVec signedData = Concat({
        Prefixed({Prefixed({Le32Bytes(kRsaPkcs1Sha256), Prefixed({Bytes(digest, 32)})})}),  // digests
        Prefixed({Prefixed({cert})}),                                                       // certificates
        Prefixed({}),                                                                       // additional attributes
    });
    const ByteVec signature = key.Sign(signedData);
    if (signature.empty()) return false;
    const ByteVec signer = Concat({Prefixed({signedData}), Prefixed({Prefixed({Le32Bytes(kRsaPkcs1Sha256), Prefixed({signature})})}),
                                   Prefixed({fields.publicKey})});
    const ByteVec value = Prefixed({Prefixed({signer})});
    block.assign(44 + value.size(), 0);
    Put64(block.data(), block.size() - 8);
    Put64(block.data() + 8, 4 + value.size());
    Put32(block.data() + 16, kV2BlockId);
    std::memcpy(block.data() + 20, value.data(), value.size());
    Put64(block.data() + 20 + value.size(), block.size() - 8);
    std::memcpy(block.data() + 28 + value.size(), "APK Sig Block 42", 16);
    return true;
}

// Walks the uint32-length-prefixed, little-endian structures the signing block is made of.
class Reader {
public:
    explicit Reader(Bytes b) : p_(b.p), n_(b.n) {}
    bool U32(uint32_t& v) {
        if (n_ < 4) return false;
        v = Le32(p_);
        p_ += 4;
        n_ -= 4;
        return true;
    }
    bool Prefixed(Bytes& out) {
        uint32_t length = 0;
        if (!U32(length) || length > n_) return false;
        out = {p_, length};
        p_ += length;
        n_ -= length;
        return true;
    }
    bool empty() const { return n_ == 0; }

private:
    const uint8_t* p_;
    size_t n_;
};

// Finds the v2 block inside the APK Signing Block, which sits just before the central directory.
bool FindV2Block(const uint8_t* d, const ZipLayout& z, Bytes& v2, uint64_t& blockStart) {
    const uint64_t cd = z.cdOffset;
    if (cd < 32 || std::memcmp(d + cd - 16, "APK Sig Block 42", 16) != 0) return false;
    const uint64_t blockSize = Le64(d + cd - 24);
    if (blockSize < 24 || blockSize > cd - 8) return false;
    blockStart = cd - blockSize - 8;
    if (Le64(d + blockStart) != blockSize) return false;
    uint64_t pos = blockStart + 8;
    const uint64_t end = cd - 24;
    while (pos < end) {
        if (end - pos < 12) return false;
        const uint64_t length = Le64(d + pos);
        if (length < 4 || length > end - pos - 8) return false;
        if (Le32(d + pos + 8) == kV2BlockId) {
            v2 = {d + pos + 12, static_cast<size_t>(length - 4)};
            return true;
        }
        pos += 8 + length;
    }
    return false;
}

// Empty when the APK carries a valid v2 signature by `expectedCert`, else what is wrong.
std::wstring VerifyV2(const uint8_t* d, uint64_t size, const ZipLayout& z, Bytes expectedCert) {
    Bytes v2;
    uint64_t blockStart = 0;
    if (!FindV2Block(d, z, v2, blockStart)) return L"it has no APK Signature Scheme v2 signature";

    const wchar_t* malformed = L"its v2 signature block is malformed";
    Bytes signers, signer, signedData, signatures, publicKey, digests, certs;
    Reader block(v2);
    if (!block.Prefixed(signers)) return malformed;
    Reader signerList(signers);
    if (!signerList.Prefixed(signer) || !signerList.empty()) return L"it does not have exactly one signer";
    Reader signerFields(signer);
    if (!signerFields.Prefixed(signedData) || !signerFields.Prefixed(signatures) || !signerFields.Prefixed(publicKey))
        return malformed;
    Reader signedFields(signedData);
    if (!signedFields.Prefixed(digests) || !signedFields.Prefixed(certs)) return malformed;

    // Picks the RSA/SHA-256 value out of a list of (algorithm id, value) records.
    auto find = [](Bytes list, Bytes& value) {
        Reader records(list);
        while (!records.empty()) {
            Bytes record, v;
            uint32_t algorithm = 0;
            if (!records.Prefixed(record)) return false;
            Reader fields(record);
            if (!fields.U32(algorithm) || !fields.Prefixed(v)) return false;
            if (algorithm == kRsaPkcs1Sha256) value = v;
        }
        return value.n != 0;
    };
    Bytes signedDigest, signature, cert;
    if (!find(digests, signedDigest) || signedDigest.n != 32) return L"it has no RSA/SHA-256 content digest";
    if (!find(signatures, signature)) return L"it has no RSA/SHA-256 signature";
    Reader certList(certs);
    if (!certList.Prefixed(cert)) return L"its signature carries no certificate";
    if (!Same(cert, expectedCert)) return L"it was signed with a different certificate";

    // The signature over the signed-data section must check out against the certificate's key,
    // and the public key recorded beside it must be that same key (Android rejects a mismatch).
    std::wstring problem;
    PCCERT_CONTEXT ctx = CertCreateCertificateContext(X509_ASN_ENCODING, cert.p, static_cast<DWORD>(cert.n));
    CERT_PUBLIC_KEY_INFO* recorded = nullptr;
    DWORD recordedSize = 0;
    BCRYPT_KEY_HANDLE key = nullptr;
    Sha256 sha;
    uint8_t hash[32];
    if (!ctx || !sha.ok()) {
        problem = L"its certificate cannot be read";
    } else if (!CryptDecodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, publicKey.p, static_cast<DWORD>(publicKey.n),
                                    CRYPT_DECODE_ALLOC_FLAG, nullptr, &recorded, &recordedSize) ||
               !CertComparePublicKeyInfo(X509_ASN_ENCODING, &ctx->pCertInfo->SubjectPublicKeyInfo, recorded)) {
        problem = L"its public key does not match its certificate";
    } else if (!CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING, &ctx->pCertInfo->SubjectPublicKeyInfo, 0, nullptr, &key)) {
        problem = L"its certificate's key cannot be loaded";
    } else {
        sha.Update(signedData.p, signedData.n);
        sha.Finish(hash);
        BCRYPT_PKCS1_PADDING_INFO padding{BCRYPT_SHA256_ALGORITHM};
        if (!BCRYPT_SUCCESS(BCryptVerifySignature(key, &padding, hash, 32, const_cast<PUCHAR>(signature.p),
                                                  static_cast<ULONG>(signature.n), BCRYPT_PAD_PKCS1)))
            problem = L"its signature does not verify";
    }
    if (key) BCryptDestroyKey(key);
    if (recorded) LocalFree(recorded);
    if (ctx) CertFreeCertificateContext(ctx);
    if (!problem.empty()) return problem;

    // As signed, the end record points at the central directory as if it followed the entries.
    ByteVec endRecord(d + z.eocd, d + size);
    Put32(endRecord.data() + 16, static_cast<uint32_t>(blockStart));
    uint8_t actual[32];
    ChunkedDigest({Bytes(d, static_cast<size_t>(blockStart)), Bytes(d + z.cdOffset, static_cast<size_t>(z.cdSize)), endRecord}, sha, actual);
    if (std::memcmp(actual, signedDigest.p, 32) != 0) return L"its contents do not match its signature";
    return L"";
}

// Uncompressed entries must start on 4-byte boundaries, and native libraries on 4 KB pages.
std::wstring CheckAlignment(const uint8_t* d, const ZipLayout& z, const std::vector<ZipEntry>& entries) {
    for (const ZipEntry& e : entries) {
        if (e.method != 0) continue;
        LocalParts local;
        if (!ReadLocal(d, z.cdOffset, e, local)) return Widen(e.name) + L" is damaged";
        if (static_cast<uint64_t>(local.data.p - d) % (EndsWith(e.name, ".so") ? 4096 : 4) != 0)
            return L"it is not zip-aligned (" + Widen(e.name) + L")";
    }
    return L"";
}

// Checks a signed APK as written: the v2 signature, alignment, and every entry as expected.
std::wstring CheckSigned(const std::wstring& path, const std::vector<ZipEntry>& expected, Bytes cert) {
    MappedFile file;
    if (!file.Open(path)) return L"it cannot be reopened";
    ZipLayout zip;
    std::vector<ZipEntry> entries;
    if (!FindZipLayout(file.data(), file.size(), zip) || !ReadEntries(file.data(), zip, entries)) return L"it is not a valid zip file";
    std::wstring problem = VerifyV2(file.data(), file.size(), zip, cert);
    if (problem.empty()) problem = CheckAlignment(file.data(), zip, entries);
    if (!problem.empty()) return problem;
    if (entries.size() != expected.size()) return L"its file list is not what was written";
    std::unordered_map<std::string, const ZipEntry*> byName;
    for (const ZipEntry& e : entries) byName.emplace(e.name, &e);
    for (const ZipEntry& e : expected) {
        const auto it = byName.find(e.name);
        if (it == byName.end()) return L"it is missing " + Widen(e.name);
        const ZipEntry& s = *it->second;
        if (s.crc != e.crc || s.size != e.size || s.method != e.method || s.compressedSize != e.compressedSize)
            return Widen(e.name) + L" is not what was written";
    }
    return L"";
}

// Checks any APK on disk for a valid v2 signature by this app's certificate (for the test harness).
[[maybe_unused]] std::wstring VerifyApkFile(const std::wstring& path) {
    MappedFile file;
    if (!file.Open(path)) return L"it cannot be opened";
    ZipLayout zip;
    std::vector<ZipEntry> entries;
    if (!FindZipLayout(file.data(), file.size(), zip) || !ReadEntries(file.data(), zip, entries)) return L"it is not a valid zip file";
    std::wstring problem = VerifyV2(file.data(), file.size(), zip, ResourceBytes(IDR_CERTIFICATE));
    return problem.empty() ? CheckAlignment(file.data(), zip, entries) : problem;
}

// Checked as soon as a file is picked, so a wrong file is caught before the save dialog.
std::wstring InspectApk(const std::wstring& path, uint64_t& size) {
    MappedFile file;
    if (!file.Open(path)) return L"That file cannot be opened, or it is empty.";
    size = file.size();
    ZipLayout zip;
    std::vector<ZipEntry> entries;
    if (!FindZipLayout(file.data(), file.size(), zip) || !ReadEntries(file.data(), zip, entries))
        return L"That file is not a valid APK.";
    return CheckEntries(entries);
}

// ---------------------------------------------------------------------------------------------
// Signing, on a worker thread

struct Outcome {
    bool ok = false;
    std::wstring output;   // where the signed APK was saved
    uint64_t size = 0;     // and how big it is
    std::wstring problem;  // one line, for the status bar
    std::wstring details;  // more for the error box, such as the Windows error
};

Outcome Failed(std::wstring problem, std::wstring details = {}) {
    Outcome outcome;
    outcome.problem = std::move(problem);
    outcome.details = std::move(details);
    return outcome;
}

// A new, uniquely named file beside `path` (so the final move is a rename), or in %TEMP%.
std::wstring TempFileBeside(const std::wstring& path) {
    wchar_t name[MAX_PATH];
    const std::wstring folder = Folder(path);
    if (!folder.empty() && GetTempFileNameW(folder.c_str(), L"apk", 0, name)) return name;
    wchar_t temp[MAX_PATH + 1];
    if (GetTempPathW(MAX_PATH + 1, temp) && GetTempFileNameW(temp, L"apk", 0, name)) return name;
    return L"";
}

bool WriteAll(const std::wstring& path, std::initializer_list<Bytes> parts) {
    HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    bool ok = true;
    for (const Bytes& part : parts) {
        for (size_t done = 0; ok && done < part.n;) {
            const DWORD chunk = static_cast<DWORD>(std::min<size_t>(part.n - done, 1 << 26));
            DWORD written = 0;
            ok = WriteFile(file, part.p + done, chunk, &written, nullptr) && written == chunk;
            done += chunk;
        }
    }
    const DWORD error = GetLastError();
    CloseHandle(file);
    SetLastError(error);
    return ok;
}

Outcome SignApk(const std::wstring& inputPath, const std::wstring& outputPath) {
    MappedFile input;
    if (!input.Open(inputPath)) return Failed(L"Could not read the APK.", ErrorText(GetLastError()));
    ZipLayout zip;
    std::vector<ZipEntry> entries;
    if (!FindZipLayout(input.data(), input.size(), zip) || !ReadEntries(input.data(), zip, entries))
        return Failed(L"That file is not a valid APK.");
    if (const std::wstring problem = CheckEntries(entries); !problem.empty()) return Failed(problem);

    const Bytes cert = ResourceBytes(IDR_CERTIFICATE);
    RsaKey key;
    if (!cert.n || !key.Load(ResourceBytes(IDR_PRIVATE_KEY))) return Failed(L"Could not load the signing key.");
    const CertificateFields fields = ReadCertificate(cert);

    // Old signature files go; everything else, the rest of META-INF included, stays.
    std::vector<ZipEntry> kept;
    for (ZipEntry& e : entries)
        if (!IsSignatureFile(e.name)) kept.push_back(std::move(e));

    std::wstring problem;
    std::vector<JarFile> jarFiles;
    if (!JarSignature(input, zip, kept, key, cert, fields, jarFiles, problem)) return Failed(problem);
    for (const JarFile& file : jarFiles) {
        ZipEntry added;
        if (!NewEntry(file.first, file.second, added)) return Failed(L"Could not compress the signature files.");
        kept.push_back(std::move(added));
    }

    ByteVec body, central;
    if (!LayOut(input, zip, kept, body, central, problem)) return Failed(problem);
    const uint32_t count = static_cast<uint32_t>(kept.size());
    const uint32_t cdSize = static_cast<uint32_t>(central.size());
    Sha256 sha;
    uint8_t digest[32];
    ChunkedDigest({body, central, EndRecord(count, cdSize, static_cast<uint32_t>(body.size()), zip.comment)}, sha, digest);
    ByteVec block;
    if (!SigningBlock(digest, key, cert, fields, block)) return Failed(L"Could not sign the APK.");
    const ByteVec end = EndRecord(count, cdSize, static_cast<uint32_t>(body.size() + block.size()), zip.comment);

    // Written beside the destination first and checked, so a bad result never replaces anything.
    const std::wstring temp = TempFileBeside(outputPath);
    if (temp.empty()) return Failed(L"Could not create a temporary file.", ErrorText(GetLastError()));
    if (!WriteAll(temp, {body, block, central, end})) {
        const DWORD error = GetLastError();
        DeleteFileW(temp.c_str());
        return Failed(L"Could not write the signed APK.", ErrorText(error));
    }
    problem = CheckSigned(temp, kept, cert);
    if (!problem.empty()) {
        DeleteFileW(temp.c_str());
        return Failed(L"The signed APK failed its own check: " + problem + L".");
    }
    input.Close();  // so saving over the original works
    if (!MoveFileExW(temp.c_str(), outputPath.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_COPY_ALLOWED | MOVEFILE_WRITE_THROUGH)) {
        const DWORD error = GetLastError();
        DeleteFileW(temp.c_str());
        return Failed(L"Could not save " + FileName(outputPath) + L".", ErrorText(error));
    }
    Outcome outcome;
    outcome.ok = true;
    outcome.output = outputPath;
    outcome.size = body.size() + block.size() + central.size() + end.size();
    return outcome;
}

struct Job {
    HWND dialog;
    std::wstring input;
    std::wstring output;
};

DWORD WINAPI SignThread(void* param) {
    Job* job = static_cast<Job*>(param);
    auto* outcome = new Outcome(SignApk(job->input, job->output));
    if (!PostMessageW(job->dialog, WM_APP_DONE, 0, reinterpret_cast<LPARAM>(outcome))) delete outcome;
    delete job;
    return 0;
}

// ---------------------------------------------------------------------------------------------
// Window

enum class Tone { Normal, Bad };

// What the box shows: waiting for an APK, an APK ready to sign, or the APK that was just signed.
enum class View { Empty, Ready, Signed };

struct State {
    HINSTANCE instance = nullptr;
    HWND dialog = nullptr;
    View view = View::Empty;
    std::wstring apk;      // the APK waiting to be signed
    uint64_t apkSize = 0;
    std::wstring saved;    // the signed APK last written
    uint64_t savedSize = 0;
    std::wstring pending;  // an APK given on the command line (or dropped on the exe's icon)
    bool busy = false;
    Tone tone = Tone::Normal;
} g;

constexpr wchar_t kIdleHint[] = L"Signs with the Android debug key.";
constexpr COLORREF kGreen = RGB(46, 164, 79);
constexpr COLORREF kSuccessText = RGB(16, 124, 16);
constexpr COLORREF kSuccessTint = RGB(237, 247, 240);

HWND Item(int id) { return GetDlgItem(g.dialog, id); }

void SetStatus(const std::wstring& text, Tone tone) {
    g.tone = tone;
    SetWindowTextW(Item(IDC_STATUS), text.c_str());
    InvalidateRect(Item(IDC_STATUS), nullptr, TRUE);
}

void Focus(int id) { SendMessageW(g.dialog, WM_NEXTDLGCTL, reinterpret_cast<WPARAM>(Item(id)), TRUE); }

// Shows and enables whatever belongs to the current view. Once an APK is signed, the box turns
// into a read-only result and "Sign another APK" takes the place of Sign.
void UpdateControls() {
    const bool done = g.view == View::Signed;
    EnableWindow(Item(IDC_DROP), !g.busy && !done);
    EnableWindow(Item(IDOK), !g.busy && g.view == View::Ready);
    ShowWindow(Item(IDOK), done ? SW_HIDE : SW_SHOW);
    ShowWindow(Item(IDC_ANOTHER), done ? SW_SHOW : SW_HIDE);
    ShowWindow(Item(IDC_STATUS), done ? SW_HIDE : SW_SHOW);
    ShowWindow(Item(IDC_LINK), done ? SW_SHOW : SW_HIDE);
    SendMessageW(g.dialog, DM_SETDEFID, done ? IDC_ANOTHER : IDOK, 0);

    // The box draws its own content, so its window text is only what screen readers (and UI
    // tests) see.
    std::wstring text;
    if (g.view == View::Empty)
        text = L"Drop an APK here, or click to browse";
    else if (g.view == View::Ready)
        text = FileName(g.apk) + L", " + FormatSize(g.apkSize) + L", in " + Folder(g.apk);
    else
        text = L"Signed successfully: " + FileName(g.saved) + L", " + FormatSize(g.savedSize) + L", saved in " +
               Folder(g.saved);
    SetWindowTextW(Item(IDC_DROP), text.c_str());
    InvalidateRect(Item(IDC_DROP), nullptr, TRUE);
}

void ShowView(View view) {
    g.view = view;
    if (view == View::Empty) {
        g.apk.clear();
        SetStatus(kIdleHint, Tone::Normal);
    } else if (view == View::Ready) {
        SetStatus(L"Ready to sign.", Tone::Normal);
    }
    UpdateControls();
    Focus(view == View::Signed ? IDC_ANOTHER : view == View::Ready ? IDOK : IDC_DROP);
}

void SetBusy(bool busy) {
    g.busy = busy;
    UpdateControls();
}

void SelectApk(const std::wstring& path) {
    uint64_t size = 0;
    const std::wstring problem = HasApkExtension(path) ? InspectApk(path, size) : L"That is not an .apk file.";
    if (!problem.empty()) {
        if (g.view == View::Signed) ShowView(View::Empty);  // that view has no status line
        SetStatus(problem, Tone::Bad);
        return;
    }
    g.apk = path;
    g.apkSize = size;
    ShowView(View::Ready);
}

void SetDialogFolder(IFileDialog* dialog, const std::wstring& folder) {
    IShellItem* item = nullptr;
    if (SUCCEEDED(SHCreateItemFromParsingName(folder.c_str(), nullptr, IID_PPV_ARGS(&item)))) {
        dialog->SetFolder(item);
        item->Release();
    }
}

std::wstring ResultPath(IFileDialog* dialog) {
    std::wstring path;
    IShellItem* item = nullptr;
    if (SUCCEEDED(dialog->GetResult(&item))) {
        PWSTR p = nullptr;
        if (SUCCEEDED(item->GetDisplayName(SIGDN_FILESYSPATH, &p))) {
            path = p;
            CoTaskMemFree(p);
        }
        item->Release();
    }
    return path;
}

const COMDLG_FILTERSPEC kApkType[] = {{L"Android package (*.apk)", L"*.apk"}};

void Browse() {
    IFileOpenDialog* dialog = nullptr;
    if (FAILED(CoCreateInstance(CLSID_FileOpenDialog, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&dialog)))) return;
    dialog->SetFileTypes(1, kApkType);
    dialog->SetTitle(L"Choose an APK to sign");
    DWORD options = 0;
    dialog->GetOptions(&options);
    dialog->SetOptions(options | FOS_FILEMUSTEXIST | FOS_FORCEFILESYSTEM);
    if (!g.apk.empty()) SetDialogFolder(dialog, Folder(g.apk));
    std::wstring path;
    if (SUCCEEDED(dialog->Show(g.dialog))) path = ResultPath(dialog);
    dialog->Release();
    if (!path.empty()) SelectApk(path);
}

// The save dialog opens in the APK's own folder, suggesting "<name>-SIGNED.apk".
std::wstring AskWhereToSave() {
    IFileSaveDialog* dialog = nullptr;
    if (FAILED(CoCreateInstance(CLSID_FileSaveDialog, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&dialog)))) return {};
    dialog->SetFileTypes(1, kApkType);
    dialog->SetDefaultExtension(L"apk");
    dialog->SetTitle(L"Save signed APK");
    DWORD options = 0;
    dialog->GetOptions(&options);
    dialog->SetOptions(options | FOS_OVERWRITEPROMPT | FOS_FORCEFILESYSTEM | FOS_PATHMUSTEXIST | FOS_NOREADONLYRETURN);
    SetDialogFolder(dialog, Folder(g.apk));
    dialog->SetFileName(SignedName(g.apk).c_str());
    std::wstring path;
    if (SUCCEEDED(dialog->Show(g.dialog))) path = ResultPath(dialog);
    dialog->Release();
    return path;
}

void StartSigning() {
    if (g.busy || g.view != View::Ready) return;
    const std::wstring output = AskWhereToSave();
    if (output.empty()) return;
    auto* job = new Job{g.dialog, g.apk, output};
    HANDLE thread = CreateThread(nullptr, 0, SignThread, job, 0, nullptr);
    if (!thread) {
        delete job;
        SetStatus(L"Could not start signing.", Tone::Bad);
        return;
    }
    CloseHandle(thread);
    SetStatus(L"Signing...", Tone::Normal);
    SetBusy(true);
}

void OnSigned(Outcome* outcome) {
    g.busy = false;
    if (outcome->ok) {
        // From here on only the signed APK matters, so the original is let go.
        g.saved = outcome->output;
        g.savedSize = outcome->size;
        g.apk.clear();
        ShowView(View::Signed);
    } else {
        UpdateControls();
        SetStatus(outcome->problem, Tone::Bad);
        std::wstring text = outcome->problem;
        if (!outcome->details.empty()) text += L"\n\n" + outcome->details;
        MessageBoxW(g.dialog, text.c_str(), L"APK Signer", MB_OK | MB_ICONERROR);
        Focus(IDOK);
    }
    delete outcome;
}

void ShowInFolder(const std::wstring& path) {
    PIDLIST_ABSOLUTE pidl = nullptr;
    if (SUCCEEDED(SHParseDisplayName(path.c_str(), nullptr, &pidl, 0, nullptr))) {
        SHOpenFolderAndSelectItems(pidl, 0, nullptr, 0);
        CoTaskMemFree(pidl);
    }
}

void OnDrop(HDROP drop) {
    std::wstring apk, first;
    const UINT count = DragQueryFileW(drop, 0xFFFFFFFF, nullptr, 0);
    for (UINT i = 0; i < count && apk.empty(); ++i) {
        const UINT length = DragQueryFileW(drop, i, nullptr, 0);
        std::wstring path(length, L'\0');
        DragQueryFileW(drop, i, path.data(), length + 1);
        if (first.empty()) first = path;
        if (HasApkExtension(path)) apk = path;
    }
    DragFinish(drop);
    if (g.busy) return;
    SetForegroundWindow(g.dialog);
    if (!apk.empty() || !first.empty()) SelectApk(apk.empty() ? first : apk);
}

// A filled-rectangle frame, dashed or solid, drawn in whole device pixels so it stays crisp.
void Frame(HDC dc, const RECT& r, int width, int dash, int gap, COLORREF color) {
    HBRUSH brush = CreateSolidBrush(color);
    auto fill = [&](LONG left, LONG top, LONG right, LONG bottom) {
        const RECT piece{left, top, right, bottom};
        FillRect(dc, &piece, brush);
    };
    const int step = gap ? dash + gap : INT_MAX / 2;
    for (LONG x = r.left; x < r.right; x += step) {
        const LONG end = gap ? std::min<LONG>(x + dash, r.right) : r.right;
        fill(x, r.top, end, r.top + width);
        fill(x, r.bottom - width, end, r.bottom);
    }
    for (LONG y = r.top; y < r.bottom; y += step) {
        const LONG end = gap ? std::min<LONG>(y + dash, r.bottom) : r.bottom;
        fill(r.left, y, r.left + width, end);
        fill(r.right - width, y, r.right, end);
    }
    DeleteObject(brush);
}

HFONT SemiboldFont(HFONT base, int numerator, int denominator) {
    LOGFONTW look{};
    GetObjectW(base, sizeof(look), &look);
    look.lfHeight = MulDiv(look.lfHeight, numerator, denominator);
    look.lfWeight = FW_SEMIBOLD;
    return CreateFontIndirectW(&look);
}

void DrawDropZone(const DRAWITEMSTRUCT& item) {
    HDC dc = item.hDC;
    const RECT& rc = item.rcItem;
    const int dpi = static_cast<int>(GetDpiForWindow(item.hwndItem));
    auto px = [dpi](int v) { return MulDiv(v, dpi, 96); };
    const bool done = g.view == View::Signed;
    // Greyed out while signing. The signed view is disabled too, since it is not clickable, but it
    // keeps its colours.
    const bool dimmed = (item.itemState & ODS_DISABLED) && !done;

    const COLORREF background = done                              ? kSuccessTint
                                : (item.itemState & ODS_SELECTED) ? RGB(236, 246, 239)
                                                                  : GetSysColor(COLOR_WINDOW);
    HBRUSH fill = CreateSolidBrush(background);
    FillRect(dc, &rc, fill);
    DeleteObject(fill);
    // Dashed grey while waiting for a file, solid green once there is one.
    if (g.view == View::Empty)
        Frame(dc, rc, std::max(1, px(1)), px(6), px(4), RGB(150, 150, 150));
    else
        Frame(dc, rc, std::max(1, px(2)), 0, 0, kGreen);

    HFONT body = reinterpret_cast<HFONT>(SendMessageW(g.dialog, WM_GETFONT, 0, 0));
    HFONT name = SemiboldFont(body, 4, 3);
    HFONT headline = SemiboldFont(body, 5, 3);

    struct Line {
        std::wstring text;
        HFONT font;
        COLORREF color;
        UINT ellipsis;  // file names lose their middle, so the version and "-SIGNED" stay visible
        int gapBefore;
        int height = 0;
    };
    const COLORREF ink = GetSysColor(COLOR_WINDOWTEXT), grey = RGB(96, 96, 96), light = RGB(130, 130, 130);
    std::vector<Line> lines;
    if (g.view == View::Empty) {
        lines = {{L"Drop an APK here", name, ink, 0, 0},
                 {L"or click to browse", body, grey, 0, px(2)}};
    } else if (g.view == View::Ready) {
        lines = {{FileName(g.apk), name, ink, DT_PATH_ELLIPSIS, 0},
                 {FormatSize(g.apkSize) + L"  ·  " + Folder(g.apk), body, grey, DT_PATH_ELLIPSIS, px(2)},
                 {g.busy ? L"Signing..." : L"Drop another APK or click to change", body, light, 0, px(8)}};
    } else {
        lines = {{L"Signed successfully", headline, kSuccessText, 0, 0},
                 {FileName(g.saved), name, ink, DT_PATH_ELLIPSIS, px(4)},
                 {FormatSize(g.savedSize) + L"  ·  " + Folder(g.saved), body, grey, DT_PATH_ELLIPSIS, px(14)}};
    }

    SetBkMode(dc, TRANSPARENT);
    HGDIOBJ oldFont = SelectObject(dc, body);
    const int icon = done ? px(48) : px(40);
    int total = icon + px(8);
    for (Line& line : lines) {
        TEXTMETRICW metrics{};
        SelectObject(dc, line.font);
        GetTextMetricsW(dc, &metrics);
        line.height = metrics.tmHeight;
        total += line.gapBefore + line.height;
    }

    int y = (rc.top + rc.bottom - total) / 2;
    HICON image = nullptr;
    if (SUCCEEDED(LoadIconWithScaleDown(g.instance, MAKEINTRESOURCEW(IDI_APP), icon, icon, &image))) {
        DrawIconEx(dc, (rc.left + rc.right - icon) / 2, y, image, icon, icon, 0, nullptr, DI_NORMAL);
        DestroyIcon(image);
    }
    y += icon + px(8);
    for (const Line& line : lines) {
        y += line.gapBefore;
        RECT area{rc.left + px(14), y, rc.right - px(14), y + line.height};
        SelectObject(dc, line.font);
        SetTextColor(dc, dimmed ? GetSysColor(COLOR_GRAYTEXT) : line.color);
        DrawTextW(dc, line.text.c_str(), -1, &area, DT_CENTER | DT_SINGLELINE | DT_NOPREFIX | line.ellipsis);
        y += line.height;
    }

    if ((item.itemState & ODS_FOCUS) && !(item.itemState & ODS_NOFOCUSRECT)) {
        RECT focus = rc;
        InflateRect(&focus, -px(5), -px(5));
        DrawFocusRect(dc, &focus);
    }
    SelectObject(dc, oldFont);
    DeleteObject(name);
    DeleteObject(headline);
}

void SetWindowIcons(HWND dialog) {
    const UINT dpi = GetDpiForWindow(dialog);
    HICON large = nullptr, little = nullptr;  // not "small": the SDK #defines that as char
    LoadIconWithScaleDown(g.instance, MAKEINTRESOURCEW(IDI_APP), GetSystemMetricsForDpi(SM_CXICON, dpi),
                          GetSystemMetricsForDpi(SM_CYICON, dpi), &large);
    LoadIconWithScaleDown(g.instance, MAKEINTRESOURCEW(IDI_APP), GetSystemMetricsForDpi(SM_CXSMICON, dpi),
                          GetSystemMetricsForDpi(SM_CYSMICON, dpi), &little);
    SendMessageW(dialog, WM_SETICON, ICON_BIG, reinterpret_cast<LPARAM>(large));
    SendMessageW(dialog, WM_SETICON, ICON_SMALL, reinterpret_cast<LPARAM>(little));
}

INT_PTR CALLBACK DialogProc(HWND dialog, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
    case WM_INITDIALOG:
        g.dialog = dialog;
        SetWindowIcons(dialog);
        DragAcceptFiles(dialog, TRUE);
        // Let Explorer's drops through even if this is ever run elevated.
        ChangeWindowMessageFilterEx(dialog, WM_DROPFILES, MSGFLT_ALLOW, nullptr);
        ChangeWindowMessageFilterEx(dialog, WM_COPYDATA, MSGFLT_ALLOW, nullptr);
        ChangeWindowMessageFilterEx(dialog, 0x0049 /* WM_COPYGLOBALDATA */, MSGFLT_ALLOW, nullptr);
        ShowView(View::Empty);
        if (!g.pending.empty()) SelectApk(g.pending);
        return FALSE;  // focus is already set

    case WM_DROPFILES:
        OnDrop(reinterpret_cast<HDROP>(wParam));
        return TRUE;

    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDC_DROP:
            if (HIWORD(wParam) == BN_CLICKED && !g.busy && g.view != View::Signed) Browse();
            return TRUE;
        case IDOK:
            StartSigning();
            return TRUE;
        case IDC_ANOTHER:
            if (!g.busy) ShowView(View::Empty);
            return TRUE;
        case IDCANCEL:
            if (g.busy)
                MessageBeep(MB_ICONWARNING);  // let the running job finish and clean up
            else
                EndDialog(dialog, 0);
            return TRUE;
        }
        break;

    case WM_DRAWITEM:
        if (wParam == IDC_DROP) {
            DrawDropZone(*reinterpret_cast<const DRAWITEMSTRUCT*>(lParam));
            return TRUE;
        }
        break;

    case WM_CTLCOLORSTATIC:
        if (reinterpret_cast<HWND>(lParam) == Item(IDC_STATUS)) {
            HDC dc = reinterpret_cast<HDC>(wParam);
            SetBkMode(dc, TRANSPARENT);
            SetTextColor(dc, g.tone == Tone::Bad ? RGB(196, 43, 28) : GetSysColor(COLOR_WINDOWTEXT));
            return reinterpret_cast<INT_PTR>(GetSysColorBrush(COLOR_BTNFACE));
        }
        break;

    case WM_SETCURSOR:
        if (reinterpret_cast<HWND>(wParam) == Item(IDC_DROP) && !g.busy && g.view != View::Signed) {
            SetCursor(LoadCursorW(nullptr, IDC_HAND));
            SetWindowLongPtrW(dialog, DWLP_MSGRESULT, TRUE);
            return TRUE;
        }
        break;

    case WM_NOTIFY: {
        const auto* header = reinterpret_cast<const NMHDR*>(lParam);
        if (header->idFrom == IDC_LINK && (header->code == NM_CLICK || header->code == NM_RETURN)) {
            ShowInFolder(g.saved);
            return TRUE;
        }
        break;
    }

    case WM_APP_DONE:
        OnSigned(reinterpret_cast<Outcome*>(lParam));
        return TRUE;
    }
    return FALSE;
}

}  // namespace

#ifndef APK_SIGNER_NO_WINMAIN
int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int) {
    g.instance = instance;
    if (FAILED(CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE))) return 1;
    const INITCOMMONCONTROLSEX controls{sizeof(controls), ICC_STANDARD_CLASSES | ICC_LINK_CLASS};
    InitCommonControlsEx(&controls);
    int argc = 0;
    if (PWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc)) {
        if (argc > 1) g.pending = argv[1];
        LocalFree(argv);
    }
    DialogBoxParamW(instance, MAKEINTRESOURCEW(IDD_MAIN), nullptr, DialogProc, 0);
    CoUninitialize();
    return 0;
}
#endif
