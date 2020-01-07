#include "carafe.hpp"

#ifdef CARAFE_AUTHENTICATED_COOKIES
#include <mutex>
#endif

#if defined(HAVE_GETRANDOM)
#include <sys/random.h>
#elif defined(_MSC_VER)
#include <random>
#endif

#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

// Begin public domain SHA512 implementation
// Thanks https://github.com/kalven/sha-2

using namespace Carafe;

static const std::array<u64, 80> K = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL, 0x3956c25bf348b538ULL,
    0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL, 0xd807aa98a3030242ULL, 0x12835b0145706fbeULL,
    0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL, 0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL,
    0xc19bf174cf692694ULL, 0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL, 0x983e5152ee66dfabULL,
    0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL, 0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
    0x06ca6351e003826fULL, 0x142929670a0e6e70ULL, 0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL,
    0x53380d139d95b3dfULL, 0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL, 0xd192e819d6ef5218ULL,
    0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL, 0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL,
    0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL, 0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL,
    0x682e6ff3d6b2b8a3ULL, 0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL, 0xca273eceea26619cULL,
    0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL, 0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL,
    0x113f9804bef90daeULL, 0x1b710b35131c471bULL, 0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL,
    0x431d67c49c100d4cULL, 0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

static u32 min(const u32 x, const u32 y) {
    return x < y ? x : y;
}

static void store64(u64 x, unsigned char *y, size_t offset, size_t y_size)
{
    if (offset + 7 >= y_size) throw std::out_of_range("store64");
    for(int i = 0; i != 8; ++i) {
        y[offset + i] = (x >> ((7-i) * 8)) & 255;
    }
}

static u64 load64(const unsigned char *y, size_t offset, size_t y_size)
{
    u64 res = 0;
    if (offset + 7 >= y_size) throw std::out_of_range("load64");
    for(int i = 0; i != 8; ++i) {
        res |= u64(y[offset + i]) << ((7-i) * 8);
    }
    return res;
}

static u64 Ch(u64 x, u64 y, u64 z)  { return z ^ (x & (y ^ z)); }
static u64 Maj(u64 x, u64 y, u64 z) { return ((x | y) & z) | (x & y); }
static u64 Rot(u64 x, u64 n)        { return (x >> (n & 63)) | (x << (64 - (n & 63))); }
static u64 Sh(u64 x, u64 n)         { return x >> n; }
static u64 Sigma0(u64 x)            { return Rot(x, 28) ^ Rot(x, 34) ^ Rot(x, 39); }
static u64 Sigma1(u64 x)            { return Rot(x, 14) ^ Rot(x, 18) ^ Rot(x, 41); }
static u64 Gamma0(u64 x)            { return Rot(x, 1) ^ Rot(x, 8) ^ Sh(x, 7); }
static u64 Gamma1(u64 x)            { return Rot(x, 19) ^ Rot(x, 61) ^ Sh(x, 6); }

static void sha_compress(_sha512_state& md, const unsigned char *buf, size_t buf_size)
{
    std::array<u64, 8> S;
    std::array<u64, 80> W;

    // Copy state into S
    for(int i = 0; i < 8; i++)
        S.at(i) = md.state.at(i);

    // Copy the state into 1024-bits into W[0..15]
    for(int i = 0; i < 16; i++)
        W.at(i) = load64(buf, 8*i, buf_size);

    // Fill W[16..79]
    for(int i = 16; i < 80; i++)
        W.at(i) = Gamma1(W.at(i - 2)) + W.at(i - 7) + Gamma0(W.at(i - 15)) + W.at(i - 16);

    // Compress
    auto RND = [W](u64 a, u64 b, u64 c, u64& d, u64 e, u64 f, u64 g, u64& h, u64 i)
    {
        u64 t0, t1;
        t0 = h + Sigma1(e) + Ch(e, f, g) + K.at(i) + W.at(i);
        t1 = Sigma0(a) + Maj(a, b, c);
        d += t0;
        h  = t0 + t1;
    };

    for(int i = 0; i < 80; i += 8)
    {
        RND(S.at(0),S.at(1),S.at(2),S.at(3),S.at(4),S.at(5),S.at(6),S.at(7),i+0);
        RND(S.at(7),S.at(0),S.at(1),S.at(2),S.at(3),S.at(4),S.at(5),S.at(6),i+1);
        RND(S.at(6),S.at(7),S.at(0),S.at(1),S.at(2),S.at(3),S.at(4),S.at(5),i+2);
        RND(S.at(5),S.at(6),S.at(7),S.at(0),S.at(1),S.at(2),S.at(3),S.at(4),i+3);
        RND(S.at(4),S.at(5),S.at(6),S.at(7),S.at(0),S.at(1),S.at(2),S.at(3),i+4);
        RND(S.at(3),S.at(4),S.at(5),S.at(6),S.at(7),S.at(0),S.at(1),S.at(2),i+5);
        RND(S.at(2),S.at(3),S.at(4),S.at(5),S.at(6),S.at(7),S.at(0),S.at(1),i+6);
        RND(S.at(1),S.at(2),S.at(3),S.at(4),S.at(5),S.at(6),S.at(7),S.at(0),i+7);
    }

    // Feedback
    for(int i = 0; i < 8; i++)
        md.state.at(i) = md.state.at(i) + S.at(i);
}

// Public interface

static void sha_init(_sha512_state& md)
{
    memset(&md, 0, sizeof(md));
    //md.curlen = 0;
    //md.length = 0;
    md.state.at(0) = 0x6a09e667f3bcc908ULL;
    md.state.at(1) = 0xbb67ae8584caa73bULL;
    md.state.at(2) = 0x3c6ef372fe94f82bULL;
    md.state.at(3) = 0xa54ff53a5f1d36f1ULL;
    md.state.at(4) = 0x510e527fade682d1ULL;
    md.state.at(5) = 0x9b05688c2b3e6c1fULL;
    md.state.at(6) = 0x1f83d9abfb41bd6bULL;
    md.state.at(7) = 0x5be0cd19137e2179ULL;
}

static void sha_process(_sha512_state& md, const void* src, u32 inlen)
{
    const u32 block_size = sizeof(_sha512_state::buf);
    auto in = static_cast<const unsigned char*>(src);

    while(inlen > 0)
    {
        if(md.curlen == 0 && inlen >= block_size)
        {
            sha_compress(md, in, inlen);
            md.length += block_size * 8;
            in        += block_size;
            inlen     -= block_size;
        }
        else
        {
            u32 n = min(inlen, (block_size - md.curlen));
            if (md.curlen + n > md.buf.size()) throw std::out_of_range("internal sha error");
            std::memcpy(md.buf.data() + md.curlen, in, n);
            md.curlen += n;
            in        += n;
            inlen     -= n;

            if(md.curlen == block_size)
            {
                sha_compress(md, md.buf.data(), md.buf.size());
                md.length += 8*block_size;
                md.curlen = 0;
            }
        }
    }
}

static void sha_done(_sha512_state& md, Sha512Output &out)
{
    // Increase the length of the message
    md.length += md.curlen * 8ULL;

    // Append the '1' bit
    md.buf.at(md.curlen++) = static_cast<unsigned char>(0x80);

    // If the length is currently above 112 bytes we append zeros then compress.
    // Then we can fall back to padding zeros and length encoding like normal.
    if(md.curlen > 112)
    {
        while(md.curlen < 128)
            md.buf.at(md.curlen++) = 0;
        sha_compress(md, md.buf.data(), md.buf.size());
        md.curlen = 0;
    }

    // Pad upto 120 bytes of zeroes
    // note: that from 112 to 120 is the 64 MSB of the length.  We assume that
    // you won't hash 2^64 bits of data... :-)
    while(md.curlen < 120)
        md.buf.at(md.curlen++) = 0;

    // Store length
    store64(md.length, md.buf.data(), 120, md.buf.size());
    sha_compress(md, md.buf.data(), md.buf.size());

    // Copy output
    for(int i = 0; i < 8; i++)
        store64(md.state.at(i), reinterpret_cast<unsigned char *>(out.data()), i*8, out.size());
}

// End public domain SHA2 implementation

std::string Sha512::compute(const char *buf, size_t size) {
    _sha512_state s;
    Sha512Output out;

    if (size > UINT32_MAX) throw std::out_of_range("Input too large");
    sha_init(s);
    sha_process(s, buf, static_cast<u32>(size));
    sha_done(s, out);
    return std::string(out.data(), out.size());
}

// Based on public domain base64
// Thanks https://en.wikibooks.org/wiki/Algorithm_Implementation/Miscellaneous/Base64#C++

const Base64::Charset Base64::CharsetStandard {
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
    '='
};

const Base64::Charset Base64::CharsetURLSafe {
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
    '.'
};

#ifndef LITTLEENDIAN
#error "Base64 routines only support little-endian architectures"
#endif
std::string Base64::encode(const char *in, size_t in_size, const Charset &charset) {
    std::string encodedString;
    encodedString.reserve(((in_size/3) + (in_size % 3 > 0)) * 4);
    uint32_t temp;
    size_t in_idx = 0;
    for (size_t idx = 0; idx < in_size/3; idx++) {
        temp  = in[in_idx++] << 16; //Convert to big endian
        temp += in[in_idx++] << 8;
        temp += in[in_idx++];
        encodedString.append(1,charset.encodeLookup.at((temp & 0x00FC0000) >> 18));
        encodedString.append(1,charset.encodeLookup.at((temp & 0x0003F000) >> 12));
        encodedString.append(1,charset.encodeLookup.at((temp & 0x00000FC0) >> 6 ));
        encodedString.append(1,charset.encodeLookup.at((temp & 0x0000003F)      ));
    }
    switch (in_size % 3) {
        case 1:
            temp  = in[in_idx++] << 16; //Convert to big endian
            encodedString.append(1,charset.encodeLookup.at((temp & 0x00FC0000) >> 18));
            encodedString.append(1,charset.encodeLookup.at((temp & 0x0003F000) >> 12));
            encodedString.append(2,charset.padCharacter);
            break;
        case 2:
            temp  = in[in_idx++] << 16; //Convert to big endian
            temp += in[in_idx++] << 8;
            encodedString.append(1,charset.encodeLookup.at((temp & 0x00FC0000) >> 18));
            encodedString.append(1,charset.encodeLookup.at((temp & 0x0003F000) >> 12));
            encodedString.append(1,charset.encodeLookup.at((temp & 0x00000FC0) >> 6 ));
            encodedString.append(1,charset.padCharacter);
            break;
    }
    return encodedString;
}

std::string Base64::decode(const char *in, size_t in_size, const Charset &charset) {
    uint_fast32_t leftover = 0;
    char i;
    std::string s;
    s.reserve((in_size * 3 / 4) + 1); // if the input lacks padding, this might be too much space
    for (size_t x = 0; x < in_size; x++) {
        char c;
        if (in[x] == charset.padCharacter) {
            x++;
            for (; x < in_size; x++) {
                if (in[x] != charset.padCharacter) throw std::out_of_range("Invalid base64 padding");
            }
            break;
        }
        bool found_char = false;
        for(c = 0; c < 64; c++) {
            if (charset.encodeLookup.at(c) == in[x]) {
                found_char = true;
                break;
            }
        }
        if (!found_char) throw std::out_of_range("Invalid base64 character");
        if (x % 4 == 0) {
            leftover = c << 2;
            continue;
        } else if (x % 4 == 1) {
            i = leftover | (c >> 4);
            leftover = c << 4;
        } else if (x % 4 == 2) {
            i = leftover | (c >> 2);
            leftover = c << 6;
        } else {
            i = leftover | c;
            //leftover = 0;
        }
        s += i;
    }
    return s;
}

// End public domain Base64

// URLSafe
std::string URLSafeCharacters::encode(const char *s) { return encode(std::string(s)); }
std::string URLSafeCharacters::encode(const std::string &s) {
    std::string r;
    for(unsigned char c : s) {
        if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '.' || c == '-' || c == '_' || c == '~') {
            r += c;
        } else {
            std::array<char, 4> hex;
            unsigned int the_char = c;
            size_t len = snprintf(hex.data(), hex.size(), "%%%02X", the_char);
            if (len >= hex.size()) throw std::out_of_range("Error in hex conversion"); // Shouldn't happen.
            r.append(hex.data(), len);
        }
    }
    return r;
}

std::string URLSafeCharacters::decode(const char *s) { return decode(std::string(s)); }
std::string URLSafeCharacters::decode(const std::string &s) {
    std::string r;
    for(size_t i = 0; i < s.size(); i++) {
        std::array<char, 3> hex;
        hex[2] = '\0';
        if (s[i] != '%') {
            r += s[i];
        } else {
            char *end;
            // std::string will throw if we read past the end, no need to check ourselves.
            hex[0] = s[++i];
            hex[1] = s[++i];
            char val = strtoul(hex.data(), &end, 16);
            if (end != &hex[2] || (val == 0 && (hex[0] != '0' || hex[1] != '0'))) {
                // If strtoul returned 0 and our 2 characters aren't zeroes,
                // then strtoul was returning an error.
                throw std::out_of_range("Invalid URL encoding");
            }
            r += val;
        }
    }
    return r;
}

// Hex
const char *Hex::CharsUpper = "%02X";
const char *Hex::CharsLower = "%02x";
std::string Hex::encode(const std::string &str, const Charset hc) { return encode(str.data(), str.size(), hc); }
std::string Hex::encode(const char *s, const Charset hc) { return encode(s, strlen(s), hc); }
std::string Hex::encode(const char *s, size_t len, const Charset hc) {
    const char *hex_conversion = CharsLower;
    if (hc == Upper) hex_conversion = CharsUpper;
    std::string r;
    r.reserve(len * 2);
    for(size_t i = 0; i < len; i++) {
        std::array<char, 3> hex;
        unsigned int c = (unsigned char) s[i];
        size_t len = snprintf(hex.data(), hex.size(), hex_conversion, c);
        if (len >= hex.size()) throw std::out_of_range("Error in hex conversion"); // Shouldn't happen.
        r.append(hex.data(), len);
    }
    return r;
}

std::string Hex::decode(const std::string &str) { return decode(str.data(), str.size()); }
std::string Hex::decode(const char *s) { return decode(s, strlen(s)); }
std::string Hex::decode(const char *s, size_t len) {
    if (len % 2 != 0) throw std::out_of_range("Invalid hex encoding");
    std::string r;
    std::array<char, 3> hex;
    r.reserve(len / 2);
    hex[2] = '\0';
    for(size_t i = 0; i < len - 1; i++) {
        char *end;
        hex[0] = s[i++];
        hex[1] = s[i];
        char val = strtoul(hex.data(), &end, 16);
        if (end != &hex[2] || (val == 0 && (hex[0] != '0' || hex[1] != '0'))) {
            // If strtoul returned 0 and our 2 characters aren't zeroes,
            // then strtoul was returning an error.
            throw std::out_of_range("Invalid hex encoding");
        }
        r += val;
    }
    return r;
}

// CookiesBase
bool CookiesBase::case_insensitive_equals(const std::string &a, const char *s) {
    if (!s) return false;
    size_t slen = strlen(s);
    if (a.size() != slen) return false;
    for (size_t i = 0; i < a.size(); i++) {
        if (tolower(a[i]) != tolower(s[i])) {
            return false;
        }
    }
    return true;
}

// We do our best, but surely there are cookies we can't parse.
void CookiesBase::load_data(const std::string &d) {
    std::string::size_type start = 0;
    std::string key, val;
    while(start != std::string::npos && start < d.size()) {
        std::string::size_type end_pos = d.find(';', start);
        std::string::size_type eqpos = d.find('=', start);
        if (end_pos == std::string::npos) end_pos = d.size();
        if (eqpos > end_pos || eqpos == std::string::npos) {
            while (d[start] == ' ') start++;
            val = d.substr(start, end_pos - start);
            // Special case-insensitive cookie flags. See rfc6265.
            bool set_special = false;
            if (process_flags_and_special) {
                if (case_insensitive_equals(val, "secure")) {
                    flag_secure = true;
                    set_special = true;
                } else if (case_insensitive_equals(val, "httponly")) {
                    flag_httponly = true;
                    set_special = true;
                }
            }
            if (!set_special) {
                cookie_map[""] = val;
            }
        } else {
            while (d[start] == ' ') start++;
            key = d.substr(start, eqpos - start);
            val = d.substr(eqpos + 1, end_pos - eqpos - 1);
            // Special case-insensitive cookie names. See rfc6265.
            bool set_special = false;
            if (process_flags_and_special) {
                if (case_insensitive_equals(key, "path")) {
                    cookie_map["path"] = val;
                    set_special = true;
                } else if (case_insensitive_equals(key, "expires")) {
                    cookie_map["expires"] = val;
                    set_special = true;
                } else if (case_insensitive_equals(key, "max-age")) {
                    cookie_map["max-age"] = val;
                    set_special = true;
                } else if (case_insensitive_equals(key, "domain")) {
                    cookie_map["domain"] = val;
                    set_special = true;
                }
            }
            if (!set_special) {
                key = URLSafeCharacters::decode(key);
                val = URLSafeCharacters::decode(val);
                if (key.size() || val.size()) cookie_map[key] = val; // key can be "", weird huh?
            }
        }
        start = end_pos + 1;
    }
}

CookiesBase::CookiesBase() {}
CookiesBase::CookiesBase(const std::string &d) {
    load_data(d);
}

StringMap &CookiesBase::CookiesBase::kv() { return cookie_map; }

void CookiesBase::erase() {
    cookie_map.erase(cookie_map.begin(), cookie_map.end());
    flag_secure = false;
    flag_httponly = false;
}

std::string CookiesBase::serialize() {
    std::string s;
    for(const auto &i : cookie_map) {
        if (!i.first.size() && !i.second.size()) continue;
        s += URLSafeCharacters::encode(i.first);
        s += '=';
        s += URLSafeCharacters::encode(i.second);
        s += ';';
        s += ' ';
    }
    if (process_flags_and_special) {
        if (flag_secure) s += "Secure; ";
        if (flag_httponly) s += "HttpOnly; ";
    }
    if (s.size()) { // trailing "; "
        s.pop_back();
        s.pop_back();
    }
    return s;
}

// Random
void Random::fill(char *buf, size_t len) {
#if defined(HAVE_ARC4RANDOM_BUF)
    // Documented as "always successful".
    arc4random_buf(buf, len);
#elif defined(HAVE_GETRANDOM)
    size_t filled = 0;
    while (filled < len) {
        ssize_t r = getrandom(buf + filled, len - filled, 0);
        if (r >= 0) {
            filled += r;
        } else {
            if (r != -1 || errno != EINTR) throw std::runtime_error("getrandom failed");
        }
    }
#elif defined(_MSC_VER)
    // Microsoft documents std::random_device as being cryptographically
    // random. I don't have a windows to test on though!
    size_t filled = 0;
    while (filled < len) {
        auto r = rd();
        while (len - filled <= chunk_size) {
            memcpy(&buf[filled], &r, chunk_size);
            filled += chunk_size;
        }
        for (size_t x = 0; x < chunk_size && filled < len; x++) {
            buf[filled++] = r & 0xFF;
            r = r >> 8;
        }
    }
#else
#error "Don't know how to generate cryptographically-secure random numbers on this platform"
#endif
}

std::string Random::get(const size_t size) {
    char temp[size];
    fill(temp, size);
    return std::string(temp, size);
}

std::string Random::get_base64(const size_t size, const Carafe::Base64::Charset &charset) {
    std::vector<char> temp;
    temp.resize(size);
    fill(temp);
    return Base64::encode(temp, charset);
}

// uuid v4
std::string Random::uuid() {
    std::array<char, 16> buf;
    fill(buf);
    char &version = buf.at(6);
    char &variant = buf.at(8);
    version &= 0b00001111;
    version |= 0b01000000;
    variant &= 0b00111111;
    variant |= 0b10000000;
    std::string r;
    r.reserve(36);
    r += Hex::encode(buf.data(), 4);
    r += '-';
    r += Hex::encode(&buf.at(4), 2);
    r += '-';
    r += Hex::encode(&buf.at(6), 2);
    r += '-';
    r += Hex::encode(&buf.at(8), 2);
    r += '-';
    r += Hex::encode(&buf.at(10), 6);
    return r;
}

#ifdef CARAFE_AUTHENTICATED_COOKIES
// SecureKey
void SecureKey::precompute_state(const char *key, const size_t len) {
    sha_init(precomputed_key_state);
    if (len < 16 || len > UINT32_MAX) throw std::runtime_error("key.size() < 16 or > UINT32_MAX");
    sha_process(precomputed_key_state, key, static_cast<u32>(len));
}

void SecureKey::rekey(const std::string &s) {
    precompute_state(s.data(), s.size());
}

void SecureKey::rekey(void) {
    std::array<char, DEFAULT_KEY_SIZE> out;
    Random::fill(out);
    precompute_state(out.data(), out.size());
}

SecureKey::SecureKey() {
    rekey();
};

SecureKey::SecureKey(const std::string &s) {
    rekey(s);
}

void SecureKey::get_keyed_state(_sha512_state &dest) const {
    memcpy(&dest, &precomputed_key_state, sizeof(precomputed_key_state));
}

// AuthenticatedCookieAuthenticator
AuthenticatedCookieAuthenticator::AuthenticatedCookieAuthenticator(const SecureKey &k) : key(k) {}

const std::string &AuthenticatedCookieAuthenticator::compute_from_string(const std::string &in) {
    _sha512_state s;
    Sha512Output out;

    if (in.size() > UINT32_MAX) throw std::out_of_range("Input too large");

    key.get_keyed_state(s);

    sha_process(s, in.data(), static_cast<u32>(in.size()));
    sha_done(s, out);

    static_assert(MAC_SIZE <= out.size() - 12, "MAC_SIZE is too large for hash output size");
    mac = Base64::encode(out.data(), MAC_SIZE);
    return mac;
}

const std::string &AuthenticatedCookieAuthenticator::to_string() const {
    if (mac.size() == 0) throw std::runtime_error("This AuthenticatedCookieAuthenticator not initialized");
    return mac;
}

void AuthenticatedCookieAuthenticator::load_from_safebase64(const std::string &in) {
    if (in.size() != (SHA512_OUTPUT_SIZE * 3 / 4)) throw std::runtime_error("Invalid input");
    mac = in;
}

bool AuthenticatedCookieAuthenticator::operator==(const AuthenticatedCookieAuthenticator &b) const {
    return this->safe_equals(b.mac);
}

bool AuthenticatedCookieAuthenticator::operator!=(const AuthenticatedCookieAuthenticator &b) const {
    return !(this->safe_equals(b.mac));
}

bool AuthenticatedCookieAuthenticator::safe_equals(const std::string &b) const {
    unsigned char t = 0;
    if (mac.size() == 0) throw std::runtime_error("This AuthenticatedCookieAuthenticator not initialized");
    if (mac.size() != b.size()) return false;
    for (size_t i = 0; i < mac.size(); i++) {
        t |= mac.at(i) ^ b.at(i);
    }
    return t == 0;
}

// CookieKeyManager
CookieKeyManager::CookieKeyManager() {};
CookieKeyManager::CookieKeyManager(const std::string &key) : encrypt_key(key) {};

CookieKeyManagerID CookieKeyManager::add_decrypt_key_no_lock(const SecureKey &new_key) {
    CookieKeyManagerID this_id;
    do {
        Random::fill(reinterpret_cast<char *>(&this_id), sizeof(this_id));
    } while (decrypt_keys.count(this_id));
    decrypt_keys[this_id] = { new_key, std::chrono::system_clock::now() };
    return this_id;
}

CookieKeyManagerID CookieKeyManager::add_decrypt_key(const SecureKey &new_key) {
    std::lock_guard<std::mutex> dlock(decrypt_key_lock);
    return add_decrypt_key_no_lock(new_key);
}

bool CookieKeyManager::remove_decrypt_key(const CookieKeyManagerID id) {
    std::lock_guard<std::mutex> dlock(decrypt_key_lock);
    return decrypt_keys.erase(id);
}

bool CookieKeyManager::has_decrypt_key(const CookieKeyManagerID id) const {
    std::lock_guard<std::mutex> dlock(decrypt_key_lock);
    return decrypt_keys.count(id);
}

size_t CookieKeyManager::decrypt_key_count() const {
    std::lock_guard<std::mutex> dlock(decrypt_key_lock);
    return decrypt_keys.size();
}

void CookieKeyManager::expire_old_decrypt_keys(const std::chrono::seconds age) {
    auto now = std::chrono::system_clock::now();
    std::lock_guard<std::mutex> dlock(decrypt_key_lock);

    for (auto it = decrypt_keys.cbegin(); it != decrypt_keys.cend(); ) {
        const auto &ts = it->second.ts;
        if (now > ts && now - age > ts) {
            it = decrypt_keys.erase(it);
        } else {
            ++it;
        }
    }
}

SecureKey CookieKeyManager::get_encrypt_key() const { // Important this returns a copy.
    std::lock_guard<std::mutex> elock(encrypt_key_lock);
    return encrypt_key;
}

CookieKeyManagerID CookieKeyManager::set_encrypt_key(const std::string &new_key) {
    // Order is important
    std::lock_guard<std::mutex> elock(encrypt_key_lock);
    std::lock_guard<std::mutex> dlock(decrypt_key_lock);

    auto r = add_decrypt_key_no_lock(encrypt_key);
    encrypt_key.rekey(new_key);
    return r;
}

CookieKeyManagerID CookieKeyManager::generate_new_encrypt_key() {
    // Order is important
    std::lock_guard<std::mutex> elock(encrypt_key_lock);
    std::lock_guard<std::mutex> dlock(decrypt_key_lock);

    auto r = add_decrypt_key_no_lock(encrypt_key);
    encrypt_key.rekey();
    return r;
}

AuthenticatedCookieAuthenticator CookieKeyManager::compute(const std::string &data) const {
    std::lock_guard<std::mutex> elock(encrypt_key_lock);
    AuthenticatedCookieAuthenticator authenticator(encrypt_key);
    authenticator.compute_from_string(data);
    return authenticator;
}

// CookieKeyManager
bool CookieKeyManager::check_valid(const std::string &data, const std::string &check_me) const {
    // Order is important
    {
        std::lock_guard<std::mutex> elock(encrypt_key_lock);
        AuthenticatedCookieAuthenticator authenticator(encrypt_key);
        authenticator.compute_from_string(data);
        if (authenticator.safe_equals(check_me)) return true;
    }

    std::lock_guard<std::mutex> dlock(decrypt_key_lock);
    for(const auto &key : decrypt_keys) {
        AuthenticatedCookieAuthenticator authenticator(key.second.key);
        authenticator.compute_from_string(data);
        if (authenticator.safe_equals(check_me)) return true;
    }

    return false;
}

// AuthenticatedCookies
const std::chrono::seconds AuthenticatedCookies::NeverExpire(0);
const std::string AuthenticatedCookies::TIMESTAMP_KEY("_ts");
AuthenticatedCookies::AuthenticatedCookies(const CookieKeyManager &km, const std::chrono::seconds age) :
    CookiesBase(),
    cookie_keys(km),
    max_age(age)
{
        process_flags_and_special = false;
}
AuthenticatedCookies::AuthenticatedCookies(const CookieKeyManager &km, const std::string &d, const std::chrono::seconds age) :
    CookiesBase(),
    cookie_keys(km),
    max_age(age)
{
    process_flags_and_special = false;
    load_data(d);
}

bool AuthenticatedCookies::load_data(const std::string &d) {
    // The mac is the AuthenticatedCookieAuthenticator::ENCODED_SIZE bytes at the
    // end, and we know there must be some data (at least the TIMESTAMP_KEY).
    if (d.size() <= AuthenticatedCookieAuthenticator::ENCODED_SIZE) return false;

    std::string mac = d.substr(d.size() - AuthenticatedCookieAuthenticator::ENCODED_SIZE, AuthenticatedCookieAuthenticator::ENCODED_SIZE);
    std::string data = d.substr(0, d.size() - AuthenticatedCookieAuthenticator::ENCODED_SIZE);

    if (!cookie_keys.check_valid(data, mac)) {
        return false;
    }

    data = Base64::decode(data);
    CookiesBase::load_data(data);

    // The timestamp is added automatically, if it's not there something went wrong.
    if (!kv().count(TIMESTAMP_KEY)) {
        erase();
        return false;
    }

    if (max_age.count()) {
        // I'm sure there's a way to do this just using std::chrono but I can't
        // figure it out.
        unsigned long long ts, now;
        // Unlikely exception, since we set this value and (hopefully) authenticate it.
        try {
            ts = std::stoull(kv()[TIMESTAMP_KEY]);
            now = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
        } catch (...) {
            erase();
            return false;
        }
        if (now > ts && now - max_age.count() > ts) {
            erase();
            return false;
        }
    }

    auth_valid = true;
    return true;
}

StringMap &AuthenticatedCookies::kv() { return CookiesBase::cookie_map; }
void AuthenticatedCookies::erase() { CookiesBase::erase(); }
bool AuthenticatedCookies::authenticated() { return auth_valid; }

std::string AuthenticatedCookies::serialize() {
    auto now = std::chrono::time_point_cast<std::chrono::seconds>(std::chrono::system_clock::now());

    CookiesBase::cookie_map[TIMESTAMP_KEY] = std::to_string(now.time_since_epoch().count());

    std::string s = Base64::encode(CookiesBase::serialize());
    AuthenticatedCookieAuthenticator mac = cookie_keys.compute(s);
    return s + mac.to_string();
}
#endif // CARAFE_AUTHENTICATED_COOKIES

// Required to let us | together the enum.
static_assert(sizeof(MHD_FLAG) <= sizeof(unsigned int), "int can't hold MHD_FLAG");

MHD_FLAG operator|(const MHD_FLAG a, const MHD_FLAG b) {
    return static_cast<MHD_FLAG>(static_cast<unsigned int>(a) | static_cast<unsigned int>(b));
}

MHD_FLAG operator&(const MHD_FLAG a, const MHD_FLAG b) {
    return static_cast<MHD_FLAG>(static_cast<unsigned int>(a) & static_cast<unsigned int>(b));
}

MHD_FLAG operator~(const MHD_FLAG a) {
    return static_cast<MHD_FLAG>(~(static_cast<unsigned int>(a)));
}

HTTPMethods operator|(const HTTPMethods a, const HTTPMethods b) {
    return static_cast<HTTPMethods>(static_cast<int>(a) | static_cast<int>(b));
}

HTTPMethods operator&(const HTTPMethods a, const HTTPMethods b) {
    return static_cast<HTTPMethods>(static_cast<int>(a) & static_cast<int>(b));
}

HTTPMethods operator~(const HTTPMethods a) {
    return static_cast<HTTPMethods>(~(static_cast<int>(a)));
}

// RouteCallbackInfo
RouteCallbackInfo::RouteCallbackInfo(const std::string &r, HTTPMethod m, RouteCallback cb) : route(r), callback(cb), allowed_methods(m) {
    std::string this_arg;
    std::string this_arg_type;
    enum processing_step { ARG_NAME, ARG_TYPE, ARG_DONE };
    processing_step step;

    if (!route.size()) throw std::runtime_error("Empty route");

    for(size_t i = 0; i < route.size(); i++) {
        char c = route[i];
        switch (c) {
            case '<':
                step = ARG_NAME;
                this_arg = this_arg_type = "";
                for(i++; i < route.size(); i++) {
                    if (route[i] == '>') {
                        step = ARG_DONE;
                        break;
                    }
                    if(route[i] == ':') {
                        if (step == ARG_TYPE) throw std::runtime_error("Got ':' when expecting '>':" + route);
                        step = ARG_TYPE;
                        continue;
                    }
                    if (step == ARG_NAME) this_arg += route[i];
                    else this_arg_type += route[i];
                }
                if (step != ARG_DONE) throw std::runtime_error("Route missing '>': " + route);

                if (this_arg_type == "" || this_arg_type == "string") {
                    route_re += "\\([^/][^/]*\\)";
                } else if (this_arg_type == "int") {
                    route_re += "\\([0-9][0-9]*\\)";
                } else if (this_arg_type == "path") {
                    route_re += "\\(..*\\)";
                } else {
                    throw std::runtime_error("Unknown arg type " + this_arg_type + " for route " + route);
                }
                arg_names.emplace_back(std::move(this_arg));
                break;

            case '.':
            case '[':
            case '\\':
            case '*':
            case '^':
            case '$':
                route_re += '\\';

            default:
                route_re += c;
        }
        re.assign(route_re, std::regex::basic | std::regex::optimize | std::regex::icase);
    }
}

// RequestPostData
RequestPostData::RequestPostData(const char *d, const char *f) : data(d), filename(f) {};

// Response
Response::Response() : code(500) {};
void Response::reset() {
    cookies.erase();
    headers.erase(headers.begin(), headers.end());
    code = 500;
}

// RequestConnectionValues
RequestConnectionValues::RequestConnectionValues(Request &r, ValueType vt, size_t ms, size_t &shared_arg_size) :
    req(r), my_type(vt), current_size(shared_arg_size), max_size(ms), all_args_populated(false)
{}

// This could be a string_view, but would be the only thing requiring C++17 support.
const std::string &RequestConnectionValues::get(const std::string &key) {
    if (!all_args_populated) load_all();
    auto f = all_args.find(key);
    if (f == all_args.end()) return no_value;
    return f->second;
}

StringMap::iterator RequestConnectionValues::begin() {
    if (!all_args_populated) load_all();
    return all_args.begin();
}

StringMap::iterator RequestConnectionValues::end() {
    if (!all_args_populated) load_all();
    return all_args.end();
}

// Request
bool Request::case_insensitive_equals(const char *a, const char *b) {
    size_t i;
    for(i = 0; a[i] != '\0' || b[i] != '\0'; i++) {
        if ((a[i] & 0x7F) != (b[i] & 0x7F)) return false;
    }
    return a[i] == b[i];
}

Request::Request(struct MHD_Connection *c, const char *m, const char *v, const char *u, size_t max_up, size_t max_header, void *ctx) :
    connection(c),
    post_processor(nullptr),
    total_post_data_size(0),
    max_upload_size(max_up),
    total_header_size(0),
    max_header_size(max_header),
    version(v),
    path(u),
    method(method_to_int(m)),
    args(*this, RequestConnectionValues::ARGS, max_header, current_arg_size),
    headers(*this, RequestConnectionValues::HEADERS, max_header, current_arg_size),
    context(ctx)
{
    if (!connection) throw std::runtime_error("connection is null");
    if (headers.get("cookie").size()) cookies.load_data(headers.get("cookie"));
};

const std::string &Request::client_ip() {
    if (!client_ip_str.size()) {
        std::array<char, INET6_ADDRSTRLEN + 1> dest;
        const union MHD_ConnectionInfo *info = MHD_get_connection_info(connection, MHD_CONNECTION_INFO_CLIENT_ADDRESS);
        if (!info || !info->client_addr) return client_ip_str; // empty

        const char *r = nullptr;
        if (info->client_addr->sa_family == AF_INET) {
            struct sockaddr_in __attribute__((__may_alias__)) *in = (struct sockaddr_in *) info->client_addr;
            r = inet_ntop(AF_INET, &in->sin_addr, dest.data(), dest.size());
        } else if (info->client_addr->sa_family == AF_INET6) {
            struct sockaddr_in6 __attribute__((__may_alias__)) *in6 = (struct sockaddr_in6 *) info->client_addr;
            r = inet_ntop(AF_INET6, &in6->sin6_addr, dest.data(), dest.size());
        }
        if (!r) return client_ip_str; // empty
        client_ip_str = dest.data();
    }
    return client_ip_str;
}

HTTPMethod Request::method_to_int(const char *method) {
    if (!method) return HTTPMethods::UNKNOWN;
    if (case_insensitive_equals(method, "GET")) {
        return HTTPMethods::GET;
    } else if (case_insensitive_equals(method, "POST")) {
        return HTTPMethods::POST;
    } else if (case_insensitive_equals(method, "PURGE")) {
        return HTTPMethods::PURGE;
    } else if (case_insensitive_equals(method, "PUT")) {
        return HTTPMethods::PUT;
    } else if (case_insensitive_equals(method, "DELETE")) {
        return HTTPMethods::DELETE;
    } else if (case_insensitive_equals(method, "HEAD")) {
        return HTTPMethods::HEAD;
    } else if (case_insensitive_equals(method, "CONNECT")) {
        return HTTPMethods::CONNECT;
    } else if (case_insensitive_equals(method, "OPTIONS")) {
        return HTTPMethods::OPTIONS;
    } else if (case_insensitive_equals(method, "TRACE")) {
        return HTTPMethods::TRACE;
    } else if (case_insensitive_equals(method, "PATCH")) {
        return HTTPMethods::PATCH;
    }
    return HTTPMethods::UNKNOWN;
}

// HTTPD
HTTPD::HTTPD(uint_fast16_t p) :
    listen_port(p),
    daemon(nullptr),
    daemon6(nullptr),
    max_upload_size(10*1024*1024), // 10 megs, arbitrary
    max_header_size(1*1024*1024), // 1 meg, arbitrary
    keep_running(true),
    timeout(60),
    thread_pool_size(1),
    dual_stack(true),
    debug(false),
    context(nullptr)
    {};

int HTTPD::mhd_handler(void *microhttpd_ptr,
                       struct MHD_Connection *connection,
                       const char *url,
                       const char *method,
                       const char *version,
                       const char *upload_data,
                       size_t *upload_data_size,
                       void **context_data) {
    if (!microhttpd_ptr || !connection || !url || !method || !version || !upload_data_size) return MHD_NO;
    HTTPD *chd = static_cast<HTTPD *>(microhttpd_ptr);

    if (!*context_data) { // Phase 1
        Request *request = new (std::nothrow) Request(connection, method, version, url, chd->max_upload_size, chd->max_header_size, chd->context);
        if (!request) return MHD_NO;
        *context_data = request;
        return MHD_YES;
    }

    // Phase 2
    if (!*context_data) return MHD_NO;
    Request *request = static_cast<Request *>(*context_data);

    if (request->method == HTTPMethods::POST) {
        request->post_processor = MHD_create_post_processor(connection, 65536, &mhd_post_iterator, request);
        if (!request->post_processor) {
            delete request;
            return MHD_NO;
        }
    }

    if (request->method == HTTPMethods::POST && *upload_data_size) {
        MHD_post_process(request->post_processor, upload_data, *upload_data_size);
        *upload_data_size = 0;
        return MHD_YES;
    }

    // Phase 2 or 3 depending on if this is a POST with data or not.
    if (request->post_processor) MHD_destroy_post_processor(request->post_processor);

    Response response;
    *context_data = NULL;

    try {
        chd->handle_route(*request, response, method);
    } catch (std::exception &e) {
        response.reset();
        if (chd->debug) {
            response.headers.emplace("Content-Type", "text/plain");
            response.body = e.what();
        }
        try {
            if (chd->error_log_callback) chd->error_log_callback(*request, method, e);
        } catch (...) {
            if (chd->debug) response.body += "\nerror_log_func exception";
        }
    }

    if (chd->access_log_callback) {
        try {
            chd->access_log_callback(*request, response, method);
        } catch (const std::exception& e) {
            chd->error_log_callback(*request, "Exception caught while calling access_log_callback", e);
        } catch (...) {
            // We tried...
        }
    }

    struct MHD_Response *mhd_response = MHD_create_response_from_buffer(
                                                                        response.body.size(),
                                                                        const_cast<void *>(static_cast<const void *>(response.body.c_str())),
                                                                        MHD_RESPMEM_MUST_COPY
                                                                        );

    for(const auto &h : response.headers) {
        MHD_add_response_header(mhd_response, h.first.c_str(), h.second.c_str());
    }

    if (response.cookies.kv().size()) {
        MHD_add_response_header(mhd_response, MHD_HTTP_HEADER_SET_COOKIE, response.cookies.serialize().c_str());
    }

    int ret = MHD_queue_response(connection, response.code, mhd_response);
    MHD_destroy_response(mhd_response);
    delete request;
    return ret;
}

int HTTPD::mhd_header_parse(void *map_ptr, enum MHD_ValueKind kind, const char *key, const char *value) {
    if (!map_ptr || !key) return MHD_NO;
    RequestConnectionValues *values = static_cast<RequestConnectionValues *>(map_ptr);
    if (*key == '\0' && value && *value == '\0') return MHD_YES; // I don't know why all empty values show up but we don't want them.

    std::string key_lc = key;
    auto &storage = values->all_args;

    if (kind == MHD_HEADER_KIND) std::transform(key_lc.begin(), key_lc.end(), key_lc.begin(), ::tolower);

    size_t previous_size = values->current_size;
    values->current_size += key_lc.size();
    if (values->current_size > values->max_size || values->current_size < previous_size) return MHD_NO;

    if (value) {
        previous_size = values->current_size;
        values->current_size += strlen(value);
        if (values->current_size > values->max_size || values->current_size < previous_size) return MHD_NO;
        storage.emplace(key_lc, value);
    } else {
        storage.emplace(key_lc, "");
    }

    return MHD_YES;
}

int HTTPD::mhd_post_iterator(void *microhttpd_req_ptr,
                             enum MHD_ValueKind kind,
                             const char *key,
                             const char *filename,
                             const char *content_type,
                             const char *transfer_encoding,
                             const char *data,
                             uint64_t off,
                             size_t size) {
    if (kind != MHD_POSTDATA_KIND || !microhttpd_req_ptr || !key) return MHD_NO;
    Request *request = static_cast<Request *>(microhttpd_req_ptr);

    request->total_post_data_size += size;
    if (request->total_post_data_size > request->max_upload_size) return MHD_NO;

    // Some of these may be null, but you can't pass null to a std::string
    // constructor, so make them point at empty strings instead.
    if (!key) key = "";
    if (!data) data = "";
    if (!filename) filename = "";

    auto found = request->post_data.find(key);
    if (found == request->post_data.end()) {
        request->post_data.emplace(std::piecewise_construct,
                                   std::forward_as_tuple(key),
                                   std::forward_as_tuple(data, filename));
    } else {
        found->second.data += data;
    }

    return MHD_YES;
}

void HTTPD::sort_routes() {
    struct {
        bool operator()(RouteCallbackInfo &a, RouteCallbackInfo &b) const {
            return a.route_re.size() < b.route_re.size();
        }
    } sorter;
    std::sort(routes.begin(), routes.end(), sorter);
}

HTTPD::~HTTPD() noexcept {
    MHD_stop_daemon(daemon);
    if (dual_stack) MHD_stop_daemon(daemon6);
}

void HTTPD::run() {
    sort_routes();

    struct MHD_OptionItem ops[] = {
        { MHD_OPTION_CONNECTION_TIMEOUT, timeout, NULL },
        { MHD_OPTION_LISTENING_ADDRESS_REUSE, 1, NULL },
        { MHD_OPTION_END, 0, NULL }, // used for MHD_OPTION_THREAD_POOL_SIZE
        { MHD_OPTION_END, 0, NULL }
    };

    // libmicrohttpd logs a message if we set this to 1 (the default), so
    // don't set it unless we're going to set it to > 1.
    if (thread_pool_size > 1) {
        ops[2] = { MHD_OPTION_THREAD_POOL_SIZE, thread_pool_size, NULL };
    }

    MHD_FLAG flags = MHD_USE_SELECT_INTERNALLY;
    if (debug) flags = flags | MHD_USE_DEBUG;

    daemon = MHD_start_daemon(flags,
                              listen_port,
                              NULL,
                              NULL,
                              mhd_handler,
                              static_cast<void *>(this),
                              MHD_OPTION_ARRAY, ops,
                              MHD_OPTION_END);
    if (!daemon) throw std::runtime_error("MHD_start_daemon");

    if (dual_stack) {
        flags = flags | MHD_USE_IPv6;
        daemon6 = MHD_start_daemon(flags,
                                   listen_port,
                                   NULL,
                                   NULL,
                                   mhd_handler,
                                   static_cast<void *>(this),
                                   MHD_OPTION_ARRAY, ops,
                                   MHD_OPTION_END);
        if (!daemon6) throw std::runtime_error("MHD_start_daemon");
    }

    MHD_run(daemon);
    if (dual_stack) MHD_run(daemon6);
}

void HTTPD::run_forever() {
    run();
    while (keep_running) {
        sleep(1);
    }
}

std::string HTTPD::generate_access_log(Request &request, Response &response, const char *method) {
    std::array<char, 27> date_buf;
    std::time_t t = std::time(nullptr);
    std::strftime(date_buf.data(), date_buf.size(), "%d/%b/%Y:%H:%M:%S %z", std::localtime(&t));
    std::string log_message = // I'm sure this is inefficient.
    request.client_ip() +
    " - - [" +
    date_buf.data() +
    "] \"" +
    method +
    ' ' +
    request.path +
    ' ' +
    request.version +
    "\" " +
    std::to_string(response.code) +
    ' ' +
    std::to_string(response.body.size());
    return log_message;
}

void HTTPD::add_route(const char *route, const HTTPMethod methods, const RouteCallback &callback) {
    RouteCallbackInfo ci(route, methods, callback);
    routes.emplace_back(std::move(ci));
}

void HTTPD::add_route(const std::string &route, const HTTPMethod methods, const RouteCallback &callback) {
    add_route(route.c_str(), methods, callback);
}

void HTTPD::handle_route(Request &request, Response &response, const char *method) {
    std::smatch arg_matches;
    HTTPMethod method_int = Request::method_to_int(method);
    for(auto &route : routes) {
        if (std::regex_match(request.path, arg_matches, route.re) && (method_int & route.allowed_methods)) {
            for(size_t i = 1 /* 0 is the whole string */; i < arg_matches.size(); i++) {
                request.vars[route.arg_names.at(i - 1)] = arg_matches[i].str();
            }
            route.callback(request, response);
            return;
        }
    }
    response.code = 404;
}

// RequestConnectionValues
void RequestConnectionValues::load_all() {
    if (all_args_populated) return;
    switch (my_type) {
        case ARGS:
            MHD_get_connection_values(req.connection, MHD_GET_ARGUMENT_KIND, HTTPD::mhd_header_parse, this);
            MHD_get_connection_values(req.connection, MHD_POSTDATA_KIND, HTTPD::mhd_header_parse, this);
            break;

        case HEADERS:
            MHD_get_connection_values(req.connection, MHD_HEADER_KIND, HTTPD::mhd_header_parse, this);
            break;

        case COOKIES:
            MHD_get_connection_values(req.connection, MHD_COOKIE_KIND, HTTPD::mhd_header_parse, this);
            break;

        default:
            throw std::logic_error("unknown kind");
    }
    all_args_populated = true;
}
