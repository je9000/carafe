#ifndef carafe_hpp
#define carafe_hpp

#include <stdexcept>
#include <string>
#include <cstdint>
#include <unordered_map>
#include <functional>
#include <vector>
#include <regex>
#include <array>
#include <chrono>
#include <random>

#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include <microhttpd.h>

// Begin public domain SHA512 implementation
// Thanks https://github.com/kalven/sha-2
struct sha512_state
{
    std::uint64_t length;
    std::uint64_t state[8];
    std::uint32_t curlen;
    unsigned char buf[128];
};

typedef std::uint32_t u32;
typedef std::uint64_t u64;

static const u64 K[80] =
{
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

static u32 min(u32 x, u32 y)
{
    return x < y ? x : y;
}

static void store64(u64 x, unsigned char* y)
{
    for(int i = 0; i != 8; ++i)
        y[i] = (x >> ((7-i) * 8)) & 255;
}

static u64 load64(const unsigned char* y)
{
    u64 res = 0;
    for(int i = 0; i != 8; ++i)
        res |= u64(y[i]) << ((7-i) * 8);
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

static void sha_compress(sha512_state& md, const unsigned char *buf)
{
    u64 S[8], W[80], t0, t1;

    // Copy state into S
    for(int i = 0; i < 8; i++)
        S[i] = md.state[i];

    // Copy the state into 1024-bits into W[0..15]
    for(int i = 0; i < 16; i++)
        W[i] = load64(buf + (8*i));

    // Fill W[16..79]
    for(int i = 16; i < 80; i++)
        W[i] = Gamma1(W[i - 2]) + W[i - 7] + Gamma0(W[i - 15]) + W[i - 16];

    // Compress
    auto RND = [&](u64 a, u64 b, u64 c, u64& d, u64 e, u64 f, u64 g, u64& h, u64 i)
    {
        t0 = h + Sigma1(e) + Ch(e, f, g) + K[i] + W[i];
        t1 = Sigma0(a) + Maj(a, b, c);
        d += t0;
        h  = t0 + t1;
    };

    for(int i = 0; i < 80; i += 8)
    {
        RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],i+0);
        RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],i+1);
        RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],i+2);
        RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],i+3);
        RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],i+4);
        RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],i+5);
        RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],i+6);
        RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],i+7);
    }

    // Feedback
    for(int i = 0; i < 8; i++)
        md.state[i] = md.state[i] + S[i];
}

// Public interface

static void sha_init(sha512_state& md)
{
    md.curlen = 0;
    md.length = 0;
    md.state[0] = 0x6a09e667f3bcc908ULL;
    md.state[1] = 0xbb67ae8584caa73bULL;
    md.state[2] = 0x3c6ef372fe94f82bULL;
    md.state[3] = 0xa54ff53a5f1d36f1ULL;
    md.state[4] = 0x510e527fade682d1ULL;
    md.state[5] = 0x9b05688c2b3e6c1fULL;
    md.state[6] = 0x1f83d9abfb41bd6bULL;
    md.state[7] = 0x5be0cd19137e2179ULL;
}

static void sha_process(sha512_state& md, const void* src, u32 inlen)
{
    const u32 block_size = sizeof(sha512_state::buf);
    auto in = static_cast<const unsigned char*>(src);

    while(inlen > 0)
    {
        if(md.curlen == 0 && inlen >= block_size)
        {
            sha_compress(md, in);
            md.length += block_size * 8;
            in        += block_size;
            inlen     -= block_size;
        }
        else
        {
            u32 n = min(inlen, (block_size - md.curlen));
            std::memcpy(md.buf + md.curlen, in, n);
            md.curlen += n;
            in        += n;
            inlen     -= n;

            if(md.curlen == block_size)
            {
                sha_compress(md, md.buf);
                md.length += 8*block_size;
                md.curlen = 0;
            }
        }
    }
}

static void sha_done(sha512_state& md, void *out)
{
    // Increase the length of the message
    md.length += md.curlen * 8ULL;

    // Append the '1' bit
    md.buf[md.curlen++] = static_cast<unsigned char>(0x80);

    // If the length is currently above 112 bytes we append zeros then compress.
    // Then we can fall back to padding zeros and length encoding like normal.
    if(md.curlen > 112)
    {
        while(md.curlen < 128)
            md.buf[md.curlen++] = 0;
        sha_compress(md, md.buf);
        md.curlen = 0;
    }

    // Pad upto 120 bytes of zeroes
    // note: that from 112 to 120 is the 64 MSB of the length.  We assume that
    // you won't hash 2^64 bits of data... :-)
    while(md.curlen < 120)
        md.buf[md.curlen++] = 0;

    // Store length
    store64(md.length, md.buf+120);
    sha_compress(md, md.buf);

    // Copy output
    for(int i = 0; i < 8; i++)
        store64(md.state[i], static_cast<unsigned char*>(out)+(8*i));
}

// End public domain SHA2 implementation

// Begin public domain BASE64
// Thanks https://en.wikibooks.org/wiki/Algorithm_Implementation/Miscellaneous/Base64#C++

typedef struct {
    std::array<char, 65> encodeLookup;
    char padCharacter;
} CarafeBase64Charset;

// Note, we use | internally as a separator for authenticated cookies.
static CarafeBase64Charset CarafeBase64CharsetStandard __attribute__((unused)) = {
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
    '='
};

static CarafeBase64Charset CarafeBase64CharsetURLSafe {
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
    '.'
};

template <typename T>
std::string CarafeBase64Encode(T inputBuffer, size_t in_size, const CarafeBase64Charset &charset)
{
    std::string encodedString;
    encodedString.reserve(((in_size/3) + (in_size % 3 > 0)) * 4);
    uint32_t temp;
    auto cursor = inputBuffer.begin();
    for(size_t idx = 0; idx < in_size/3; idx++)
    {
        temp  = (*cursor++) << 16; //Convert to big endian
        temp += (*cursor++) << 8;
        temp += (*cursor++);
        encodedString.append(1,charset.encodeLookup[(temp & 0x00FC0000) >> 18]);
        encodedString.append(1,charset.encodeLookup[(temp & 0x0003F000) >> 12]);
        encodedString.append(1,charset.encodeLookup[(temp & 0x00000FC0) >> 6 ]);
        encodedString.append(1,charset.encodeLookup[(temp & 0x0000003F)      ]);
    }
    switch(in_size % 3)
    {
        case 1:
            temp  = (*cursor++) << 16; //Convert to big endian
            encodedString.append(1,charset.encodeLookup[(temp & 0x00FC0000) >> 18]);
            encodedString.append(1,charset.encodeLookup[(temp & 0x0003F000) >> 12]);
            encodedString.append(2,charset.padCharacter);
            break;
        case 2:
            temp  = (*cursor++) << 16; //Convert to big endian
            temp += (*cursor++) << 8;
            encodedString.append(1,charset.encodeLookup[(temp & 0x00FC0000) >> 18]);
            encodedString.append(1,charset.encodeLookup[(temp & 0x0003F000) >> 12]);
            encodedString.append(1,charset.encodeLookup[(temp & 0x00000FC0) >> 6 ]);
            encodedString.append(1,charset.padCharacter);
            break;
    }
    return encodedString;
}

// End public domain BASE64

class CarafeURLSafe {
public:
    static std::string encode(const char *s) { std::string s2 = s; return encode(s2); }
    static std::string encode(const std::string &s) {
        std::string r;
        for(unsigned char c : s) {
            if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '.' || c == '-' || c == '_' || c == '~') {
                r += c;
            } else {
                std::array<char, 4> hex;
                size_t len = snprintf(hex.data(), hex.size(), "%%%02X", c);
                if (len >= hex.size()) throw std::out_of_range("Error in hex conversion");
                r.append(hex.data(), len);
            }
        }
        return r;
    }

    static std::string decode(const char *s) { std::string s2 = s; return decode(s2); }
    static std::string decode(const std::string &s) {
        std::string r;
        for(size_t i = 0; i < s.size(); i++) {
            if (s[i] != '%') {
                r += s[i];
            } else {
                std::array<char, 3> hex;
                char *end;
                hex[0] = s[++i];
                hex[1] = s[++i];
                hex[2] = '\0';
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
};

template <typename T>
std::string CarafeBase64Encode(T inputBuffer, const CarafeBase64Charset &charset) {
    return CarafeBase64Encode(inputBuffer, inputBuffer.size(), charset);
}

template <typename T>
std::string CarafeBase64Decode(const T& input, const CarafeBase64Charset &charset) {
    uint_fast32_t leftover = 0;
    char i;
    std::string s;
    s.reserve(input.size() * 3 / 4); // if the input lacks padding, this might be too much space
    for (size_t x = 0; x < input.size(); x++) {
        char c;
        if (input[x] == charset.padCharacter) break;
        for(c = 0; c < 64; c++) if (charset.encodeLookup[c] == input[x]) break;
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

class CarafeMACKey {
private:
    static constexpr size_t KEY_SIZE = 72; // Size of SHA512 output + a little mode padded to alignment
    std::string key;
    sha512_state precomputed_key_state;

    void hash_key() {
        std::array<char, HASH_SIZE> out;
        sha512_state s;

        sha_init(s);
        sha_process(s, key.data(), static_cast<u32>(key.size()));
        sha_done(s, out.data());

        key = std::string(out.data(), out.size());

        sha_init(precomputed_key_state);
        sha_process(s, key.data(), static_cast<u32>(key.size()));
    }
public:
    static constexpr size_t HASH_SIZE = 64; // 512/8

    CarafeMACKey(const std::string &s) {
        // Put some sane limit on the key size.
        if (s.size() < 16) throw std::out_of_range("Key length < 16 characters");
        key = s;
        hash_key();
    }
    CarafeMACKey() {
        std::random_device rd;
        static_assert(sizeof(decltype(rd())) == 4, "random_device return too small");
        static_assert(KEY_SIZE % sizeof(decltype(rd())) == 0, "KEY_SIZE not a multiple of sizeof(decltype(rd()))");
        key.reserve(KEY_SIZE);
        for (size_t i = 0; i < KEY_SIZE / 4; i++) {
            auto r = rd();
            for (size_t x = 0; x < sizeof(decltype(rd())); x++) {
                key += (char) r & 0xFF;
                r = r >> 8;
            }
        }
        hash_key();
    }

    const std::string &get_key() const { return key; }
    const void copy_keyed_state(sha512_state &s) const {
        memcpy(&s, &precomputed_key_state, sizeof(precomputed_key_state));
    }
};

class CarafeMAC {
private:
    std::string mac;
    const CarafeMACKey &key;
public:
    // SHA512/264, so there are no padding characters. We also don't benefit
    // from HMAC because we use random, hashed keys appended to data, and we
    // discard 248 bits of output the attacker would need to guess.
    static constexpr size_t MAC_SIZE = 33;
    static_assert(MAC_SIZE * 4 % 3 == 0, "MAC_SIZE requires padding");
    static constexpr size_t ENCODED_SIZE = MAC_SIZE * 4 / 3;

    CarafeMAC(const CarafeMACKey &k) : key(k) {}

    const std::string &compute_from_string(const std::string &in) {
        sha512_state s;
        std::array<char, CarafeMACKey::HASH_SIZE> out;

        if (in.size() > UINT32_MAX) throw std::out_of_range("Input too large");

        key.copy_keyed_state(s);

        sha_process(s, in.data(), static_cast<u32>(in.size()));
        sha_done(s, out.data());

        mac = CarafeBase64Encode(out, MAC_SIZE, CarafeBase64CharsetURLSafe);
        return mac;
    }

    const std::string &to_string() {
        if (mac.size() == 0) throw std::runtime_error("invalid CarafeMAC");
        return mac;
    }

    void from_safebase64(const std::string &in) {
        if (in.size() != (MAC_SIZE * 3 / 4)) throw std::runtime_error("Invalid CarafeMAC");
        mac = in;
    }

    bool operator==(const CarafeMAC &b) {
        return *this == b.mac;
    }

    bool operator!=(const CarafeMAC &b) {
        return !(*this == b.mac);
    }

    bool operator==(const std::string &b) {
        unsigned char t = 0;
        if (mac.size() == 0) throw std::runtime_error("invalid CarafeMACKey");
        if (mac.size() != b.size()) return false;
        for (size_t i = 0; i < mac.size(); i++) {
            t |= mac[i] ^ b[i];
        }
        return t == 0;
    }

    bool operator!=(const std::string &b) {
        return !(*this == b);
    }
};

typedef std::unordered_map<std::string, std::string> CarafeCookieMap;

class CarafeAuthenticatedCookie;
class CarafeCookie {
private:
    friend CarafeAuthenticatedCookie;
    CarafeCookieMap kv;
public:
    void load_data(std::string d) {
        std::string::size_type start = 0;
        while(start != std::string::npos && start < d.size()) {
            std::string::size_type end_pos = d.find(';', start);
            std::string::size_type eqpos = d.find('=', start);
            if (end_pos == std::string::npos) end_pos = d.size();
            if (eqpos > end_pos || eqpos == std::string::npos) {
                while (d[start] == ' ') start++;
                kv[d.substr(start, end_pos - start)] = "";
            } else {
                std::string key, val;
                while (d[start] == ' ') start++;
                key = CarafeURLSafe::decode(d.substr(start, eqpos - start));
                val = CarafeURLSafe::decode(d.substr(eqpos + 1, end_pos - eqpos - 1));
                if (key.size()) {
                    kv[key] = val;
                } else {
                    kv[val] = "";
                }
            }
            start = end_pos + 1;
        }
    }

    CarafeCookie() {}
    CarafeCookie(const std::string &d) {
        load_data(d);
    }

    CarafeCookieMap &key_value() { return kv; }
    void erase() {
        kv.erase(kv.begin(), kv.end());
    }

    std::string serialize() {
        std::string s;
        for(const auto &i : kv) {
            s += CarafeURLSafe::encode(i.first);
            s += '=';
            s += CarafeURLSafe::encode(i.second);
            s += "; ";
        }
        if (s.size()) { // trailing space
            s.pop_back();
        }
        return s;
    }
};

class CarafeAuthenticatedCookie {
private:
    const CarafeMACKey &key;
    CarafeCookie cookie;
public:
    CarafeAuthenticatedCookie(const CarafeMACKey &k) : key(k) {}
    bool load_data(const std::string &d) {
        // split data on |, compare mac of first half to second, then decode.
        auto sep = d.find('|');
        if (sep == 0 || sep == d.size() - 1 || sep == std::string::npos || d.size() - sep - 1 != CarafeMAC::ENCODED_SIZE) return false;

        std::string mac = d.substr(sep + 1, std::string::npos);
        std::string data = d.substr(0, sep);

        auto expected_mac = CarafeMAC(key);
        expected_mac.compute_from_string(data);

        if (expected_mac != mac) {
            return false;
        }

        data = CarafeBase64Decode(data, CarafeBase64CharsetURLSafe);
        cookie.load_data(data);
        return true;
    }

    CarafeCookieMap &key_value() { return cookie.kv; }
    void erase() { cookie.erase(); }

    std::string serialize() {
        if (cookie.kv.count("_carafe_ts")) {
            cookie.kv.emplace("_carafe_ts", std::to_string(std::chrono::system_clock::now().time_since_epoch().count()));
        }

        std::string s = CarafeBase64Encode(cookie.serialize(), CarafeBase64CharsetURLSafe);
        std::string mac = CarafeMAC(key).compute_from_string(s);
        return s + "|" + mac;
    }
};

// Required to let us | together the enum.
static_assert(sizeof(MHD_FLAG) == sizeof(unsigned int), "int can't hold MHD_FLAG");

inline MHD_FLAG operator|(const MHD_FLAG a, const MHD_FLAG b) {
    return static_cast<MHD_FLAG>(static_cast<unsigned int>(a) | static_cast<unsigned int>(b));
}

inline MHD_FLAG operator&(const MHD_FLAG a, const MHD_FLAG b) {
    return static_cast<MHD_FLAG>(static_cast<unsigned int>(a) & static_cast<unsigned int>(b));
}

inline MHD_FLAG operator~(const MHD_FLAG a) {
    return static_cast<MHD_FLAG>(~(static_cast<unsigned int>(a)));
}

// Methods, stored as individual bits so they can be |'d together.
enum CarafeHTTPMethods {
    UNKNOWN = 0,
    GET = 1,
    HEAD = 1 << 1,
    POST = 1 << 2,
    PUT = 1 << 3,
    DELETE = 1 << 4,
    CONNECT = 1 << 5,
    OPTIONS = 1 << 6,
    TRACE = 1 << 7,
    PATCH = 1 << 8,
    PURGE = 1 << 9
};

typedef unsigned long CarafeHTTPMethod;

inline CarafeHTTPMethods operator|(const CarafeHTTPMethods a, const CarafeHTTPMethods b) {
    return static_cast<CarafeHTTPMethods>(static_cast<int>(a) | static_cast<int>(b));
}

inline CarafeHTTPMethods operator&(const CarafeHTTPMethods a, const CarafeHTTPMethods b) {
    return static_cast<CarafeHTTPMethods>(static_cast<int>(a) & static_cast<int>(b));
}

inline CarafeHTTPMethods operator~(const CarafeHTTPMethods a) {
    return static_cast<CarafeHTTPMethods>(~(static_cast<int>(a)));
}

class CarafeHTTPD;
class CarafeRequest;
class CarafeResponse;
typedef std::unordered_map<std::string, std::string> CarafeRequestStringMap;
typedef std::function<void(CarafeRequest &, CarafeResponse &)> CarafeRouteCallback;
typedef std::function<void(CarafeRequest &, CarafeResponse &, const char *)> CarafeAccessLogCallback;
typedef std::function<void(CarafeRequest &, const char *, std::exception &)> CarafeErrorLogCallback;

class CarafeRouteCallbackInfo {
public:
    std::string route;
    std::string route_re;
    std::regex re;
    std::vector<std::string> arg_names;
    CarafeRouteCallback callback;
    CarafeHTTPMethod allowed_methods;
    CarafeRouteCallbackInfo(const std::string &r, CarafeHTTPMethod m, CarafeRouteCallback cb) : route(r), callback(cb), allowed_methods(m) {
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
};

class CarafeRequestPostData {
public:
    std::string data, filename;
    CarafeRequestStringMap headers;
    CarafeRequestPostData(const char *d, const char *f) : data(d), filename(f) {};
};

typedef std::unordered_map<std::string, CarafeRequestPostData> CarafeRequestPostDataMap;

class CarafeResponse {
public:
    int code;
    std::string body;
    CarafeRequestStringMap headers;
    CarafeCookie cookies;
    CarafeResponse() : code(500) {};
    void reset() {
        cookies.erase();
        headers.erase(headers.begin(), headers.end());
        code = 500;
    }
};

class CarafeRequestConnectionValues {
private:
    friend CarafeRequest;
    enum ValueType {
        ARGS,
        COOKIES,
        HEADERS
    };
    CarafeRequest &req;
    ValueType my_type;
    CarafeRequestStringMap all_args;
    bool all_args_populated;

    void load_all();
public:
    CarafeRequestConnectionValues(CarafeRequest &r, ValueType vt) : req(r), my_type(vt), all_args_populated(false) {}

    // This could be a string_view, but would be the only thing requiring C++17 support.
    std::string get(std::string key, std::string def = "") {
        if (!all_args_populated) load_all();
        auto f = all_args.find(key);
        if (f == all_args.end()) return def;
        return f->second;
    }

    CarafeRequestStringMap::iterator begin() {
        if (!all_args_populated) load_all();
        return all_args.begin();
    }

    CarafeRequestStringMap::iterator end() {
        if (!all_args_populated) load_all();
        return all_args.end();
    }
};

class CarafeRequest {
private:
    friend CarafeHTTPD;
    friend CarafeRequestConnectionValues;
    struct MHD_Connection *connection;
    struct MHD_PostProcessor *post_processor;
    std::string client_ip_str;

    inline static bool case_insensitive_equals(const char *a, const char *b) {
        size_t i;
        for(i = 0; a[i] != '\0' || b[i] != '\0'; i++) {
            if ((a[i] & 0x7F) != (b[i] & 0x7F)) return false;
        }
        return a[i] == b[i];
    }

public:
    std::string version, path;
    CarafeHTTPMethod method;
    CarafeRequestPostDataMap post_data;
    CarafeRequestConnectionValues args, headers;
    CarafeCookie cookies;
    CarafeRequestStringMap vars;
    size_t total_post_data_size, max_upload_size;

    CarafeRequest(struct MHD_Connection *c, const char *m, const char *v, const char *u, size_t mus) :
        connection(c),
        post_processor(nullptr),
        version(v),
        path(u),
        method(method_to_int(m)),
        args(*this, CarafeRequestConnectionValues::ARGS),
        headers(*this, CarafeRequestConnectionValues::HEADERS),
        total_post_data_size(0),
        max_upload_size(mus)
    {
        if (!connection) throw std::runtime_error("connection is null");
        if (headers.get("cookie").size()) cookies.load_data(headers.get("cookie"));
    };

    inline const std::string &client_ip() {
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

    inline static CarafeHTTPMethod method_to_int(const char *method) {
        if (case_insensitive_equals(method, "GET")) {
            return CarafeHTTPMethods::GET;
        } else if (case_insensitive_equals(method, "POST")) {
            return CarafeHTTPMethods::POST;
        } else if (case_insensitive_equals(method, "PURGE")) {
            return CarafeHTTPMethods::PURGE;
        } else if (case_insensitive_equals(method, "PUT")) {
            return CarafeHTTPMethods::PUT;
        } else if (case_insensitive_equals(method, "DELETE")) {
            return CarafeHTTPMethods::DELETE;
        } else if (case_insensitive_equals(method, "HEAD")) {
            return CarafeHTTPMethods::HEAD;
        } else if (case_insensitive_equals(method, "CONNECT")) {
            return CarafeHTTPMethods::CONNECT;
        } else if (case_insensitive_equals(method, "OPTIONS")) {
            return CarafeHTTPMethods::OPTIONS;
        } else if (case_insensitive_equals(method, "TRACE")) {
            return CarafeHTTPMethods::TRACE;
        } else if (case_insensitive_equals(method, "PATCH")) {
            return CarafeHTTPMethods::PATCH;
        }
        return CarafeHTTPMethods::UNKNOWN;
    }
};

class CarafeHTTPD {
private:
    friend CarafeRequestConnectionValues;
    uint_fast16_t listen_port;
    struct MHD_Daemon *daemon;
    struct MHD_Daemon *daemon6;
    std::vector<CarafeRouteCallbackInfo> routes;

    static int mhd_handler(void *microhttpd_ptr,
                                struct MHD_Connection *connection,
                                const char *url,
                                const char *method,
                                const char *version,
                                const char *upload_data,
                                size_t *upload_data_size,
                                void **context_data) {
        if (!microhttpd_ptr || !connection || !url || !method || !version || !upload_data_size) return MHD_NO;
        CarafeHTTPD *chd = static_cast<CarafeHTTPD *>(microhttpd_ptr);

        if (!*context_data) { // Phase 1
            CarafeRequest *request = new (std::nothrow) CarafeRequest(connection, method, version, url, chd->max_upload_size);
            if (!request) return MHD_NO;
            *context_data = request;
            return MHD_YES;
        }

        // Phase 2
        if (!*context_data) return MHD_NO;
        CarafeRequest *request = static_cast<CarafeRequest *>(*context_data);

        if (request->method == CarafeHTTPMethods::POST) {
            request->post_processor = MHD_create_post_processor(connection, 65536, &mhd_post_iterator, request);
            if (!request->post_processor) {
                delete request;
                return MHD_NO;
            }
        }

        if (request->method == CarafeHTTPMethods::POST && *upload_data_size) {
            MHD_post_process(request->post_processor, upload_data, *upload_data_size);
            *upload_data_size = 0;
            return MHD_YES;
        }

        // Phase 2 or 3 depending on if this is a POST with data or not.
        if (request->post_processor) MHD_destroy_post_processor(request->post_processor);

        CarafeResponse response;
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
            } catch (...) {
                ; // Oh well?
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

        if (response.cookies.key_value().size()) {
            MHD_add_response_header(mhd_response, MHD_HTTP_HEADER_SET_COOKIE, response.cookies.serialize().c_str());
        }

        int ret = MHD_queue_response(connection, response.code, mhd_response);
        MHD_destroy_response(mhd_response);
        delete request;
        return ret;
    }

    static int mhd_header_parse(void *map_ptr, enum MHD_ValueKind kind, const char *key, const char *value) {
        if (!map_ptr || !key) return MHD_NO;
        CarafeRequestStringMap *storage = static_cast<CarafeRequestStringMap *>(map_ptr);
        if (*key == '\0' && value && *value == '\0') return MHD_YES; // I don't know why all empty values show up but we don't want them.

        std::string key_lc = key;
        if (kind == MHD_HEADER_KIND) std::transform(key_lc.begin(), key_lc.end(), key_lc.begin(), ::tolower);
        if (value) {
            storage->emplace(key_lc, value);
        } else {
            storage->emplace(key_lc, "");
        }

        return MHD_YES;
    }

    static int mhd_post_iterator(void *microhttpd_req_ptr,
                                 enum MHD_ValueKind kind,
                                 const char *key,
                                 const char *filename,
                                 const char *content_type,
                                 const char *transfer_encoding,
                                 const char *data,
                                 uint64_t off,
                                 size_t size) {
        if (kind != MHD_POSTDATA_KIND || !microhttpd_req_ptr || !key) return MHD_NO;
        CarafeRequest *request = static_cast<CarafeRequest *>(microhttpd_req_ptr);

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

    inline void sort_routes() {
        struct {
            bool operator()(CarafeRouteCallbackInfo &a, CarafeRouteCallbackInfo &b) const {
                return a.route_re.size() < b.route_re.size();
            }
        } sorter;
        std::sort(routes.begin(), routes.end(), sorter);
    }

public:
    size_t max_upload_size;
    volatile bool keep_running;
    CarafeAccessLogCallback access_log_callback;
    CarafeErrorLogCallback error_log_callback;
    unsigned int timeout, thread_pool_size;
    bool dual_stack;
    bool debug;

    CarafeHTTPD(uint_fast16_t p) :
        listen_port(p),
        daemon(nullptr),
        daemon6(nullptr),
        max_upload_size(10*1024*1024), // 10 megs, arbitrary
        keep_running(true),
        timeout(60),
        thread_pool_size(1),
        dual_stack(true),
        debug(false)
    {};

    ~CarafeHTTPD() noexcept {
        MHD_stop_daemon(daemon);
        if (dual_stack) MHD_stop_daemon(daemon6);
    }

    inline void run() {
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

    inline void run_forever() {
        run();
        while (keep_running) {
            sleep(1);
        }
    }

    static inline std::string generate_access_log(CarafeRequest &request, CarafeResponse &response, const char *method) {
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

    inline void add_route(const char *route, const CarafeHTTPMethod methods, const CarafeRouteCallback &callback) {
        CarafeRouteCallbackInfo ci(route, methods, callback);
        routes.emplace_back(std::move(ci));
    }

    inline void add_route(const std::string &route, const CarafeHTTPMethod methods, const CarafeRouteCallback &callback) {
        add_route(route.c_str(), methods, callback);
    }

    inline void handle_route(CarafeRequest &request, CarafeResponse &response, const char *method) {
        std::smatch arg_matches;
        CarafeHTTPMethod method_int = CarafeRequest::method_to_int(method);
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
};

inline void CarafeRequestConnectionValues::load_all() {
    if (all_args_populated) return;
    switch (my_type) {
        case ARGS:
            MHD_get_connection_values(req.connection, MHD_GET_ARGUMENT_KIND, CarafeHTTPD::mhd_header_parse, &all_args);
            MHD_get_connection_values(req.connection, MHD_POSTDATA_KIND, CarafeHTTPD::mhd_header_parse, &all_args);
            break;

        case HEADERS:
            MHD_get_connection_values(req.connection, MHD_HEADER_KIND, CarafeHTTPD::mhd_header_parse, &all_args);
            break;

        case COOKIES:
            MHD_get_connection_values(req.connection, MHD_COOKIE_KIND, CarafeHTTPD::mhd_header_parse, &all_args);
            break;

        default:
            throw std::logic_error("unknown kind");
    }
    all_args_populated = true;
}

#endif /* carafe_hpp */