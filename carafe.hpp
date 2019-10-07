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

#ifdef CARAFE_AUTHENTICATED_COOKIES
#include <atomic>
#endif

#include <microhttpd.h>

namespace Carafe {

// For the public domain SHA512 implementation
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
static const size_t SHA512_OUTPUT_SIZE = 64; // 512/8

// end

class Sha512 {
public:
    template <typename T>
    static std::string calculate(const T &);

    static std::string calculate(const char *, size_t);
};

#ifndef LITTLEENDIAN
#error "Base64 routines only support little-endian architectures"
#endif

class Base64 {
public:
    typedef struct {
        std::array<char, 65> encodeLookup;
        char padCharacter;
    } Base64Charset;

    // Note, we use | internally as a separator for authenticated cookies, so don't
    // add it to any of these character sets!
    static const Base64Charset CharsetStandard __attribute__((unused));

    // Matches the "standard" web-safe base64 character set.
    static const Base64Charset CharsetURLSafe;

    template <typename T>
    static std::string encode(const T &, const size_t, const Base64Charset & = CharsetURLSafe);
    template <typename T>
    static std::string encode(const T &, const Base64Charset & = CharsetURLSafe);
    template <typename T>
    static std::string decode(const T &, const size_t, const Base64Charset & = CharsetURLSafe);
    template <typename T>
    static std::string decode(const T &, const Base64Charset & = CharsetURLSafe);
};

class URLSafe {
public:
    static std::string encode(const char *);
    static std::string encode(const std::string &);

    static std::string decode(const char *);
    static std::string decode(const std::string &);
};

class Hex {
public:
    static std::string encode(const std::string &);
    static std::string encode(const char *);
    static std::string encode(const char *, size_t);
    static std::string decode(const std::string &);
    static std::string decode(const char *);
    static std::string decode(const char *, size_t);
};

typedef std::unordered_map<std::string, std::string> CookieMap;

class CookiesBase {
protected:
    bool flag_secure = false;
    bool flag_httponly = false;
    CookieMap kv;
private:
    static bool case_insensitive_equals(const std::string &, const char *);
public:
    void load_data(const std::string &);

    CookiesBase();
    CookiesBase(const std::string &);

    CookieMap &key_value();
    void erase();

    std::string serialize();
};

class Random {
private:
#if defined(_MSC_VER)
    static std::random_device rd;
    static const size_t chunk_size = sizeof(decltype(rd()));
#endif
public:
    static void fill(char *, size_t);

    template <typename T>
    static void fill(T);

    static std::string get(size_t = 16);

    static std::string get_base64(size_t = 16);

    // uuid v4
    static std::string uuid();
};

#ifdef CARAFE_AUTHENTICATED_COOKIES
// Holder (and possibly generator) of the MAC Key.
// Pre-computes the hash of the key, so subsequent hashes are all already keyed.
class SecureKey {
private:
    static constexpr size_t DEFAULT_KEY_SIZE = 24; // Arbitrary
    sha512_state precomputed_key_state;

    void precompute_state(const char *, const size_t);
public:
    void rekey(const std::string &);

    void rekey(void);

    SecureKey();

    SecureKey(const std::string &);

    void get_keyed_state(sha512_state &) const;
};

// Class that represents the MAC on a string. Performs a secure MAC string
// comparison.
class AuthenticatedCookieAuthenticator {
private:
    std::string mac; // MAC stored in url-safe base64 encoding.
    const SecureKey &key;
public:
    // SHA512/264, so there are no base64 padding characters.
    static constexpr size_t MAC_SIZE = 33;
    static_assert((MAC_SIZE * 4) % 3 == 0, "MAC_SIZE requires padding");
    static constexpr size_t ENCODED_SIZE = (MAC_SIZE * 4) / 3;

    AuthenticatedCookieAuthenticator(const SecureKey &);

    const std::string &compute_from_string(const std::string &);

    const std::string &to_string() const;

    void load_from_safebase64(const std::string &);

    bool operator==(const AuthenticatedCookieAuthenticator &) const;

    bool operator!=(const AuthenticatedCookieAuthenticator &) const;

    bool safe_equals(const std::string &) const;
};

typedef uint64_t CookieKeyManagerID;
typedef struct {
    SecureKey key;
    std::chrono::time_point<std::chrono::system_clock> ts;
} CookieSecreKeyAndTime;

class CookieKeyManager {
private:
    SecureKey encrypt_key;
    std::unordered_map<CookieKeyManagerID, CookieSecreKeyAndTime> decrypt_keys;
    class Spinlock { // Only to be used with lock_guard.
        std::atomic_flag flag = ATOMIC_FLAG_INIT;
    public:
        void lock();
        void unlock();
    };

    mutable Spinlock encrypt_key_lock, decrypt_key_lock;

    CookieKeyManagerID add_decrypt_key_no_lock(const SecureKey &);
public:
    CookieKeyManager();
    CookieKeyManager(const std::string &key) : encrypt_key(key);

    // Don't want to copy the Spinlock, so just disable all copies. Shouldn't
    // be necessary anyway.
    CookieKeyManager(const CookieKeyManager &) = delete;

    CookieKeyManagerID add_decrypt_key(const SecureKey &);

    bool remove_decrypt_key(const CookieKeyManagerID);

    bool has_decrypt_key(const CookieKeyManagerID) const;

    size_t decrypt_key_count() const;

    void expire_old_decrypt_keys(const std::chrono::seconds);

    SecureKey get_encrypt_key() const;

    CookieKeyManagerID set_encrypt_key(const std::string &);
    CookieKeyManagerID generate_new_encrypt_key();

    AuthenticatedCookieAuthenticator compute(const std::string &) const;

    bool check_valid(const std::string &, const std::string &) const;
};

class AuthenticatedCookies : private CookiesBase {
private:
    const CookieKeyManager &cookie_keys;
    bool auth_valid = false;
    const std::chrono::seconds max_age;
public:
    static const std::string TIMESTAMP_KEY;
    AuthenticatedCookies(const CookieKeyManager &, const std::chrono::seconds);
    AuthenticatedCookies(const CookieKeyManager &, const std::string &, const std::chrono::seconds);
    bool load_data(const std::string &);

    CookieMap &key_value();
    void erase();
    bool authenticated();

    std::string serialize();
};
#endif // CARAFE_AUTHENTICATED_COOKIES

class Cookies : public CookiesBase {};

// Methods, stored as individual bits so they can be |'d together.
enum HTTPMethods {
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

typedef unsigned long HTTPMethod;

class HTTPD;
class Request;
class Response;
typedef std::unordered_map<std::string, std::string> RequestStringMap;
typedef std::function<void(Request &, Response &)> RouteCallback;
typedef std::function<void(Request &, Response &, const char *)> AccessLogCallback;
typedef std::function<void(Request &, const char *, const std::exception &)> ErrorLogCallback;

class RouteCallbackInfo {
public:
    std::string route;
    std::string route_re;
    std::regex re;
    std::vector<std::string> arg_names;
    RouteCallback callback;
    HTTPMethod allowed_methods;
    RouteCallbackInfo(const std::string &, HTTPMethod, RouteCallback);
};

class RequestPostData {
public:
    std::string data, filename;
    RequestStringMap headers;
    RequestPostData(const char *, const char *);
};

typedef std::unordered_map<std::string, RequestPostData> RequestPostDataMap;

class Response {
public:
    int code;
    std::string body;
    RequestStringMap headers;
    Cookies cookies;
    Response();
    void reset();
};

class RequestConnectionValues {
private:
    friend Request;
    friend HTTPD;
    enum ValueType {
        ARGS,
        COOKIES,
        HEADERS
    };
    Request &req;
    ValueType my_type;
    RequestStringMap all_args;
    size_t &current_size, max_size;
    bool all_args_populated;
    const std::string no_value;

    void load_all();
public:
    RequestConnectionValues(Request &, ValueType, size_t, size_t &);

    const std::string &get(const std::string &);

    RequestStringMap::iterator begin();

    RequestStringMap::iterator end();
};

class Request {
private:
    friend HTTPD;
    friend RequestConnectionValues;
    struct MHD_Connection *connection;
    struct MHD_PostProcessor *post_processor;
    std::string client_ip_str;

    static bool case_insensitive_equals(const char *, const char *);

public:
    size_t total_post_data_size, max_upload_size;
    size_t total_header_size, max_header_size;
    std::string version, path;
    HTTPMethod method;
    RequestPostDataMap post_data;
    RequestConnectionValues args, headers;
    CarafeCookies cookies;
    CarafeRequestStringMap vars;
    void *context;

    size_t current_arg_size = 0;

    CarafeRequest(struct MHD_Connection *, const char *, const char *, const char *, size_t, size_t, void *);

    const std::string &client_ip();

    inline static CarafeHTTPMethod method_to_int(const char *);
};

class HTTPD {
private:
    friend RequestConnectionValues;
    uint_fast16_t listen_port;
    struct MHD_Daemon *daemon;
    struct MHD_Daemon *daemon6;
    std::vector<CarafeRouteCallbackInfo> routes;

    static int mhd_handler(void *,
                           struct MHD_Connection *,
                           const char *,
                           const char *,
                           const char *,
                           const char *,
                           size_t *,
                           void **);

    static int mhd_header_parse(void *, enum MHD_ValueKind, const char *, const char *);

    static int mhd_post_iterator(void *,
                                 enum MHD_ValueKind ,
                                 const char *,
                                 const char *,
                                 const char *,
                                 const char *,
                                 const char *,
                                 uint64_t,
                                 size_t);

    void sort_routes();

public:
    size_t max_upload_size, max_header_size;
    bool keep_running;
    CarafeAccessLogCallback access_log_callback;
    CarafeErrorLogCallback error_log_callback;
    unsigned int timeout, thread_pool_size;
    bool dual_stack;
    bool debug;
    void *context;

    CarafeHTTPD(uint_fast16_t p);
    ~CarafeHTTPD() noexcept;

    void run();

    void run_forever();

    static std::string generate_access_log(CarafeRequest &, CarafeResponse &, const char *);

    void add_route(const char *, const CarafeHTTPMethod, const CarafeRouteCallback &);
    void add_route(const std::string &, const CarafeHTTPMethod, const CarafeRouteCallback &);

    void handle_route(CarafeRequest &, CarafeResponse &, const char *);
};

};

#endif /* carafe_hpp */
