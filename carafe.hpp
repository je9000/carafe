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

#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include <microhttpd.h>

// TODO logging

// Required to let us | together the enum.
inline MHD_FLAG operator|(const MHD_FLAG a, const MHD_FLAG b) {
    static_assert(sizeof(MHD_FLAG) == sizeof(int), "int can't hold MHD_FLAG");
    return static_cast<MHD_FLAG>(static_cast<int>(a) | static_cast<int>(b));
}

inline MHD_FLAG operator&(const MHD_FLAG a, const MHD_FLAG b) {
    return static_cast<MHD_FLAG>(static_cast<int>(a) & static_cast<int>(b));
}

inline MHD_FLAG operator~(const MHD_FLAG a) {
    return static_cast<MHD_FLAG>(~(static_cast<int>(a)));
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
    PATCH = 1 << 8
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
    CarafeRequestStringMap headers, cookies;
    CarafeResponse() : code(500) {};
    void reset() {
        cookies.erase(cookies.begin(), cookies.end());
        headers.erase(headers.begin(), headers.end());
        code = 500;
    }
};

class CarafeRequestConnectionValues {
private:
    friend CarafeRequest;
    enum ValueType {
        ARGS,
        COOKIES
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
        return get(key.c_str(), def.c_str());
    }
    std::string get(const char *key, const char *def = nullptr);

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
    CarafeRequestConnectionValues args, cookies;
    CarafeRequestStringMap vars;
    size_t total_post_data_size, max_upload_size;

    CarafeRequest(struct MHD_Connection *c, const char *m, const char *v, const char *u, size_t mus) :
        connection(c),
        post_processor(nullptr),
        version(v),
        path(u),
        method(method_to_int(m)),
        args(*this, CarafeRequestConnectionValues::ARGS),
        cookies(*this, CarafeRequestConnectionValues::COOKIES),
        total_post_data_size(0),
        max_upload_size(mus) {
        if (!connection) throw std::runtime_error("connection is null");
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

        if (response.cookies.size()) {
            size_t count = response.cookies.size();
            size_t processed = 0;
            std::string final_cookie;
            for(const auto &h : response.cookies) {
                final_cookie += h.first;
                final_cookie += '=';
                final_cookie += h.second;
                if (processed++ <= count) {
                    final_cookie += ';';
                    final_cookie += ' ';
                }
            }
            MHD_set_connection_value(connection, MHD_HEADER_KIND, MHD_HTTP_HEADER_SET_COOKIE, final_cookie.c_str());
        }

        int ret = MHD_queue_response(connection, response.code, mhd_response);
        MHD_destroy_response(mhd_response);
        delete request;
        return ret;
    }

    static int mhd_header_parse(void *map_ptr, enum MHD_ValueKind kind, const char *key, const char *value) {
        if (!map_ptr || !key) return MHD_NO;
        CarafeRequestStringMap *storage = static_cast<CarafeRequestStringMap *>(map_ptr);

        if (value) {
            storage->emplace(key, value);
        } else {
            storage->emplace(key, "");
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

inline std::string CarafeRequestConnectionValues::get(const char *key, const char *def) {
    const char *val;
    switch (my_type) {
        case ARGS:
            val = MHD_lookup_connection_value(req.connection, MHD_GET_ARGUMENT_KIND, key);
            if (val) return std::string(val);

            val = MHD_lookup_connection_value(req.connection, MHD_POSTDATA_KIND, key);
            if (val) return std::string(val);
            break;

        case COOKIES:
            val = MHD_lookup_connection_value(req.connection, MHD_COOKIE_KIND, key);
            if (val) return std::string(val);

        default:
            break;
    }

    if (def) return std::string(def);
    throw std::out_of_range("key not found");
}

inline void CarafeRequestConnectionValues::load_all() {
    if (all_args_populated) return;
    switch (my_type) {
        case ARGS:
            MHD_get_connection_values(req.connection, MHD_HEADER_KIND, CarafeHTTPD::mhd_header_parse, &all_args);
            MHD_get_connection_values(req.connection, MHD_POSTDATA_KIND, CarafeHTTPD::mhd_header_parse, &all_args);
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
