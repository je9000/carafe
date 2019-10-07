#include <iostream>

#include <microhttpd.h>

#include "carafe.hpp"

#ifdef CARAFE_AUTHENTICATED_COOKIES
Carafe::AuthenticatedKeyManager cm;
Carafe::SecureKey mac_key("here's an example key, the real key should be more complex!");
#endif

void test(Carafe::Request &request, Carafe::Response &response) {
    response.code = 200;
    response.body = "Headers:\n";

    for(auto i : request.headers) {
        response.body += i.first + "=" + i.second + "\n";
    }

    response.body += "\nRegular cookie:" + request.cookies.key_value()["regular_cookies"] + "\n";

#ifdef CARAFE_AUTHENTICATED_COOKIES
    if (!request.cookies.key_value().count("authenticated_cookies")) {
        response.body += "\nAuthenticated cookie not found!\n";
    } else {
        response.body += "\nAuthenticated cookie:" + request.cookies.key_value().at("authenticated_cookies") + "\n";
        auto auth = Carafe::AuthenticatedCookies(cm);
        auth.load_data(request.cookies.key_value().at("authenticated_cookies"));
        if (!auth.authenticated()) {
            response.body += "\nAuthenticated cookie contents not valid!\n";
            return;
        }
        for(auto i : auth.key_value()) { // key_value will be empty if !authenticated().
            response.body += i.first + "=" + i.second + "\n";
        }
    }
#endif
}

void var(Carafe::Request &request, Carafe::Response &response) {
    response.body = request.vars["var"];
    response.code = 200;

#ifdef CARAFE_AUTHENTICATED_COOKIES
    auto auth = Carafe::AuthenticatedCookies(cm);
    auth.key_value().emplace("authenticated_key", "authenticated_value");
    response.cookies.key_value().emplace("authenticated_cookies", auth.serialize());
#endif

    response.cookies.key_value().emplace("regular_cookies", "yum");
}

void post(Carafe::Request &request, Carafe::Response &response) {
    for(const auto &p : request.post_data) {
        response.body += p.first + "=" + p.second.data + "\n";
    }
    response.code = 200;
}

int main(int argc, char **argv) {
    long port = 8080;
    if (argc > 1) port = strtol(argv[1], NULL, 10);

#ifdef CARAFE_AUTHENTICATED_COOKIES
    Carafe::CookieKeyManager ck("heres a long key");
    // Inner authenticated cookie
    auto c = Carafe::AuthenticatedCookies(ck);
    c.key_value().emplace("securekey1", "secureval1");
    c.key_value().emplace("securekey2", "secureval2");

    // Cookie in response object
    auto c2 = Carafe::Cookies();
    c2.load_data("Test=test_value; expires=Sat, 01-Jan-2000 00:00:00 GMT; path=/; HTTPOnly; =value");
    c2.key_value().emplace("auth", c.serialize());

    // Cookie in request object
    auto c3 = Carafe::Cookies();
    c3.load_data(c2.serialize());

    // Innter authenticated cookie
    auto c4 = Carafe::AuthenticatedCookies(ck);
    if (!c2.key_value().count("auth")) throw std::runtime_error("Couldn't extract secure cookies!");
    // If we didn't explicitely check above, could throw if "auth", the secure cookie, isn't found.
    c4.load_data(c2.key_value().at("auth"));
    if (!c4.authenticated()) throw std::runtime_error("Securec cookie did not authenticate!");
    if (c4.key_value()["securekey2"] != "secureval2") throw std::runtime_error("Secure ccookie value incorrect!");
#endif

    Carafe::HTTPD httpd(port);
    httpd.debug = true;
    httpd.add_route("/test", Carafe::HTTPMethods::GET | Carafe::HTTPMethods::HEAD, test);
    httpd.add_route("/var/<var>", Carafe::HTTPMethods::GET, var);
    httpd.add_route("/post", Carafe::HTTPMethods::POST, post);

    httpd.access_log_callback= [](Carafe::Request &request, Carafe::Response &response, const char *method) {
        std::cout << Carafe::HTTPD::generate_access_log(request, response, method) << "\n";
    };

    httpd.error_log_callback = [](Carafe::Request &request, const char *method, const std::exception e) {
        std::cerr << "Exception: " << e.what() << "\n";
    };

    std::clog << "Listening on " << port << "\n";
    httpd.run_forever();

    return 0;
}
