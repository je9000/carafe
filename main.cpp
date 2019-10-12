#include <iostream>

#include <microhttpd.h>

#include "src/carafe.hpp"

#ifdef CARAFE_AUTHENTICATED_COOKIES
Carafe::CookieKeyManager cm;
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
        Carafe::AuthenticatedCookies auth(cm, std::chrono::duration_cast<std::chrono::seconds>(std::chrono::hours(24 * 7)));
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
    Carafe::AuthenticatedCookies auth(cm);
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

    if (Carafe::Hex::encode(Carafe::Sha512::compute("abc", 3), Carafe::Hex::Lower) != "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f") {
        throw std::runtime_error("hex(sha512(abc)) test failed");
    }

    if (Carafe::Hex::encode(Carafe::Sha512::compute("", 0), Carafe::Hex::Lower) != "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e") {
        throw std::runtime_error("hex(sha512()) test failed");
    }

    std::string longsha(1000000, 'a');
    if (Carafe::Hex::encode(Carafe::Sha512::compute(longsha), Carafe::Hex::Lower) != "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b") {
        throw std::runtime_error("hex(sha512(longsha)) test failed");
    }

#ifdef CARAFE_AUTHENTICATED_COOKIES
    Carafe::CookieKeyManager ck("heres a long key");
    // Inner authenticated cookie
    Carafe::AuthenticatedCookies c(ck);
    c.key_value().emplace("authenticatedkey1", "authenticatedval1");
    c.key_value().emplace("authenticatedkey2", "authenticatedval2");

    // Cookie in response object
    auto c2 = Carafe::Cookies();
    c2.load_data("Test=test_value; expires=Sat, 01-Jan-2000 00:00:00 GMT; path=/; HTTPOnly; =value");
    c2.key_value().emplace("auth", c.serialize());

    // Cookie in request object
    auto c3 = Carafe::Cookies();
    c3.load_data(c2.serialize());

    // Innter authenticated cookie
    Carafe::AuthenticatedCookies c4(ck);
    if (!c2.key_value().count("auth")) throw std::runtime_error("Couldn't extract authenticated cookies!");
    // If we didn't explicitely check above, could throw if "auth", the authenticated sub-cookie, isn't found.
    c4.load_data(c2.key_value().at("auth"));
    if (!c4.authenticated()) throw std::runtime_error("Authenticated cookie did not authenticate!");
    if (c4.key_value()["authenticatedkey2"] != "authenticatedval2") throw std::runtime_error("Authenticated cookie value incorrect!");
#endif

    Carafe::HTTPD httpd(port);
    httpd.debug = true;
    httpd.add_route("/test", Carafe::HTTPMethods::GET | Carafe::HTTPMethods::HEAD, test);
    httpd.add_route("/var/<var>", Carafe::HTTPMethods::GET, var);
    httpd.add_route("/post", Carafe::HTTPMethods::POST, post);

    httpd.access_log_callback= [](Carafe::Request &request, Carafe::Response &response, const char *method) {
        std::cout << Carafe::HTTPD::generate_access_log(request, response, method) << "\n";
    };

    httpd.error_log_callback = [](Carafe::Request &request, const char *method, const std::exception &e) {
        std::cerr << "Exception: " << e.what() << "\n";
    };

    std::clog << "Listening on " << port << "\n";
    httpd.run_forever();

    return 0;
}
