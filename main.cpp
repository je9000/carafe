#include <iostream>

#include <microhttpd.h>

#include "src/carafe.hpp"

#ifdef CARAFE_AUTHENTICATED_COOKIES
Carafe::CookieKeyManager cm;
Carafe::SecureKey mac_key;
#endif

void test(Carafe::Request &request, Carafe::Response &response) {
    response.code = 200;
    response.body = "Headers:\n";

    for(auto i : request.headers) {
        response.body += i.first + "=" + i.second + "\n";
    }

    response.body += "\nCookies: " + request.cookies.key_value()["regular_cookies"] + "\n";

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
