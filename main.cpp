#include <iostream>

#include <microhttpd.h>

#include "src/carafe.hpp"

Carafe::CookieKeyManager cm;

void hello(Carafe::Request &request, Carafe::Response &response) {
    response.code = 200;
    response.headers["Content-type"] = "text/html";
    response.body = "<body><h1>Hello world!</h1></body>\n";
}

void headers(Carafe::Request &request, Carafe::Response &response) {
    response.code = 200;
    response.body = "Headers:\n";

    for(auto i : request.headers) {
        response.body += i.first + "=" + i.second + "\n";
    }

    response.body += "\nCookies: " + request.cookies.kv()["regular_cookies"] + "\n";

    if (request.cookies.kv().count("authenticated_cookies")) {
        response.body += "\nAuthenticated cookie:" + request.cookies.kv().at("authenticated_cookies") + "\n";
        Carafe::AuthenticatedCookies auth(cm, std::chrono::hours(24 * 7));
        auth.load_data(request.cookies.kv().at("authenticated_cookies"));
        if (!auth.authenticated()) {
            response.body += "\nAuthenticated cookie contents not valid!\n";
            return;
        }
        for(auto i : auth.kv()) { // key_value will be empty if !authenticated().
            response.body += i.first + "=" + i.second + "\n";
        }
    }
}

void var(Carafe::Request &request, Carafe::Response &response) {
    response.body = request.vars["var"];
    response.code = 200;

    Carafe::AuthenticatedCookies auth(cm);
    auth.kv().emplace("authenticated_key", "authenticated_value");
    response.cookies.kv().emplace("authenticated_cookies", auth.serialize());
    response.cookies.kv().emplace("regular_cookies", "yum");
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
    httpd.add_route("/", Carafe::HTTPMethods::GET | Carafe::HTTPMethods::HEAD, hello);
    httpd.add_route("/headers", Carafe::HTTPMethods::GET | Carafe::HTTPMethods::HEAD, headers);
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
