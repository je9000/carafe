#include <iostream>

#include <microhttpd.h>

#include "carafe.hpp"

CarafeMACKey mac_key("here's an example key, the real key should be more complex!");

void test(CarafeRequest &request, CarafeResponse &response) {
    response.code = 200;
    response.body = "Headers:\n";
    for( auto i : request.headers ) {
        response.body += i.first + "=" + i.second + "\n";
    }

    response.body += "\nSecure cookie:" + request.cookies.key_value()["bananas"] + "\n";
    auto auth = CarafeAuthenticatedCookie(mac_key);
    auth.load_data(request.cookies.key_value()["bananas"]);
    for( auto i : auth.key_value() ) {
        response.body += i.first + "=" + i.second + "\n";
    }
}

void var(CarafeRequest &request, CarafeResponse &response) {
    response.body = request.vars["var"];
    response.code = 200;

    auto auth = CarafeAuthenticatedCookie(mac_key);
    auth.key_value().emplace("secure", "value");

    response.cookies.key_value().emplace("bananas", auth.serialize());
}

void post(CarafeRequest &request, CarafeResponse &response) {
    for(const auto &p : request.post_data) {
        response.body += p.first + "=" + p.second.data + "\n";
    }
    response.code = 200;
}

int main(int argc, char **argv) {
    long port = 8080;
    if (argc > 1) port = strtol(argv[1], NULL, 10);

    CarafeHTTPD httpd(port);
    httpd.debug = true;
    httpd.add_route("/test", CarafeHTTPMethods::GET | CarafeHTTPMethods::HEAD, test);
    httpd.add_route("/var/<var>", CarafeHTTPMethods::GET, var);
    httpd.add_route("/post", CarafeHTTPMethods::POST, post);

    httpd.access_log_callback= [](CarafeRequest &request, CarafeResponse &response, const char *method) {
        std::cout << CarafeHTTPD::generate_access_log(request, response, method) << "\n";
    };

    httpd.error_log_callback = [](CarafeRequest &request, const char *method, const std::exception e) {
        std::cerr << "Exception: " << e.what() << "\n";
    };

    std::clog << "Listening on " << port << "\n";
    httpd.run_forever();
    return 0;
}
