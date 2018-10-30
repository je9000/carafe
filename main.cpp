#include <iostream>

#include <microhttpd.h>

#include "carafe.hpp"

CarafeMACKey mac_key("here's an example key, the real key should be more complex!");

void test(CarafeRequest &request, CarafeResponse &response) {
    response.code = 200;
    response.body = "Headers:\n";

#ifdef ECHO_COOKIES
    for( auto i : request.headers ) {
        response.body += i.first + "=" + i.second + "\n";
    }

    response.body += "\nSecure cookie:" + request.cookies.key_value()["bananas"] + "\n";
    auto auth = CarafeAuthenticatedCookie(mac_key);
    if !(auth.load_data(request.cookies.key_value()["bananas"])) {
        response.code = 500;
        response.body = "Invalid cookie";
        return;
    }
    for( auto i : auth.key_value() ) {
        response.body += i.first + "=" + i.second + "\n";
    }
#endif
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

#ifdef TEST_COOKIES
    auto ck = CarafeMACKey("heres a long key");
    // Inner authenticated cookie
    auto c = CarafeAuthenticatedCookie(ck);
    c.key_value().emplace("key1", "val1");
    c.key_value().emplace("key4", "val4");

    // Cookie in response object
    auto c2 = CarafeCookie();
    c2.load_data("Test=test_value; expires=Sat, 01-Jan-2000 00:00:00 GMT; path=/; HTTPOnly; =value");
    c2.key_value().emplace("auth", c.serialize());

    // Cookie in request object
    auto c3 = CarafeCookie();
    c3.load_data(c2.serialize());

    // Innter authenticated cookie
    auto c4 = CarafeAuthenticatedCookie(ck);
    if (!c4.load_data(c2.key_value().at("auth"))) throw std::runtime_error("Cookie doesn't authenticate!");
    if (c4.key_value()["key4"] != "val4") throw std::runtime_error("Cookie value incorrect!");
#endif

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
