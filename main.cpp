#include <iostream>

#include <microhttpd.h>

#include "carafe.hpp"

void test(CarafeRequest &request, CarafeResponse &response) {
    response.body = request.path;
    response.code = 200;
}

void var(CarafeRequest &request, CarafeResponse &response) {
    response.body = request.vars["var"];
    response.code = 200;
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
    httpd.add_route("/hello", CarafeHTTPMethods::GET | CarafeHTTPMethods::HEAD, test);
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
