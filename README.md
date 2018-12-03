# Carafe

Basic web framework for C++11 based on Python Flask and libmicrohttpd

# Description

Carafe is a basic web framework designed after Python's Flask targeting C++11
and above. Carafe uses libmicrohttpd for all socket handling and HTTP parsing,
and gives developers a simple API for developing web applications.

Carafe will parse create sockets, parse and emit HTTP, handle routes and
variables (both GET and POST), and set and parse (optionally authenticated)
cookies. IPv4 and IPv6 are both supported but TLS isn't yet implemented. It's
recommended Carafe apps be run internally only or placed behind a reverse
proxy with access to the internet.

Carafe is designed to be easy to use more than it is designed to be fast.
Carafe is implemented in a single header file with no dependencies other than
libmicrohttpd, standard C and C++11 libraries, and POSIX arpa/inet.h. Care was
taken to avoid manual memory management (though memcpy is used in two places)
and to use the standard library whenever possible.

# Examples

## Simple example

```
#include <iostream>
#include "carafe.hpp"

void var(CarafeRequest &request, CarafeResponse &response) {
    response.body = request.vars["var"];
    response.code = 200;
}

int main(int argc, char **argv) {
    long port = 8080;
    CarafeHTTPD httpd(port);
    httpd.add_route("/var/<var>", CarafeHTTPMethods::GET, var);

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
```

## Other examples

See main.cpp for more examples.

# License

Carafe is licensed under the MIT license. Carafe applications can be
dynamically linked against libmicrohttpd (which is licensed under the GNU LGPL
v2.1 or any later version, but don't take my word for it and read the license
yourself).

