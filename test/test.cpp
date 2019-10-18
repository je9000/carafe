#define CATCH_CONFIG_MAIN
#include "catch.hpp"

#include <string.h>

#include "carafe.hpp"

TEST_CASE("hex encode and decode", "[hex]") {
    std::array<unsigned char, 2> c = { 0, 254 };
    REQUIRE(Carafe::Hex::encode(reinterpret_cast<char *>(c.data()), c.size()) == "00fe");

    REQUIRE(Carafe::Hex::encode("abcd") == "61626364");

    REQUIRE(Carafe::Hex::encode("010102020303") == Carafe::Hex::encode("010102020303"));

    std::string s;
    s += '\0';
    s += 'f';
    s += (char)255;
    REQUIRE(Carafe::Hex::decode("0066FF") == s);

    std::string chars("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()-=_+");
    REQUIRE(Carafe::Hex::decode(Carafe::Hex::encode(chars)) == chars);

    REQUIRE_THROWS(Carafe::Hex::decode("not valid hex"));
}

TEST_CASE("sha512 and hex", "[sha]") {
    REQUIRE(Carafe::Hex::encode(Carafe::Sha512::compute("abc", 3), Carafe::Hex::Lower) ==
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
     );

    REQUIRE(Carafe::Hex::encode(Carafe::Sha512::compute("", 0), Carafe::Hex::Lower) ==
             "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    );

    std::string s("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
    REQUIRE(Carafe::Hex::encode(Carafe::Sha512::compute(s), Carafe::Hex::Lower) ==
            "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445"
    );


    s = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    REQUIRE(Carafe::Hex::encode(Carafe::Sha512::compute(s), Carafe::Hex::Lower) ==
            "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"
    );

    std::string longsha(1000000, 'a');
    REQUIRE(Carafe::Hex::encode(Carafe::Sha512::compute(longsha), Carafe::Hex::Lower) ==
            "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b"
    );
}

TEST_CASE("base64", "[base64]") {
    std::string s("hello world!");
    std::string b1 = Carafe::Base64::encode(s);

    REQUIRE(b1 == "aGVsbG8gd29ybGQh");
    REQUIRE(Carafe::Base64::decode(b1) == s);

    s = "really long string whats up! really long string whats up! really long string whats up! really long string whats up! really long string whats up!!";
    b1 = Carafe::Base64::encode(s, Carafe::Base64::CharsetStandard);
    REQUIRE(b1 == "cmVhbGx5IGxvbmcgc3RyaW5nIHdoYXRzIHVwISByZWFsbHkgbG9uZyBzdHJpbmcgd2hhdHMgdXAhIHJlYWxseSBsb25nIHN0cmluZyB3aGF0cyB1cCEgcmVhbGx5IGxvbmcgc3RyaW5nIHdoYXRzIHVwISByZWFsbHkgbG9uZyBzdHJpbmcgd2hhdHMgdXAhIQ==");
    REQUIRE(Carafe::Base64::decode(b1, Carafe::Base64::CharsetStandard) == s);
    b1 = Carafe::Base64::encode(s, Carafe::Base64::CharsetURLSafe);
    REQUIRE(b1 == "cmVhbGx5IGxvbmcgc3RyaW5nIHdoYXRzIHVwISByZWFsbHkgbG9uZyBzdHJpbmcgd2hhdHMgdXAhIHJlYWxseSBsb25nIHN0cmluZyB3aGF0cyB1cCEgcmVhbGx5IGxvbmcgc3RyaW5nIHdoYXRzIHVwISByZWFsbHkgbG9uZyBzdHJpbmcgd2hhdHMgdXAhIQ..");
    REQUIRE(Carafe::Base64::decode(b1, Carafe::Base64::CharsetURLSafe) == s);

    s = std::string("some\0null", 9);
    b1 = Carafe::Base64::encode(s);
    REQUIRE(b1 == "c29tZQBudWxs");
    REQUIRE(Carafe::Base64::decode(b1) == s);

    REQUIRE_THROWS(Carafe::Base64::decode(std::string("not valid base64!!")));
    REQUIRE_THROWS(Carafe::Base64::decode(std::string("garbage..padding")));
}

TEST_CASE("random", "[random]") {
    std::string r1 = Carafe::Random::get();
    std::string r2 = Carafe::Random::get();
    std::string r3 = Carafe::Random::get(500);
    REQUIRE(r1.size() != 0);
    REQUIRE(r2.size() != 0);
    REQUIRE(r3.size() == 500);
    REQUIRE(r1 != r2);

    std::string b1 = Carafe::Random::get_base64(12);
    std::string b2 = Carafe::Random::get_base64(12);
    std::string b3 = Carafe::Random::get_base64(29, Carafe::Base64::CharsetStandard);
    REQUIRE(b1.size() == 16);
    REQUIRE(b2.size() == 16);
    REQUIRE(b3.size() == 40);
    REQUIRE(b1 != b2);

    REQUIRE(b1.find_first_not_of(Carafe::Base64::CharsetURLSafe.encodeLookup.data()) == std::string::npos);
    REQUIRE(b2.find_first_not_of(Carafe::Base64::CharsetURLSafe.encodeLookup.data()) == std::string::npos);
    INFO(b3);
    REQUIRE(b3[b3.size() - 1] == Carafe::Base64::CharsetStandard.padCharacter);
    b3.pop_back();
    REQUIRE(b3.find_first_not_of(Carafe::Base64::CharsetStandard.encodeLookup.data()) == std::string::npos);

    std::array<char, 1024> buf1, buf2;
    memset(buf1.data(), 0, buf1.size());
    memset(buf2.data(), 0, buf2.size());
    Carafe::Random::fill(buf1);
    REQUIRE(bcmp(buf1.data(), buf2.data(), buf1.size()) != 0);
}

#ifdef CARAFE_AUTHENTICATED_COOKIES
TEST_CASE("secure key", "[secure_key]")  {
    Carafe::SecureKey k1, k2;
    Carafe::_sha512_state s1, s2;

    memset(&s1, 0, sizeof(s1));
    memset(&s2, 0, sizeof(s2));
    k1.get_keyed_state(s1);
    k2.get_keyed_state(s2);

    REQUIRE(bcmp(&s1, &s2, sizeof(s1)) != 0);

    k1.rekey();
    k1.get_keyed_state(s2); // s1 has pre-rekey state, s3 has post-rekey state

    REQUIRE(bcmp(&s1, &s2, sizeof(s1)) != 0);
}

TEST_CASE("authenticated cookies", "[authenticated_cookies][cookies]")  {
    Carafe::CookieKeyManager cm;
    Carafe::SecureKey mac_key;

    Carafe::CookieKeyManager ck("heres a long key");
    // Inner authenticated cookie
    Carafe::AuthenticatedCookies c(ck);
    c.kv().emplace("authenticatedkey1", "authenticatedval1");
    c.kv().emplace("authenticatedkey2", "authenticatedval2");

    // Cookie in response object
    auto c2 = Carafe::Cookies();
    c2.load_data("Test=test_value; expires=Sat, 01-Jan-2000 00:00:00 GMT; path=/; HTTPOnly; =value");
    c2.kv().emplace("auth", c.serialize());

    // Cookie in request object
    auto c3 = Carafe::Cookies();
    c3.load_data(c2.serialize());

    // Innter authenticated cookie
    Carafe::AuthenticatedCookies c4(ck);
    REQUIRE(c2.kv().count("auth"));
    // If we didn't explicitely check above, could throw if "auth", the authenticated sub-cookie, isn't found.
    c4.load_data(c2.kv().at("auth"));
    REQUIRE (c4.authenticated());
    REQUIRE(c4.kv()["authenticatedkey2"] == "authenticatedval2");
}
#endif

TEST_CASE("cookies", "[cookies]") {
    Carafe::Cookies cookies;
    cookies.kv().emplace("cookie", "value");
    REQUIRE(cookies.serialize() == "cookie=value");
    cookies.kv().emplace("c2", "encode me");
    cookies.kv().emplace("bunch=o;garbage", std::string("needs\0encoding\n", 15));
    // Iteration order not guaranteed, so we just find what we expect to see
    auto s = cookies.serialize();
    INFO(s);
    REQUIRE(s.find("cookie=value") != std::string::npos);
    REQUIRE(s.find("c2=encode%20me") != std::string::npos);
    REQUIRE(s.find("bunch%3Do%3Bgarbage=needs") != std::string::npos);

    Carafe::Cookies c2;
    c2.load_data(cookies.serialize());
    REQUIRE(c2.kv().size() == 3);
    REQUIRE(c2.kv()["cookie"] == "value");
    REQUIRE(c2.kv().at("c2") == "encode me");
    REQUIRE(c2.kv().at("bunch=o;garbage") == std::string("needs\0encoding\n", 15));
}
