include_directories (../src)

file(GLOB SOURCES "*.cpp")
add_executable(carafe-test ${SOURCES} "../src/carafe.cpp")
add_test(NAME carafe-test COMMAND carafe-test)
target_link_libraries(carafe-test microhttpd)
