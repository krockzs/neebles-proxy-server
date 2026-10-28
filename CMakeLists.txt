cmake_minimum_required(VERSION 3.21)
project(neebles_proxy_server VERSION 0.1.0 LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
find_package(Qt6 6.8 COMPONENTS Core Widgets Network REQUIRED)
qt_standard_project_setup()
qt_add_executable(neebles-proxy-server src/main.cpp)
target_link_libraries(neebles-proxy-server PRIVATE Qt6::Core Qt6::Widgets)
qt_add_executable(neebles-proxy-server-inspect src/inspect.cpp)
target_link_libraries(neebles-proxy-server-inspect PRIVATE Qt6::Core Qt6::Network)
enable_testing()
add_test(NAME neebles-proxy-server_help COMMAND neebles-proxy-server --help)
set_tests_properties(neebles-proxy-server_help PROPERTIES PASS_REGULAR_EXPRESSION "NEEBLES Proxy")
add_test(NAME neebles-proxy-server-inspect_help COMMAND neebles-proxy-server-inspect --help)
set_tests_properties(neebles-proxy-server-inspect_help PROPERTIES PASS_REGULAR_EXPRESSION "read-only Tailscale inspector")

# Stage 004: read-only policy contract, no privileged network operations.
qt_add_executable(neebles-proxy-server-policy src/policy.cpp)
target_link_libraries(neebles-proxy-server-policy PRIVATE Qt6::Core Qt6::Network)
add_test(NAME neebles-proxy-server-policy_help COMMAND neebles-proxy-server-policy --help)
set_tests_properties(neebles-proxy-server-policy_help PROPERTIES PASS_REGULAR_EXPRESSION "read-only whitelist policy")
add_test(NAME neebles-proxy-server-policy_fixture COMMAND neebles-proxy-server-policy
    --policy ${CMAKE_SOURCE_DIR}/contracts/allowlist.example.json
    --status-fixture ${CMAKE_SOURCE_DIR}/tests/tailscale.status.fixture.json)
set_tests_properties(neebles-proxy-server-policy_fixture PROPERTIES PASS_REGULAR_EXPRESSION "not_configured")

# Stage 005: read-only exit-node controller plan. No privileged network operations.
qt_add_executable(neebles-proxy-server-controller src/controller.cpp)
target_link_libraries(neebles-proxy-server-controller PRIVATE Qt6::Core Qt6::Network)
add_test(NAME neebles-proxy-server-controller_help COMMAND neebles-proxy-server-controller --help)
set_tests_properties(neebles-proxy-server-controller_help PROPERTIES PASS_REGULAR_EXPRESSION "read-only")
add_test(NAME neebles-proxy-server-controller_fixture COMMAND neebles-proxy-server-controller
    --policy ${CMAKE_SOURCE_DIR}/contracts/allowlist.example.json
    --status-fixture ${CMAKE_SOURCE_DIR}/tests/tailscale.status.fixture.json)
set_tests_properties(neebles-proxy-server-controller_fixture PROPERTIES PASS_REGULAR_EXPRESSION "tailnet_acl_enforcement_not_verified")

# Stage 006: Tailscale-bound health listener. It never enables forwarding or advertises Exit Node.
qt_add_executable(neebles-proxy-server-health src/health.cpp)
target_link_libraries(neebles-proxy-server-health PRIVATE Qt6::Core Qt6::Network)
add_test(NAME neebles-proxy-server-health_help COMMAND neebles-proxy-server-health --help)
set_tests_properties(neebles-proxy-server-health_help PROPERTIES PASS_REGULAR_EXPRESSION "HTTP health service")
add_test(NAME neebles-proxy-server-health_fixture COMMAND neebles-proxy-server-health
    --check --policy ${CMAKE_SOURCE_DIR}/contracts/allowlist.example.json
    --status-fixture ${CMAKE_SOURCE_DIR}/tests/tailscale.health.fixture.json)
set_tests_properties(neebles-proxy-server-health_fixture PROPERTIES PASS_REGULAR_EXPRESSION "exit_ready")
