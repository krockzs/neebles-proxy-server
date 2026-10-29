cmake_minimum_required(VERSION 3.21)
project(neebles_proxy_server VERSION 1.0.0 LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
find_package(Qt6 6.8 COMPONENTS Core Widgets Network REQUIRED)
qt_standard_project_setup()
qt_add_executable(neebles-proxy-server src/main.cpp src/vault_install.cpp)
target_link_libraries(neebles-proxy-server PRIVATE Qt6::Core Qt6::Widgets Qt6::Network)
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

# Stage 007: runtime health HTTP integration test on the active Stark tailnet.
find_package(Python3 COMPONENTS Interpreter REQUIRED)
add_test(NAME neebles-proxy-server-health_integration
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/tests/health_integration.py
    --binary $<TARGET_FILE:neebles-proxy-server-health>
    --policy ${CMAKE_SOURCE_DIR}/contracts/allowlist.example.json)
set_tests_properties(neebles-proxy-server-health_integration PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 20)

# F04: dedicated native ELF for Boss platform operations.
# No automatic privileged execution during install or tests.
qt_add_executable(neebles-proxy-server-platform src/platform.cpp)
target_link_libraries(neebles-proxy-server-platform
    PRIVATE Qt6::Core Qt6::Network)

add_test(
    NAME neebles-proxy-server-platform_help
    COMMAND neebles-proxy-server-platform --help
)
set_tests_properties(neebles-proxy-server-platform_help
    PROPERTIES PASS_REGULAR_EXPRESSION
    "privileged native operation")

# F05: non-mutating security contract and non-root rejection.
add_test(
    NAME neebles-proxy-server-platform_security
    COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_SOURCE_DIR}/tests/verify_platform_candidate.py
        $<TARGET_FILE:neebles-proxy-server-platform>
        ${CMAKE_SOURCE_DIR}/contracts/platform-operations.candidate.json
)
set_tests_properties(
    neebles-proxy-server-platform_security
    PROPERTIES
        SKIP_RETURN_CODE 77
        TIMEOUT 15
)

# F17: protocol tests against a local mock, never real Secrets.
add_test(
    NAME neebles-proxy-server-vault_install_ipc
    COMMAND ${Python3_EXECUTABLE}
        -B ${CMAKE_SOURCE_DIR}/tests/test_vault_install_ipc.py
        --binary $<TARGET_FILE:neebles-proxy-server>
)
set_tests_properties(
    neebles-proxy-server-vault_install_ipc
    PROPERTIES TIMEOUT 150
)

# F22: native privilege-free preflight never changes Tailscale state.
add_test(NAME neebles-proxy-server-platform_preflight
    COMMAND ${Python3_EXECUTABLE} -B ${CMAKE_SOURCE_DIR}/tests/test_platform_preflight.py
    $<TARGET_FILE:neebles-proxy-server-platform>)
set_tests_properties(neebles-proxy-server-platform_preflight PROPERTIES TIMEOUT 15)
