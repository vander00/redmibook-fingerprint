set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set_target_properties(jinx PROPERTIES CXX_VISIBILITY_PRESET hidden)

# manager
add_library(manager STATIC manager.cpp)
target_include_directories(manager PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(manager PUBLIC jinx jinx::usb jinx::dbus)

find_package(OpenSSL REQUIRED)
# driver
add_subdirectory(drv_fpc)

# main
add_executable(fingerprint-ocv main.cpp)
target_link_libraries(fingerprint-ocv PRIVATE 
    jinx
    jinx::openssl
    manager
    fpcnative
    $<TARGET_OBJECTS:fpc9201>
)
set_target_properties(fingerprint-ocv PROPERTIES CXX_VISIBILITY_PRESET hidden)

install(TARGETS fingerprint-ocv RUNTIME DESTINATION bin)


if(BUILD_TESTING)
    find_package(Python3 COMPONENTS Interpreter REQUIRED)
    add_executable(test_native_engine ../tests/native/test_engine.cpp drv_fpc/fingerprint.cpp drv_fpc/crypto.cpp)
    target_compile_definitions(test_native_engine PRIVATE FPC_FIXTURE_DIR="${PROJECT_SOURCE_DIR}/tests/native/preprocessing")
    target_link_libraries(test_native_engine PRIVATE fpcnative manager jinx::openssl OpenSSL::Crypto)
    add_executable(test_usb_lifetime ../tests/native/test_usb_lifetime.cpp)
    target_link_libraries(test_usb_lifetime PRIVATE manager)
    add_test(NAME usb-transfer-lifetime COMMAND test_usb_lifetime)
    add_test(NAME native-engine COMMAND test_native_engine)
    add_test(NAME native-primitives COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/tests/native/verify.py)
endif()
