
if (APPLE)
set(OPENSSL_ROOT_DIR /usr/local/opt/openssl)
endif(APPLE)

find_package(OpenSSL REQUIRED)

add_library(fpcnative STATIC native/fpc_recovered.c native/profile300.c native/enrollment.c)
target_compile_options(fpcnative PRIVATE -ffp-contract=off -fno-fast-math)
target_link_libraries(fpcnative PUBLIC m)

add_library(fpc9201 STATIC crypto.cpp fpc9201.cpp fpcbio.cpp fingerprint.cpp)
target_link_libraries(fpc9201 PUBLIC fpcnative jinx manager OpenSSL::SSL OpenSSL::Crypto jinx::usb jinx::dbus jinx::openssl)
