set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set_target_properties(jinx PROPERTIES CXX_VISIBILITY_PRESET hidden)

# manager
add_library(manager STATIC manager.cpp)
target_include_directories(manager PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(manager PUBLIC jinx jinx::usb jinx::dbus)

# cvext
if (DEFINED ENV{OPENCV_SDK_HOME})
set(OpenCV_DIR $ENV{OPENCV_SDK_HOME}/lib/cmake/opencv4)
endif()

find_package(OpenCV REQUIRED)

add_library(cvext STATIC cvext.cpp)
target_include_directories(cvext PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
# OpenCV 5 renamed the features2d and calib3d modules to features and calib.
# OpenCV_VERSION_MAJOR is exported by OpenCVConfig.cmake on both 4.x and 5.x.
if (OpenCV_VERSION_MAJOR VERSION_GREATER_EQUAL 5)
set(OPENCV_FEATURES2D_LIB opencv_features)
set(OPENCV_CALIB3D_LIB opencv_calib)
else()
set(OPENCV_FEATURES2D_LIB opencv_features2d)
set(OPENCV_CALIB3D_LIB opencv_calib3d)
endif()

target_link_libraries(cvext PUBLIC opencv_core opencv_imgproc ${OPENCV_FEATURES2D_LIB} opencv_imgcodecs ${OPENCV_CALIB3D_LIB} opencv_flann)

if (CMAKE_BUILD_TYPE STREQUAL Debug)
target_link_libraries(cvext PUBLIC opencv_highgui)
endif()

# driver
add_subdirectory(drv_fpc)

# main
add_executable(fingerprint-ocv main.cpp)
target_link_libraries(fingerprint-ocv PRIVATE 
    jinx
    jinx::openssl
    cvext
    manager
    $<TARGET_OBJECTS:fpc9201>
)
set_target_properties(fingerprint-ocv PROPERTIES CXX_VISIBILITY_PRESET hidden)

install(TARGETS fingerprint-ocv)

if (BUILD_TESTING)
add_executable(test_fingerprint_multitemplate
    test_fingerprint_multitemplate.cpp
    drv_fpc/fingerprint.cpp
    drv_fpc/crypto.cpp
)
target_link_libraries(test_fingerprint_multitemplate PRIVATE
    jinx
    jinx::openssl
    cvext
)
add_test(NAME fingerprint-multitemplate COMMAND test_fingerprint_multitemplate)
endif()
