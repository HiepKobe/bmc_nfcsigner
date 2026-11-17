# The Flutter tooling requires that developers have CMake 3.10 or later
# installed. You should not increase this version, as doing so will cause
# the plugin to fail to compile for some customers of the plugin.
cmake_minimum_required(VERSION 3.10)

set(PROJECT_NAME "nfcsigner")
project(${PROJECT_NAME} LANGUAGES CXX)

# This value is used when generating builds using this plugin, so it must
# not be changed.
set(PLUGIN_NAME "nfcsigner_plugin")

find_package(PkgConfig REQUIRED)

# PC/SC Lite (bắt buộc): sudo apt install libpcsclite-dev pcscd
pkg_check_modules(PCSC REQUIRED IMPORTED_TARGET libpcsclite)

# PoDoFo >= 0.10 (tuỳ chọn, cho ký PDF): sudo apt install libpodofo-dev
pkg_check_modules(PODOFO QUIET IMPORTED_TARGET libpodofo)
if(NOT PODOFO_FOUND)
  pkg_check_modules(PODOFO QUIET IMPORTED_TARGET libpodofo-0)
endif()

add_library(${PLUGIN_NAME} SHARED
  "nfcsigner_plugin.cc"
)

apply_standard_settings(${PLUGIN_NAME})

set_target_properties(${PLUGIN_NAME} PROPERTIES
  CXX_VISIBILITY_PRESET hidden)
target_compile_definitions(${PLUGIN_NAME} PRIVATE FLUTTER_PLUGIN_IMPL)
target_compile_features(${PLUGIN_NAME} PRIVATE cxx_std_17)

target_include_directories(${PLUGIN_NAME} INTERFACE
  "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_link_libraries(${PLUGIN_NAME} PRIVATE flutter PkgConfig::GTK PkgConfig::PCSC)

if(PODOFO_FOUND)
  message(STATUS "nfcsigner: PoDoFo ${PODOFO_VERSION} — bật ký PDF")
  target_compile_definitions(${PLUGIN_NAME} PRIVATE HAVE_PODOFO=1)
  target_link_libraries(${PLUGIN_NAME} PRIVATE PkgConfig::PODOFO)
else()
  message(WARNING "nfcsigner: không tìm thấy PoDoFo — signPdf sẽ trả OPERATION_NOT_SUPPORTED")
endif()

# List of absolute paths to libraries that should be bundled with the plugin.
set(nfcsigner_bundled_libraries
  ""
  PARENT_SCOPE
)
