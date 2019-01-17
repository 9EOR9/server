# Copyright (c) 2009, 2012, Oracle and/or its affiliates.
# Copyright (c) 2011, 2017, MariaDB Corporation
# 
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

# We support different versions of SSL:
# - "bundled" uses source code in <source dir>/extra/yassl
# - "system"  (typically) uses headers/libraries in /usr/lib and /usr/lib64
# - a custom installation of openssl can be used like this
#     - cmake -DCMAKE_PREFIX_PATH=</path/to/custom/openssl> -DWITH_SSL="system"
#   or
#     - cmake -DWITH_SSL=</path/to/custom/openssl>
#
# The default value for WITH_SSL is "bundled"
# set in cmake/build_configurations/feature_set.cmake
#
# For custom build/install of openssl, see the accompanying README and
# INSTALL* files. When building with gcc, you must build the shared libraries
# (in addition to the static ones):
#   ./config --prefix=</path/to/custom/openssl> --shared; make; make install
# On some platforms (mac) you need to choose 32/64 bit architecture.
# Build/Install of openssl on windows is slightly different: you need to run
# perl and nmake. You might also need to
#   'set path=</path/to/custom/openssl>\bin;%PATH%
# in order to find the .dll files at runtime.

SET(WITH_SSL_DOC "bundled (use yassl)")
SET(WITH_SSL_DOC
  "${WITH_SSL_DOC}, yes (prefer os library if present, otherwise use bundled)")
SET(WITH_SSL_DOC
  "${WITH_SSL_DOC}, system (use os library)")
SET(WITH_SSL_DOC
  "${WITH_SSL_DOC}, </path/to/custom/installation>")

MACRO (CHANGE_SSL_SETTINGS string)
  SET(WITH_SSL ${string} CACHE STRING ${WITH_SSL_DOC} FORCE)
ENDMACRO()

INCLUDE(ExternalProject)
MACRO (ADD_EXTERNAL_PROJECT_LIBRESSL)
  if(MSVC)
    set(LIBRESSL_EXTRA_CMAKE_FLAGS "-DCMAKE_C_FLAGS=/wd4152 /wd4701 /wd4702 /wd4090 /wd4295 /wd4132 /wd4204 /wd4206 /WX-")
  endif()
  if(UNIX)
    set(PIC_FLAG -fPIC)
  else()
    set(PIC_FLAG)
  endif()

  set(LIBRESSL_VERSION "2.8.3")
  set(LIBRESSL_URL http://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-${LIBRESSL_VERSION}.tar.gz)
  set(LIBRESSL_INSTALL_DIR "${CMAKE_CURRENT_BINARY_DIR}/thirdparty/libressl-install")
  ExternalProject_Add(libressl
    URL ${LIBRESSL_URL}
    CMAKE_ARGS
    -Wno-dev
    "-DLIBRESSL_TESTS=OFF"
    "-DCMAKE_INSTALL_PREFIX=${LIBRESSL_INSTALL_DIR}"
    "-DCMAKE_C_FLAGS_DEBUG=${CMAKE_C_FLAGS_DEBUG} ${PIC_FLAG}"
    "-DCMAKE_C_FLAGS_RELWITHDEBINFO=${CMAKE_C_FLAGS_RELWITHDEBINFO} ${PIC_FLAG}"
    "-DCMAKE_C_FLAGS_RELEASE=${CMAKE_C_FLAGS_RELEASE} ${PIC_FLAG}"
    "-DCMAKE_C_FLAGS_MINSIZEREL=${CMAKE_C_FLAGS_MINSIZEREL} ${PIC_FLAG}"
     ${LIBRESSL_EXTRA_CMAKE_FLAGS}
  )
  foreach(lib crypto ssl)
    add_library(${lib} STATIC IMPORTED)
    set_target_properties(${lib} PROPERTIES IMPORTED_LOCATION 
      "${LIBRESSL_INSTALL_DIR}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}${lib}${CMAKE_STATIC_LIBRARY_SUFFIX}")
    add_dependencies(${lib} libressl)
  endforeach()
  set_target_properties(ssl PROPERTIES INTERFACE_LINK_LIBRARIES crypto)

  set(OPENSSL_FOUND TRUE CACHE BOOL "")
  set(OPENSSL_INCLUDE_DIR "${LIBRESSL_INSTALL_DIR}/include" CACHE STRING "")
  set(OPENSSL_CRYPTO_LIBRARY  crypto CACHE STRING "")
  set(OPENSSL_SSL_LIBRARY ssl CACHE STRING "")
  set(SSL_LIBRARIES crypto ssl  CACHE STRING "")
  set(SSL_INCLUDE_DIRS ${OPENSSL_INCLUDE_DIR})
  set(SSL_INTERNAL_INCLUDE_DIRS "")
  set(SSL_DEFINES "-DHAVE_OPENSSL")
ENDMACRO()

MACRO (MYSQL_USE_BUNDLED_SSL)
  ADD_EXTERNAL_PROJECT_LIBRESSL()
ENDMACRO()

# MYSQL_CHECK_SSL
#
# Provides the following configure options:
# WITH_SSL=[yes|bundled|system|<path/to/custom/installation>]
MACRO (MYSQL_CHECK_SSL)
  IF(NOT WITH_SSL)
   IF(WIN32)
     CHANGE_SSL_SETTINGS("bundled")
   ELSE()
     SET(WITH_SSL "yes")
   ENDIF()
  ENDIF()

  # See if WITH_SSL is of the form </path/to/custom/installation>
  FILE(GLOB WITH_SSL_HEADER ${WITH_SSL}/include/openssl/ssl.h)
  IF (WITH_SSL_HEADER)
    SET(WITH_SSL_PATH ${WITH_SSL} CACHE PATH "path to custom SSL installation")
  ENDIF()

  IF(WITH_SSL STREQUAL "bundled")
    MYSQL_USE_BUNDLED_SSL()
  ELSEIF(WITH_SSL STREQUAL "system" OR
         WITH_SSL STREQUAL "yes" OR
         WITH_SSL_PATH
         )
    IF(NOT OPENSSL_ROOT_DIR)
      IF(WITH_SSL_PATH)
        SET(OPENSSL_ROOT_DIR ${WITH_SSL_PATH})
      ENDIF()
    ENDIF()
    FIND_PACKAGE(OpenSSL)
    IF(OPENSSL_FOUND)
      SET(OPENSSL_LIBRARY ${OPENSSL_SSL_LIBRARY})
      INCLUDE(CheckSymbolExists)
      SET(SSL_SOURCES "")
      SET(SSL_LIBRARIES ${OPENSSL_SSL_LIBRARY} ${OPENSSL_CRYPTO_LIBRARY})
      IF(CMAKE_SYSTEM_NAME MATCHES "SunOS")
        SET(SSL_LIBRARIES ${SSL_LIBRARIES} ${LIBSOCKET})
      ENDIF()
      IF(CMAKE_SYSTEM_NAME MATCHES "Linux")
        SET(SSL_LIBRARIES ${SSL_LIBRARIES} ${LIBDL})
      ENDIF()

      MESSAGE_ONCE(OPENSSL_INCLUDE_DIR "OPENSSL_INCLUDE_DIR = ${OPENSSL_INCLUDE_DIR}")
      MESSAGE_ONCE(OPENSSL_SSL_LIBRARY "OPENSSL_SSL_LIBRARY = ${OPENSSL_SSL_LIBRARY}")
      MESSAGE_ONCE(OPENSSL_CRYPTO_LIBRARY "OPENSSL_CRYPTO_LIBRARY = ${OPENSSL_CRYPTO_LIBRARY}")
      MESSAGE_ONCE(OPENSSL_VERSION "OPENSSL_VERSION = ${OPENSSL_VERSION}")
      MESSAGE_ONCE(SSL_LIBRARIES "SSL_LIBRARIES = ${SSL_LIBRARIES}")
      SET(SSL_INCLUDE_DIRS ${OPENSSL_INCLUDE_DIR})
      SET(SSL_INTERNAL_INCLUDE_DIRS "")
      SET(SSL_DEFINES "-DHAVE_OPENSSL")

      SET(CMAKE_REQUIRED_INCLUDES ${OPENSSL_INCLUDE_DIR})
      SET(CMAKE_REQUIRED_LIBRARIES ${SSL_LIBRARIES})
      CHECK_SYMBOL_EXISTS(ERR_remove_thread_state "openssl/err.h"
                          HAVE_ERR_remove_thread_state)
      CHECK_SYMBOL_EXISTS(EVP_aes_128_ctr "openssl/evp.h"
                          HAVE_EncryptAes128Ctr)
      CHECK_SYMBOL_EXISTS(EVP_aes_128_gcm "openssl/evp.h"
                          HAVE_EncryptAes128Gcm)
      SET(CMAKE_REQUIRED_INCLUDES)
      SET(CMAKE_REQUIRED_LIBRARIES)
    ELSE()
      IF(WITH_SSL STREQUAL "system")
        MESSAGE(FATAL_ERROR "Cannot find appropriate system libraries for SSL. Use WITH_SSL=bundled to enable SSL support")
      ENDIF()
      MYSQL_USE_BUNDLED_SSL()
    ENDIF()
  ELSE()
    MESSAGE(FATAL_ERROR
      "Wrong option for WITH_SSL. Valid values are: ${WITH_SSL_DOC}")
  ENDIF()
ENDMACRO()


# Many executables will depend on libeay32.dll and ssleay32.dll at runtime.
# In order to ensure we find the right version(s), we copy them into
# the same directory as the executables.
# NOTE: Using dlls will likely crash in malloc/free,
#       see INSTALL.W32 which comes with the openssl sources.
# So we should be linking static versions of the libraries.
MACRO (COPY_OPENSSL_DLLS target_name)
  IF (WIN32 AND WITH_SSL_PATH)
    GET_FILENAME_COMPONENT(CRYPTO_NAME "${OPENSSL_CRYPTO_LIBRARY}" NAME_WE)
    GET_FILENAME_COMPONENT(OPENSSL_NAME "${OPENSSL_SSL_LIBRARY}" NAME_WE)
    FILE(GLOB HAVE_CRYPTO_DLL "${WITH_SSL_PATH}/bin/${CRYPTO_NAME}.dll")
    FILE(GLOB HAVE_OPENSSL_DLL "${WITH_SSL_PATH}/bin/${OPENSSL_NAME}.dll")
    IF (HAVE_CRYPTO_DLL AND HAVE_OPENSSL_DLL)
      ADD_CUSTOM_COMMAND(OUTPUT ${target_name}
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
          "${WITH_SSL_PATH}/bin/${CRYPTO_NAME}.dll"
          "${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_CFG_INTDIR}/${CRYPTO_NAME}.dll"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
          "${WITH_SSL_PATH}/bin/${OPENSSL_NAME}.dll"
          "${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_CFG_INTDIR}/${OPENSSL_NAME}.dll"
        )
      ADD_CUSTOM_TARGET(${target_name} ALL)
    ENDIF()
  ENDIF()
ENDMACRO()
