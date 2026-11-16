# wolfCrypt and the wolfSSL TLS client (for OpenVPN), built from the pinned
# upstream checkout in third_party/ with the project's own settings
# (config/user_settings.h) - the same file list and configuration the
# simulator's Makefile uses.
set(W ${CMAKE_CURRENT_LIST_DIR}/../../third_party/wolfssl)
set(names aes asn coding curve25519 ed25519 ecc error fe_operations ge_operations hash hmac
          kdf logging md5 memory pwdbased random rsa sha sha256 sha512 signature sp_int wc_port
          wc_encrypt wolfmath)
set(srcs)
foreach(n ${names})
    list(APPEND srcs ${W}/wolfcrypt/src/${n}.c)
endforeach()
foreach(n internal keys ssl tls tls13 wolfio)
    list(APPEND srcs ${W}/src/${n}.c)
endforeach()

idf_component_register(SRCS ${srcs}
                       INCLUDE_DIRS ${W} ${CMAKE_CURRENT_LIST_DIR}/../../config)
target_compile_definitions(${COMPONENT_LIB} PUBLIC WOLFSSL_USER_SETTINGS)
target_compile_options(${COMPONENT_LIB} PRIVATE -w)
