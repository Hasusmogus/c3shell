# wolfSSH (client only), from the pinned upstream checkout in third_party/.
set(S ${CMAKE_CURRENT_LIST_DIR}/../../third_party/wolfssh)
set(srcs)
foreach(n internal io log port ssh keygen ossh misc)
    list(APPEND srcs ${S}/src/${n}.c)
endforeach()

idf_component_register(SRCS ${srcs}
                       INCLUDE_DIRS ${S}
                       REQUIRES wolfssl lwip)
target_compile_options(${COMPONENT_LIB} PRIVATE -w)
