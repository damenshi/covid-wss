ACLOCAL_AMFLAGS = -I build-aux/m4

lib_LTLIBRARIES = libucake.la
if USE_JNI
JNI_LIB = libucake_jni.la
noinst_LTLIBRARIES = $(JNI_LIB)
else
JNI_LIB =
endif
 
include_HEADERS = include/kex_api.h
noinst_HEADERS =
noinst_HEADERS += src/scalar.h
noinst_HEADERS += src/scalar_4x64.h
noinst_HEADERS += src/scalar_8x32.h
noinst_HEADERS += src/scalar_low.h
noinst_HEADERS += src/scalar_impl.h
noinst_HEADERS += src/scalar_4x64_impl.h
noinst_HEADERS += src/scalar_8x32_impl.h
noinst_HEADERS += src/scalar_low_impl.h
noinst_HEADERS += src/group.h
noinst_HEADERS += src/sm3.h
noinst_HEADERS += src/e_os2.h
noinst_HEADERS += src/modes_local.h
noinst_HEADERS += src/sm4.h
noinst_HEADERS += src/cbc128.h
noinst_HEADERS += src/encrypt.h
noinst_HEADERS += src/cbc128.c
noinst_HEADERS += src/group_impl.h
noinst_HEADERS += src/num_gmp.h
noinst_HEADERS += src/num_gmp_impl.h
noinst_HEADERS += src/ecdsa.h
noinst_HEADERS += src/ecdsa_impl.h
noinst_HEADERS += src/eckey.h
noinst_HEADERS += src/eckey_impl.h
noinst_HEADERS += src/ecmult.h
noinst_HEADERS += src/ecmult_impl.h
noinst_HEADERS += src/ecmult_const.h
noinst_HEADERS += src/ecmult_const_impl.h
noinst_HEADERS += src/ecmult_gen.h
noinst_HEADERS += src/ecmult_gen_impl.h
noinst_HEADERS += src/num.h
noinst_HEADERS += src/num_impl.h
noinst_HEADERS += src/myOpenSSL.h
noinst_HEADERS += src/myOpenSSL.c
noinst_HEADERS += src/field_10x26.h
noinst_HEADERS += src/field_10x26_impl.h
noinst_HEADERS += src/field_5x52.h
noinst_HEADERS += src/field_5x52_impl.h
noinst_HEADERS += src/field_5x52_int128_impl.h
noinst_HEADERS += src/field_5x52_asm_impl.h
noinst_HEADERS += src/util.h
noinst_HEADERS += src/scratch.h
noinst_HEADERS += src/scratch_impl.h
noinst_HEADERS += src/testrand.h
noinst_HEADERS += src/testrand_impl.h
noinst_HEADERS += src/hash.h
noinst_HEADERS += src/hash_impl.h
noinst_HEADERS += src/field.h
noinst_HEADERS += src/field_impl.h
noinst_HEADERS += src/bench.h
noinst_HEADERS += contrib/lax_der_parsing.h
noinst_HEADERS += contrib/lax_der_parsing.c
noinst_HEADERS += contrib/lax_der_privatekey_parsing.h
noinst_HEADERS += contrib/lax_der_privatekey_parsing.c


if USE_EXTERNAL_ASM
COMMON_LIB = libucake_common.la
noinst_LTLIBRARIES = $(COMMON_LIB)
else
COMMON_LIB =
endif

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libucake.pc

if USE_EXTERNAL_ASM
if USE_ASM_ARM
libucake_common_la_SOURCES = src/asm/field_10x26_arm.s
endif
endif

libucake_la_SOURCES = src/secp256k1.c 
libucake_la_CPPFLAGS = -DSECP256K1_BUILD -I$(top_srcdir)/include -I$(top_srcdir)/src $(SECP_INCLUDES)
libucake_la_LIBADD = $(JNI_LIB) $(SECP_LIBS) $(COMMON_LIB)


libucake_jni_la_CPPFLAGS = -DSECP256K1_BUILD $(JNI_INCLUDES)

noinst_PROGRAMS =
 

TESTS =
if USE_TESTS
noinst_PROGRAMS +=   testcake_kex  
if !ENABLE_COVERAGE
testcake_kex_SOURCES = src/testcake_kex.c
testcake_kex_CPPFLAGS = -DSECP256K1_BUILD -I$(top_srcdir)/src -I$(top_srcdir)/include $(SECP_INCLUDES) $(SECP_TEST_INCLUDES)
testcake_kex_CPPFLAGS += -DVERIFY 
endif
testcake_kex_LDADD = $(SECP_LIBS) $(SECP_TEST_LIBS) $(COMMON_LIB)
testcake_kex_LDFLAGS = -static  -lucake
TESTS +=   testcake_kex
endif

 

