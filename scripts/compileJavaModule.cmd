
-I../pdm-crypt-module/src/app/pdm-crypt-module/src/include \
-I../pdm-crypt-module/src/app/pdm-crypt-module/src/lib \
-I../pdm-crypt-module/src/app/pdm-crypt-module/src/lib/wasm \
-I../pdm-crypt-module/src/app/pdm-crypt-module/src/lib/cpp-mmf \
-I../pdm-crypt-module/src/app/pdm-crypt-module/src/lib/poly1305-donna-master \
-I../pdm-crypt-module/src/app/pdm-crypt-module/src/lib/ecc \
-I../pdm-crypt-module/src/app/pdm-crypt-module/src/lib/scrypt/include \
-I../pdm-crypt-module/src/app/pdm-crypt-module/src/lib/scrypt \
../pdm-crypt-module/src/app/pdm-crypt-module/src/lib/cc20_file.cpp \
../pdm-crypt-module/src/app/pdm-crypt-module/src/lib/sha3.cpp \
../pdm-crypt-module/src/app/pdm-crypt-module/src/lib/cpp-mmf/memory_mapped_file.cpp \
../pdm-crypt-module/src/app/pdm-crypt-module/src/lib/poly1305-donna-master/poly1305-donna.c \
../pdm-crypt-module/src/app/pdm-crypt-module/src/lib/ecc/ecdh_curve25519.c \
../pdm-crypt-module/src/app/pdm-crypt-module/src/lib/ecc/curve25519.c \
../pdm-crypt-module/src/app/pdm-crypt-module/src/lib/ecc/fe25519.c \
../pdm-crypt-module/src/app/pdm-crypt-module/src/lib/ecc/bigint.c \
../pdm-crypt-module/src/app/pdm-crypt-module/src/lib/scrypt/src/hmac.c \
../pdm-crypt-module/src/app/pdm-crypt-module/src/lib/scrypt/src/pbkdf2.c \
../pdm-crypt-module/src/app/pdm-crypt-module/src/lib/scrypt/src/salsa20.c \
../pdm-crypt-module/src/app/pdm-crypt-module/src/lib/scrypt/src/scrypt.c \
../pdm-crypt-module/src/app/pdm-crypt-module/src/empp.cpp \
../pdm-crypt-module/src/app/pdm-crypt-module/src/lib/scrypt/src/sha256.c \
../pdm-crypt-module/src/app/pdm-crypt-module/src/lib/ec.cpp \
../pdm-crypt-module/src/app/pdm-crypt-module/src/cc20core/cc20_multi.cpp

-fpermissive
-std=c++17
-O3
-DLINUX
-DWEB_RELEASE
-DSINGLETHREADING
-DWEB_RELEASE_LINUX_TEST