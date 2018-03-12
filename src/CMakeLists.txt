cmake_minimum_required(VERSION 2.8)

project(zcash-minimal)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_FLAGS "-DMULTICORE -DCURVE_ALT_BN128 -fopenmp -O1 -DBINARY_OUTPUT -fPIC -DPERFORMANCE")
set(ZCASH_MINIMAL_SOURCE ${CMAKE_CURRENT_SOURCE_DIR})

include_directories(${ZCASH_MINIMAL_SOURCE}
                    ${ZCASH_MINIMAL_SOURCE}/3rd
                    ${ZCASH_MINIMAL_SOURCE}/3rd/libsodium-1.0.12/build/include
                    ${ZCASH_MINIMAL_SOURCE}/3rd/snark/build/include
                    ${ZCASH_MINIMAL_SOURCE}/3rd/snark/build/include/libsnark
                    )
# libgmpxx.a 与 libgmp.a 的顺序不能互换

set(ZCASH_DEPEND_LIBS ${ZCASH_MINIMAL_SOURCE}/3rd/snark/build/lib/libsnark.a 
                      ${ZCASH_MINIMAL_SOURCE}/3rd/libsodium-1.0.12/build/lib/libsodium.a
                      ${ZCASH_MINIMAL_SOURCE}/3rd/gmp-6.1.2/build/lib/libgmpxx.a
                      ${ZCASH_MINIMAL_SOURCE}/3rd/gmp-6.1.2/build/lib/libgmp.a
                      
                      )


set(ZCASH_MINIMAL_DEPEND_SRC ${ZCASH_MINIMAL_SOURCE}/crypto/sha256.cpp
                             ${ZCASH_MINIMAL_SOURCE}/support/cleanse.cpp
                             ${ZCASH_MINIMAL_SOURCE}/utils/uint256.cpp
                             ${ZCASH_MINIMAL_SOURCE}/utils/utilstrencodings.cpp
                             )
add_subdirectory(3rd)
add_subdirectory(zcash)
