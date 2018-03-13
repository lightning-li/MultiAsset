cmake_minimum_required(VERSION 2.8)

project(MultiAsset)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_FLAGS "-DMULTICORE -DCURVE_ALT_BN128 -fopenmp -O1 -DBINARY_OUTPUT -fPIC -DPERFORMANCE")
set(MULTIASSET_SOURCE ${CMAKE_CURRENT_SOURCE_DIR})

include_directories(${MULTIASSET_SOURCE}
                    ${MULTIASSET_SOURCE}/3rd
                    ${MULTIASSET_SOURCE}/3rd/libsodium-1.0.12/build/include
                    ${MULTIASSET_SOURCE}/3rd/snark/build/include
                    ${MULTIASSET_SOURCE}/3rd/snark/build/include/libsnark
                    )
# libgmpxx.a 与 libgmp.a 的顺序不能互换

set(ZCASH_DEPEND_LIBS ${MULTIASSET_SOURCE}/3rd/snark/build/lib/libsnark.a 
                      ${MULTIASSET_SOURCE}/3rd/libsodium-1.0.12/build/lib/libsodium.a
                      ${MULTIASSET_SOURCE}/3rd/gmp-6.1.2/build/lib/libgmpxx.a
                      ${MULTIASSET_SOURCE}/3rd/gmp-6.1.2/build/lib/libgmp.a
                      
                      )


set(MULTIASSET_DEPEND_SRC ${MULTIASSET_SOURCE}/crypto/sha256.cpp
                             ${MULTIASSET_SOURCE}/support/cleanse.cpp
                             ${MULTIASSET_SOURCE}/utils/uint256.cpp
                             ${MULTIASSET_SOURCE}/utils/utilstrencodings.cpp
                             )
add_subdirectory(3rd)
add_subdirectory(zcash)
