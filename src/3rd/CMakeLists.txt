set(CMAKE_CXX_STANDARD 11)
execute_process(COMMAND tar xjvf gmp-6.1.2.tar.bz2 WORKING_DIRECTORY ${ZCASH_MINIMAL_SOURCE}/3rd)
execute_process(COMMAND tar xzvf libsodium-1.0.12.tar.gz WORKING_DIRECTORY ${ZCASH_MINIMAL_SOURCE}/3rd)
execute_process(COMMAND make all WORKING_DIRECTORY ${ZCASH_MINIMAL_SOURCE}/3rd)