set(CMAKE_CXX_STANDARD 11)

if (NOT EXISTS ${MULTIASSET_SOURCE}/3rd/gmp-6.1.2)
    execute_process(COMMAND tar xjvf gmp-6.1.2.tar.bz2 WORKING_DIRECTORY ${MULTIASSET_SOURCE}/3rd)
endif

if (NOT EXISTS ${MULTIASSET_SOURCE}/3rd/libsodium-1.0.12)
    execute_process(COMMAND tar xzvf libsodium-1.0.12.tar.gz WORKING_DIRECTORY ${MULTIASSET_SOURCE}/3rd)
endif

if (NOT EXISTS ${MULTIASSET_SOURCE}/3rd/rocksdb-5.11.3)
    execute_process(COMMAND tar xzvf rocksdb-5.11.3.tar.gz WORKING_DIRECTORY ${MULTIASSET_SOURCE}/3rd)
endif

execute_process(COMMAND make all WORKING_DIRECTORY ${MULTIASSET_SOURCE}/3rd)