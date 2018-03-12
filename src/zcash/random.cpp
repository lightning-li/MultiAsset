
#include "zcash/random.h"
#include "sodium.h"
#include <limits>

void GetRandBytes(unsigned char* buf, size_t num) {
    randombytes_buf(buf, num);
}

uint64_t GetRand(uint64_t nMax) {
    if (nMax == 0) {
        return 0;
    }

    uint64_t nRange = (std::numeric_limits<uint64_t>::max() / nMax) * nMax;
    uint64_t nRand = 0;
    do {
        GetRandBytes((unsigned char*)&nRand, sizeof(nRand)); 
    } while (nRand >= nRange);
    return (nRand % nMax);
}

int GetRandInt(int nMax) {
    return GetRand(nMax);
}