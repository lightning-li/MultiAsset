
#ifndef BUBI_RANDOM_H
#define BUBI_RANDOM_H

#include "utils/uint256.h"
#include <functional>
#include <stdint.h>

/**
 * 通过 libsodium CSPRNG 来收集随机数据的函数
 */

void GetRandBytes(unsigned char* buf, size_t num);
uint64_t GetRand(uint64_t nMax);
int GetRandInt(int nMax);

// 随机排列 [first, first + len) 里的元素
// [mapFirst, mapFirst+len) 根据上述元素的排列进行相同的排列，便于调用者追踪排列
// gen 使用整数 n 作为参数，并且产生一个位于 [0,n) 随机的输出

template <typename RandomAccessIterator, typename MapRandomAccessIterator>
void MappedShuffle(RandomAccessIterator first,
                   MapRandomAccessIterator mapFirst,
                   size_t len,
                   std::function<int(int)> gen)
{
    for (size_t i = len-1; i > 0; --i) {
        auto r = gen(i+1);
        assert(r >= 0);
        assert(r <= i);
        std::swap(first[i], first[r]);
        std::swap(mapFirst[i], mapFirst[r]);
    }
}

#endif
