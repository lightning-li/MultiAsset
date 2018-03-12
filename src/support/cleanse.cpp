// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "support/cleanse.h"
#include <string.h>

//#include <openssl/crypto.h>
// learned from openssl/crypto/mem_clr.c

typedef void *(*memset_t)(void *, int, size_t);
static volatile memset_t memset_func = memset;

void OPENSSL_cleanse(void *ptr, size_t len) {
    memset_func(ptr, 0, len);
}

void memory_cleanse(void *ptr, size_t len)
{
    OPENSSL_cleanse(ptr, len);
}
