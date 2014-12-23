// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef HASH_LYRA2RE
#define HASH_LYRA2RE

#include "uint256.h"
#include "serialize.h"
#include "Lyra2RE.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "sph_blake.h"
#include "sph_groestl.h"
#include "sph_keccak.h"
#include "sph_skein.h"
#include "Lyra2.h"

#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <vector>

template<typename T1>
inline uint256 HashLyra2RE(const T1 pbegin, const T1 pend)

void lyra2re_hash(const char* input, char* output)
{
    sph_blake256_context ctx_blake;
	sph_groestl256_context ctx_groestl;
	sph_keccak256_context ctx_keccak;
	sph_skein256_context ctx_skein;
    static unsigned char pblank[1];

#ifndef QT_NO_DEBUG
    //std::string strhash;
    //strhash = "";
#endif
      
    uint32_t hashA[8], hashB[8];
	
	sph_blake256_init(&ctx_blake);
	sph_blake256 (&ctx_blake, input, 80);
	sph_blake256_close (&ctx_blake, hashA);
	
	sph_keccak256_init(&ctx_keccak);
	sph_keccak256 (&ctx_keccak,hashA, 32);
	sph_keccak256_close(&ctx_keccak, hashB);
	
		LYRA2(hashA, 32, hashB, 32, hashB, 32, 1, 8, 8);
		
	sph_skein256_init(&ctx_skein);
	sph_skein256 (&ctx_skein, hashA, 32);
	sph_skein256_close(&ctx_skein, hashB);
	
	sph_groestl256_init(&ctx_groestl);
	sph_groestl256 (&ctx_groestl, hashB, 32);
	sph_groestl256_close(&ctx_groestl, hashA);
	
		memcpy(output, hashA, 32);
}

#endif
