/*
 * SHA-256 driver for ASM routine for x86_64 on Linux
 * Copyright (c) Mark Crichton <crichton@gimp.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 */

#define WANT_X8664_SSE2
#ifdef WANT_X8664_SSE2

#include <string.h>
#include <assert.h>

#include <xmmintrin.h>
#include <stdint.h>
#include <stdio.h>
#include <openssl/sha.h>
#define unlikely(a) (a)
 
#include "uint256.h"

extern "C" void CalcSha256_x64(__m128i *res, __m128i *data, uint32_t init[8], __m128i * sha256_k);
void FormatHashBuffers(char* pblock, char* pmidstate, char* pdata, char* phash1);

uint32_t g_sha256_k[] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, /*  0 */
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, /*  8 */
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, /* 16 */
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, /* 24 */
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, /* 32 */
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, /* 40 */
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, /* 48 */
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, /* 56 */
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};


uint32_t g_sha256_hinit[8] =
{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

__m128i g_4sha256_k[64];

#pragma pack(push,1)
struct work {
	char pdata[128];
	char phash[32];
	uint32_t max_nonce;
	uint64_t nHashesDone;
};
#pragma pack(pop)

template<typename T1>
inline uint256 Hash(const T1 pbegin, const T1 pend)
{
    static unsigned char pblank[1];
    uint256 hash1;
    SHA256((pbegin == pend ? pblank : (unsigned char*)&pbegin[0]), (pend - pbegin) * sizeof(pbegin[0]), (unsigned char*)&hash1);
    uint256 hash2;
    SHA256((unsigned char*)&hash1, sizeof(hash1), (unsigned char*)&hash2);
    return hash2;
}
inline uint32_t ByteReverse(uint32_t value)
{
		value = ((value & 0xFF00FF00) >> 8) | ((value & 0x00FF00FF) << 8);
    return (value<<16) | (value>>16);
}

inline __m128i ByteReverseM128(__m128i value)
{
	  const __m128i t00FF = _mm_set1_epi32(0x00FF00FF);
	  const __m128i tFF00 = _mm_set1_epi32(0xFF00FF00);
	  
    value=_mm_or_si128(_mm_srli_epi32(_mm_and_si128(value,tFF00),8),_mm_slli_epi32(_mm_and_si128(value,t00FF),8));
    
    //value = ((value & 0xFF00FF00) >> 8) | ((value & 0x00FF00FF) << 8);
    return _mm_or_si128(_mm_srli_epi32(value,16),_mm_slli_epi32(value,16));
}

inline __m128i _mm_mod_epi32( __m128i a, uint32_t s )
{
	union {
		__m128i m;
		uint32_t i[4];
	} mi;
	mi.m=a;
	mi.i[0]%=s;
	mi.i[1]%=s;
	mi.i[2]%=s;
	mi.i[3]%=s;
	return mi.m;	
}
inline __m128i _mm_mul_epi32( __m128i a, uint32_t s )
{
	union {
		__m128i m;
		uint32_t i[4];
	} mi;
	mi.m=a;
	mi.i[0]*=s;
	mi.i[1]*=s;
	mi.i[2]*=s;
	mi.i[3]*=s;
	return mi.m;	
}

inline __m128i checkMod( __m128i a[8], uint32_t b )
{
	int i;
	__m128i c[8];
	union {
		__m128i m;
		uint32_t i[4];
	} mi;
	
	uint32_t m = (uint32_t)(0x100000000ULL%b);
	//printf("%x %x\n",b,m);
	for( i=0;i<8;i++ ) {
		c[i] = _mm_mod_epi32(a[i],b);
		mi.m = c[i];
		//printf("c[%d]=%d\n",i,(int)mi.i[0]);
	}
	for( i=7;i>=1;i-- ) {
		c[i-1] = _mm_add_epi32(c[i-1],_mm_mul_epi32(c[i],m));
		c[i-1] = _mm_mod_epi32(c[i-1],b);
		mi.m = c[i-1];
		//printf("c[%d]=%d\n",i-1,(int)mi.i[0]);
	}
	return _mm_mod_epi32(c[0],b);	
}
/*
inline __m128i check3_5_17(__m128i m[8]) 
{
	__m128i t = _mm_set1_epi32(0);
	const __m128i tFF = _mm_set1_epi32(0xFF);  
	for( i=0;i<8;i++ ) {
		__m128i c = m[i];
		t = _mm_add_epi32(t,_mm_mod_epi32(c,tFF));
	}
	return _mm_mod_epi32(c,tFF);
}
*/
extern "C" uint32_t checkmod( uint32_t a[8], uint32_t b )
{
	__m128i t[8];
	int i;
	for( i=0;i<8;i++ )
		t[i] = _mm_set1_epi32(a[i]);
	__m128i r = checkMod(t,b);
	union {
		__m128i m;
		uint32_t i[4];
	} mi;
	mi.m=r;
	return mi.i[0];
}
/*int scanhash_sse2_64(int thr_id, const unsigned char *pmidstate,
	unsigned char *pdata,
	unsigned char *phash1, unsigned char *phash,
	const unsigned char *ptarget,
	uint32_t max_nonce, unsigned long *nHashesDone) */
extern "C" int scanhash_sse2_64( const void *pWork )
{
	int i;
	struct work *pwork = (struct work *)pWork;
	char pmidstate[32];
	char *pdata2 = pwork->pdata;
	char *pdata=pdata2+64;
	char phash1[64];
	char *phash = pwork->phash;
	uint32_t max_nonce = pwork->max_nonce;
	uint64_t *nHashesDone = &(pwork->nHashesDone);
	
	
	/*
	printf("work\n");
	char *pc = (char *)pWork;
	for( i=0;i<sizeof(struct work);i++ )
		printf("%02x",(int)pc[i]&0xff);
	printf("\n");
	unsigned int tmp[21];
	for (unsigned int i = 0; i < 20; i++)
  	tmp[i] = (((unsigned int*)&pwork->pdata)[i]);
		
	uint256 testout = Hash(tmp,tmp+20);
	printf("%s\n",testout.GetHex().c_str());
	*/
	FormatHashBuffers(pwork->pdata,pmidstate,pdata2,phash1);
	uint32_t *nNonce_p = (uint32_t *)(pdata + 12);
	uint32_t nonce = ByteReverse(*nNonce_p);
	
	printf("max = %d, nonce = %d\n",max_nonce,nonce);
	
	uint32_t m_midstate[8], m_w[16], m_w1[16];
	__m128i m_4w[64], m_4hash[64], m_4hash1[64];
	__m128i offset;
	/*
	printf("midstate:\n");
	pc = (char *)pmidstate;
	for( i=0;i<32;i++ )
		printf("%02x",(int)pc[i]&0xff);
	printf("\n");

	printf("hash1:\n");
	pc = (char *)phash1;
	for( i=0;i<64;i++ )
		printf("%02x",(int)pc[i]&0xff);
	printf("\n");

	printf("data:\n");
	pc = (char *)pdata2;
	for( i=0;i<128;i++ )
		printf("%02x",(int)pc[i]&0xff);
	printf("\n");
	printf("%x\n",*nNonce_p);
	*/
	/* For debugging */
	union {
		__m128i m;
		uint32_t i[4];
	} mi,yi;
	/* Message expansion */
	memcpy(m_midstate, pmidstate, sizeof(m_midstate));
	memcpy(m_w, pdata, sizeof(m_w)); /* The 2nd half of the data */
	memcpy(m_w1, phash1, sizeof(m_w1));
	memset(m_4hash, 0, sizeof(m_4hash));
	
	/* Transmongrify */
	for (i = 0; i < 16; i++)
		m_4w[i] = _mm_set1_epi32(m_w[i]);
	
	for (i = 0; i < 16; i++)
		m_4hash1[i] = _mm_set1_epi32(m_w1[i]);
	
	for (i = 0; i < 64; i++)
		g_4sha256_k[i] = _mm_set1_epi32(g_sha256_k[i]);
	
	offset = _mm_set_epi32(0x3, 0x2, 0x1, 0x0);
	for (;;)
	{
		int j;

		m_4w[3] = _mm_add_epi32(offset, _mm_set1_epi32(nonce));

		/* Some optimization can be done here W.R.T. precalculating some hash */
		CalcSha256_x64(m_4hash1, m_4w, m_midstate,g_4sha256_k);
		/*
		printf("fist round\n");
		for (i = 0; i < 8; i++) {
			mi.m = m_4hash1[i];
			*(uint32_t *)&(phash)[i*4] = mi.i[0];
		}
		printf("hash1:\n");
		pc = (char *)phash;
		for( i=0;i<32;i++ )
			printf("%02x",(int)pc[i]&0xff);
		printf("\n");
		*/
		CalcSha256_x64(m_4hash, m_4hash1, g_sha256_hinit,g_4sha256_k);
		
		j=0;
		for (i = 0; i < 8; i++) {
			m_4hash[i]=ByteReverseM128(m_4hash[i]);
		}
		mi.m = checkMod(m_4hash,210); 
		/*		//if (fulltest(phash, ptarget))
	printf("hash:\n");
	pc = (char *)phash;
	for( i=0;i<32;i++ )
		printf("%02x",(int)pc[i]&0xff);
	printf("\n");
	*/for( j=0;j<4;j++ )
		if( mi.i[j]==0 )
		{
			*nHashesDone = nonce;
			*nNonce_p = ByteReverse(nonce + j);
			
			for( i=0;i<8;i++ ) {
				yi.m=m_4hash[i];
				((uint32_t*)phash)[i]=yi.i[j];
			}
			
			return nonce + j;
		}
		nonce += 4;

		if (unlikely((nonce >= max_nonce))) {
			*nHashesDone = nonce;
			return -1;
		}
	}
}


int FormatHashBlocks(void* pbuffer, unsigned int len)
{
    unsigned char* pdata = (unsigned char*)pbuffer;
    unsigned int blocks = 1 + ((len + 8) / 64);
    unsigned char* pend = pdata + 64 * blocks;
    memset(pdata + len, 0, 64 * blocks - len);
    pdata[len] = 0x80;
    unsigned int bits = len * 8;
    pend[-1] = (bits >> 0) & 0xff;
    pend[-2] = (bits >> 8) & 0xff;
    pend[-3] = (bits >> 16) & 0xff;
    pend[-4] = (bits >> 24) & 0xff;
    return blocks;
}

static const unsigned int pSHA256InitState[8] =
{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

void SHA256Transform(void* pstate, void* pinput, const void* pinit)
{
    SHA256_CTX ctx;
    unsigned char data[64];

    SHA256_Init(&ctx);

    for (int i = 0; i < 16; i++)
        ((uint32_t*)data)[i] = ByteReverse(((uint32_t*)pinput)[i]);

    for (int i = 0; i < 8; i++)
        ctx.h[i] = ((uint32_t*)pinit)[i];

    SHA256_Update(&ctx, data, sizeof(data));
    for (int i = 0; i < 8; i++)
        ((uint32_t*)pstate)[i] = ctx.h[i];
}

void FormatHashBuffers(char* pblock, char* pmidstate, char* pdata, char* phash1)
{
    //
    // Pre-build hash buffers
    //
    struct
    {
        struct unnamed2
        {
            int nVersion;
            uint256 hashPrevBlock;
            uint256 hashMerkleRoot;
            unsigned int nTime;
            unsigned int nBits;
            unsigned int nNonce;
        }
        block;
        unsigned char pchPadding0[64];
        uint256 hash1;
        unsigned char pchPadding1[64];
    }
    tmp;
    memset(&tmp, 0, sizeof(tmp));

    memcpy(&tmp.block,pblock, sizeof(tmp.block));

    FormatHashBlocks(&tmp.block, sizeof(tmp.block));
    FormatHashBlocks(&tmp.hash1, sizeof(tmp.hash1));

    // Byte swap all the input buffer
    for (unsigned int i = 0; i < sizeof(tmp)/4; i++)
        ((unsigned int*)&tmp)[i] = ByteReverse(((unsigned int*)&tmp)[i]);
		char state[32];
		char *p = (char *)&tmp.block;
    // Precalc the first half of the first hash, which stays constant
    SHA256Transform(pmidstate, p, pSHA256InitState);
		SHA256Transform(state, p+64, pmidstate);
		/*
		printf("state:\n");
		char *pc = (char *)state;
		for( int i=0;i<32;i++ )
			printf("%02x",(int)pc[i]&0xff);
		printf("\n");
    */
    memcpy(pdata, &tmp.block, 128);
    memcpy(phash1, &tmp.hash1, 64);
}


#endif /* WANT_X8664_SSE2 */

