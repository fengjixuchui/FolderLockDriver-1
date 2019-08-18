//
// Author:
//
//		Burlutsky Stas
//		burluckij@gmail.com
//

#pragma once

#include <ntifs.h>

typedef unsigned long ulong;
typedef unsigned char uchar;
typedef unsigned long long uint64_t;
typedef unsigned __int64    size_t;

static const int SizeOfEncryptionKey = 64;

#define FLOCK_GRADER_ROUNDS             10


//
//  Encrypts array of bytes
//  Note: length - count of bytes in _pBuffer, must be a multiple to one byte.
//  key - 64 bits
//
void FLockCryptEncodeData(char* _pBuffer, size_t _length, uint64_t _key, int _rounds);

//
//  Decrypts array of bytes
//  Note: length - count of bytes in _pBuffer, must be a multiple to one byte.
//  key - 64 bits 
//
void FLockCryptDecodeData(char* _pBuffer, size_t _length, uint64_t _key, int _rounds);

