//
// Author:
//
//		Burlutsky Stas
//		burluckij@gmail.com
//

#include "FLockCrypt.h"

#pragma warning(disable:4201) // warning C4201: nonstandard extension used : nameless struct/union


//
//  Some additional type declarations are here. It is required just for comfort work with different bytes of data.
//

typedef struct Data4Bytes
{
    union
    {
        ulong data_32;

        struct
        {
            int l0 : 8;
            int l1 : 8;
            int l2 : 8;
            int l3 : 8;
        };
    };
} Data4Bytes, *PData4Bytes;

typedef struct Data8Bytes
{
    union
    {
        char buf[8];
        uint64_t data64;

        struct
        {
            Data4Bytes low;
            Data4Bytes high;
        };
    };
} Data8Bytes, *PData8Bytes;


//
//  And implementation is here.
//

ulong f4b(ulong _L, ulong _key)
{
    Data4Bytes val;
    ulong modLeft = _L ^ _key;
    Data4Bytes* ptr32Data = (Data4Bytes*)(&modLeft);

    val.l0 = ptr32Data->l0 ^ ptr32Data->l3;
    val.l1 = ptr32Data->l2 ^ ptr32Data->l3;
    val.l2 = ptr32Data->l1 ^ ptr32Data->l3;
    val.l3 = ptr32Data->l2 ^ ptr32Data->l3;

    return val.data_32;
}

ulong f1b(unsigned char _1char, ulong _key)
{
    Data4Bytes val;
    ulong modLeft = _1char ^ _key;
    Data4Bytes* ptr32Data = (Data4Bytes*)(&modLeft);

    val.l0 = ptr32Data->l0 ^ ptr32Data->l3;
    val.l1 = ptr32Data->l2 ^ ptr32Data->l3;
    val.l2 = ptr32Data->l1 ^ ptr32Data->l3;
    val.l3 = ptr32Data->l2 ^ ptr32Data->l3;

    return val.data_32;
}

ulong getKey(uint64_t _key, int _i)
{
    PData8Bytes keyBuffer = (PData8Bytes)(&_key);
    int n = (_i * 2) % (SizeOfEncryptionKey);

    _key = (_key << n) | (_key >> (SizeOfEncryptionKey - n));

    return keyBuffer->low.data_32;
}


void FLockCryptEncode4b(ulong* _left, ulong* _right, uint64_t _key, int _rounds)
{
    for (int i = 0; i < _rounds; i++)
    {
        ulong temp = *_right ^ f4b(*_left, getKey(_key, i));
        *_right = *_left;
        *_left = temp;
    }
}

void FLockCryptEncode1b(unsigned char* _left, unsigned char* _right, uint64_t _key, int _rounds)
{
    for (int i = 0; i < _rounds; i++)
    {
        unsigned char temp = *_right ^ f1b(*_left, getKey(_key, i));
        *_right = *_left;
        *_left = temp;
    }
}

void FLockCryptDecode(ulong* _left, ulong* _right, uint64_t _key, int _rounds)
{
    for (int i = _rounds - 1; i >= 0; i--)
    {
        ulong temp = *_left ^ f4b(*_right, getKey(_key, i));
        *_left = *_right;
        *_right = temp;
    }
}

void FLockCryptDecode1b(unsigned char* _left, unsigned char* _right, uint64_t _key, int _rounds)
{
    for (int i = _rounds - 1; i >= 0; i--)
    {
        unsigned char temp = *_left ^ f1b(*_right, getKey(_key, i));
        *_left = *_right;
        *_right = temp;
    }
}

void FLockCryptEncodeData(char* _pBuffer, size_t _length, uint64_t _key, int _rounds)
{
    const char* pEndOfBuffer = _pBuffer + _length;

    //
    // Обработать первые байты кодируемых данных, в случае если его размер не кратен восьми.
    //
    int residueKey = _length % sizeof(_key);

    if (residueKey)
    {
        char* tmpBufPtr = _pBuffer;
        int residue2 = residueKey % 2;
        
        if (residue2)
        {
            Data8Bytes* p64Key = (Data8Bytes*)(&_key);
            unsigned char xorKeyFoFirstByte = p64Key->low.l0 ^ p64Key->low.l1 ^ p64Key->low.l2 ^ _rounds;
            *tmpBufPtr = *tmpBufPtr ^ xorKeyFoFirstByte;
            tmpBufPtr++;
        }

        for (const char* pBorder = tmpBufPtr + residueKey - residue2; tmpBufPtr < pBorder; tmpBufPtr += 2)
        {
            FLockCryptEncode1b((unsigned char*)tmpBufPtr, ((unsigned char*)(tmpBufPtr + sizeof(unsigned char))), _key, _rounds);
        }
    }

    for (_pBuffer += residueKey; _pBuffer < pEndOfBuffer; _pBuffer += sizeof(ulong) * 2)
    {
        FLockCryptEncode4b((ulong*)_pBuffer, ((ulong*)(_pBuffer + sizeof(ulong))), _key, _rounds);
    }
}

void FLockCryptDecodeData(char* _pBuffer, size_t _length, uint64_t _key, int _rounds)
{
    const char* pEndOfBuffer = _pBuffer + _length;
    int residueKey = _length % sizeof(_key);

    if (residueKey)
    {
        char* tmpBufPtr = _pBuffer;
        int residue2 = residueKey % 2;

        if (residue2)
        {
            Data8Bytes* p64Key = (Data8Bytes*)(&_key);
            unsigned char xorKey = p64Key->low.l0 ^ p64Key->low.l1 ^ p64Key->low.l2 ^ _rounds;
            *tmpBufPtr = *tmpBufPtr ^ xorKey;
            tmpBufPtr++;
        }

        for (const char* pBorder = tmpBufPtr + residueKey - residue2; tmpBufPtr < pBorder; tmpBufPtr += 2)
        {
            FLockCryptDecode1b((unsigned char*)tmpBufPtr, ((unsigned char*)(tmpBufPtr + sizeof(unsigned char))), _key, _rounds);
        }
    }

    for (_pBuffer += residueKey; _pBuffer < pEndOfBuffer; _pBuffer += sizeof(ulong) * 2)
    {
        FLockCryptDecode((ulong*)_pBuffer, ((ulong*)(_pBuffer + sizeof(ulong))), _key, _rounds);
    }
}

