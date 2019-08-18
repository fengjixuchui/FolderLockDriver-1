//
// Project:
//
//		Data Guard FLock driver.
//
// Author:
//
//		Burlutsky Stanislav
//		burluckij@gmail.com
//

#pragma once

#include <ntifs.h>

typedef unsigned char	MD5BYTE; /* 8-bit byte */
typedef unsigned int	MD5WORD; /* 32-bit word */

typedef struct _FLOCK_MD5STATE {
	MD5WORD count[2];    /* message length in bits, lsw first */
	MD5WORD abcd[4];     /* digest buffer */
	MD5BYTE buf[64];     /* accumulate block */
} FLOCK_MD5STATE;

VOID FLockMd5Init(
	__in FLOCK_MD5STATE *pms
	);

VOID FLockMd5Append(
	__in FLOCK_MD5STATE *pms,
	__in const MD5BYTE *data,
	__in int nbytes);

VOID FLockMd5Finish(
	__in FLOCK_MD5STATE *pms,
	__inout MD5BYTE digest[16]
	);

VOID FLockMd5Calc(
	__in PUCHAR _data,
	__in ULONG _length,
	__out MD5BYTE digest[16]
	);
