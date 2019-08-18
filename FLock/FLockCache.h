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

#include "flock.h"


typedef struct _FLOCK_CACHE_ENTRY
{
	BOOLEAN occupied;
	UCHAR hash[16];

	BOOLEAN presentMeta;

	// Some optimization things.
// 	union {
// 		struct {
// 			UCHAR i : 1;
// 			BOOLEAN presentMeta : 1;
// 		};
// 
// 		UCHAR data;
// 	};

}FLOCK_CACHE_ENTRY, *PFLOCK_CACHE_ENTRY;

typedef struct _FLOCK_CACHE_DATA
{
	//	Common volume of cache.
	ULONG capacity;
	
	//	Current size of cache.
	ULONG length;

	//	Limit to which cache can grow.
	ULONG occupancyLimit;

	//	Common count collisions occurred.
	ULONG collisionOccurrences;

	ULONG collisionMaxResolveOffset;

	//	Imagine we need insert element in to last position which is occupied,
	//	In that case we need start search from first position to - 'collisionResolveIfNoPlace'.
	//	It like interval [0, collisionResolveIfNoPlace].
	ULONG collisionResolveIfNoPlaceBorder;

	PFLOCK_CACHE_ENTRY cached;
	ERESOURCE	lock;
	BOOLEAN enabled;
	BOOLEAN needStop;
} FLOCK_CACHE_DATA, *PFLOCK_CACHE_DATA;


//
//	That two functions should be called no more then one time!
//

BOOLEAN FLockCacheInit();
void FLockCacheDeinitialyze();


//
//	Returns true if cache enabled.
//

BOOLEAN FLockCacheIsEnabled();


VOID FLockCacheEnable();
VOID FLockCacheDisable();

void FLockCacheLock();
void FLockCacheUnlock();

ULONG FLockCacheCapacity();
ULONG FLockCacheLength();


VOID FLockCacheGetInfo(
	PFLOCK_CACHE_INFO _info
	);


BOOLEAN FLockCacheLookup(
	__in PUCHAR _hash,
	__out PFLOCK_CACHE_ENTRY _result,
	__out ULONG* _stepsRequiredToFind
	);


BOOLEAN FLockCacheLookupOneCall(
	__in PUCHAR _hash,
	__out PFLOCK_CACHE_ENTRY _result,
	__out ULONG* _stepsRequiredToFind
	);


VOID FLockCacheAdd(
	__in PFLOCK_CACHE_ENTRY _newEntry
	);


VOID FLockCacheUpdateOrAdd(
	__in PFLOCK_CACHE_ENTRY _newEntry
	);


//
//	Adds new flock info into internal hash-table in one call.
//	This function includes all calls for acquiring and leaving synchronization resources.
//

VOID FLockCacheAddEntryOneCall(
	const unsigned char* _hash,
	BOOLEAN _present
	);


//
//	Removes all data in hash table and changes current length to 0, but does not change .capacity.
//

VOID FLockCacheErase();


//
//	Does the same as  FLockCacheErase() but acquires additional internal ERESOURCE object.
//

VOID FLockCacheEraseOneCall();
