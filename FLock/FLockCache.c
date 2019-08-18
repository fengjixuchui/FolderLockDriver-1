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

#include "FLock.h"
#include "FLockCache.h"

#define FLOCK_CACHE_TABLE_INDEX_LIMIT		(100 * 1000)
#define FLOCK_CACHE_TABLE_SIZE				(FLOCK_CACHE_TABLE_INDEX_LIMIT - 1)
#define FLOCK_CACHE_OCCUPANCY_LIMIT			(33 * 1000)

extern ULONG gTraceFlags;
FLOCK_CACHE_DATA g_cache = { 0 };



BOOLEAN FLockCacheInit()
{
	RtlZeroMemory(&g_cache, sizeof(FLOCK_CACHE_DATA));

	ExInitializeResourceLite(&g_cache.lock);

	g_cache.capacity = FLOCK_CACHE_TABLE_SIZE;
	g_cache.length = 0;
	g_cache.occupancyLimit = /*(FLOCK_CACHE_TABLE_INDEX_LIMIT / 3);*/ FLOCK_CACHE_OCCUPANCY_LIMIT;
	g_cache.collisionResolveIfNoPlaceBorder = 700;
	g_cache.enabled = TRUE;
	g_cache.collisionMaxResolveOffset = 0;

	g_cache.cached = (PFLOCK_CACHE_ENTRY)ExAllocatePool(NonPagedPoolNx, (g_cache.capacity + 1) * sizeof(FLOCK_CACHE_ENTRY) );

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("FLock!%s: Cache configuration - %d buckets, %d limit, %d collision resolve if no place.\n",
			__FUNCTION__,
			(g_cache.capacity + 1),
			g_cache.occupancyLimit,
			g_cache.collisionResolveIfNoPlaceBorder)
		);

	if ( g_cache.cached == NULL )
	{
		g_cache.enabled = FALSE;

		PT_DBG_PRINT(PTDBG_TRACE_ERRORS, ("FLock!%s error - couldn't create hash table with %d buckets.\n", __FUNCTION__, (g_cache.capacity + 1) ));
	}

	return (g_cache.cached != NULL);
}

void FLockCacheDeinitialyze()
{
	FLockCacheLock();
	FLockCacheDisable();

	if (g_cache.cached) {

		ExFreePool(g_cache.cached);
		g_cache.cached = NULL;
	}

	FLockCacheUnlock();
	ExDeleteResourceLite(&g_cache.lock);
}

VOID FLockCacheGetInfo(
	PFLOCK_CACHE_INFO _info
	)
{
	if (_info)
	{
		RtlZeroMemory(_info, sizeof(FLOCK_CACHE_INFO));
		_info->enabled = g_cache.enabled;

		if (g_cache.enabled)
		{
			_info->capacity = g_cache.capacity;
			_info->occupancyLimit = g_cache.occupancyLimit;
			_info->collisionMaxResolveOffset = g_cache.collisionMaxResolveOffset;
			_info->collisionResolveIfNoPlaceBorder = g_cache.collisionResolveIfNoPlaceBorder;
			_info->currentSize = g_cache.length;
			// _info->maxStepsCounter;
		}
	}
}

BOOLEAN FLockCacheIsEnabled()
{
	return g_cache.enabled;
}

VOID FLockCacheEnable()
{
	g_cache.enabled = TRUE;
}

VOID FLockCacheDisable()
{
	g_cache.enabled = FALSE;
}

void FLockCacheLock()
{
	KeEnterCriticalRegion();
	ExAcquireResourceExclusiveLite(&g_cache.lock, TRUE);
}

void FLockCacheUnlock()
{
	ExReleaseResourceLite(&g_cache.lock);
	KeLeaveCriticalRegion();
}

ULONG FLockCacheCapacity()
{
	return g_cache.capacity;
}

ULONG FLockCacheLength()
{
	return g_cache.length;
}

ULONG FLockCacheCalcIndex(
	__in PUCHAR _hash,
	__in ULONG _length, // length should be equal to 16 bytes
	__in ULONG _highBorder
	)
{
	UNREFERENCED_PARAMETER(_length);

	ULONG dataForIndex = 0, index = 0;
	UCHAR dword_[4] = { 0 };

	//
	//	Говорю честно, эту функцию нужно написать максимально граматно.
	//	Распределение должно быть равномерным и не занимать крайние ячейки таблицы.
	//

// 	dword_[3] = _hash[3];
// 	dword_[2] = _hash[2];
	dword_[1] = _hash[1];
	dword_[0] = _hash[0];

// 	dword_[3] = 0;
// 	dword_[2] = 0;

	dataForIndex = *((ULONG*)dword_);

// 	for (int i = 0; i < _length; ++i)
// 	{
// 		dword_[]
// 	}

	index = (dataForIndex % ( _highBorder /*FLOCK_CACHE_TABLE_SIZE*/));

	//PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: data for index %lu, index itself %d\n", __FUNCTION__, dataForIndex, index));

	return index;
}

BOOLEAN FLockCacheLookupIndexForNewRoom(
	__in ULONG _lookupIndexLimit,
	__in  PUCHAR _hash,
	__out PULONG _freeIndex,
	__out PBOOLEAN _collisionOccured,
	__out PULONG _stepsToPlaceNewEntry
	)
{
	ULONG resolvingSteps = 0;
	ULONG index = FLockCacheCalcIndex(_hash, 16, _lookupIndexLimit);

	SETPTR(_collisionOccured, FALSE);

	for (ULONG i = index; i <= _lookupIndexLimit; i++)
	{
		PFLOCK_CACHE_ENTRY cache_pos = g_cache.cached + i;

		if (cache_pos->occupied == TRUE)
		{
			if (memcmp(cache_pos->hash, _hash, 16) == 0)
			{
				// Yes, Strike!

				*_freeIndex = i;
				return TRUE;
			}
			else
			{
				SETPTR(_collisionOccured, TRUE);

				(*_stepsToPlaceNewEntry)++;

				resolvingSteps++;
			}
		}
		else
		{
			//
			//	Ok. We found a free room.
			//

			*_freeIndex = i;

			return TRUE;
		}
	}

	//
	//	If we are here, it means that we did not find right free room for new entry,
	//	start search from beginning.
	//

	for (ULONG i = 0; i <= g_cache.collisionResolveIfNoPlaceBorder; i++)
	{
		PFLOCK_CACHE_ENTRY cache_pos = g_cache.cached + i;

		if (cache_pos->occupied == TRUE)
		{
			if (memcmp(cache_pos->hash, _hash, 16) == 0)
			{
				// Yes, Strike!

				*_freeIndex = i;
				return TRUE;
			}
			else
			{
				SETPTR(_collisionOccured, TRUE);

				(*_stepsToPlaceNewEntry)++;
			}
		}
		else
		{
			// It is a free room.

			*_freeIndex = i;

			return TRUE;
		}
	}

	return FALSE;
}


BOOLEAN FLockCacheLookup(
	__in PUCHAR _hash,
	__out PFLOCK_CACHE_ENTRY _result,
	__out ULONG* _stepsRequiredToFind
	)
{
	ULONG i = 0;
	ULONG index = FLockCacheCalcIndex(_hash, 16, g_cache.capacity);

	SETPTR(_stepsRequiredToFind, 0);

	// Index was successfully calculated, find available bucket for use.
	for (i = index; i <= g_cache.capacity; i++)
	{
		PFLOCK_CACHE_ENTRY cache_pos = g_cache.cached + i;

		if (cache_pos->occupied == TRUE)
		{
			if ( memcmp(cache_pos->hash, _hash, 16) == 0 )
			{
				// Yes, Strike!

				memcpy( _result, cache_pos, sizeof(FLOCK_CACHE_ENTRY) );
				return TRUE;
			}
			else
			{
				// It is collision, we need to further.
				(*_stepsRequiredToFind)++;
			}
		}
		else
		{
			// Stop search if found non occupied bucket.
			// Search further has no sense.
			return FALSE;
		}
	}

	// If we achieved bottom of the table and did not find what we actually need,
	// in that case need start search from beginning.
	for (i = 0; i < g_cache.collisionResolveIfNoPlaceBorder; ++i)
	{
		PFLOCK_CACHE_ENTRY cache_pos = g_cache.cached + i;

		// Does a bucket occupied?
		if (cache_pos->occupied == TRUE)
		{
			// Yes, verify its content.
			if (memcmp(cache_pos->hash, _hash, 16) == 0)
			{
				// Yes, Strike!
				memcpy(_result, cache_pos, sizeof(FLOCK_CACHE_ENTRY));
				return TRUE;
			}
			else
			{
				(*_stepsRequiredToFind)++;
			}
		}
		else
		{
			break;
		}
	}

	return FALSE;
}

BOOLEAN FLockCacheLookupOneCall(
	__in PUCHAR _hash,
	__out PFLOCK_CACHE_ENTRY _foundEntry,
	__out ULONG* _stepsRequiredToFind
	)
{
	BOOLEAN found = FALSE;

	FLockCacheLock();
	found = FLockCacheLookup(_hash, _foundEntry, _stepsRequiredToFind);
	FLockCacheUnlock();

	return found;
}

VOID FLockCacheAdd(
	__in PFLOCK_CACHE_ENTRY _newEntry
	)
{
	BOOLEAN collisionOccured = FALSE;
	ULONG insertIndex = 0, stepsToPlaceEntry = 0;

	if (g_cache.length > g_cache.occupancyLimit)
	{
		PT_DBG_PRINT(PTDBG_TRACE_CACHE_COLLISION, ("FLock!%s: FLOCK_CACHE_OCCUPANCY_LIMIT achieved! Cache.length %d\n", __FUNCTION__, g_cache.length));

		RtlZeroMemory(g_cache.cached, sizeof(FLOCK_CACHE_ENTRY) * g_cache.capacity);
		g_cache.length = 0;
	}

	if (FLockCacheLookupIndexForNewRoom(g_cache.capacity, _newEntry->hash, &insertIndex, &collisionOccured, &stepsToPlaceEntry))
	{
		PFLOCK_CACHE_ENTRY tableEntry = g_cache.cached + insertIndex;

		RtlCopyMemory(tableEntry, _newEntry, sizeof(FLOCK_CACHE_ENTRY));

		tableEntry->occupied = TRUE;
		g_cache.length++;

		if (collisionOccured)
		{
			if (stepsToPlaceEntry > g_cache.collisionMaxResolveOffset)
			{
				PT_DBG_PRINT(PTDBG_TRACE_ROUTINES | PTDBG_TRACE_CACHE_COLLISION,
					("FLock!%s: Cache_info. New max collision distance is %d, old was %d, current cache.length %d.\n",
					__FUNCTION__,
					stepsToPlaceEntry,
					g_cache.collisionMaxResolveOffset,
					g_cache.length));

				g_cache.collisionMaxResolveOffset = stepsToPlaceEntry;
			}

			PT_DBG_PRINT(PTDBG_TRACE_CACHE_COLLISION,
				("FLock!%s: Cache_info. Added with collision. Index is %d, steps counter %d, cache.length %d.\n",
				__FUNCTION__,
				insertIndex,
				stepsToPlaceEntry,
				g_cache.length));
		}
	}
	else
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES | PTDBG_TRACE_ERRORS,
			("FLock!%s: CRITICAL - Refresh cache. No free index to use in cache table. Index is %d, cache.length %d.\n",
			__FUNCTION__,
			insertIndex,
			g_cache.length));

		FLockCacheErase();

		//
		//	Be careful. Recursive call.
		//

		FLockCacheAdd(_newEntry);
	}
}

VOID FLockCacheUpdateOrAdd(
	__in PFLOCK_CACHE_ENTRY _newEntry
	)
{
	FLockCacheAdd(_newEntry);
}

VOID FLockCacheAddEntryOneCall(const unsigned char* _hash, BOOLEAN _presentFlockMeta)
{
	FLOCK_CACHE_ENTRY newCacheEntry = { 0 };
	newCacheEntry.presentMeta = _presentFlockMeta;
	RtlCopyMemory(newCacheEntry.hash, _hash, sizeof(newCacheEntry.hash));

	FLockCacheLock();
	FLockCacheUpdateOrAdd(&newCacheEntry);
	FLockCacheUnlock();
}

VOID FLockCacheErase()
{
	if (g_cache.cached)
	{
		RtlZeroMemory(g_cache.cached, sizeof(FLOCK_CACHE_ENTRY) * g_cache.capacity);
	}

	g_cache.length = 0;
	g_cache.collisionMaxResolveOffset = 0;
	//g_cache.collisionOccurrences
}

VOID FLockCacheEraseOneCall()
{
	FLockCacheLock();
	FLockCacheErase();
	FLockCacheUnlock();
}
