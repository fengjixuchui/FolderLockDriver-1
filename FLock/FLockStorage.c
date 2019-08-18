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

#include "flock.h"
#include "FLockStorage.h"


//////////////////////////////////////////////////////////////////////////
//
//
// Global variables is here.
//
//

#define STORAGE_HEAD				((PFLOCK_STORAGE_HEADER)(g_flockStorage.pMappedData))



EXTERN_C ULONG gTraceFlags;

FLOCK_STORAGE g_flockStorage;
WCHAR* g_storageFile = L"\\??\\c:\\flock_lists.bin";


BOOLEAN FLockStorageLookupInArray(
	__in PUCHAR _flockId, // Pointer to UCHAR[16] array.
	__out PULONG _ptrIndex,
	__out PFLOCK_STORAGE_ENTRY _outEntry)
{
	if (_ptrIndex && _outEntry)
	{
		for (ULONG i = 0; i < g_flockStorage.arrayLength; ++i)
		{
			PFLOCK_STORAGE_ENTRY pe = (g_flockStorage.flockArray + i);

			if (memcmp(pe->id, _flockId, sizeof(pe->id) ) == 0)
			{
				*_ptrIndex = i;
				RtlCopyMemory(_outEntry, pe, sizeof(FLOCK_STORAGE_ENTRY));
				return TRUE;
			}
		}
	}

	return FALSE;
}

BOOLEAN FLockStorageLookupPtrInArray(
	__in PUCHAR _flockId, // Pointer to UCHAR[16] array.
	__out PULONG _ptrIndex,
	__out PFLOCK_STORAGE_ENTRY* _outPtr)
{
	if (_ptrIndex && _outPtr)
	{
		for (ULONG i = 0; i < g_flockStorage.arrayLength; ++i)
		{
			PFLOCK_STORAGE_ENTRY pe = (g_flockStorage.flockArray + i);

			if (memcmp(pe->id, _flockId, sizeof(pe->id)) == 0)
			{
				*_outPtr = pe;
				*_ptrIndex = i;

				return TRUE;
			}
		}
	}

	return FALSE;
}

//
//	Updates information about state of storage entries:
//		- Does storage have hidden objects?
//		- Does storage have locked objects?
//

EXTERN_C VOID FLockStorageUpdateInternalInfo()
{
	BOOLEAN hasLocked = FALSE, hasHidden = FALSE;

	if (g_flockStorage.arrayLength != 0)
	{
		for (ULONG i = 0; i < g_flockStorage.arrayLength; ++i)
		{
			PFLOCK_STORAGE_ENTRY pe = (g_flockStorage.flockArray + i);

			if (BooleanFlagOn(pe->flockFlag, FLOCK_FLAG_HIDE)) {
				hasHidden = TRUE;
			}

			if (BooleanFlagOn(pe->flockFlag, FLOCK_FLAG_LOCK_ACCESS)) {
				hasLocked = TRUE;
			}
		}
	}

	g_flockStorage.hasUserObjectsToLock = hasLocked;
	g_flockStorage.hasUserObjectsToHide = hasHidden;
}


ULONG FLockStorageGetFlocksCount()
{
	ULONG length = 0;

#pragma region SYNC_CRITICAL_SECTION

	KeEnterCriticalRegion();
	ExAcquireResourceSharedLite(&g_flockStorage.lockRules, TRUE);

	length = g_flockStorage.arrayLength;

	ExReleaseResourceLite(&g_flockStorage.lockRules);
	KeLeaveCriticalRegion();

#pragma endregion SYNC_CRITICAL_REGION

	return length;
}


EXTERN_C BOOLEAN FLockStorageLookup(
	__in PUCHAR _flockId, // Pointer to UCHAR[16] array.
	__out PFLOCK_STORAGE_ENTRY _foundResult
	)
{
	BOOLEAN result = FALSE;
	ULONG position = 0;

	if (!_foundResult){
		return FALSE;
	}

#pragma region SYNC_CRITICAL_SECTION

	KeEnterCriticalRegion();
	ExAcquireResourceSharedLite(&g_flockStorage.lockRules, TRUE);

	result = FLockStorageLookupInArray(_flockId, &position, _foundResult);

	ExReleaseResourceLite(&g_flockStorage.lockRules);
	KeLeaveCriticalRegion();

#pragma endregion SYNC_CRITICAL_REGION

	return result;
}


EXTERN_C BOOLEAN FLockStorageIsPresent(
	__in PUCHAR _flockId // Pointer to UCHAR[16] array.
	)
{
	FLOCK_STORAGE_ENTRY flockInfo;
	ULONG position = 0;

#pragma region SYNC_CRITICAL_SECTION

	KeEnterCriticalRegion();
	ExAcquireResourceSharedLite(&g_flockStorage.lockRules, TRUE);

	BOOLEAN result = FLockStorageLookupInArray(_flockId, &position, &flockInfo);

	ExReleaseResourceLite(&g_flockStorage.lockRules);
	KeLeaveCriticalRegion();

#pragma endregion SYNC_CRITICAL_REGION

	return result;
}


EXTERN_C BOOLEAN FLockStorageHasHiddenUserObjects()
{
	BOOLEAN result = g_flockStorage.hasUserObjectsToHide;
	return result;
}

EXTERN_C BOOLEAN FLockStorageHasLockedUserObjects()
{
	BOOLEAN result = g_flockStorage.hasUserObjectsToLock;
	return result;
}

EXTERN_C VOID FLockStorageClearInMemory()
{
	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s\n", __FUNCTION__));

#pragma region SYNC_CRITICAL_SECTION

	KeEnterCriticalRegion();
	ExAcquireResourceExclusiveLite(&g_flockStorage.lockRules, TRUE);

	if (g_flockStorage.arrayLength)
	{
		RtlZeroMemory(g_flockStorage.flockArray, g_flockStorage.arrayLength * sizeof(FLOCK_STORAGE_ENTRY));
	}

	g_flockStorage.arrayLength = 0;

	FLockStorageUpdateInternalInfo();

	ExReleaseResourceLite(&g_flockStorage.lockRules);
	KeLeaveCriticalRegion();

#pragma endregion SYNC_CRITICAL_REGION
}


EXTERN_C BOOLEAN FLockStorageUpdateEntry(
	__in PFLOCK_STORAGE_ENTRY _changedEntry
	)
{
	PFLOCK_STORAGE_ENTRY ptr = NULL;
	BOOLEAN result = FALSE;
	ULONG position = 0;

	if (!_changedEntry){
		return FALSE;
	}

#pragma region SYNC_CRITICAL_SECTION

	KeEnterCriticalRegion();
	ExAcquireResourceExclusiveLite(&g_flockStorage.lockRules, TRUE);
	
	result = FLockStorageLookupPtrInArray(_changedEntry->id, &position, &ptr);
	if (result)
	{
		result = memcmp(ptr->id, _changedEntry->id, sizeof(_changedEntry->id)) == 0;

		// Re-write information!
		if (result)
		{
			RtlCopyMemory(ptr, _changedEntry, sizeof(FLOCK_STORAGE_ENTRY));
		}
	}

	FLockStorageUpdateInternalInfo();

	ExReleaseResourceLite(&g_flockStorage.lockRules);
	KeLeaveCriticalRegion();

#pragma endregion SYNC_CRITICAL_REGION

	return result;
}

EXTERN_C BOOLEAN FLockStorageUpdateFlags(
	__in PFLOCK_ID _flockId,
	__in ULONG _newFlags
	)
{
	PFLOCK_STORAGE_ENTRY foundEntry = NULL;
	ULONG position = 0;

	if (!_flockId){
		return FALSE;
	}

#pragma region SYNC_CRITICAL_SECTION

	KeEnterCriticalRegion();
	ExAcquireResourceExclusiveLite(&g_flockStorage.lockRules, TRUE);

	BOOLEAN result = FLockStorageLookupPtrInArray(_flockId->id, &position, &foundEntry);
	if (result)
	{
		foundEntry->flockFlag = _newFlags;
	}

	FLockStorageUpdateInternalInfo();

	ExReleaseResourceLite(&g_flockStorage.lockRules);
	KeLeaveCriticalRegion();

#pragma endregion SYNC_CRITICAL_REGION

	return result;
}

EXTERN_C BOOLEAN FLockStorageRemove(
	PUCHAR _flockId // Pointer to UCHAR[16] array.
	)
{
	BOOLEAN result = FALSE;
	ULONG removingPos = 0;
	FLOCK_STORAGE_ENTRY fse = { 0 };
	BOOLEAN needToFlush = TRUE;

#pragma region SYNC_CRITICAL_SECTION

	KeEnterCriticalRegion();
	ExAcquireResourceExclusiveLite(&g_flockStorage.lockRules, TRUE);

	needToFlush = (FLockStorageLookupInArray(_flockId, &removingPos, &fse) == TRUE);

	if ( needToFlush )
	{
		removingPos = 0;

		// If it is a removing not form the last position.
		if (removingPos != (g_flockStorage.arrayLength - 1))
		{
			// Take an element from the tail and insert it into removing position.
			g_flockStorage.flockArray[removingPos] = g_flockStorage.flockArray[g_flockStorage.arrayLength - 1];
		}

		// Change size of the array.
		g_flockStorage.arrayLength--;

		result = TRUE;
	}

	FLockStorageUpdateInternalInfo();

	ExReleaseResourceLite(&g_flockStorage.lockRules);
	KeLeaveCriticalRegion();

#pragma endregion SYNC_CRITICAL_REGION

	//
	// Writes data on disk if it's need.
	//
	// SETPTR(_needFlush, needToFlush);
	//if (needToFlush) FLockStorageExport();

	return result;
}


EXTERN_C BOOLEAN FLockStorageAdd(
	__in PUCHAR _flockId, // Pointer to UCHAR[16] array.
	__in ULONG _actionPolicy
	)
{
	BOOLEAN result = FALSE;
	ULONG index = 0;
	FLOCK_STORAGE_ENTRY fse = { 0 };

#pragma region SYNC_CRITICAL_SECTION

	KeEnterCriticalRegion();
	ExAcquireResourceExclusiveLite(&g_flockStorage.lockRules, TRUE);

	if (!FLockStorageLookupInArray(_flockId, &index, &fse))
	{
		//
		// Does it need increase array size?
		//

		if ((g_flockStorage.arrayLength + 1) >= g_flockStorage.arrayMaxLength)
		{
			ULONG newLength = g_flockStorage.arrayMaxLength * 2;
			ULONG newLengthBytes = newLength * sizeof(FLOCK_STORAGE_ENTRY);
			PVOID newArray = ExAllocatePool(NonPagedPool, newLengthBytes);

			if (newArray)
			{
				// Copy from old array to new one.
				RtlCopyMemory(newArray, g_flockStorage.flockArray, sizeof(FLOCK_STORAGE_ENTRY) * g_flockStorage.arrayLength);

				// Save new array length.
				g_flockStorage.arrayMaxLength = newLength;

				// Free memory for old array data.
				ExFreePool(g_flockStorage.flockArray);

				// Forget about old array, use new one.
				g_flockStorage.flockArray = (PFLOCK_STORAGE_ENTRY) newArray;
			}
			else
			{
				PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: failed - ExAllocatePool for %d bytes\n", __FUNCTION__, newLengthBytes));

				goto _leave_and_exit;
			}
		}

		FLOCK_STORAGE_ENTRY newEntry = { 0 };
		newEntry.version = 0;
		newEntry.flockFlag = _actionPolicy;
		RtlCopyMemory(newEntry.id, _flockId, sizeof(newEntry.id) /* 16 */ );

		// Place new FLock in our array.
		RtlCopyMemory((g_flockStorage.flockArray + g_flockStorage.arrayLength /** sizeof(FLOCK_STORAGE_ENTRY)*/), &newEntry, sizeof(FLOCK_STORAGE_ENTRY));

		// Increase length of the array including new entry.
		g_flockStorage.arrayLength++;

		// Success, all things done.
		result = TRUE;

		FLockStorageUpdateInternalInfo();
	}
	else
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: warning - entry was not added, because it's already present.\n", __FUNCTION__));
	}

_leave_and_exit:
	ExReleaseResourceLite(&g_flockStorage.lockRules);
	KeLeaveCriticalRegion();

#pragma endregion SYNC_CRITICAL_REGION

	return result;
}


EXTERN_C BOOLEAN FLockStorageAddWithFlush(
	__in PUCHAR _flockId, // Pointer to UCHAR[16] array.
	__in ULONG _actionPolicy
	)
{
	BOOLEAN result = FLockStorageAdd(_flockId, _actionPolicy);

	if (result)
	{
		result = NT_SUCCESS(FLockStorageExportToSection());
		if (!result)
		{
			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: error - couldn't flush just modified data on disk.\n", __FUNCTION__));
		}
	}

	return result;
}


EXTERN_C BOOLEAN FLockStorageGetAll(
	__in BOOLEAN _useNonPagedMemory,
	__out PULONG _copiedNumbers,
	__out PFLOCK_STORAGE_ENTRY* _poutBuffer
	)
{
	BOOLEAN result = FALSE;

	if (!_copiedNumbers || !_poutBuffer)
	{
		return FALSE;
	}

#pragma region SYNC_CRITICAL_SECTION

	KeEnterCriticalRegion();
	ExAcquireResourceSharedLite(&g_flockStorage.lockRules, TRUE);

	if (g_flockStorage.arrayLength == 0)
	{
		*_copiedNumbers = 0;
		*_poutBuffer = NULL;
		result = TRUE;
	}
	else
	{
		ULONG allocationSize = g_flockStorage.arrayLength * sizeof(FLOCK_STORAGE_ENTRY);
		PVOID copyArray = ExAllocatePool((_useNonPagedMemory ? NonPagedPool : PagedPool), allocationSize);

		if (copyArray)
		{
			RtlCopyMemory(copyArray, g_flockStorage.flockArray, allocationSize);

			*_copiedNumbers = g_flockStorage.arrayLength;
			*_poutBuffer = (PFLOCK_STORAGE_ENTRY) copyArray;

			result = TRUE;
		}
		else
		{
			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: failed - ExAllocatePool for %d bytes\n", __FUNCTION__, allocationSize));
		}
	}

	ExReleaseResourceLite(&g_flockStorage.lockRules);
	KeLeaveCriticalRegion();

#pragma endregion SYNC_CRITICAL_REGION

	return result;
}


EXTERN_C BOOLEAN FLockStorageVerifyLock(
	__in PFLOCK_ID _flockId // Pointer to UCHAR[16] array.
	)
{
	return FLockStorageVerifyFlag((PFLOCK_ID)_flockId->id, FLOCK_FLAG_LOCK_ACCESS);
}

BOOLEAN FLockStorageDirHasFlocks(
	__in PFLOCK_ID _flockId
	)
{
	return FLockStorageVerifyFlag((PFLOCK_ID)_flockId->id, FLOCK_FLAG_HAS_FLOCKS);
}

BOOLEAN FLockStorageVerifyHidding(
	__in PFLOCK_ID _flockId
	)
{
	return FLockStorageVerifyFlag((PFLOCK_ID)_flockId->id, FLOCK_FLAG_HIDE);
}

EXTERN_C BOOLEAN FLockStorageVerifyFlag(
	__in PFLOCK_ID _flockId, // Pointer to UCHAR[16] array.
	__in DWORD	_flag
	)
{
	BOOLEAN result = FALSE;
	ULONG index = 0;
	FLOCK_STORAGE_ENTRY fse;

#pragma region SYNC_CRITICAL_SECTION

	KeEnterCriticalRegion();
	ExAcquireResourceSharedLite(&g_flockStorage.lockRules, TRUE);

	result = FLockStorageLookupInArray(_flockId->id, &index, &fse);
	if (result)
	{
		result = BooleanFlagOn(fse.flockFlag, _flag);
	}

	ExReleaseResourceLite(&g_flockStorage.lockRules);
	KeLeaveCriticalRegion();

#pragma endregion SYNC_CRITICAL_REGION

	return result;
}


EXTERN_C BOOLEAN FLockStorageIsValid()
{
	BOOLEAN result = FALSE;

#pragma region SYNC_CRITICAL_SECTION

	KeEnterCriticalRegion();
	ExAcquireResourceExclusiveLite(&g_flockStorage.lockRules, TRUE);

	if (g_flockStorage.pMappedData)
	{
		result = (STORAGE_HEAD->signature == FLOCK_STORAGE_SIGNATURE);
	}

	ExReleaseResourceLite(&g_flockStorage.lockRules);
	KeLeaveCriticalRegion();

#pragma endregion SYNC_CRITICAL_SECTION

	return result;
}


EXTERN_C BOOLEAN FLockStorageImport()
{
	BOOLEAN result = FALSE;

#pragma region SYNC_CRITICAL_SECTION

	KeEnterCriticalRegion();
	ExAcquireResourceExclusiveLite(&g_flockStorage.lockRules, TRUE);

	if (g_flockStorage.pMappedData)
	{
		if (STORAGE_HEAD->signature == FLOCK_STORAGE_SIGNATURE)
		{
			ULONG currentLength = STORAGE_HEAD->length;
			ULONG maxArrayLength = 0;

			// Free currently using array.
			if (g_flockStorage.flockArray)
			{
				ExFreePool(g_flockStorage.flockArray);

				g_flockStorage.flockArray = NULL;
				g_flockStorage.arrayLength = 0;
				g_flockStorage.arrayMaxLength = 0;
			}

			//
			// Calculate size for FLocks array and allocate memory for it.
			//
			if (currentLength < STORAGE_BASE_ARRAY_SIZE)
			{
				maxArrayLength = STORAGE_BASE_ARRAY_SIZE;
			}
			else
			{
				maxArrayLength = currentLength * 2;
			}

			ULONG allocationSize = maxArrayLength * sizeof(FLOCK_STORAGE_ENTRY);

			g_flockStorage.flockArray = (PFLOCK_STORAGE_ENTRY)ExAllocatePool(NonPagedPool, allocationSize);
			if (g_flockStorage.flockArray)
			{
				g_flockStorage.arrayMaxLength = maxArrayLength;
				g_flockStorage.arrayLength = currentLength;

				RtlCopyMemory(g_flockStorage.flockArray, (((PUCHAR)g_flockStorage.pMappedData) + sizeof(FLOCK_STORAGE_HEADER)), allocationSize);

				FLockStorageUpdateInternalInfo();

				result = TRUE;
			}
			else
			{
				 PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: failed - ExAllocatePool couldn't allocate %d bytes.\n", __FUNCTION__, allocationSize));
			}
		}
		else
		{
			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: failed - storage was corrupted.\n", __FUNCTION__));
		}
	}

	ExReleaseResourceLite(&g_flockStorage.lockRules);
	KeLeaveCriticalRegion();

#pragma endregion SYNC_CRITICAL_SECTION

	return result;
}


//
//	Writes all FLocks entries from an array in non-paged memory into mapped file on disk.
//

BOOLEAN FLockStorageExportToSection()
{
	BOOLEAN result = FALSE, canWriteData = TRUE;

#pragma region SYNC_CRITICAL_SECTION

	KeEnterCriticalRegion();
	ExAcquireResourceExclusiveLite(&g_flockStorage.lockRules, TRUE);

	ULONG flocksArraySize = g_flockStorage.arrayLength * sizeof(FLOCK_STORAGE_ENTRY);
	ULONG needTotal = flocksArraySize + sizeof(FLOCK_STORAGE_HEADER);

	if (g_flockStorage.mapSize < needTotal)
	{
		//
		// Need increase storage file size.
		//
		ULONG targetSize = BYTES_TO_PAGES(needTotal) * PAGE_SIZE;

		canWriteData = FLockStorageIncreaseMap(targetSize);
		if (!canWriteData)
		{
			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: failed - couldn't increase the storage length to %d bytes\n", __FUNCTION__, targetSize));
		}
	}

	if (canWriteData)
	{
		// Write header each time when export FLock entries.
		STORAGE_HEAD->signature = FLOCK_STORAGE_SIGNATURE;
		STORAGE_HEAD->length = g_flockStorage.arrayLength;

		if (g_flockStorage.arrayLength)
		{
			// Transfer flocks from internal array to section.
			RtlCopyMemory(
				((PUCHAR)g_flockStorage.pMappedData) + sizeof(FLOCK_STORAGE_HEADER),
				g_flockStorage.flockArray,
				flocksArraySize);

			// Flush buffers.
			if (g_flockStorage.hFile)
			{
				IO_STATUS_BLOCK ios = { 0 };
				ZwFlushBuffersFile(g_flockStorage.hFile, &ios);
			}
		}

		result = TRUE;
	}

	ExReleaseResourceLite(&g_flockStorage.lockRules);
	KeLeaveCriticalRegion();

#pragma endregion SYNC_CRITICAL_SECTION

	return result;
}


BOOLEAN FLockStorageInit()
{
	//
	// Fill all fields of the storage management structure.
	//
	RtlZeroMemory(&g_flockStorage, sizeof(g_flockStorage));

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: called.\n", __FUNCTION__));

	NTSTATUS status = ExInitializeResourceLite(&g_flockStorage.lockRules);

	if (!NT_SUCCESS(status))
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: failed - ExInitializeResourceLite for lockArray, status code is 0x%x\n", __FUNCTION__, status));
		return FALSE;
	}

	g_flockStorage.initializationState = TRUE;

	// Success.
	return TRUE;
}

EXTERN_C BOOLEAN FLockStorageIsInitialized()
{
	return g_flockStorage.initializationState != FALSE;
}

EXTERN_C BOOLEAN FLockStorageDeinitialize()
{
	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s called\n", __FUNCTION__));

	if (FLockStorageGetHolderId() == PsGetCurrentProcessId())
	{
		FLockStorageFlushFile();
		FLockStorageCloseFile();
	}

	if (g_flockStorage.initializationState == FALSE)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s error - you called this routine for uninitialized storage.\n", __FUNCTION__));
		return FALSE;
	}

	if ( !NT_SUCCESS(ExDeleteResourceLite(&g_flockStorage.lockRules)) )
    {
		return FALSE;
	}

	g_flockStorage.initializationState = FALSE;

	if (g_flockStorage.flockArray)
	{
		ExFreePool(g_flockStorage.flockArray);
		g_flockStorage.flockArray = 0;
		g_flockStorage.arrayLength = 0;
		g_flockStorage.arrayMaxLength = 0;
	}

	return TRUE;
}

BOOLEAN FLockStorageOpenFile()
{
	BOOLEAN result = FALSE;
	HANDLE hFile;
	IO_STATUS_BLOCK ioStatus = { 0 };
	OBJECT_ATTRIBUTES oaFile = { 0 };
	UNICODE_STRING usFilePath = { 0 };

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: called.\n", __FUNCTION__));

#pragma region SYNC_CRITICAL_SECTION

	KeEnterCriticalRegion();
	ExAcquireResourceExclusiveLite(&g_flockStorage.lockRules, TRUE);

	//
	// g_flockStorage.hFile should be equal to zero if it was not opened yet.
	//

	if (g_flockStorage.hFile == 0)
	{
		RtlInitUnicodeString(&usFilePath, g_storageFile);

		InitializeObjectAttributes(&oaFile, &usFilePath, /*OBJ_EXCLUSIVE |*/ OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

		NTSTATUS status = ZwCreateFile(&hFile,
			FILE_WRITE_DATA | FILE_READ_DATA,
			&oaFile,
			&ioStatus,
			NULL, // AllocationSize
			FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM /* FILE_ATTRIBUTE_NORMAL*/, // FileAttributes
			0, // FILE_SHARE_READ , Exclusive share access
			FILE_OPEN_IF,
			0, //FILE_DIRECTORY_FILE for directory
			NULL, //EaBuffer
			0); // EaLength

		if ( NT_SUCCESS(status) )
		{
			result = TRUE;
			g_flockStorage.hFile = hFile;

			g_flockStorage.holderId = PsGetCurrentProcessId();

			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: storage opened %wZ in 0x%x context.\n", __FUNCTION__, &usFilePath, g_flockStorage.holderId));
		}
		else
		{
			PT_DBG_PRINT(PTDBG_TRACE_ERRORS, ("FLock!%s: ZwCreateFile failed - couldn't open %wZ, status code is 0x%x.\n", __FUNCTION__, &usFilePath, status));
		}
	}
	else
	{
		PT_DBG_PRINT(PTDBG_TRACE_ERRORS, ("FLock!%s: failed - storage file was opened earlier.\n", __FUNCTION__));
	}
	
	ExReleaseResourceLite(&g_flockStorage.lockRules);
	KeLeaveCriticalRegion();

#pragma endregion SYNC_CRITICAL_SECTION

	return result;
}


EXTERN_C BOOLEAN FLockStorageIsOpened()
{
#pragma region SYNC_CRITICAL_SECTION

	KeEnterCriticalRegion();
	ExAcquireResourceSharedLite(&g_flockStorage.lockRules, TRUE);

	BOOLEAN opened = (g_flockStorage.hFile != 0);

	ExReleaseResourceLite(&g_flockStorage.lockRules);
	KeLeaveCriticalRegion();

#pragma endregion SYNC_CRITICAL_SECTION

	return opened;
}


EXTERN_C BOOLEAN FLockStorageCloseFile()
{
	BOOLEAN result = FALSE;

#pragma region SYNC_CRITICAL_SECTION

	KeEnterCriticalRegion();
	ExAcquireResourceExclusiveLite(&g_flockStorage.lockRules, TRUE);

	if (g_flockStorage.hFile)
	{
		NTSTATUS status = ZwClose(g_flockStorage.hFile);

        result = NT_SUCCESS(status);

		if(result)
		{
			g_flockStorage.hFile = 0;
			g_flockStorage.holderId = 0;
		}
		else
		{
			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: failed - couldn't close the storage file, status is 0x%x\n", __FUNCTION__, status));
		}
	}

	ExReleaseResourceLite(&g_flockStorage.lockRules);
	KeLeaveCriticalRegion();

#pragma endregion SYNC_CRITICAL_SECTION

	return result;
}


BOOLEAN FLockStorageLoadSection()
{
	BOOLEAN result = FALSE;
	PVOID pMappedTo = NULL;
	HANDLE hSection;
	IO_STATUS_BLOCK /*ioStatus = { 0 },*/ ioInf = { 0 };
	OBJECT_ATTRIBUTES /*oaFile = { 0 },*/ oaSection = { 0 };
	FILE_STANDARD_INFORMATION fileInfo = { 0 };
	//ULONG mapSize = 0;
	SIZE_T mapSize = 0;
	BOOLEAN firstLoad = FALSE;

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s called.\n", __FUNCTION__));

	LARGE_INTEGER maxStorageFileSize;
	maxStorageFileSize.HighPart = 0;
	maxStorageFileSize.LowPart = FLOCK_MAX_STORAGE_SIZE;

#pragma region SYNC_CRITICAL_SECTION

	KeEnterCriticalRegion();
	ExAcquireResourceExclusiveLite(&g_flockStorage.lockRules, TRUE);

	if (g_flockStorage.hFile)
	{
		NTSTATUS status = ZwQueryInformationFile(
			g_flockStorage.hFile,
			&ioInf,
			&fileInfo,
			sizeof(fileInfo),
			FileStandardInformation);

		if (!NT_SUCCESS(status))
		{
			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: error - ZwQueryInformationFile failed status code is 0x%x.\n", __FUNCTION__, status));
			goto _leave_and_exit;
		}

		if (fileInfo.EndOfFile.LowPart <= 1)
		{
			// It's an empty file.
			mapSize = (SIZE_T)(PAGE_SIZE * 2);

			firstLoad = TRUE;
		}
		else
		{
			// Map hole file.
			mapSize = fileInfo.EndOfFile.LowPart;
		}

		//PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: map size is %d bytes.\n", __FUNCTION__));

		InitializeObjectAttributes(&oaSection, NULL, /*OBJ_EXCLUSIVE |*/ OBJ_KERNEL_HANDLE, NULL, NULL);

		status = ZwCreateSection(&hSection,
			SECTION_ALL_ACCESS,
			&oaSection, // ObjectAttributes
			&maxStorageFileSize, // Max size
			PAGE_READWRITE,
			SEC_COMMIT,
			g_flockStorage.hFile);

		if (NT_SUCCESS(status))
		{
			status = ZwMapViewOfSection(
				hSection,
				ZwCurrentProcess(),
				&pMappedTo,
				(ULONG_PTR) NULL,
				mapSize, //CommitSize
				0, // PLARGE_INTEGER  SectionOffset,
				&mapSize, //PSIZE_T         ViewSize,
				ViewShare /*ViewUnmap*/, // SECTION_INHERIT InheritDisposition,
				0, // ULONG           AllocationType,
				PAGE_READWRITE // ULONG           Win32Protect
				);

			if (NT_SUCCESS(status))
			{
				PFLOCK_STORAGE_HEADER header = (PFLOCK_STORAGE_HEADER)pMappedTo;

				// Initialize format of on disk storage file with hard-coded signature. 
				if (firstLoad)
				{
					header->signature = FLOCK_STORAGE_SIGNATURE;
					header->length = 0;
				}

				g_flockStorage.hSection = hSection;
				g_flockStorage.mapSize = mapSize;
				g_flockStorage.pMappedData = pMappedTo;

				// Success.
				result = TRUE;

				PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: the Storage was loaded from file.\n", __FUNCTION__));
			}
			else
			{
				PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: ZwMapViewOfSection failed - can't map view of the storage file, status code is 0x%x.\n", __FUNCTION__, status));

				ZwClose(hSection);

				// I prefer not to touch that data.
				//g_flockStorage.hSection = 0;
				//g_flockStorage.mapSize = 0;
				//g_flockStorage.pMappedData = 0;
			}
		}
		else
		{
			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: error - ZwCreateSection failed, status code is 0x%x.\n", __FUNCTION__, status));
		}
	}
	else
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: failed - can't load storage, storage file is not opened.\n", __FUNCTION__));
	}

_leave_and_exit:

	ExReleaseResourceLite(&g_flockStorage.lockRules);
	KeLeaveCriticalRegion();

#pragma endregion SYNC_CRITICAL_SECTION

	// Flush just changed data.
	if (firstLoad) {
		FLockStorageFlushFile();
	}

	return result;
}


EXTERN_C BOOLEAN FLockStorageIsLoaded()
{
#pragma region SYNC_CRITICAL_SECTION

	KeEnterCriticalRegion();
	ExAcquireResourceSharedLite(&g_flockStorage.lockRules, TRUE);

	BOOLEAN loaded = (g_flockStorage.pMappedData != NULL);

	ExReleaseResourceLite(&g_flockStorage.lockRules);
	KeLeaveCriticalRegion();

#pragma endregion SYNC_CRITICAL_SECTION

	return loaded;
}


HANDLE FLockStorageGetHolderId()
{
	return g_flockStorage.holderId;
}


BOOLEAN FLockStorageIncreaseMap(
	ULONG _targetSize
	)
{
	BOOLEAN result = FALSE;

	NTSTATUS status = ZwUnmapViewOfSection(ZwCurrentProcess(), g_flockStorage.pMappedData);

	if (NT_SUCCESS(status))
	{
		// Forget about old data.
		g_flockStorage.pMappedData = NULL;
		g_flockStorage.mapSize = 0;

		status = ZwClose(g_flockStorage.hSection);

		if (NT_SUCCESS(status))
		{
			// Forget about old data.
			g_flockStorage.hSection = 0;

			HANDLE hSection = 0;
			OBJECT_ATTRIBUTES oaSection = { 0 };

			LARGE_INTEGER maxStorageFileSize;
			maxStorageFileSize.HighPart = 0;
			maxStorageFileSize.LowPart = _targetSize;

			InitializeObjectAttributes(&oaSection, NULL, /*OBJ_EXCLUSIVE |*/ OBJ_KERNEL_HANDLE, NULL, NULL);

			status = ZwCreateSection(&hSection,
				SECTION_ALL_ACCESS,
				&oaSection, // ObjectAttributes
				&maxStorageFileSize, // Max size
				PAGE_READWRITE,
				SEC_COMMIT,
				g_flockStorage.hFile);

			if (NT_SUCCESS(status))
			{
				// Save.
				g_flockStorage.hSection = hSection;

				SIZE_T /*ULONG*/ mappedAreaSize = _targetSize;
				PVOID pMappedAddress = NULL;

				status = ZwMapViewOfSection(hSection,
					ZwCurrentProcess(),
					&pMappedAddress,
					(ULONG_PTR) NULL,
					mappedAreaSize, //CommitSize
					0, // PLARGE_INTEGER  SectionOffset,
					&mappedAreaSize, //PSIZE_T         ViewSize,
					ViewShare /*ViewUnmap*/, // SECTION_INHERIT InheritDisposition,
					0, // ULONG           AllocationType,
					PAGE_READWRITE // ULONG           Win32Protect
					);

				if (NT_SUCCESS(status))
				{
					//
					// Success! The storage file size was increased.
					//
					result = TRUE;

					// Save.
					g_flockStorage.mapSize = mappedAreaSize;
					g_flockStorage.pMappedData = pMappedAddress;
				}
				else
				{
					PT_DBG_PRINT(PTDBG_TRACE_ERRORS, ("FLock!%s: failed - couldn't create mapview for the storage, ZwMapViewOfSection status code is 0x%x\n", __FUNCTION__, status));
				}
			}
			else
			{
				PT_DBG_PRINT(PTDBG_TRACE_ERRORS, ("FLock!%s: failed - couldn't create section for the storage, ZwCreateSection status code is 0x%x\n", __FUNCTION__, status));
			}
		}
		else
		{
			PT_DBG_PRINT(PTDBG_TRACE_ERRORS, ("FLock!%s: failed - couldn't close g_flockStorage.hSection, ZwClose status code is 0x%x\n", __FUNCTION__, status));
		}
	}
	else
	{
		PT_DBG_PRINT(PTDBG_TRACE_ERRORS, ("FLock!%s: failed - couldn't unmap g_flockStorage.pMappedData, ZwUnmapViewOfSection status code is 0x%x\n", __FUNCTION__, status));
	}

	return result;
}


BOOLEAN FLockStorageFlushFromMemoryToDisk()
{
	BOOLEAN result = FALSE;

	PT_DBG_PRINT(PTDBG_TRACE_ERRORS, ("FLock!%s\n", __FUNCTION__));

	// We can not flush data if storage file was not opened already.
	if (!FLockStorageIsOpened())
	{
		PT_DBG_PRINT(PTDBG_TRACE_ERRORS, ("FLock!%s: error - storage is not opened.\n", __FUNCTION__));
		return FALSE;
	}

	if (FLockStorageGetHolderId() != PsGetCurrentProcessId())
	{
		PT_DBG_PRINT(PTDBG_TRACE_ERRORS, ("FLock!%s: error - we can not flush data because holder id is 0x%x but now we are in 0x%x.\n", 
			__FUNCTION__,
			FLockStorageGetHolderId(),
			PsGetCurrentProcessId()));

		return FALSE;
	}

	// We can not flush data if we is not in a right context process.
// 	if (FLockStorageIsLoaded())
// 	{
// 		PT_DBG_PRINT(PTDBG_TRACE_ERRORS, ("FLock!%s: error - storage is loaded by other process.\n", __FUNCTION__));
// 		return FALSE;
// 	}
	
	// Create section in a right process context (we talk about 'System' process context) for flushing .
	if (!FLockStorageLoadSection())
	{
		PT_DBG_PRINT(PTDBG_TRACE_ERRORS, ("FLock!%s: error - could not load storage.\n", __FUNCTION__));
		return FALSE;
	}

	result = FLockStorageExportToSection();
	if (result)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ERRORS, ("FLock!%s: Success - flocks were exported.\n", __FUNCTION__));
	} else
	{
		PT_DBG_PRINT(PTDBG_TRACE_ERRORS, ("FLock!%s: error - could not export to storage.\n", __FUNCTION__));
	}

	if (!FLockStorageUnloadMap()) {
		PT_DBG_PRINT(PTDBG_TRACE_ERRORS, ("FLock!%s: error - could not unload map.\n", __FUNCTION__));
	}

	return result;
}


EXTERN_C BOOLEAN FLockStorageFlushFile()
{
	BOOLEAN result = FALSE;

#pragma region SYNC_CRITICAL_SECTION

	KeEnterCriticalRegion();
	ExAcquireResourceExclusiveLite(&g_flockStorage.lockRules, TRUE);

	if (g_flockStorage.hFile)
	{
		IO_STATUS_BLOCK ioblock = { 0 };
		result = NT_SUCCESS(ZwFlushBuffersFile(g_flockStorage.hFile, &ioblock));
	}

	ExReleaseResourceLite(&g_flockStorage.lockRules);
	KeLeaveCriticalRegion();

#pragma endregion SYNC_CRITICAL_SECTION

	return result;
}


EXTERN_C BOOLEAN FLockStorageUnloadMap()
{
	BOOLEAN result = FALSE;
	NTSTATUS status;

#pragma region SYNC_CRITICAL_SECTION

	KeEnterCriticalRegion();
	ExAcquireResourceExclusiveLite(&g_flockStorage.lockRules, TRUE);

	// Unmap earlier mapped file view.
	if (g_flockStorage.pMappedData)
	{
		status = ZwUnmapViewOfSection(ZwCurrentProcess(), g_flockStorage.pMappedData);

		if (NT_SUCCESS(status))
		{
			g_flockStorage.mapSize = 0;
			g_flockStorage.pMappedData = NULL;
		}
		else
		{
			PT_DBG_PRINT(PTDBG_TRACE_ERRORS, ("FLock!%s: failed - ZwUnmapViewOfSection failed for g_flockStorage.pMappedData, status code is 0x%x\n", __FUNCTION__, status));
			goto _leave_lock_and_exit;
		}
	}

	// Close section.
	if (g_flockStorage.hSection)
	{
		status = ZwClose(g_flockStorage.hSection);

		if (NT_SUCCESS(status))
		{
			g_flockStorage.hSection = 0;
		}
		else
		{
			PT_DBG_PRINT(PTDBG_TRACE_ERRORS, ("FLock!%s: failed - ZwClose failed for g_flockStorage.hSection, status code is 0x%x\n", __FUNCTION__, status));
			goto _leave_lock_and_exit;
		}
	}

	// Flush file's data.
	if (g_flockStorage.hFile)
	{
		IO_STATUS_BLOCK ioblock = { 0 };
		status = ZwFlushBuffersFile(g_flockStorage.hFile, &ioblock);

		if ( !NT_SUCCESS(status) )
		{
			PT_DBG_PRINT(PTDBG_TRACE_ERRORS, ("FLock!%s: failed - ZwFlushBuffersFile failed, status code is 0x%x\n", __FUNCTION__, status));
		}
	}

	// All resources left correctly.
	result = TRUE;

_leave_lock_and_exit:

	ExReleaseResourceLite(&g_flockStorage.lockRules);
	KeLeaveCriticalRegion();

#pragma endregion SYNC_CRITICAL_SECTION

	return result;
}
