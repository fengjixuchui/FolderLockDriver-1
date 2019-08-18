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


/* Max size for the storage. */
#define FLOCK_MAX_STORAGE_SIZE		(1024 * 1024 * 10)
#define STORAGE_BASE_ARRAY_SIZE		50
#define FLOCK_STORAGE_SIGNATURE		0x12FA7788
#define FLOCK_ID_SIZE				16


//////////////////////////////////////////////////////////////////////////
//
// Structures are defined here.
//

#pragma pack(push, 1)

typedef struct _FLOCK_ID
{
	// Id is a signature which unique describes FLock.
	// Actually, this is md5 hash which calculates one time.
	//
	UCHAR id[16];
}FLOCK_ID, *PFLOCK_ID;

typedef struct _FLOCK_STORAGE_HEADER
{
	DWORD signature; // = FLOCK_STORAGE_SIGNATURE;
	ULONG length;

} FLOCK_STORAGE_HEADER, *PFLOCK_STORAGE_HEADER;

typedef struct _FLOCK_STORAGE_ENTRY
{
	UCHAR version;
	UCHAR id[16];
	ULONG32 flockFlag;
}FLOCK_STORAGE_ENTRY, *PFLOCK_STORAGE_ENTRY;

typedef struct _FLOCK_STORAGE
{
	ERESOURCE	lockRules;

	// Id of the process in which context storage file was opened.
	HANDLE		holderId;

	//
	// Lock map area.
	//
	//////////////////////////////////////////////////////////////////////////
	HANDLE		hFile;
	HANDLE		hSection;
	PVOID		pMappedData;
	SIZE_T		mapSize;
	// LARGE_INTEGER mapFileSize;
	//////////////////////////////////////////////////////////////////////////

	//
	// Lock array area.
	//
	//////////////////////////////////////////////////////////////////////////
	//FLOCK_TIME_STAMP changeStamp;
	BOOLEAN		hasUserObjectsToHide; // TRUE if storage has one or more objects to hide.
	BOOLEAN		hasUserObjectsToLock; // TRUE if storage has one or more objects with locked access policy.
	ULONG		arrayLength;
	ULONG		arrayMaxLength; // Max size of flockArray. 
	PFLOCK_STORAGE_ENTRY flockArray; // NonPaged buffer.
	//////////////////////////////////////////////////////////////////////////

	BOOLEAN initializationState; // Zero if the storage is not initialized.

} FLOCK_STORAGE, *PFLOCK_STORAGE;

#pragma pack(pop)


ULONG FLockStorageGetFlocksCount();


//
// Initializes synchronization primitives for future work.
// Please, do not call that function twice and more times.
//
BOOLEAN FLockStorageInit();


//
// Returns TRUE if internal storage structures initialized.
//
EXTERN_C BOOLEAN FLockStorageIsInitialized();


//
// Does completely opposite actions to FLockStorageInit(..):
// - Delete all earlier initialized synchronization objects.
// - If you have ever called FLockStorageInit(..) that you should called this routine and only once.
//
EXTERN_C BOOLEAN FLockStorageDeinitialize();

//
// Before to flush data from memory to disk, it also verifies context of the process in which file was opened.
// It protects us from using handles in invalid process context.
//
BOOLEAN FLockStorageFlushFromMemoryToDisk();


//
// Creates or opens the storage file exclusively.
//
BOOLEAN FLockStorageOpenFile();

//
// Returns TRUE if the storage file was exclusively opened.
//
EXTERN_C BOOLEAN FLockStorageIsOpened();

//
// Creates mapping of the storage file into memory.
// Notes:
//		This function do not copy data from disk into memory!
//		That does separate function.
//
BOOLEAN FLockStorageLoadSection();

//
// Returns TRUE if storage data was mapped into memory.
//
EXTERN_C BOOLEAN FLockStorageIsLoaded();

//
// Returns ID of process in which context storage was opened.
//
HANDLE FLockStorageGetHolderId();

//
// Close handle of previously opened file of the storage, using ZwClose(..) call.
//
EXTERN_C BOOLEAN FLockStorageCloseFile();

//
// Increases file file mapping view to target size.
//
BOOLEAN FLockStorageIncreaseMap(
	ULONG _targetSize
	);

//
// Returns TRUE only if storage loaded and has right signature.
//
EXTERN_C BOOLEAN FLockStorageIsValid();

//
// Imports all storage information about FLocks into NonPaged memory.
// I.e. It makes a second copy of already mapped data.
//
EXTERN_C BOOLEAN FLockStorageImport();

//
// Writes all FLocks entries from an array in non-paged memory to mapped file on disk.
//
BOOLEAN FLockStorageExportToSection();


EXTERN_C BOOLEAN FLockStorageUnloadMap();

EXTERN_C BOOLEAN FLockStorageFlushFile();


EXTERN_C BOOLEAN FLockStorageAdd(
	PUCHAR _flockId, // Pointer to UCHAR[16] array.
	ULONG actionPolicy
	);


EXTERN_C BOOLEAN FLockStorageAddWithFlush(
	PUCHAR _flockId, // Pointer to UCHAR[16] array.
	ULONG flockFlag
	);


EXTERN_C BOOLEAN FLockStorageRemove(
	PUCHAR _flockId // Pointer to UCHAR[16] array.
	);


//
// Clears all entries in memory and on disk.
//
EXTERN_C VOID FLockStorageClearInMemory();

//
// Makes copy of all available FLocks.
//
// _useNonPagedMemory - does it need to allocate NonPaged memory? TRUE if it is.
// _copiedNumbers - count copied entries.
// _poutBuffer - array with entries, do not forget to free memory allocated for using ExFreePool(..).
//
EXTERN_C BOOLEAN FLockStorageGetAll(
	__in BOOLEAN _useNonPagedMemory,
	__out PULONG _copiedNumbers,
	__out PFLOCK_STORAGE_ENTRY* _poutBuffer
	);


EXTERN_C BOOLEAN FLockStorageLookup(
	__in PUCHAR _flockId, // Pointer to UCHAR[16] array.
	__out PFLOCK_STORAGE_ENTRY _foundResult
	);

EXTERN_C BOOLEAN FLockStorageIsPresent(
	__in PUCHAR _flockId // Pointer to UCHAR[16] array.
	);

// Returns TRUE if the flock with specified identificator is in storage
// and has locked access rule.
//
EXTERN_C BOOLEAN FLockStorageVerifyLock(
	__in PFLOCK_ID _flockId // Pointer to UCHAR[16] array.
	);

BOOLEAN FLockStorageDirHasFlocks(
	__in PFLOCK_ID _flockId
);

BOOLEAN FLockStorageVerifyHidding(
	__in PFLOCK_ID _flockId
	);

EXTERN_C BOOLEAN FLockStorageVerifyFlag(
	__in PFLOCK_ID _flockId, // Pointer to UCHAR[16] array.
	__in DWORD	_flag
	);

EXTERN_C BOOLEAN FLockStorageUpdateEntry(
	__in PFLOCK_STORAGE_ENTRY _changedEntry
	);

EXTERN_C BOOLEAN FLockStorageUpdateFlags(
	__in PFLOCK_ID _flockId,
	__in ULONG _newFlags
	);

//
// Returns TRUE if the storage has one or more hidden user files.
//
EXTERN_C BOOLEAN FLockStorageHasHiddenUserObjects();

//
// Returns TRUE if the storage has one or more user files to with locked access.
//
EXTERN_C BOOLEAN FLockStorageHasLockedUserObjects();
