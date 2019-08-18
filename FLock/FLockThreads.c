//
// Author:
//		Burlutsky Stas
//
//		burluckij@gmail.com
//

#include "FLock.h"
#include "FLockCache.h"
#include "FLockStorage.h"

extern ULONG gTraceFlags;


//
// Kernel thread routine.
//

VOID FLockStorageLoader(
	PVOID _context
	)
{
	UNREFERENCED_PARAMETER(_context);

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("\nFLock!%s.\n", __FUNCTION__));

	PFLOCK_DEVICE_DATA pFLockEngine = FLockData();

	//
	// Exit if storage was loaded already.
	//

	if (FLockStorageGetFlocksCount() != 0)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: was loaded already.\n", __FUNCTION__));

		//
		// Ok, go away, flocks were read from storage already.
		//

		pFLockEngine->storageLoaderFinished = TRUE;
		PsTerminateSystemThread(0);
	}

	//
	// We need to have that own thread because of problems with ability to open storage file.
	// On early system loading steps file system could be not available, that is why we need to wait some time,
	// until system loads and initiates file system drivers.
	//

	NTSTATUS status = STATUS_UNSUCCESSFUL;
	LARGE_INTEGER interval;

	//
	// At first we should open our storage file.
	//

	while (!FLockStorageIsOpened())
	{
		if (FLockStorageOpenFile())
		{
			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: xfile was opened.\n", __FUNCTION__));
		}
		else
		{
			PT_DBG_PRINT(PTDBG_TRACE_ERRORS, ("FLock!%s: error - can't opened x.\n", __FUNCTION__));
		}

		// Sleep 1 second and repeat to open the storage.
		interval.QuadPart = -10000000;

		KeDelayExecutionThread(KernelMode, FALSE, &interval);
	}

	//
	// Than we need to import all available data from kernel storage file.
	// Important thing to know - file should be mapped only in context of 'System' process.
	//

	while (!FLockStorageIsLoaded())
	{
		if (FLockStorageLoadSection())
		{
			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: Storage was load.\n", __FUNCTION__));
		}
		else
		{
			PT_DBG_PRINT(PTDBG_TRACE_ERRORS, ("FLock!%s: error - could not load.\n", __FUNCTION__));
		}

		interval.QuadPart = -10000000;
		KeDelayExecutionThread(KernelMode, FALSE, &interval);
	}

	//
	// When storage loaded, it is require to verify the signature. 
	// May be it was corrupted, changed, hacked by someone?
	//

	if (!FLockStorageIsValid())
	{
		//
		//	I think it would be fair to clear all storage file and remove all.
		//

		PT_DBG_PRINT(PTDBG_TRACE_ERRORS, ("FLock!%s: error - storage is corrupted. Require to do recovery operations.\n", __FUNCTION__));
	}

	if (!FLockStorageImport())
	{
		//
		// This error could be if system does not have enough memory to hold all flocks.
		// But it is something unbelievable.
		//

		PT_DBG_PRINT(PTDBG_TRACE_ERRORS, ("FLock!%s: error - could not import flocks.\n", __FUNCTION__));
	}
	else
	{
		PT_DBG_PRINT(PTDBG_TRACE_ERRORS, ("FLock!%s: Count of read flocks is %d.\n", __FUNCTION__, FLockStorageGetFlocksCount()));
	}

	if (FLockCacheIsEnabled()) {
		FLockCacheEraseOneCall();
	}

	FLockStampUpdate(NULL);

	if (!FLockStorageUnloadMap())
	{
		PT_DBG_PRINT(PTDBG_TRACE_ERRORS, ("FLock!%s: error happened while unload data process.\n", __FUNCTION__));
	}

	//
	// Here we should leave storage file opened to protected data from unknown access.
	//

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: finished.\n", __FUNCTION__));

	//
	// Just leave note that loader did its job.
	//

	pFLockEngine->storageLoaderFinished = TRUE;

	//
	// Ok. Storage was loaded completely. Finish that current thread.
	//

	PsTerminateSystemThread(0);
}


//
// This thread is responsible for flushing flocks copy from memory to hard disk.
// Flushing process activates by signaling internal KEVENT object.
//

VOID FLockStorageFlusher(
	PVOID _context
	)
{
	UNREFERENCED_PARAMETER(_context);

	PFLOCK_DEVICE_DATA pFLockEngine = FLockData();

	for (;;)
	{
		//
		// Wait till somebody asks to flush changes.
		//

		NTSTATUS status = KeWaitForSingleObject(&pFLockEngine->eventFlush, Executive, KernelMode, FALSE, NULL);

		if ((status == STATUS_SUCCESS) || (status == STATUS_ALERTED))
		{
			if (FLockStorageFlushFromMemoryToDisk())
			{
				PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("\nFLock!%s: Data was flushed successfully.\n", __FUNCTION__));
			}
			else
			{
				PT_DBG_PRINT(PTDBG_TRACE_ERRORS, ("FLock!%s: error - failed to flush.\n", __FUNCTION__));
			}
		}

		if (FLockDoesItRequireToStop())
		{
			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: it is require to stop.\n", __FUNCTION__));
			break;
		}
	}

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: finished.\n", __FUNCTION__));

    pFLockEngine->flusherFinished = TRUE;

	PsTerminateSystemThread(0);
}

//////////////////////////////////////////////////////////////////////////
