/*++

Module Name:

    FLock.c

Abstract:

    This is the main module of the FLock miniFilter driver.

Environment:

    Kernel mode

Author:
	
	Burlutsky Stanislav (burluckij@gmail.com)

Creation time:
	
	12.05.2018 21:10:12

--*/

#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>

#include "flock.h"
#include "FLockStorage.h"
#include "FLockCache.h"
#include "FLockCrypt.h"

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

//////////////////////////////////////////////////////////////////////////
// Потомкам =)
//////////////////////////////////////////////////////////////////////////
static char AuthorsMessage[] = "\nThis is a Data Guard file system lock driver.\n"\
"Developer: Burlutsky Stas burluckij@gmail.com\n"\
"\n\tProtect your data - protect your right to have privacy!\n"\
"\twww.dguard.org\n\n";
//////////////////////////////////////////////////////////////////////////

ULONG_PTR OperationStatusCtx = 1;
FLOCK_DEVICE_DATA g_flockData;
ULONG gTraceFlags = 0;
ANSI_STRING g_flockMetaName;
char* dataw = FLOCK_META_NAME;


/*************************************************************************
    Prototypes
*************************************************************************/

DRIVER_INITIALIZE DriverEntry;
NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    );

NTSTATUS
FLockInstanceSetup (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    );

VOID
FLockInstanceTeardownStart (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    );

VOID
FLockInstanceTeardownComplete (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    );

NTSTATUS
FLockUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    );

NTSTATUS
FLockInstanceQueryTeardown (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    );

VOID
FLockContextCleanup(
	_In_ PFLT_CONTEXT Context,
	_In_ FLT_CONTEXT_TYPE ContextType
);


//
//  Assign text sections for each routine.
//

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, FLockUnload)
#pragma alloc_text(PAGE, FLockInstanceQueryTeardown)
#pragma alloc_text(PAGE, FLockInstanceSetup)
#pragma alloc_text(PAGE, FLockInstanceTeardownStart)
#pragma alloc_text(PAGE, FLockInstanceTeardownComplete)
#endif

//
//  Operation registration
//	Here we notify filter manager about which IRP packets we want to process
//

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {

    {
		IRP_MJ_CREATE,
		0,
		FLockPreCreate,
		FLockPostCreate,
		NULL
	},

	{
		IRP_MJ_DIRECTORY_CONTROL,
		0,
		FLockPreDirectoryControl,
		FLockPostDirectoryControl,
		NULL
	},

	{
		IRP_MJ_QUERY_EA,
		0,
		FLockPreQueryEa,
		FLockPostQueryEa,
		NULL
	},

	{
		IRP_MJ_SET_EA,
		0,
		FLockPreSetEa,
		FLockPostSetEa,
		NULL
	},

    { IRP_MJ_OPERATION_END }
};

const FLT_CONTEXT_REGISTRATION ContextRegistration[] = {

	{ FLT_VOLUME_CONTEXT,
	0,
	FLockContextCleanup,
	sizeof(FLOCK_FLT_CONTEXT),
	FLOCK_CONTEXT_TAG },

	{ FLT_FILE_CONTEXT,
	0,
	FLockContextCleanup,
	sizeof(FLOCK_FLT_CONTEXT),
	FLOCK_CONTEXT_TAG },

	{ FLT_CONTEXT_END }
};

//
//  This defines what we want to filter with FltMgr
//

CONST FLT_REGISTRATION FilterRegistration = {

    sizeof( FLT_REGISTRATION ),         //  Size
    FLT_REGISTRATION_VERSION,           //  Version
    0,                                  //  Flags
	ContextRegistration,                //  Context
    Callbacks,                          //  Operation callbacks
    FLockUnload,                        //  MiniFilterUnload
    FLockInstanceSetup,                 //  InstanceSetup
    FLockInstanceQueryTeardown,         //  InstanceQueryTeardown
    FLockInstanceTeardownStart,         //  InstanceTeardownStart
    FLockInstanceTeardownComplete,      //  InstanceTeardownComplete
	NULL,                               //  GenerateFileName
	NULL,                               //  GenerateDestinationFileName
	NULL,                               //  NormalizeNameComponent
	NULL,								//  TransactionNotification

#if FLT_MGR_WIN8
	NULL,
#endif

	NULL                                //  NormalizeNameComponentEx
};


PFLOCK_DEVICE_DATA FLockData()
{
	return &g_flockData;
}


BOOLEAN FLockUseContextHelp()
{
	return FLockData()->ctxEnabled;
}


VOID FLockContextEnable(BOOLEAN _enable)
{
	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("FLock!%s: Ctxs enabled - %d, old state %d.\n",
		__FUNCTION__,
		_enable,
		FLockData()->ctxEnabled));

	FLockData()->ctxEnabled = _enable;
}

VOID FLockRegisterServiceProcess(
	__in PEPROCESS _process
	)
{
	// ... lock ...
	FLockData()->serviceProcess = _process;
	FLockData()->serviceProcessId = (DWORD)PsGetProcessId(_process);
	// ... unlock ...
}


VOID FLockUnregisterServiceProcess()
{
	// ... lock ...
	FLockData()->serviceProcess = NULL;
	FLockData()->serviceProcessId = 0;
	// ... unlock ...
}


PEPROCESS FLockGetServiceProcess()
{
	return g_flockData.serviceProcess;
}


DWORD FLockGetServiceProcessId()
{
	return g_flockData.serviceProcessId;
}


void FLockStampGenerate(
	PFLOCK_TIME_STAMP _stamp
	)
{
	if (_stamp)
	{
		KeQueryTickCount(&_stamp->stamp);
	}
}

VOID FLockStampUpdate(
	__out PFLOCK_TIME_STAMP _newStamp
	)
{
	FLOCK_TIME_STAMP newGeneratedStale = { 0 };
	FLockStampGenerate(&newGeneratedStale);

	LONGLONG comperand = g_flockData.ctxLastStamp.stamp.QuadPart;

	LONGLONG oldStamp = InterlockedCompareExchange64(
		&g_flockData.ctxLastStamp.stamp.QuadPart,
		newGeneratedStale.stamp.QuadPart,
		comperand);

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES | PTGBG_TRACE_CONTEXT,
		("FLock!%s: Main context stamp is updated, old value %lld, new %lld.\n",
		__FUNCTION__,
		oldStamp,
		newGeneratedStale.stamp.QuadPart));

	if (_newStamp)
	{
		RtlCopyMemory(_newStamp, &newGeneratedStale, sizeof(newGeneratedStale));
	}
}


BOOLEAN FLockStampIsStale(
	PFLOCK_TIME_STAMP _timeStamp
	)
{
	return (_timeStamp->stamp.QuadPart < g_flockData.ctxLastStamp.stamp.QuadPart);
}


BOOLEAN FLockAreWeInServiceProcessContext()
{
	DWORD servPid = FLockGetServiceProcessId();
	PEPROCESS servProcess = FLockGetServiceProcess();
	PEPROCESS currentProcess = PsGetCurrentProcess();
	DWORD currentPid = (HANDLE)PsGetProcessId(currentProcess);

	return (servProcess == currentProcess) && (servPid == currentPid);
}

//
//	This procedure starts each time when a process creates or terminates.
//

void FLockNotifyRoutineProcessCreated(
	PEPROCESS _pEPROCESS,
	HANDLE _processId,
	PPS_CREATE_NOTIFY_INFO _createInfo
	)
{
	UNREFERENCED_PARAMETER(_pEPROCESS);

	if (_createInfo == NULL)
	{
		//
		//	This is a process termination event.
		//

		if (FLockGetServiceProcessId() == (DWORD)_processId)
		{
			//
			//	It is a termination of manager service process.
			//	Update internal information.
			//

			FLockUnregisterServiceProcess();

			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: Warning! Managing service process is terminating - %d.\n",
				__FUNCTION__,
				_processId));
		}
	}
}

VOID FLockPrintMeta(
	__in PFLOCK_META _info
	)
{
	if (_info)
	{
		PUCHAR p = _info->uniqueId;
		PUCHAR k = _info->signature;

		DbgPrint("FLock!%s: .version = 0x%x .flags = 0x%x .uniqieId = %x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x, .signature = %x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x\n",
			__FUNCTION__,
			_info->version,
			_info->flags,
			p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15],
			k[0], k[1], k[2], k[3], k[4], k[5], k[6], k[7], k[8], k[9], k[10], k[11], k[12], k[13], k[14], k[15]
			);
	}
}

BOOLEAN FLockDriverPrepareStorage()
{
	BOOLEAN storageLoadedSucessfully = FALSE;

	if (FLockStorageOpenFile())
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: storage is loaded.\n", __FUNCTION__));

		if (FLockStorageLoadSection())
		{
			storageLoadedSucessfully = FLockStorageImport();

			if (!storageLoadedSucessfully)
			{
				PT_DBG_PRINT(PTDBG_TRACE_ERRORS, ("FLock!%s: error - couldn't import data.\n", __FUNCTION__));
			}

			if ( !FLockStorageUnloadMap() )
			{
				PT_DBG_PRINT(PTDBG_TRACE_ERRORS, ("FLock!%s: error - could not unload storage map.\n", __FUNCTION__));
			}
		}
		else
		{
			PT_DBG_PRINT(PTDBG_TRACE_ERRORS, ("FLock!%s: FLockStorageLoad failed.\n", __FUNCTION__));
		}
	}
	else
	{
		PT_DBG_PRINT(PTDBG_TRACE_ERRORS, ("FLock!%s: error - storage was not loaded.\n", __FUNCTION__));
	}

	return storageLoadedSucessfully;
}

EXTERN_C VOID FLockDriverCloseStorage()
{
	BOOLEAN loaded = FALSE;

	if (FLockStorageIsOpened())
	{
		//
		// Do we have something to flush?
		//

		if (FLockStorageGetFlocksCount() > 0)
		{
			//
			// Load storage data if it was not loaded yet.
			//
			loaded = FLockStorageIsLoaded();

			if (!loaded)
			{
				loaded = FLockStorageLoadSection();
			}

			// Flush data if we have something to flush.
			if (loaded)
			{
				FLockStorageExportToSection();

				FLockStorageFlushFile();

				FLockStorageUnloadMap();
			}

			FLockStorageCloseFile();
		}
	}

	FLockStorageDeinitialize();
}

void FLockStopInternals()
{
    //
	//  'Signal' about termination process.
	//
    g_flockData.stopAll = TRUE;

	FLockSyncGenerateFlushEvent();

	// Generate terminate event.
	// ... not implemented yet ...

    //
    //  Wait until flusher thread is finished.
    //
    for (; !FLockData()->flusherFinished; );

	// Delete create process notification handler from system.
	if (g_flockData.createProcessNotificatorRegistered)
	{
        NTSTATUS status = PsSetCreateProcessNotifyRoutineEx((PCREATE_PROCESS_NOTIFY_ROUTINE_EX)FLockNotifyRoutineProcessCreated, TRUE);
		if (NT_SUCCESS(status))
		{
			g_flockData.createProcessNotificatorRegistered = FALSE;
		}
	}

	if (FLockStorageIsOpened())
	{
		if (!FLockStorageCloseFile())
		{
			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: warning - storage file was not closed.\n", __FUNCTION__));
		}
	}
	else
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: warning - storage was not opened yet.\n", __FUNCTION__));
	}

	//	Close loader thread object.
	if (g_flockData.storageLoaderThreadObj)
	{
		ObDereferenceObject(g_flockData.storageLoaderThreadObj);
		g_flockData.storageLoaderThreadObj = NULL;
	}

	//	Close flusher thread.
	if (g_flockData.storageFlusherThreadObj)
	{
		ObDereferenceObject(g_flockData.storageFlusherThreadObj);
		g_flockData.storageFlusherThreadObj = NULL;
	}
}


/*************************************************************************
	MiniFilter entry point.
*************************************************************************/


NTSTATUS
DriverEntry(
_In_ PDRIVER_OBJECT DriverObject,
_In_ PUNICODE_STRING RegistryPath
)
{
	NTSTATUS status = STATUS_SUCCESS;
	BOOLEAN needCleanup = FALSE;

	RtlZeroMemory(&g_flockData, sizeof(FLOCK_DEVICE_DATA));

	DbgPrint("%s", AuthorsMessage);

    uint64_t  key = 0x5f920;
    FLockCryptEncodeData(AuthorsMessage, sizeof(AuthorsMessage), key, 10);
    FLockCryptDecodeData(AuthorsMessage, sizeof(AuthorsMessage), key, 10);

    DbgPrint("Decoded message: %s", AuthorsMessage);

	//
	// Set flags about information messages which we want to see in DbgView application.
	//

	gTraceFlags |= PTDBG_TRACE_FULL;
	//gTraceFlags = PTGBG_FLOCK_CACHE;

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: registry path is %wZ.\n", __FUNCTION__, RegistryPath));

	KeInitializeEvent(&g_flockData.eventFlush, SynchronizationEvent /*NotificationEvent*/, FALSE);

	//
	// Before to work with our kernel-mode storage we need to initialize synchronization objects
	// and some internal variables which describe internal state (enabled\disabled).
	//

	if ( !FLockStorageInit() )
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: error - couldn't initialize flocks storage.\n", __FUNCTION__));
		return STATUS_UNSUCCESSFUL;
	}

	//
	// Prepare cache for future work - init synchronization primitives, internal variables, allocate memory for cache table.
	//

	if ( !FLockCacheInit() )
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: error - couldn't initialize cache.\n", __FUNCTION__));
		return STATUS_UNSUCCESSFUL;
	}

	//
	//	Try to load storage from file right to kernel-mode memory in context of current thread (which is 'System' process).
	//	On early steps of operation system loading driver could not load storage from disk file
	//	(that's because of file-system could not be prepared yet and some drives is not mounted).
	//	In that case we need create separate kernel thread which will load storage later, file system fill be prepared. 
	//

	BOOLEAN storageLoaded = FLockDriverPrepareStorage();
	if (!storageLoaded)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: error - the storage was not prepared to work with us, load later.\n", __FUNCTION__));
	}

	//
	//	Register create process notification routine.
	//

	status = PsSetCreateProcessNotifyRoutineEx((PCREATE_PROCESS_NOTIFY_ROUTINE_EX)FLockNotifyRoutineProcessCreated, FALSE);
	g_flockData.createProcessNotificatorRegistered = NT_SUCCESS(status);
	if (!NT_SUCCESS(status))
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: 0x%x error - could not register crproc notification routine.\n", __FUNCTION__, status));
		// Now it is not so important to fail hole initialization process.
		// goto cleanup;
	}

	RtlInitUnicodeString(&g_flockData.deviceNameUnicodeString, FLOCK_DEVICE_NAME);
	RtlInitUnicodeString(&g_flockData.deviceLinkUnicodeString, FLOCK_DEVICE_LINK);

	status = IoCreateDevice(DriverObject,
		0,
		&g_flockData.deviceNameUnicodeString,
		FLOCK_DEVICE,
		FILE_DEVICE_SECURE_OPEN, // 0
		FALSE, // TRUE
		&g_flockData.deviceObject);

	if (!NT_SUCCESS(status))
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: failed to create device, status code is 0x%x (%d)\n", __FUNCTION__, status, status));
		goto cleanup_device;
	}

	status = IoCreateSymbolicLink(&g_flockData.deviceLinkUnicodeString, &g_flockData.deviceNameUnicodeString);

	if (!NT_SUCCESS(status))
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: failed to create symbolic link, status code is 0x%x (%d)\n", __FUNCTION__, status, status));
		goto cleanup_symlink;
	}

	g_flockData.driverObject = DriverObject;
	
	//
	//	Prepare driver for using context's help.
	//

	FLockStampUpdate(NULL);
	g_flockData.ctxEnabled = TRUE;

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: Device was successfully created.", __FUNCTION__));

	//
	//  Register with FltMgr to tell it our callback routines.
	//

	status = FltRegisterFilter(DriverObject, &FilterRegistration, &g_flockData.filterHandle);

	FLT_ASSERT(NT_SUCCESS(status));

	if (NT_SUCCESS(status))
	{
		//
		//  Start filtering i/o
		//

		status = FltStartFiltering(g_flockData.filterHandle);

		if (!NT_SUCCESS(status))
		{
			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: failed to start the mini-filter, status code is 0x%x (%d)\n", __FUNCTION__, status, status));
			goto cleanup_unregister_filter;
		}
	}
	else
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: failed to register the mini-filter, status code is 0x%x (%d)\n", __FUNCTION__, status, status));
		goto cleanup_symlink;
	}

	//
	//	Create storage loader thread.
	//

	HANDLE hStorageLoader;
	status = PsCreateSystemThread(
		&hStorageLoader,
		THREAD_ALL_ACCESS,
		NULL,
		NULL,
		NULL,
		(PKSTART_ROUTINE)FLockStorageLoader,
		NULL
		);

	if (NT_SUCCESS(status))
	{
		status = ObReferenceObjectByHandle(
			hStorageLoader,
			0,
			NULL,
			KernelMode,
			&g_flockData.storageLoaderThreadObj,
			NULL
			);

		if (NT_SUCCESS(status))
		{
			ZwClose(hStorageLoader);
		}
		else 
		{
			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: 0x%x error - could not get ref to loader object.\n", __FUNCTION__, status));
		}
	}
	else
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: 0x%x error - could not create loader thread.\n", __FUNCTION__, status));
		goto cleanup_loader;
	}

	//
	//	Create Flusher thread.
	//

	HANDLE hFlusher;
	status = PsCreateSystemThread(
		&hFlusher,
		THREAD_ALL_ACCESS,
		NULL,
		NULL,
		NULL,
		(PKSTART_ROUTINE)FLockStorageFlusher,
		NULL
		);

	if (NT_SUCCESS(status))
	{
		status = ObReferenceObjectByHandle(
			hFlusher,
			0,
			NULL,
			KernelMode,
			&g_flockData.storageFlusherThreadObj,
			NULL
			);

		if (NT_SUCCESS(status)) {

			ZwClose(hFlusher);
		}
		else {
			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: 0x%x error - could not get ref to flusher object.\n", __FUNCTION__, status));
		}
	}
	else
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: 0x%x error - could not create flusher thread.\n", __FUNCTION__, status));
		goto cleanup_flusher;
	}

	//
	// Register IRP handler. We have one handler on all requests.
	//

	DriverObject->MajorFunction[IRP_MJ_SHUTDOWN] =
	DriverObject->MajorFunction[IRP_MJ_CREATE] =
	DriverObject->MajorFunction[IRP_MJ_READ] =
	DriverObject->MajorFunction[IRP_MJ_WRITE] =
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = FLockSuccessDispatcher;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = FLockDeviceControlDispatcher;

	//
	// User should have no an opportunity to unload the driver.
	//

	DriverObject->DriverUnload = DriverUnload; // Uncomment for tests only.

	if (needCleanup)
	{
	cleanup_flusher:
		if (g_flockData.storageLoaderThreadObj) {
			ObDereferenceObject(g_flockData.storageLoaderThreadObj);
			g_flockData.storageLoaderThreadObj = 0;
		}

	cleanup_loader:

	cleanup_unregister_filter:
		FltUnregisterFilter(g_flockData.filterHandle);

	cleanup_symlink:
		IoDeleteSymbolicLink(&g_flockData.deviceLinkUnicodeString);

	cleanup_device:
		IoDeleteDevice(g_flockData.deviceObject);

		FLockStorageDeinitialize();

		FLockCacheDeinitialyze();

		if (g_flockData.createProcessNotificatorRegistered) {
			g_flockData.createProcessNotificatorRegistered = NT_SUCCESS(PsSetCreateProcessNotifyRoutineEx((PCREATE_PROCESS_NOTIFY_ROUTINE_EX)FLockNotifyRoutineProcessCreated, TRUE));
		}

		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("\nFLock!%s: Driver loading failed.\n", __FUNCTION__));
	}
	else
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("\nFLock!%s: Driver was successfully loaded and initialized.\n", __FUNCTION__));
	}

	return status;
}

VOID FLockStop()
{
	g_flockData.stopAll = TRUE;
}

BOOLEAN FLockDoesItRequireToStop()
{
	return g_flockData.stopAll;
}

void FLockSyncGenerateFlushEvent()
{
	KeSetEvent(&g_flockData.eventFlush, 0, FALSE);
}

void DriverUnload(
	IN PDRIVER_OBJECT pDrvObj
	)
{
	UNREFERENCED_PARAMETER(pDrvObj);

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: Driver is going to be unloaded.", __FUNCTION__));

    UNICODE_STRING filterName = { 0 };
    RtlInitUnicodeString(&filterName, FLOCK_FILTER_NAME);
    NTSTATUS status = FltUnloadFilter(&filterName);

    if (NT_SUCCESS(status))
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: filter was successfully unloaded.", __FUNCTION__));
    }
    else
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES | PTDBG_TRACE_ERRORS, ("FLock!%s: error 0x%x - failed to unload filter.", __FUNCTION__, status));
    }

	FLockStopInternals();

    //
    //  Close all resources (cache and flock's storage) used by filter handlers only after completion execution of handlers itself.
    //  All filter contexts are freed implicitly by filter manager.
    //

    FLockStorageDeinitialize();

	FLockCacheDisable();
	FLockCacheDeinitialyze();

	IoDeleteSymbolicLink(&g_flockData.deviceLinkUnicodeString);
	IoDeleteDevice(g_flockData.deviceObject);
}

NTSTATUS
FLockInstanceSetup (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    )
/*++

Routine Description:

    This routine is called whenever a new instance is created on a volume. This
    gives us a chance to decide if we need to attach to this volume or not.

    If this routine is not defined in the registration structure, automatic
    instances are always created.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Flags describing the reason for this attach request.

Return Value:

    STATUS_SUCCESS - attach
    STATUS_FLT_DO_NOT_ATTACH - do not attach

--*/
{
    UNREFERENCED_PARAMETER( Flags );

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!FLockInstanceSetup: VolumeDeviceType 0x%x, VolumeFilesystemType 0x%x.\n", VolumeDeviceType, VolumeFilesystemType));

	NTSTATUS	status = STATUS_SUCCESS;
	BOOLEAN		isWritable = FALSE;

	PAGED_CODE();

	//return STATUS_SUCCESS;

	if (FILE_DEVICE_DISK_FILE_SYSTEM != VolumeDeviceType)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: not FILE_DEVICE_DISK_FILE_SYSTEM.\n", __FUNCTION__));
		return STATUS_FLT_DO_NOT_ATTACH;
	}

	status = FltIsVolumeWritable(FltObjects->Volume, &isWritable);

	if (!NT_SUCCESS(status))
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: do not attach to the volume.\n", __FUNCTION__));
		return STATUS_FLT_DO_NOT_ATTACH;
	}

	if (isWritable)
	{
        //
        //  Connect to all file systems by default.
        //  But explicitly ignore FAT and FAT32.
        //
        status = STATUS_SUCCESS;

		switch (VolumeFilesystemType)
		{
		case FLT_FSTYPE_NTFS:
			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!Attach to NTFS.\n"));
			status = STATUS_SUCCESS;
			break;

		case FLT_FSTYPE_REFS:
			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!Attach to REFS.\n"));
			status = STATUS_SUCCESS;
			break;

		case FLT_FSTYPE_FAT:
			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!FAT.\n"));
			status = STATUS_FLT_DO_NOT_ATTACH;
			break;

		case FLT_FSTYPE_EXFAT:
			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!EXFAT.\n"));
			status = STATUS_FLT_DO_NOT_ATTACH;
			break;
		}

		return status;
	}

	return STATUS_FLT_DO_NOT_ATTACH;
}


NTSTATUS
FLockInstanceQueryTeardown (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This is called when an instance is being manually deleted by a
    call to FltDetachVolume or FilterDetach thereby giving us a
    chance to fail that detach request.

    If this routine is not defined in the registration structure, explicit
    detach requests via FltDetachVolume or FilterDetach will always be
    failed.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Indicating where this detach request came from.

Return Value:

    Returns the status of this operation.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES, ("FLock!FLockInstanceQueryTeardown: Entered\n") );

    return STATUS_SUCCESS;
}


VOID
FLockInstanceTeardownStart (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This routine is called at the start of instance teardown.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Reason why this instance is being deleted.

Return Value:

    None.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES, ("FLock!FLockInstanceTeardownStart: Entered\n") );
}


VOID
FLockInstanceTeardownComplete (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This routine is called at the end of instance teardown.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Reason why this instance is being deleted.

Return Value:

    None.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES, ("FLock!FLockInstanceTeardownComplete: Entered\n") );
}


NTSTATUS
FLockUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    )
/*++

Routine Description:

    This is the unload routine for this miniFilter driver. This is called
    when the mini-filter is about to be unloaded. We can fail this unload
    request if this is not a mandatory unload indicated by the Flags
    parameter.

Arguments:

    Flags - Indicating if this is a mandatory unload.

Return Value:

    Returns STATUS_SUCCESS.

--*/
{
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s\n", __FUNCTION__));

	FltUnregisterFilter(g_flockData.filterHandle);

    return STATUS_SUCCESS;
}


__declspec(dllexport)
VOID
EXTERN_C
GoAwayAndFuckYourself()
{
	return;
}

