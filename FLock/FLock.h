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


#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>

#pragma warning(disable:4995)
#pragma warning(disable:4201) // warning C4201: nonstandard extension used : nameless struct/union


//#define NTSTRSAFE_NO_CCH_FUNCTIONS
#define NTSTRSAFE_NO_CB_FUNCTIONS
#include <Ntstrsafe.h>
#include "FLockStorage.h"

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")


#define	FLOCK_DEVICE_LINK				L"\\DosDevices\\FLockFsFilter"
#define FLOCK_DEVICE_NAME				L"\\Device\\FLockFsFilter"
#define FLOCK_DEV_NAME					L"\\\\.\\FlockFsFilter"
#define FLOCK_FILTER_NAME               L"FLock"

#define FLOCK_DRIVER_VERSION            1

#define FLOCK_DEVICE					FILE_DEVICE_UNKNOWN /* 0x00002a7b */
#define FLOCK_CONTEXT_TAG				'lFxC'
#define FLOCK_CONTEXT_SIGNATURE			0x1F0830A0
#define PTDBG_TRACE_ROUTINES            0x00000001
#define PTDBG_TRACE_OPERATION_STATUS    0x00000002
#define PTDBG_TRACE_ERRORS				0x00000004
#define PTDBG_TRACE_CACHE_COLLISION		0x00000008
#define PTGBG_FLOCK_CACHE				(16 | PTDBG_TRACE_CACHE_COLLISION)
#define PTGBG_TRACE_CONTEXT				(32)
#define PTDBG_TRACE_FULL				(PTDBG_TRACE_ROUTINES | PTDBG_TRACE_OPERATION_STATUS | PTDBG_TRACE_ERRORS | PTGBG_FLOCK_CACHE | PTGBG_TRACE_CONTEXT)
#define PTDBG_TRACE_COMMON				(PTDBG_TRACE_ROUTINES | PTDBG_TRACE_ERRORS | PTDBG_TRACE_OPERATION_STATUS)

//
//	FLock - file system object (file, dir, volume) which should be protected (locked, hidden).
//

//
//	List of request codes.
//	All that requests come from user-mode application.
//

//	Provides information about internal state of the driver.
#define IOCTL_FLOCK_COMMON_INFO				CTL_CODE(FLOCK_DEVICE, 0x0710, METHOD_BUFFERED, FILE_ANY_ACCESS)

//
//	Provides to an ability to unload the driver by standard operation system mechanisms.
//	With calling DriverUnload() routine.
//

#define IOCTL_FLOCK_ENABLE_UNLOADING		CTL_CODE(FLOCK_DEVICE, 0x0711, METHOD_BUFFERED, FILE_ANY_ACCESS)

//	Returns info about service process.
#define IOCTL_FLOCK_GET_SERVICE				CTL_CODE(FLOCK_DEVICE, 0x0712, METHOD_BUFFERED, FILE_ANY_ACCESS)

//	Detaches service from driver.
#define IOCTL_FLOCK_UNREGISTER_SERVICE		CTL_CODE(FLOCK_DEVICE, 0x0713, METHOD_BUFFERED, FILE_ANY_ACCESS)

//
//	This is a service registration request.
//	There is could be registered only one service.
//	Service could be registered twice or more times only if it was crashed or restarted. 
//

#define IOCTL_FLOCK_REGISTER_SERVICE		CTL_CODE(FLOCK_DEVICE, 0x0714, METHOD_BUFFERED, FILE_ANY_ACCESS)

//	Query list of all FLocks with detailed information.
#define IOCTL_FLOCK_QUERY_LIST		CTL_CODE(FLOCK_DEVICE, 0x0715, METHOD_BUFFERED /*METHOD_NEITHER*/, FILE_ANY_ACCESS)

//	Adds new FLock for: lock access, hide.
#define IOCTL_FLOCK_STORAGE_ADD		CTL_CODE(FLOCK_DEVICE, 0x0716, METHOD_BUFFERED, FILE_ANY_ACCESS)

//	Returns info about one flock.
#define IOCTL_FLOCK_STORAGE_QUERY_ONE		CTL_CODE(FLOCK_DEVICE, 0x0719, METHOD_BUFFERED, FILE_ANY_ACCESS)

//	Removes a flock from common flocks list in deriver storage.
#define IOCTL_FLOCK_STORAGE_REMOVE			CTL_CODE(FLOCK_DEVICE, 0x0720, METHOD_BUFFERED, FILE_ANY_ACCESS)

//	Verifies presence of a flock in common list of known flocks.
#define IOCTL_FLOCK_STORAGE_PRESENT			CTL_CODE(FLOCK_DEVICE, 0x0721, METHOD_BUFFERED, FILE_ANY_ACCESS)

//	Let as enable\disable protection for the flock.
#define IOCTL_FLOCK_STORAGE_UPDATE_FLAGS	CTL_CODE(FLOCK_DEVICE, 0x0722, METHOD_BUFFERED, FILE_ANY_ACCESS)

//	Removes all flock entries in driver's storage.
#define IOCTL_FLOCK_CLEAR_ALL				CTL_CODE(FLOCK_DEVICE, 0x0723, METHOD_BUFFERED, FILE_ANY_ACCESS)

//	Returns info about the storage - Was the storage loaded correctly?
#define IOCTL_FLOCK_STORAGE_LOADED			CTL_CODE(FLOCK_DEVICE, 0x0724, METHOD_BUFFERED, FILE_ANY_ACCESS)

//	Was the storage file opened?
#define IOCTL_FLOCK_STORAGE_FILE_OPENED		CTL_CODE(FLOCK_DEVICE, 0x0740, METHOD_BUFFERED, FILE_ANY_ACCESS)

//	Request to flush flocks from memory to disk with overriding old data.
#define IOCTL_FLOCK_STORAGE_FLUSH			CTL_CODE(FLOCK_DEVICE, 0x0741, METHOD_BUFFERED, FILE_ANY_ACCESS)

//	Changes file for kernel mode storage.
//	This file will be used in next system load time.
#define IOCTL_FLOCK_STORAGE_CHANGE_FILE		CTL_CODE(FLOCK_DEVICE, 0x0742, METHOD_BUFFERED, FILE_ANY_ACCESS)


/************************************************************************/
/*        IOCTLs for driver managing						           */
/************************************************************************/

#define IOCTL_FLOCK_SET_DBGOUTPUT			CTL_CODE(FLOCK_DEVICE, 0x0801, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_FLOCK_SHUTDOWN				CTL_CODE(FLOCK_DEVICE, 0x0802, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_FLOCK_CACHE_RESIZE			CTL_CODE(FLOCK_DEVICE, 0x0803, METHOD_BUFFERED, FILE_ANY_ACCESS)

//	Helps to disable or enable use of internal cache.
#define IOCTL_FLOCK_CACHE_ENABLE			CTL_CODE(FLOCK_DEVICE, 0x0805, METHOD_BUFFERED, FILE_ANY_ACCESS)

//	Helps to clear internal cache.
#define IOCTL_FLOCK_CACHE_CLEAR				CTL_CODE(FLOCK_DEVICE, 0x0806, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_FLOCK_CACHE_XXXXXX			CTL_CODE(FLOCK_DEVICE, 0x0807, METHOD_BUFFERED, FILE_ANY_ACCESS)

//	Forces driver to generate new time stamp value for invalidating all available contexts.
#define IOCTL_FLOCK_CONTEXT_RESET			CTL_CODE(FLOCK_DEVICE, 0x0808, METHOD_BUFFERED, FILE_ANY_ACCESS)

//	Provides an ability to install or disable using contexts.
#define IOCTL_FLOCK_CONTEXT_ENABLE			CTL_CODE(FLOCK_DEVICE, 0x0809, METHOD_BUFFERED, FILE_ANY_ACCESS)



/************************************************************************/
/*        IOCTLs for work with extended attributes			           */
/************************************************************************/

//	Zeros (makes invalid) flock-meta attributes in file's EAs.
#define IOCTL_FLOCK_MAKE_BAD		CTL_CODE(FLOCK_DEVICE, 0x0718, METHOD_BUFFERED, FILE_ANY_ACCESS)

//	Reads flock-meta from file's EAs.
#define IOCTL_FLOCK_READ_META		CTL_CODE(FLOCK_DEVICE, 0x0717, METHOD_BUFFERED, FILE_ANY_ACCESS)

//	Writes flock-meta into EAs.
#define IOCTL_FLOCK_MARK_FILE		CTL_CODE(FLOCK_DEVICE, 0x0725, METHOD_BUFFERED, FILE_ANY_ACCESS)



//
//	FLock status codes.
//

#define FLOCK_STATUS_SUCCESS			0
#define FLOCK_STATUS_ERROR				1
#define FLOCK_STATUS_NOT_FOUND			3
#define FLOCK_STATUS_PRESENT			4
#define FLOCK_STATUS_CANT_CHANGE		5
#define FLOCK_STATUS_HAVE_NO_BODY		6
#define FLOCK_STATUS_SMALL_BUFFER		7
#define FLOCK_STATUS_WRONG_DATA			8
#define FLOCK_STATUS_WRONG_SIZE			9
#define FLOCK_STATUS_NOT_LOADED			10
#define FLOCK_STATUS_ALREADY_PRESENT	11
#define FLOCK_STATUS_UNKNOWN_ERROR		12



#define	GET_NONPAGED(size)				ExAllocatePool(NonPagedPool, size)
#define GET_NONPAGED_TAG(size)			ExAllocatePoolWithTag(NonPagedPool, size, 'stan');
#define WCHAR_COUNT(len_bytes)					( len_bytes / sizeof(WCHAR))
#define WCHAR_LEN(wchars_count)					(wchars_count * sizeof(WCHAR))


#define PT_DBG_PRINT( _dbgLevel, _string )          \
    (FlagOn(gTraceFlags,(_dbgLevel)) ?              \
        DbgPrint _string :                          \
        ((int)0))

#define SETPTR(ptr, data)\
	if(ptr != NULL)\
		(*ptr) = data;

//
// Signature for secure identificating a request to the driver.
//

#define FLOCK_REQUEST_SIGNATURE			{0xA3, 0xFE, 0x01, 0x14, /*1*/ 0xE2, 0xCE, 0x77, 0x21, /*2*/ 0xF3, 0x12, 0x12, 0x01 /*3*/, 0x28, 0x03, 0x19, 0x00 /*4*/}
#define FLOCK_RESPONSE_SIGNATURE		{0x11, 0xC3, 0x21, 0x94, /*1*/ 0xA2, 0xFE, 0x60, 0x08, /*2*/ 0xAA, 0xBE, 0xD3, 0x38 /*3*/, 0x48, 0x51, 0x23, 0x00 /*4*/}

//
// Signature for meta information.
//

#define FLOCK_META_SIGNATURE		{0xB1, 0x0E, 0x21, 0xf4, /*1*/ 0xb2, 0x1E, 0x27, 0x21, /*2*/ 0x12, 0x12, 0x12, 0x12 /*3*/, 0x28, 0x33, 0x92, 0x11 /*4*/}
#define FLOCK_META_NAME				"FLOCK_META" /* 10 bytes */
#define FLOCK_META_NAME_SIZE		10
#define FLOCK_UNIQUE_ID_LENGTH		16

#define FLOCK_FAKE_META_NAME		"AWC10XY34F" /* 10 bytes, should have the same size as FLOCK_META_NAME string. */ 
#define FLOCK_FAKE_META_NAME_SIZE	FLOCK_META_NAME_SIZE

//
// Flag says that the directory includes objects which should be protected.
//
#define FLOCK_FLAG_HAS_FLOCKS		0x01

//
// Flag says that we need ho have an access to the file.
//
#define FLOCK_FLAG_HIDE				0x02

//
// Flag says that we need to protect an access to the file.
//
#define FLOCK_FLAG_LOCK_ACCESS		0x04


#define OFFSET_OF(TYPE, MEMBER) ((ULONG) &((TYPE *)0)->MEMBER)


#define FLOCK_POST_VOLUME_FLAG		0x1fe2;

#pragma pack(push, 1)

//
// All structures should be declared here.
//


// 
// This is a meta information which should be in Extended Attributes (EA).
//

typedef struct _FLOCK_META
{
	UCHAR signature[16];
	DWORD version; /* zero by default */
	UCHAR uniqueId[FLOCK_UNIQUE_ID_LENGTH]; /* unique identificator for a file system object */
	DWORD flags;
} FLOCK_META, *PFLOCK_META;


//
// Helps us to keep file context information in actual state.
//

typedef struct _FLOCK_TIME_STAMP
{
	union 
	{
		LARGE_INTEGER stamp;
		UCHAR signature[8];
	};
	
} FLOCK_TIME_STAMP, *PFLOCK_TIME_STAMP;


//
// Context structure which we assign with any open files.
//

typedef struct _FLOCK_FLT_CONTEXT
{
	union {
		struct {
			
			//
			//	Indicates that FILE has FLOCK_META information among its EAs.
			//	Practice says that volume does not have EAs =(
			//

			int hasMetaInfo : 1;

			//	Volume or directory includes hidden objects.
            int hasHiddenObject	:	1;
		};

		UCHAR data;
	};

	// The time when '.hasMetaInfo' field was set.
	FLOCK_TIME_STAMP timeStamp;

	//  Lock is used to protect this context.
	EX_PUSH_LOCK resource;

} FLOCK_FLT_CONTEXT, *PFLOCK_FLT_CONTEXT;


//
//	Structure which holds most important driver's data.
//

typedef struct _FLOCK_DEVICE_DATA
{
	PDRIVER_OBJECT driverObject;
	PDEVICE_OBJECT deviceObject;

	UNICODE_STRING	deviceNameUnicodeString;
	UNICODE_STRING	deviceLinkUnicodeString;

	PFLT_FILTER	filterHandle;

	DWORD serviceProcessId;
	PEPROCESS serviceProcess;

	PVOID storageLoaderThreadObj;
	PVOID storageFlusherThreadObj;

	KEVENT eventFlush;

	KEVENT terminationEvent;
	volatile BOOLEAN stopAll;
	volatile BOOLEAN createProcessNotificatorRegistered;
	volatile BOOLEAN storageLoaderFinished;
    volatile BOOLEAN flusherFinished;

	// Time when had occurred last change of flocks list. We use it as a signature.
	FLOCK_TIME_STAMP ctxLastStamp;
	volatile BOOLEAN ctxEnabled;

} FLOCK_DEVICE_DATA, *PFLOCK_DEVICE_DATA;

typedef struct _FLOCK_CACHE_INFO
{
	BOOLEAN enabled;

	ULONG capacity;
	ULONG currentSize;
	ULONG occupancyLimit;
	ULONG collisionResolveIfNoPlaceBorder;
	ULONG collisionMaxResolveOffset;

} FLOCK_CACHE_INFO, *PFLOCK_CACHE_INFO;


typedef struct _FLOCK_COMMON_INFO
{
    DWORD version;
	DWORD serviceProcessId;

	BOOLEAN stopAll;
	BOOLEAN createProcessNotificatorRegistered;
	BOOLEAN storageLoaderFinished;

	ULONG traceFlags;
	ULONG flocksCount;
	BOOLEAN storageLoaded;

	BOOLEAN ctxEnabled;
	FLOCK_TIME_STAMP ctxLastStamp;

	FLOCK_CACHE_INFO cache;
}FLOCK_COMMON_INFO, *PFLOCK_COMMON_INFO;


typedef struct _FLOCK_REQUEST_HEADER
{
	UCHAR signature[16]; //	FLOCK_REQUEST_SIGNATURE
	DWORD version;
	DWORD requestId;
	DWORD length; //	Body part size in bytes.

	union
	{
		BOOLEAN boolValue;
		DWORD context;
		DWORD counter;
	} params;

} FLOCK_REQUEST_HEADER, *PFLOCK_REQUEST_HEADER;


typedef struct _FLOCK_RESPONSE_HEADER
{
	UCHAR signature[16]; // FLOCK_RESPONSE_SIGNATURE
	DWORD version;
	DWORD flockStatus; // FLOCK_STATUS_XXX
	DWORD length; // Size of response body in bytes.

	union
	{
		BOOLEAN boolValue;
		DWORD context;
		DWORD requireLength;
	}params;

} FLOCK_RESPONSE_HEADER, *PFLOCK_RESPONSE_HEADER;


typedef struct _FLOCK_FILE_PATH
{
	USHORT filePathLength; // in bytes.
	WCHAR filePath[1]; // It can not include the last zero symbol.
} FLOCK_FILE_PATH, *PFLOCK_FILE_PATH;


typedef struct _FLOCK_REQUEST_MARK_FILE
{
	FLOCK_META info;
	USHORT filePathLength; // in bytes.
	WCHAR filePath[1];
} FLOCK_REQUEST_MARK_FILE, *PFLOCK_REQUEST_MARK_FILE;


typedef struct _FLOCK_REQUEST_SET_FLAG
{
	UCHAR flockId[16]; // unique id.
	BOOLEAN toSet; // TRUE if need to raise a flag, remove means remove the flag.
	ULONG flockFlag; // FLOCK_FLAG_HIDE , FLOCK_FLAG_LOCK_ACCESS, FLOCK_FLAG_XXX and etc.

} FLOCK_REQUEST_SET_FLAG, *PFLOCK_REQUEST_SET_FLAG;


typedef struct _FLOCK_REQUEST_QUERY_INFO
{
	UCHAR uniqueId[FLOCK_UNIQUE_ID_LENGTH];
} FLOCK_REQUEST_QUERY_INFO, *PFLOCK_REQUEST_QUERY_INFO;


typedef struct _FLOCK_RESPONSE_QUERY_INFO
{
	FLOCK_STORAGE_ENTRY info;
} FLOCK_RESPONSE_QUERY_INFO, *PFLOCK_RESPONSE_QUERY_INFO;

#pragma pack(pop)


void DriverUnload(
	_In_ PDRIVER_OBJECT pDrvObj
	);

//////////////////////////////////////////////////////////////////////////
//
// Flocks threads are defined here.
//

VOID FLockStorageLoader(
	PVOID _context
	);

VOID FLockStorageFlusher(
	PVOID _context
	);

//////////////////////////////////////////////////////////////////////////


//
// Sets event into signal state. 
//
void FLockSyncGenerateFlushEvent();


//
// Returns pointer on main driver structure which keeps all important information.
//

PFLOCK_DEVICE_DATA FLockData();


VOID FLockStop();


void FLockStampGenerate(
	PFLOCK_TIME_STAMP _stamp
	);


VOID FLockStampUpdate(
	__out PFLOCK_TIME_STAMP _newStamp
	);


//
//	Returns TRUE if specified '_timeStamp' is older than used in 'FLOCK_DATA' STRUCTURE.
//

BOOLEAN FLockStampIsStale(
	PFLOCK_TIME_STAMP _timeStamp
	);


//
// Return TRUE when require to stop all FLock activity.
//

BOOLEAN FLockDoesItRequireToStop();


//
// Returns pointer to service process structure.
//
PEPROCESS FLockGetServiceProcess();

//
// Indicates that require to use help of FltContexts.
//

BOOLEAN FLockUseContextHelp();


//
// Turns on or turns off using flt contexts. Helps to improve system performance!
//

VOID FLockContextEnable(BOOLEAN _enable);


NTSTATUS FLockContextProcess(
	__in	PCFLT_RELATED_OBJECTS _fltObjects,
	_In_	PFLT_CALLBACK_DATA _cbd,
	__in	PFLOCK_FLT_CONTEXT* _flockContext,
	__in	BOOLEAN _thisIsVolumeRequest,
	__out	PBOOLEAN _contextCreated,
	__out	PBOOLEAN _contextAcquired,
	__out	PBOOLEAN _contextIsStale
	);

VOID	FLockContextRelease(
	PFLOCK_FLT_CONTEXT _context
	);

//
// Returns service process ID.
//

DWORD FLockGetServiceProcessId();


VOID FLockRegisterServiceProcess(
	__in PEPROCESS _process
	);


VOID FLockUnregisterServiceProcess();


BOOLEAN FLockDriverPrepareStorage();


BOOLEAN FLockLogicNeedProtect(
	__in PUNICODE_STRING _ptrFsPath
	);


//
//	1. Opens file thought FltCreateFile(..)
//	2. Get PFILE_OBJET from HANDLE through ObReferenceObjectByHandle(..)
//	3. Reads FLock-meta using FLockFltReadFirstMeta(..)
//

BOOLEAN FLockFltOpenAndReadFirstMeta(
	__in PFLT_FILTER	_filter,
	__in PFLT_INSTANCE  _instance,
	//__in PFLT_CALLBACK_DATA _fltData,
	__in PUNICODE_STRING _filePath,
	__out PFLOCK_META _readMetaInfo,
	__out NTSTATUS* _errorCode
	);


//
// Call when you are at <= APC_LEVEL only.
//
// Returns TRUE when finds FLock-meta on a some of path.
//
// The path could be a X:\work\protected\sara\docs\secrets.txt , but
// FLock-meta is only in one directory -  X:\work\protected, it means that this function should do
// the following steps:
//		1) Verify FLock-meta in X:\work\protected\sara\docs
//		2) Verify the same in X:\work\protected\sara
//		3) Verify ... in X:\work\protected
//		4) And finally find FLock-meta in 'X:\work\protected' directory, which is one of parents to secrets.txt.
//

BOOLEAN FLockFltSearchFirstMetaPath(
	__in PFLT_FILTER	_filter,
	__in PFLT_INSTANCE  _instance,
	__in PFLT_CALLBACK_DATA _fltData,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__in BOOLEAN _skipFirstFile,
	__out PFLOCK_META _readMetaInfo,
	__out PUNICODE_STRING _foundPath,
	__out NTSTATUS* _errorCode
	);


//
// Return file path in '_filePath' argument and
// do not forget to free memory of '_filePath->Buffer' through ExFreePool(..) later.
// 
// An example of file path: \Device\HarddiskVolume1\Windows\System32\notepad.exe
//

BOOLEAN FLockFltGetPath(
	__in PFLT_FILTER	_filter,
	__in PFLT_INSTANCE  _instance,
	__in PFLT_CALLBACK_DATA _fltData,
	//__in PCFLT_RELATED_OBJECTS FltObjects,
	__out PUNICODE_STRING _filePath,
	__out NTSTATUS* _errorCode
	);


//
// This function reads FLock's EAs, doing following things:
//
//	1. Get file path by using FltGetFileNameInformation(..), FltParseFileNameInformation(..)
//	2. Reads FLock-meta using FLockFltOpenAndReadFirstMeta(..)
//	3. Copy string with path of the file if it has FLock-meta.
//

BOOLEAN FLockFltReadFirstMetaWithGetFilePath(
	__in PFLT_FILTER	_filter,
	__in PFLT_INSTANCE  _instance,
	__in PFLT_CALLBACK_DATA _fltData,
	__out PFLOCK_META _readMeta,
	__out_opt  PUNICODE_STRING _outFilePath,
	__out_opt NTSTATUS* _errorCode
	);


//
// Works faster then first one because
//	1. Does not allocate any additional memory - reads EAs right to buffer (local array on stack).
//	2. Before initiate a read request the function sets info about which EA to search.
//

BOOLEAN FLockReadFastFirstMeta(
	__in HANDLE _hFile,
	__out PFLOCK_META _readMetaInfo,
	__out NTSTATUS* _errorCode
	);


//
// Does the same as FLockReadFastFirstMeta(..) but use filter manager functions.
// Use it only when current IRQL is < DISPATCH_LEVEL.
//

BOOLEAN FLockFltReadFirstMeta(
	__in PFLT_INSTANCE Instance,
	__in PFILE_OBJECT  FileObject,
	__out PFLOCK_META _readMetaInfo,
	__out NTSTATUS* _errorCode
	);


//
// Writes flock meta information uses FILE_OBJECT for that and avoids receiving IRP_MJ_SET_EA request.
//

BOOLEAN FLockFltWriteFlockMeta(
	__in PFLT_INSTANCE _instance,
	__in PFILE_OBJECT  _fileObject,
	__in PFLOCK_META _metaInfo,
	__out NTSTATUS* _errorCode
	);


//
// Opens '_filePath' file path and searches 'FLOCK_META' in EAs, returns data in case the data is found.
//

BOOLEAN FLockFileReadFastFirstMeta(
	__in WCHAR* _filePath,
	__out PFLOCK_META _readMetaInfo,
	__out NTSTATUS* _errorCode
	);


BOOLEAN FLockFileReadFastFirstMeta2(
	__in PUNICODE_STRING _filePath,
	__out PFLOCK_META _readMetaInfo,
	__out_opt NTSTATUS* _errorCode
	);


//
// Return TRUE if file stream has 'FLOCK_META' attribute.
//

BOOLEAN FLockHasMeta(
	__in HANDLE _hFile
	);


// 
// Writes FLock meta info to file stream as an Extended Attribute.
//

BOOLEAN FLockWriteMeta(
	__in HANDLE _hFile,
	__out PFLOCK_META _metaInfo,
	__out NTSTATUS* _errorCode
	);


BOOLEAN FLockFileWriteMeta(
	__in WCHAR* _filePath,
	__out PFLOCK_META _metaInfo,
	__out NTSTATUS* _errorCode
	);


BOOLEAN FLockFileWriteMeta2(
	__in PUNICODE_STRING _filePath,
	__in PFLOCK_META _metaInfo,
	__out_opt NTSTATUS* _errorCode
	);


//
// Case sensitive.
//

BOOLEAN FLockEqualAnsiStrings(
	__in PANSI_STRING _first,
	__in PANSI_STRING _second
	);


BOOLEAN FLockIsVolumeRequest(
	_In_ PCFLT_RELATED_OBJECTS FltObjects
	);

//
// Handles all user-mode requests which was send through DeviceIoControl(..)
//

NTSTATUS FLockDeviceControlDispatcher(
	PDEVICE_OBJECT Fdo,
	PIRP Irp
	);


//
// Just a pass-through dispatcher.
//

NTSTATUS FLockSuccessDispatcher(
	PDEVICE_OBJECT _deviceObject,
	PIRP _irp
	);


//
// Returns TRUE if the code executes in service process context.
//

BOOLEAN FLockAreWeInServiceProcessContext();


VOID FLockPrintMeta(
	__in PFLOCK_META _info
	);


BOOLEAN FLockHasBackslash(
	__in PUNICODE_STRING _str
	);

//////////////////////////////////////////////////////////////////////////
//
// Routines for using file-system contexts.
//


VOID FLockContextCleanup(
_In_ PFLT_CONTEXT Context,
_In_ FLT_CONTEXT_TYPE ContextType
);


NTSTATUS FLockCreateFileContext(
	_Outptr_ PFLOCK_FLT_CONTEXT *_fileContext
	);


//
// This routine finds the file context for the target file.
// Optionally, if the context does not exist this routing creates
// a new one and attaches the context to the file.
//

NTSTATUS FLockFindOrCreateFileContext(
	_In_ PFLT_CALLBACK_DATA _cbd,
	_In_ BOOLEAN _createIfNotFound,
	_Outptr_ PFLOCK_FLT_CONTEXT *_fileContext,
	_Out_opt_ PBOOLEAN _contextCreated
	);


NTSTATUS FLockFindOrCreateVolumeContext(
	_In_ PCFLT_RELATED_OBJECTS _fltRelated,
	_In_ BOOLEAN _createIfNotFound,
	_Outptr_ PFLOCK_FLT_CONTEXT *_volumeContext,
	_Out_opt_ PBOOLEAN _contextCreated
	);

//////////////////////////////////////////////////////////////////////////


//////////////////////////////////////////////////////////////////////////
//
// File system filters.
//

FLT_PREOP_CALLBACK_STATUS FLockPreFsControl(
	_Inout_ PFLT_CALLBACK_DATA    Data,
	_In_    PCFLT_RELATED_OBJECTS FltObjects,
	_Out_   PVOID                 *CompletionContext
	);

FLT_POSTOP_CALLBACK_STATUS FLockPostFsControl(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
	);

FLT_PREOP_CALLBACK_STATUS flockPreMdlRead(
	_Inout_ PFLT_CALLBACK_DATA    Data,
	_In_    PCFLT_RELATED_OBJECTS FltObjects,
	_Out_   PVOID                 *CompletionContext
	);

FLT_POSTOP_CALLBACK_STATUS flockPostMdlRead(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
	);

FLT_PREOP_CALLBACK_STATUS FLockPreQueryEa(
	_Inout_ PFLT_CALLBACK_DATA    Data,
	_In_    PCFLT_RELATED_OBJECTS FltObjects,
	_Out_   PVOID                 *CompletionContext
	);

FLT_POSTOP_CALLBACK_STATUS FLockPostQueryEa(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
	);

FLT_PREOP_CALLBACK_STATUS flockPreQueryInformation(
	_Inout_ PFLT_CALLBACK_DATA    Data,
	_In_    PCFLT_RELATED_OBJECTS FltObjects,
	_Out_   PVOID                 *CompletionContext
	);

FLT_POSTOP_CALLBACK_STATUS flockPostQueryInformation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
	);

FLT_PREOP_CALLBACK_STATUS FLockPreSetEa(
	_Inout_ PFLT_CALLBACK_DATA    Data,
	_In_    PCFLT_RELATED_OBJECTS FltObjects,
	_Out_   PVOID                 *CompletionContext
	);

FLT_POSTOP_CALLBACK_STATUS FLockPostSetEa(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
	);

FLT_PREOP_CALLBACK_STATUS FLockPreSetInformation(
	_Inout_ PFLT_CALLBACK_DATA    Data,
	_In_    PCFLT_RELATED_OBJECTS FltObjects,
	_Out_   PVOID                 *CompletionContext
	);

FLT_POSTOP_CALLBACK_STATUS FLockPostSetInformation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
	);

FLT_PREOP_CALLBACK_STATUS FLockPreDirectoryControl(
	_Inout_ PFLT_CALLBACK_DATA    Data,
	_In_    PCFLT_RELATED_OBJECTS FltObjects,
	_Out_   PVOID                 *CompletionContext
	);

FLT_POSTOP_CALLBACK_STATUS FLockPostDirectoryControl(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
	);

FLT_PREOP_CALLBACK_STATUS FLockPreCreate(
	_Inout_ PFLT_CALLBACK_DATA    Data,
	_In_    PCFLT_RELATED_OBJECTS FltObjects,
	_Out_   PVOID                 *CompletionContext
	);

FLT_POSTOP_CALLBACK_STATUS FLockPostCreate(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
	);

FLT_PREOP_CALLBACK_STATUS flockPreClose(
	_Inout_ PFLT_CALLBACK_DATA    Data,
	_In_    PCFLT_RELATED_OBJECTS FltObjects,
	_Out_   PVOID                 *CompletionContext
	);

FLT_POSTOP_CALLBACK_STATUS flockPostClose(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
	);

//////////////////////////////////////////////////////////////////////////
// end //
