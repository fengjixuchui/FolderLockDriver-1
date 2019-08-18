//
// Author:
//		Burlutsky Stas
//
//		burluckij@gmail.com
//

#include "../flock.h"
#include "../FLockStorage.h"
#include "../FLockCache.h"
#include "../FLockMd5.h"



#define FLOCK_FIELD_READ(_base, _offset, _fieldType)				(   *( (_fieldType*)( ((PUCHAR)_base) + _offset) )   )
#define FLOCK_FIELD_PTR(_base, _offset, _fieldType)					(   ( (_fieldType*)( ((PUCHAR)_base) + _offset) )   )
#define FLOCK_WRITE_FIELD(_base, _offset, _fieldType, _value)		(   *((_fieldType*)(((PUCHAR)_base) + _offset)) = _value  )



extern ULONG gTraceFlags;
extern FLOCK_DEVICE_DATA g_flockData;



NTSTATUS
FLockHandleFileBothDirectoryInformation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	__in PUNICODE_STRING _requestedDir
);


NTSTATUS
FLockHandleFileDirectoryInformation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	__in PUNICODE_STRING _requestedDir
);


NTSTATUS
FLockHandleFileFullDirectoryInformation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	__in PUNICODE_STRING _requestedDir
);


NTSTATUS
FLockHandleFileIdBothDirectoryInformation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	__in PUNICODE_STRING _requestedDir
);


NTSTATUS
FLockHandleFileIdFullDirectoryInformation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	__in PUNICODE_STRING _requestedDir
);


NTSTATUS
FLockHandleFileNamesInformation(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
__in PUNICODE_STRING _requestedDir
);


NTSTATUS
FLockHandleFileObjectIdInformation(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
__in PUNICODE_STRING _requestedDir
);


NTSTATUS
FLockHandleFileReparsePointInformation(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
__in PUNICODE_STRING _requestedDir
);



FLT_PREOP_CALLBACK_STATUS FLockPreDirectoryControl(
	_Inout_ PFLT_CALLBACK_DATA    Data,
	_In_    PCFLT_RELATED_OBJECTS FltObjects,
	_Out_   PVOID                 *CompletionContext
	)
{
	UNREFERENCED_PARAMETER(CompletionContext);

	PFLOCK_FLT_CONTEXT flockContext = NULL;
	NTSTATUS status, contextStatus, finalResult = FLT_PREOP_SUCCESS_NO_CALLBACK;
	UNICODE_STRING path = { 0 }, filepath = { 0 };
	FLOCK_META fm = { 0 };
	UCHAR hashByFilePath[16];
	BOOLEAN hasFlockMeta = FALSE, requireReadMeta = TRUE, hasHash = FALSE, volumeRequest = FALSE;
	BOOLEAN contextAcquired = FALSE, contextIsStale = TRUE, contextCreated = FALSE;

	// PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: entered.\n", __FUNCTION__));

	if (FLockDoesItRequireToStop())
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if (FLT_IS_FASTIO_OPERATION(Data))
	{
		return FLT_PREOP_DISALLOW_FASTIO;
	}

	if (!FLT_IS_IRP_OPERATION(Data))
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if (BooleanFlagOn(Data->Iopb->OperationFlags, SL_OPEN_PAGING_FILE))
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if (!FLockStorageHasHiddenUserObjects())
	{
		// PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: There is no one object which should be hidden.\n", __FUNCTION__));
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if (Data->Iopb->MinorFunction != IRP_MN_QUERY_DIRECTORY)
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	// 	if (IoGetTopLevelIrp() == FSRTL_FSP_TOP_LEVEL_IRP)
	// 	{
	// 		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	// 	}

	if (Data->Iopb->TargetFileObject)
	{
		if (FsRtlIsPagingFile(Data->Iopb->TargetFileObject))
		{
			return FLT_PREOP_SUCCESS_NO_CALLBACK;
		}
	}
	else
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: warning it's no FILE_OBJECT.\n", __FUNCTION__));
	}

	volumeRequest = FLockIsVolumeRequest(FltObjects);

// 	if (volumeRequest)
// 	{
// 		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: info - volume query dirs info, schedule post-handler!\n", __FUNCTION__));
// 		return FLT_PREOP_SYNCHRONIZE;
// 	}

	//
	//	If contexts are available we should use it.
	//	Context helps to improve 
	//

#pragma region WORK_WITH_CONTEXT

	if (FLockUseContextHelp())
	{
		contextStatus = FLockContextProcess(
			FltObjects,
			Data,
			&flockContext,
			volumeRequest,
			&contextCreated,
			&contextAcquired,
			&contextIsStale);

		if (NT_SUCCESS(contextStatus))
		{
			if (contextAcquired)
			{
				//
				//	Volumes do not have EAs (or sometimes we just can not open volume's root folder, it is a critical for us), that's why we need to process it in a special way.
				//	That sad fact arose suddenly in final tests =)
				//

				if (volumeRequest)
				{
					if (contextCreated || contextIsStale)
					{
						//
						//	Because the context was just created, we need to verify all included entries.
						//	Post-handler does all job. Nothing to do in pre-handler.
						//

						FLockContextRelease(flockContext);
						return FLT_PREOP_SYNCHRONIZE;
					}

					if (flockContext->hasHiddenObject || flockContext->hasMetaInfo)
					{
						//
						//	In root folder of the volume we have something to protect.
						//	Process the request in our post-handler.
						//

						finalResult = FLT_PREOP_SYNCHRONIZE;
						goto complete_handling;
					}
					else
					{
						//
						//	Do not handle incoming request at all because context says - there is nothing to hide in a root folder.
						//

						PT_DBG_PRINT(PTGBG_TRACE_CONTEXT, ("FLock!%s: Ctx. Ignore vol - %wZ.\n", __FUNCTION__, &FltObjects->FileObject->FileName));

						finalResult = FLT_PREOP_SUCCESS_NO_CALLBACK;
						goto complete_handling;
					}
				}
				else
				{
					if (!contextIsStale)
					{
						//
						//	Information in context is in actual state. We can use it.
						//	

						if (!flockContext->hasMetaInfo)
						{
							PT_DBG_PRINT(PTGBG_TRACE_CONTEXT, ("FLock!%s: Ctx. Ignore dir - %wZ.\n", __FUNCTION__, &FltObjects->FileObject->FileName));

							finalResult = FLT_PREOP_SUCCESS_NO_CALLBACK;
							goto complete_handling;
						}
					}
				}
			}
		}
		else
		{
			PT_DBG_PRINT(PTGBG_TRACE_CONTEXT | PTDBG_TRACE_ERRORS,
				("FLock!%s: Ctx. Failed to process - %wZ, vol %d.\n",
				__FUNCTION__,
				&FltObjects->FileObject->FileName,
				volumeRequest));
		}
	}
	else
	{
		if (volumeRequest)
		{
			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: no ctx. Volume query, schedule post-handler.\n", __FUNCTION__));
			return FLT_PREOP_SYNCHRONIZE;
		}
	}

#pragma endregion WORK_WITH_CONTEXT

	//
	//	If cache enabled, we should handle this request through cache for improving hole system performance.
	//

#pragma region WORK_WITH_CACHE

	if ( FLockCacheIsEnabled() )
	{
		BOOLEAN hasFilePath = FLockFltGetPath(g_flockData.filterHandle, Data->Iopb->TargetInstance, Data, &path, &status);

		if (hasFilePath)
		{
			//
			//	Calculate hash if we have file path.
			//

			if (path.Length)
			{
				hasHash = TRUE;
				FLockMd5Calc( (PUCHAR) path.Buffer, path.Length, hashByFilePath);

				ULONG stepsRequired = 0;
				FLOCK_CACHE_ENTRY fce = { 0 };

				if (FLockCacheLookupOneCall(hashByFilePath, &fce, &stepsRequired))
				{
					//
					//	Update contexts info if it is required.
					//	Context and cache should be consistent.
					//

					if (contextAcquired && contextIsStale)
					{
						flockContext->hasMetaInfo = fce.presentMeta;
						FLockStampGenerate(&flockContext->timeStamp);

						PT_DBG_PRINT(PTGBG_TRACE_CONTEXT,
							("FLock!%s: Ctx. Update using cached info - %wZ (vol %d), has meta %d, stamp %lld.\n",
							__FUNCTION__,
							&FltObjects->FileObject->FileName,
							volumeRequest,
							fce.presentMeta,
							flockContext->timeStamp.stamp.QuadPart));
					}

					if (fce.presentMeta == FALSE)
					{
						//
						//	It is not require to read FLock-meta information from disk. Cache helped us here.
						//

						PT_DBG_PRINT(PTGBG_FLOCK_CACHE,
							("FLock!%s: cache_strike. Ignore reading meta. Cached entry found, required to do %d steps.\n",
							__FUNCTION__,
							stepsRequired));

						requireReadMeta = FALSE;

						finalResult = FLT_PREOP_SUCCESS_NO_CALLBACK;
						goto complete_handling;
					}
					else
					{
						PT_DBG_PRINT(PTGBG_FLOCK_CACHE,
							("FLock!%s: cache_strike. Cache entry found - read meta! It took %d steps.\n",
							__FUNCTION__,
							stepsRequired));
					}
				}
			}

			ExFreePool(path.Buffer);
		}
		else
		{
			PT_DBG_PRINT(PTDBG_TRACE_ERRORS,
				("FLock!%s: error 0x%x - couldn't find file path for the opening file.\n",
				status,
				__FUNCTION__));
		}
	}

#pragma endregion WORK_WITH_CACHE

	if (requireReadMeta)
	{
		//
		// Path is c:\work\dir
		// Нужно ли нам скрывать что-то для этого каталога? 
		// Он может быть родительским для целевого, скрываемого нами каталога - c:\work\dir\hidden
		//

		if (Data->Iopb->TargetFileObject)
		{
			hasFlockMeta = FLockFltReadFirstMeta(
				Data->Iopb->TargetInstance, 
				Data->Iopb->TargetFileObject, 
				&fm, 
				&status);
		}
		else
		{
			hasFlockMeta = FLockFltReadFirstMetaWithGetFilePath(
				g_flockData.filterHandle,
				Data->Iopb->TargetInstance,
				Data,
				&fm,
				&filepath,
				&status);
		}

		//
		//	Update in cache.
		//

#pragma region WORK_WITH_CACHE

		if (FLockCacheIsEnabled() && hasHash)
		{
			FLockCacheAddEntryOneCall(hashByFilePath, hasFlockMeta);
		}

#pragma endregion WORK_WITH_CACHE

		//
		//	Update context only if timestamp is stale.
		//	Save the same information which was earlier saved in cache.
		//

		if (contextAcquired && contextIsStale)
		{
			flockContext->hasMetaInfo = hasFlockMeta;
			FLockStampGenerate(&flockContext->timeStamp);

			PT_DBG_PRINT(PTGBG_TRACE_CONTEXT,
				("FLock!%s: Ctx. Is stale, update. Name %wZ, has meta %d, vol %d, stamp %lld.\n",
				__FUNCTION__,
				&FltObjects->FileObject->FileName,
				hasFlockMeta,
				volumeRequest,
				flockContext->timeStamp.stamp.QuadPart));

			//
			//	Here we can free early acquired context.
			//	It helps to improve common system performance.
			//

			FLockContextRelease(flockContext);
			contextAcquired = FALSE;
		}
		else if (contextAcquired && !contextIsStale)
		{
			if (flockContext->hasMetaInfo != hasFlockMeta)
			{
				//
				//	Update context only if early saved info not equal to real file state.
				//	Actually, we should not have this situation in reality, but I prefer to be prepared.
				//

				flockContext->hasMetaInfo = hasFlockMeta;
				FLockStampGenerate(&flockContext->timeStamp);
			}
		}

		if (hasFlockMeta)
		{
			FLockPrintMeta(&fm);

			//
			// Requested directory has something to be protected.
			//

			if (fm.flags & FLOCK_FLAG_HAS_FLOCKS)
			{
				if (filepath.Length)
				{
					PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: there is something to protect in %wZ.\n", __FUNCTION__, &filepath));
				}
				else
				{
					PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: there is something to protect in the directory.\n", __FUNCTION__));
				}

				//
				//	Hide target objects in post-callback.
				//

				finalResult = FLT_PREOP_SYNCHRONIZE;
				goto complete_handling;
			}
		}
		else
		{
			PT_DBG_PRINT(PTDBG_TRACE_ERRORS, ("FLock!%s: error - can't read flock-meta, status is 0x%x.\n", __FUNCTION__, status));
		}
	}
	
complete_handling:
	if (contextAcquired)
	{
		FLockContextRelease(flockContext);
	}

	if (filepath.Length && filepath.Buffer)
	{
		ExFreePool(filepath.Buffer);
	}

	return finalResult;
}


FLT_POSTOP_CALLBACK_STATUS FLockPostDirectoryControl(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
	)
{
	UNREFERENCED_PARAMETER(CompletionContext);

	// PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s entered.\n", __FUNCTION__));

	NTSTATUS status = STATUS_UNSUCCESSFUL;

	if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING) || FLockDoesItRequireToStop())
	{
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	if (!NT_SUCCESS(Data->IoStatus.Status) || Data->IoStatus.Status == STATUS_REPARSE)
	{
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	if (IoGetTopLevelIrp() == FSRTL_FSP_TOP_LEVEL_IRP)
	{
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	if (FsRtlIsPagingFile(Data->Iopb->TargetFileObject))
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s it is page file opening. Ignore.\n", __FUNCTION__));
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	//
	//	Do not read data from VOLUME.
	//
	// ...

	// volumeRequest

	//
	//	Read file path and pass it further.
	//
	
	UNICODE_STRING requestedDirPath = { 0 };
	BOOLEAN result = FLockFltGetPath(g_flockData.filterHandle, Data->Iopb->TargetInstance, Data, &requestedDirPath, &status);

	if (!result)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: error - can't get requested directory path info.\n", __FUNCTION__));
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: ready to process the request for %wZ.\n", __FUNCTION__, &requestedDirPath));

	switch (Data->Iopb->Parameters.DirectoryControl.QueryDirectory.FileInformationClass)
	{
	case FileBothDirectoryInformation:
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: requested 'FileBothDirectoryInformation'\n", __FUNCTION__));
		status = FLockHandleFileBothDirectoryInformation(Data, FltObjects, &requestedDirPath);
		break;

	case FileDirectoryInformation:
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: requested 'FileDirectoryInformation'\n", __FUNCTION__));
		status = FLockHandleFileDirectoryInformation(Data, FltObjects, &requestedDirPath);
		break;

	case FileFullDirectoryInformation:
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: requested 'FileFullDirectoryInformation'\n", __FUNCTION__));
		status = FLockHandleFileFullDirectoryInformation(Data, FltObjects, &requestedDirPath);
		break;

	case FileIdBothDirectoryInformation:
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: requested 'FileIdBothDirectoryInformation'\n", __FUNCTION__));
		status = FLockHandleFileIdBothDirectoryInformation(Data, FltObjects, &requestedDirPath);
		break;

	case FileIdFullDirectoryInformation:
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: requested 'FileIdFullDirectoryInformation'\n", __FUNCTION__));
		status = FLockHandleFileIdFullDirectoryInformation(Data, FltObjects, &requestedDirPath);
		break;

	case FileNamesInformation:
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: requested 'FileNamesInformation'\n", __FUNCTION__));
		status = FLockHandleFileNamesInformation(Data, FltObjects, &requestedDirPath);
		break;

	case FileObjectIdInformation:
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: requested 'FileObjectIdInformation'\n", __FUNCTION__));
		break;

	case FileReparsePointInformation:
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: requested 'FileReparsePointInformation'\n", __FUNCTION__));
		break;

	default:
		status = STATUS_UNSUCCESSFUL;
		break;
	}

	if (requestedDirPath.Buffer)
	{
		ExFreePool(requestedDirPath.Buffer);
	}

	return FLT_POSTOP_FINISHED_PROCESSING;
}



//
//	These are routines for hiding objects.
//

NTSTATUS FLockHandleByPath2(
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_Inout_ PFLT_CALLBACK_DATA Data,
__in PUNICODE_STRING _requestedDir,
__in ULONG _offsetNextEntry,
__in ULONG _offsetFileNameLength,
__in ULONG _offsetFileName,
__in ULONG _sizeOfStruct,
__in ULONG _offsetShortFileName /* could be or couldn't be - depends from structure. */
)
{
	NTSTATUS status = 0;
	FLOCK_META fm = { 0 };

	//
	//	That parameter indicates - Does the directory really contain one or more file which required to be hidden?
	//	If actually the directory has no one object with FLOCK_META in EAs - it means that we should remove
	//	FLOCK_FLAG_HAS_FLOCKS flag from the directory. It helps us to improve system performance and avoid unnecessary filtering actions.
	//

	BOOLEAN flockMetaFound = FALSE, targetDirHasSomethingToHide = FALSE;
	BOOLEAN accessDeniedOccurred = FALSE, volumeRequest = FLockIsVolumeRequest(FltObjects);

	ULONG bufferLength = Data->Iopb->Parameters.DirectoryControl.QueryDirectory.Length;
	PMDL mdlAddress = Data->Iopb->Parameters.DirectoryControl.QueryDirectory.MdlAddress;
	PVOID buffer = Data->Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer;
	UNICODE_STRING filePathString = { 0 };
	USHORT allocatedBufferLength = _requestedDir->Length + WCHAR_LEN(512);
	WCHAR* preAllocatedFullFilePath = ExAllocatePool(NonPagedPool, allocatedBufferLength);

	if (!preAllocatedFullFilePath)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	RtlInitEmptyUnicodeString(&filePathString, preAllocatedFullFilePath, allocatedBufferLength);
	RtlCopyUnicodeString(&filePathString, _requestedDir);

	if ((buffer == NULL) && (mdlAddress != NULL))
	{
		// Work with an MDL?
	}

	if (buffer)
	{
		for (PUCHAR pFileInfo = (PUCHAR)buffer, prev = NULL;;)
		{
			ULONG nextEntryOffset = FLOCK_FIELD_READ(pFileInfo, _offsetNextEntry, ULONG);
			ULONG fileNameLength = FLOCK_FIELD_READ(pFileInfo, _offsetFileNameLength, ULONG);
			BOOLEAN foundMeta = FALSE, requireHide = FALSE, requireReadMeta = TRUE;
			UCHAR hashByFilePath[16] = { 0 };

			// Save pointer on first unreferenced object.
			if (prev == NULL)
			{
				prev = pFileInfo;
			}

			UNICODE_STRING fileName;
			fileName.Length = (USHORT)fileNameLength /*pFileInfo->FileNameLength*/;
			fileName.MaximumLength = (USHORT)fileNameLength; // pFileInfo->FileNameLength;
			fileName.Buffer = FLOCK_FIELD_PTR(pFileInfo, _offsetFileName, WCHAR); //pFileInfo->FileName;

			//
			// In each directory we have as minimum two sub folders '.',  '..'
			// but not in the root (volume) directory - "c:\","x:\".
			//

			// Do not process default entries like - '.' and '..'.
			// It is a little optimization feature.
			if (((fileName.Length == sizeof(WCHAR)) && (fileName.Buffer[0] == L'.')) ||
				((fileName.Length == (sizeof(WCHAR) * 2)) && ((fileName.Buffer[0] == L'.') && (fileName.Buffer[1] == L'.'))))
			{
				goto to_next_iteration;
			}

			ULONG requieredSize = _requestedDir->Length + 2 * sizeof(WCHAR) /* for the back slash symbol '\' */ + fileNameLength /* pFileInfo->FileNameLength */;

			if (requieredSize > allocatedBufferLength)
			{
				//
				// Free memory for the old buffer and allocate new memory block.
				//

				ExFreePool(preAllocatedFullFilePath);

				preAllocatedFullFilePath = ExAllocatePool(NonPagedPool, requieredSize);
				if (!preAllocatedFullFilePath)
				{
					//
					// That is not good to as we do.
					//

					return STATUS_INSUFFICIENT_RESOURCES;
				}

				//
				// Save new buffer size and prepare unicode string for future work.
				//
				allocatedBufferLength = (USHORT)requieredSize;

				RtlInitEmptyUnicodeString(&filePathString, preAllocatedFullFilePath, allocatedBufferLength);
				RtlCopyUnicodeString(&filePathString, _requestedDir);
			}

			//
			// Cut a length of the string.
			//

			filePathString.Length = _requestedDir->Length;

			//
			// Add backslash if it's need. Ignore all NT_SUCCESS validations, the memory was prepared earlier.
			//
			if (!FLockHasBackslash(&filePathString))
			{
				RtlAppendUnicodeToString(&filePathString, L"\\");
			}

			RtlAppendUnicodeStringToString(&filePathString, &fileName);

			//
			//	Print name of the just built file path.
			//

			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: file enumerate: %wZ, full path is %wZ\n", __FUNCTION__, &fileName, &filePathString));

			//
			//	If cache enabled, we should handle this request through our internal cache.
			//

#pragma region WORK_WITH_CACHE

			if (FLockCacheIsEnabled())
			{
				if (filePathString.Length)
				{
					FLockMd5Calc((PUCHAR)filePathString.Buffer, filePathString.Length, hashByFilePath);

					ULONG stepsRequired = 0;
					FLOCK_CACHE_ENTRY fce = { 0 };

					if (FLockCacheLookupOneCall(hashByFilePath, &fce, &stepsRequired))
					{
						if (fce.presentMeta == FALSE)
						{
							PT_DBG_PRINT(PTGBG_FLOCK_CACHE,
								("FLock!%s: cache_strike. Ignore reading EAs. Cached entry found, required to do %d steps.\n",
								__FUNCTION__,
								stepsRequired));

							requireReadMeta = FALSE;
						}
						else
						{
							PT_DBG_PRINT(PTGBG_FLOCK_CACHE,
								("FLock!%s: cache_strike. Cache entry found - read EAs! It took %d steps.\n",
								__FUNCTION__,
								stepsRequired));
						}
					}
				}
			}

#pragma endregion WORK_WITH_CACHE

			if (requireReadMeta)
			{
				//
				//	Open the file by path and read FLock-meta.
				//

				foundMeta = FLockFltOpenAndReadFirstMeta(
					g_flockData.filterHandle,
					Data->Iopb->TargetInstance,
					&filePathString,
					&fm,
					&status);

				//
				//	It is important to save in cache just read information from disk.
				//

#pragma region WORK_WITH_CACHE

				if (FLockCacheIsEnabled())
				{
					FLockMd5Calc( (PUCHAR) filePathString.Buffer, filePathString.Length, hashByFilePath);

					FLockCacheAddEntryOneCall(hashByFilePath, foundMeta);
				}

#pragma endregion WORK_WITH_CACHE

				if (foundMeta)
				{
					//
					//	Yes, that directory really has something to protect.
					//	And may be we should really to hide the file system object.
					//

					flockMetaFound = TRUE;
					requireHide = FLockStorageVerifyHidding(  (PFLOCK_ID)fm.uniqueId );

					if (requireHide)
					{
						targetDirHasSomethingToHide = TRUE;

						PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: to hide - %wZ.\n", __FUNCTION__, &filePathString));
					}
				}
				else
				{
					if (status == STATUS_ACCESS_DENIED)
					{
						accessDeniedOccurred = TRUE;

						PT_DBG_PRINT(PTDBG_TRACE_ERRORS,
							("FLock!%s: error STATUS_ACCESS_DENIED - can't touch %wZ (status is 0x%x).\n",
							__FUNCTION__,
							&filePathString,
							status));
					}
				}
			}

			//
			//	Process the file - hide it if it's really need.
			//

			if (requireHide)
			{
				PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: require to hide %wZ.\n", __FUNCTION__, &filePathString));

				if (prev == pFileInfo)
				{
					//
					//	In sub folder we two included directories - "." and "..", but we have no them
					//	when we are in the root of volume - "\Device\HarddiskVolume1\".
					//
					//	Here we have to handle following cases:
					//
					//	1. There is only one file\folder in the root and in that case we can some things:
					//		* Complete the request with an error;
					//		* Show file with unknown name.
					//
					//	2. There are many different files but our file (or files!) is first in the list.
					//		* Move all entries to top position (from end to begin).
					//

					PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: there is no previous entry for : %wZ\n", __FUNCTION__, &filePathString));

					if (nextEntryOffset)
					{
						//
						//	There are some entries after current, move them all from end to begin of the buffer.
						//

						PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: there is a next entry for : %wZ\n", __FUNCTION__, &filePathString));

						PUCHAR nextEntryAddress = (PUCHAR)pFileInfo + nextEntryOffset;
						ULONG sizeOfDataToMove = ((PUCHAR)buffer + bufferLength) /* end of buffer */ - ((PUCHAR) nextEntryAddress) /* next entry */;

						RtlCopyMemory(pFileInfo, nextEntryAddress, sizeOfDataToMove);

						FltIsCallbackDataDirty(Data);

						//	Go to next iteration.
						prev = NULL;
						continue;
					}
					else
					{
						//
						//	This is a single entry which should be protected. There no others - before and after us.
						//

						PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: ignore. There is no next entry for : %wZ\n", __FUNCTION__, &filePathString));
						
						//
						//	Change name to the file. It happens seldom but we can handle and that case too.
						//

						WCHAR replaceSymbol = L'R';
						PWCHAR fileNameBuffer = FLOCK_FIELD_PTR(pFileInfo, _offsetFileName, WCHAR); //pFileInfo->FileName;

						for (ULONG pos = 0; pos < fileNameLength; pos++)
						{
							fileNameBuffer[pos] = replaceSymbol;
						}

						if (_offsetShortFileName != 0)
						{
							PWCHAR shortFileNameBuffer = FLOCK_FIELD_PTR(pFileInfo, _offsetShortFileName, WCHAR); //pFileInfo->ShortName;
							ULONG shortNameBufferSize = 12 /* WCHARs */;

							for (ULONG pos = 0; pos < shortNameBufferSize; pos++)
							{
								WCHAR ch = shortFileNameBuffer[pos];

								if ((ch != 0) && (ch != L'.'))
								{
									shortFileNameBuffer[pos] = replaceSymbol;
								}
							}
						}
					}
				}
				else
				{
					if (nextEntryOffset) /*pFileInfo->NextEntryOffset*/
					{
						//
						//	Calculate offset to next element for previous entry.
						//	That next element actually is an element which is the next for current (hiding) element. 
						//

						ULONG offset = ((ULONG)((PUCHAR)pFileInfo - (PUCHAR)prev)) + nextEntryOffset;
						//offset = ALIGN_DOWN(offset, LONGLONG);

						FLOCK_WRITE_FIELD(prev, _offsetNextEntry, ULONG, offset);
						// prev->NextEntryOffset = offset;

						RtlZeroMemory(pFileInfo, _sizeOfStruct);

						PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: set prev.next to %d for - %wZ\n", __FUNCTION__, offset, &filePathString));
					}
					else
					{
						//
						//	We have previous entry, but have no next.
						//	Mark previous as last and write zeros for our (hiding) entry.
						//

						FLOCK_WRITE_FIELD(prev, _offsetNextEntry, ULONG, 0);
						//prev->NextEntryOffset = 0;

						// Here I do not delete fileName (only first character). I remove just a part of the structure with fixed size.
						RtlZeroMemory(pFileInfo, _sizeOfStruct);

						PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: mark previous entry as last - %wZ\n", __FUNCTION__));
					}

					//
					//	I'm not sure about that call, but it's better to do than not! 
					//	Because actually we just changed the original data.
					//

					FltIsCallbackDataDirty(Data);
				}
			}
			else
			{
				// Update link.
				prev = pFileInfo;
			}

			//
			//	To go further if it's where to go =)
			//

to_next_iteration:

			//	ULONG nextEntry = FLOCK_FIELD_READ(pFileInfo, _offsetNextEntry, ULONG);
			if (nextEntryOffset /*pFileInfo->NextEntryOffset*/)
			{
				pFileInfo = ((PUCHAR)pFileInfo + nextEntryOffset);
			}
			else
			{
				break;
			}
		}
	}

	//
	//	To do some small and important optimization things.
	//

	if ((!volumeRequest) && (!flockMetaFound) && (!accessDeniedOccurred))
	{
		//
		//	Here we can decide to remove FLOCK_META from requested directory in case we 
		//	did not find any FLOCK_META attributes in included files in target directory
		//	and also if we did not get access denied error while tried to read extended attributes.
		//
		//	if (No one FLOCK_META was read and STATUS_ACCESS_DENIED not occurred)
		//

		//
		//	Notes:
		//		Here we need update information in cache and in storage!
		//

		FLOCK_META targetDirFm = { 0 };

		if (FLockFltReadFirstMeta(Data->Iopb->TargetInstance, Data->Iopb->TargetFileObject, &targetDirFm, &status))
		{
			ClearFlag(targetDirFm.flags, FLOCK_FLAG_HAS_FLOCKS);

			if (FLockFltWriteFlockMeta(Data->Iopb->TargetInstance, Data->Iopb->TargetFileObject, &targetDirFm, &status))
			{
				PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: success - unused flag was cleared in flock's meta.\n", __FUNCTION__));
			}
			else
			{
				PT_DBG_PRINT(PTDBG_TRACE_ERRORS,
					("FLock!%s: error - couldn't clear flag in flock meta in target location, status is 0x%x.\n",
					__FUNCTION__,
					status));
			}
		}
	}
	else if (volumeRequest)
	{
		//
		//	For volume request we need to set property context information.
		//	It will help us to ignore unnecessary calls in a future.
		//

#pragma region WORK_WITH_CONTEXT

		PFLOCK_FLT_CONTEXT flockContext = NULL;
		BOOLEAN contextAcquired = FALSE, contextIsStale = TRUE, contextCreated = FALSE;

		if (FLockUseContextHelp())
		{
			NTSTATUS contextStatus = FLockContextProcess(
				FltObjects,
				Data,
				&flockContext,
				volumeRequest,
				&contextCreated,
				&contextAcquired,
				&contextIsStale);

			if (NT_SUCCESS(contextStatus))
			{
				if (contextAcquired)
				{
					//
					//	Update volume's context information.
					//

					flockContext->hasMetaInfo = flockMetaFound;
					flockContext->hasHiddenObject = targetDirHasSomethingToHide;
					FLockStampGenerate(&flockContext->timeStamp);

					FLockContextRelease(flockContext);
				}
			}
			else
			{
				PT_DBG_PRINT(PTGBG_TRACE_CONTEXT | PTDBG_TRACE_ERRORS,
					("FLock!%s: Ctx. Failed to get - %wZ, vol %d.\n",
					__FUNCTION__,
					&FltObjects->FileObject->FileName,
					volumeRequest));
			}
		}

#pragma endregion WORK_WITH_CONTEXT
	}

	if (preAllocatedFullFilePath)
	{
		ExFreePool(preAllocatedFullFilePath);
	}

	return STATUS_SUCCESS;
}


NTSTATUS
FLockHandleFileIdBothDirectoryInformation(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
__in PUNICODE_STRING _requestedDir
)
{
	const ULONG offsetNextEntry = OFFSET_OF(FILE_ID_BOTH_DIR_INFORMATION, NextEntryOffset);
	const ULONG offsetFileNameLength = OFFSET_OF(FILE_ID_BOTH_DIR_INFORMATION, FileNameLength);
	const ULONG offsetFileName = OFFSET_OF(FILE_ID_BOTH_DIR_INFORMATION, FileName);
	const ULONG sizeOfStructure = sizeof(FILE_ID_BOTH_DIR_INFORMATION);
	const ULONG offsetShortName = OFFSET_OF(FILE_ID_BOTH_DIR_INFORMATION, ShortName);

	return FLockHandleByPath2(FltObjects, Data, _requestedDir, offsetNextEntry, offsetFileNameLength, offsetFileName, sizeOfStructure, offsetShortName);
}

NTSTATUS
FLockHandleFileBothDirectoryInformation(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
__in PUNICODE_STRING _requestedDir
)
{
	const ULONG offsetNextEntry = OFFSET_OF(FILE_BOTH_DIR_INFORMATION, NextEntryOffset);
	const ULONG offsetFileNameLength = OFFSET_OF(FILE_BOTH_DIR_INFORMATION, FileNameLength);
	const ULONG offsetFileName = OFFSET_OF(FILE_BOTH_DIR_INFORMATION, FileName);
	const ULONG sizeOfStructure = sizeof(FILE_BOTH_DIR_INFORMATION);
	const ULONG offsetShortName = OFFSET_OF(FILE_BOTH_DIR_INFORMATION, ShortName);

	return FLockHandleByPath2(FltObjects, Data, _requestedDir, offsetNextEntry, offsetFileNameLength, offsetFileName, sizeOfStructure, offsetShortName);
}


NTSTATUS
FLockHandleFileDirectoryInformation(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
__in PUNICODE_STRING _requestedDir
)
{
	const ULONG offsetNextEntry = OFFSET_OF(FILE_DIRECTORY_INFORMATION, NextEntryOffset);
	const ULONG offsetFileNameLength = OFFSET_OF(FILE_DIRECTORY_INFORMATION, FileNameLength);
	const ULONG offsetFileName = OFFSET_OF(FILE_DIRECTORY_INFORMATION, FileName);
	const ULONG sizeOfStructure = sizeof(FILE_DIRECTORY_INFORMATION);

	return FLockHandleByPath2(FltObjects, Data, _requestedDir, offsetNextEntry, offsetFileNameLength, offsetFileName, sizeOfStructure, 0);
}


NTSTATUS
FLockHandleFileFullDirectoryInformation(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
__in PUNICODE_STRING _requestedDir
)
{
	const ULONG offsetNextEntry = OFFSET_OF(FILE_FULL_DIR_INFORMATION, NextEntryOffset);
	const ULONG offsetFileNameLength = OFFSET_OF(FILE_FULL_DIR_INFORMATION, FileNameLength);
	const ULONG offsetFileName = OFFSET_OF(FILE_FULL_DIR_INFORMATION, FileName);
	const ULONG sizeOfStructure = sizeof(FILE_FULL_DIR_INFORMATION);

	return FLockHandleByPath2(FltObjects, Data, _requestedDir, offsetNextEntry, offsetFileNameLength, offsetFileName, sizeOfStructure, 0);
}


NTSTATUS
FLockHandleFileIdFullDirectoryInformation(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
__in PUNICODE_STRING _requestedDir
)
{
	const ULONG offsetNextEntry = OFFSET_OF(FILE_ID_FULL_DIR_INFORMATION, NextEntryOffset);
	const ULONG offsetFileNameLength = OFFSET_OF(FILE_ID_FULL_DIR_INFORMATION, FileNameLength);
	const ULONG offsetFileName = OFFSET_OF(FILE_ID_FULL_DIR_INFORMATION, FileName);
	const ULONG sizeOfStructure = sizeof(FILE_ID_FULL_DIR_INFORMATION);

	return FLockHandleByPath2(FltObjects, Data, _requestedDir, offsetNextEntry, offsetFileNameLength, offsetFileName, sizeOfStructure, 0);
}


NTSTATUS
FLockHandleFileNamesInformation(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
__in PUNICODE_STRING _requestedDir
)
{
	const ULONG offsetNextEntry = OFFSET_OF(FILE_NAMES_INFORMATION, NextEntryOffset);
	const ULONG offsetFileNameLength = OFFSET_OF(FILE_NAMES_INFORMATION, FileNameLength);
	const ULONG offsetFileName = OFFSET_OF(FILE_NAMES_INFORMATION, FileName);
	const ULONG sizeOfStructure = sizeof(FILE_NAMES_INFORMATION);

	return FLockHandleByPath2(FltObjects, Data, _requestedDir, offsetNextEntry, offsetFileNameLength, offsetFileName, sizeOfStructure, 0);
}

NTSTATUS
FLockHandleFileObjectIdInformation(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
__in PUNICODE_STRING _requestedDir
)
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(_requestedDir);

	return STATUS_NOT_IMPLEMENTED;
}


NTSTATUS
FLockHandleFileReparsePointInformation(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
__in PUNICODE_STRING _requestedDir
)
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(_requestedDir);

	return STATUS_NOT_IMPLEMENTED;
}
