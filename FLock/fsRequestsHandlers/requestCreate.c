//
// Author:
//
//		Burlutsky Stas
//		burluckij@gmail.com
//

#include "../flock.h"
#include "../FLockStorage.h"
#include "../FLockCache.h"
#include "../FLockMd5.h"

extern ULONG gTraceFlags;
extern FLOCK_DEVICE_DATA g_flockData;

//
//	Minifilter drivers should not return FLT_PREOP_SYNCHRONIZE for create operations, because these operations
//	are already synchronized by the filter manager.If a minifilter driver has registered preoperation and postoperation
//	callback routines for IRP_MJ_CREATE operations, the post - create callback routine is called at IRQL =
//	PASSIVE_LEVEL, in the same thread context as the pre - create callback routine.
//


FLT_PREOP_CALLBACK_STATUS FLockPreCreate(
	_Inout_ PFLT_CALLBACK_DATA    Data,
	_In_    PCFLT_RELATED_OBJECTS FltObjects,
	_Out_   PVOID                 *CompletionContext
	)
{
	UNREFERENCED_PARAMETER(CompletionContext);

	PAGED_CODE();

	// PT_DBG_PRINT(PTDBG_TRACE_ERRORS, ("FLock!%s: entered.\n", __FUNCTION__));

	NTSTATUS status = STATUS_SUCCESS;
	FLOCK_META fm = { 0 };

	if (FLockDoesItRequireToStop())
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if (FLT_IS_FASTIO_OPERATION(Data))
	{
		return FLT_PREOP_DISALLOW_FASTIO;
	}

	if (BooleanFlagOn(Data->Iopb->OperationFlags, SL_OPEN_PAGING_FILE))
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: warning - its a page file opening.", __FUNCTION__));
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	//
	// Do we actually have something to protect?
	//

	if (!FLockStorageHasLockedUserObjects())
	{
		// There is no one object which should be protected for an access.
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if (BooleanFlagOn(FltObjects->FileObject->Flags, FO_VOLUME_OPEN))
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: info - this is a volume open request.", __FUNCTION__));
	}

	if (IoGetTopLevelIrp() == FSRTL_FSP_TOP_LEVEL_IRP)
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if (Data->Iopb->TargetFileObject)
	{
		if (FsRtlIsPagingFile(Data->Iopb->TargetFileObject))
		{
			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: it is page file opening. Ignore.\n", __FUNCTION__));
			return FLT_PREOP_SUCCESS_NO_CALLBACK;
		}
	}

	if (!FLT_IS_IRP_OPERATION(Data))
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: it is not IRP based operation.\n", __FUNCTION__));
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

// 	ULONG	createDisposition = (Data->Iopb->Parameters.Create.Options >> 24) & 0x000000ff;
// 	ULONG	createOptions = Data->Iopb->Parameters.Create.Options & 0x00ffffff;
 	ULONG	desiredAccess = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;

	//if (BooleanFlagOn(Data->Iopb->Parameters.Create.Options, FILE_OPEN_BY_FILE_ID)) {
	//	Process as a typical request.
	//}

	//
	//	If it the FILE_DELETE_ON_CLOSE flag is set than we should handle that request here in pre-operation handler.
	//	If the flag is not set then we need left all work to post-operation handler.
	//

	if ( BooleanFlagOn(desiredAccess, FILE_DELETE_ON_CLOSE) )
	{
		//
		// Later we will handle verification of the access request through FLockCache.
		//

		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: read-flocks.\n", __FUNCTION__));

		UNICODE_STRING filepath = { 0 };
		BOOLEAN result = FLockFltReadFirstMetaWithGetFilePath(
			g_flockData.filterHandle,
			Data->Iopb->TargetInstance,
			Data,
			&fm,
			&filepath,
			&status);

		if (result)
		{
			//
			// Verify an access policy.
			//

			BOOLEAN lockAccessPolicy = FALSE;

			//
			// Search data in our storage with access policies.
			//

			if (FLockStorageIsLoaded())
			{
				lockAccessPolicy = FLockStorageVerifyLock( (PFLOCK_ID) fm.uniqueId);
			}

			// For first time we use that.
			if (!lockAccessPolicy)
			{
				lockAccessPolicy = BooleanFlagOn(fm.flags, FLOCK_FLAG_LOCK_ACCESS);
			}

			if (lockAccessPolicy)
			{
				PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: access was locked to %wZ\n", __FUNCTION__, &filepath));

				if (filepath.Buffer)
				{
					ExFreePool(filepath.Buffer);
				}

				//
				//	Lock an access to a file.
				//

				Data->IoStatus.Status = STATUS_ACCESS_DENIED;
				return FLT_PREOP_COMPLETE;
			}
			else
			{
				//
				// Free memory for a file path buffer.
				//

				if (filepath.Buffer)
				{
					ExFreePool(filepath.Buffer);
				}
			}
		}
		else
		{
			//
			//	Couldn't read flock-meta from a file or just not found.
			//
		}

		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	
	//
	//	Mini-filter drivers should not return FLT_PREOP_SYNCHRONIZE for create operations, because these operations
	//	are already synchronized by the filter manager. If a mini-filter driver has registered pre-operation and post-operation
	//	callback routines for IRP_MJ_CREATE operations, the post - create callback routine is called at IRQL = PASSIVE_LEVEL,
	//	in the same thread context as the pre-create callback routine.
	//

	return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}


FLT_POSTOP_CALLBACK_STATUS FLockPostCreate(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
	)
{
	NTSTATUS status, contextStatus = STATUS_NOT_ALLOWED_ON_SYSTEM_FILE, finalResult = FLT_POSTOP_FINISHED_PROCESSING;
	FLOCK_META fm = { 0 };
	UCHAR hash[16] = { 0 };
	UNICODE_STRING fpath = { 0 };
	PFLOCK_FLT_CONTEXT flockContext = NULL;
	BOOLEAN contextCreated = FALSE, contextAcquired = FALSE, contextIsStale = TRUE, volumeOpenRequest = FALSE;
	BOOLEAN hasHash = FALSE, readFLockMetaSuccessfully = FALSE;

	UNREFERENCED_PARAMETER(CompletionContext);

	// 
	//	Do not process the request if one of the follow conditions is true:
	//
	//	1. Create operation completed with an error status;
	//	2. Require to re-issue new request because of STATUS_REPARSE;
	//	3. The instance of the driver is going to be closed, FLTFL_POST_OPERATION_DRAINING flags says about it.
	//

    if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING) || FLockDoesItRequireToStop())
    {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

	if (!NT_SUCCESS(Data->IoStatus.Status) || (Data->IoStatus.Status == STATUS_REPARSE))
	{
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	if (IoGetTopLevelIrp() == FSRTL_FSP_TOP_LEVEL_IRP)
	{
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	if (FsRtlIsPagingFile(Data->Iopb->TargetFileObject))
	{
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	// 
	//	Condition to clarification that it is an open-volume request (https://community.osr.com/discussion/77301).
	//

	volumeOpenRequest = FLockIsVolumeRequest(FltObjects);

#pragma region WORK_WITH_CONTEXT

	if (FLockUseContextHelp())
	{
		if (volumeOpenRequest)
		{
			PT_DBG_PRINT(PTGBG_TRACE_CONTEXT,
				("FLock!%s: It is a request to open volume. FLen %d : FRelated %p.\n",
				__FUNCTION__,
				FltObjects->FileObject->FileName.Length,
				FltObjects->FileObject->RelatedFileObject));

			contextStatus = FLockFindOrCreateVolumeContext(FltObjects, TRUE, &flockContext, &contextCreated);
		}
		else
		{
			contextStatus = FLockFindOrCreateFileContext(Data, TRUE, &flockContext, &contextCreated);
		}

		if (NT_SUCCESS(contextStatus))
		{
			//
			//	Mark context as acquired.
			//
			//	It is require to do following things later:
			//	1. ExRelease... flockContext->Resource;
			//	2. FltReleaseContext(flockContext);
			//
			//	I'm concerned about using PUSH_LOCKs for big parts of code.
			//	Here I acquire lock before touching FS and leave it after. I have suspicious about it.
			//

			// KeEnterCriticalRegion(); << not require to call it.
			FltAcquirePushLockExclusive(&flockContext->resource);
			contextAcquired = TRUE;
		}

		//
		//	Do verifications - how old information we have in flock's context?
		//	If information we have is in actual state - we can use it freely,
		//	otherwise if information we have is stale - we should update it!
		//

		if (contextAcquired)
		{
			if (contextCreated)
			{
				//
				//	If it is a newly created context we should consider it as a context with a stale information.
				//	Because we do not know real state of the file, cache can help us not to do additional disk operation.
				//	Also here we should re-acquire the same resource exclusively.
				//

				contextIsStale = TRUE;
			}
			else
			{
				if (contextIsStale = FLockStampIsStale(&flockContext->timeStamp))
				{
					//
					//	Information we have is stale. Update it.
					//
				}
				else
				{
					if (flockContext->hasMetaInfo)
					{
						//
						//	Just opened file has flock's meta attributes.
						//	Now we should try to find information in our internal cache or read from disk in case we fail to find them in memory.
						//

						PT_DBG_PRINT(PTGBG_TRACE_CONTEXT,
							("FLock!%s: Ctx. We should verify incoming request! Stamp info is %lld.\n",
							__FUNCTION__,
							flockContext->timeStamp.stamp.QuadPart));
					}
					else
					{
						//
						//	Target file has no any flock meta information, ignore any handling.
						//	Do not touch FlockCache at all! (Now I'm not sure in that actions. Leave it for later.)
						//

						PT_DBG_PRINT(PTGBG_TRACE_CONTEXT,
							("FLock!%s: Ctx. We should ignore incoming request. Stamp is %lld for %wZ.\n",
							__FUNCTION__,
							flockContext->timeStamp.stamp.QuadPart,
							&FltObjects->FileObject->FileName));

						finalResult = FLT_POSTOP_FINISHED_PROCESSING;
						goto complete_handling;
					}
				}
			}
		}
	}

#pragma endregion WORK_WITH_CONTEXT

#pragma region WORK_WITH_CACHE

	if (FLockCacheIsEnabled())
	{
		BOOLEAN hasFilePath = FLockFltGetPath(
			g_flockData.filterHandle,
			Data->Iopb->TargetInstance,
			Data,
			&fpath,
			&status);

		if (hasFilePath)
		{
			if (fpath.Length)
			{
				hasHash = TRUE;
				FLockMd5Calc( (PUCHAR) fpath.Buffer, fpath.Length, hash);
			}

			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
				("FLock!%s: open for caching - %wZ : %wZ (%d).\n",
				__FUNCTION__,
				&fpath,
				&FltObjects->FileObject->FileName,
				FltObjects->FileObject->FileName.Length));

			ExFreePool(fpath.Buffer);
		}
		else
		{
			PT_DBG_PRINT(PTDBG_TRACE_ERRORS, ("FLock!%s: error - couldn't find file path for the opening file.\n", __FUNCTION__));
		}

		if (hasHash)
		{
			//
			//	To find info about that object in cache and skip handling if the file has no flock-meta.
			//

			ULONG stepsRequired = 0;
			FLOCK_CACHE_ENTRY fce = { 0 };

			if ( FLockCacheLookupOneCall(hash, &fce, &stepsRequired) )
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
						("FLock!%s: Ctx. Update using cached info. File %wZ (vol %d), has meta %d, stamp %lld.\n",
						__FUNCTION__,
						&FltObjects->FileObject->FileName,
						volumeOpenRequest,
						fce.presentMeta,
						flockContext->timeStamp.stamp.QuadPart));
				}

				if (fce.presentMeta == FALSE)
				{
					PT_DBG_PRINT(PTGBG_FLOCK_CACHE,
						("FLock!%s: cache_strike. Cached found - file %wZ (vol %d), took %d steps. Ignore.\n",
						__FUNCTION__,
						&FltObjects->FileObject->FileName,
						volumeOpenRequest,
						stepsRequired));

					finalResult = FLT_POSTOP_FINISHED_PROCESSING;
					goto complete_handling;
				}
				else
				{
					PT_DBG_PRINT(PTGBG_FLOCK_CACHE,
						("FLock!%s: cache_strike - %wZ (vol %d), took %d steps. Require read meta!\n", 
						__FUNCTION__,
						&FltObjects->FileObject->FileName,
						volumeOpenRequest,
						stepsRequired));
				}
			}
		}
	}

#pragma endregion WORK_WITH_CACHE

	//
	//	Here we need to read extended attributes from drive and to decide what to do with that file-open request.
	//

	readFLockMetaSuccessfully = FLockFltReadFirstMeta(
		Data->Iopb->TargetInstance,
		Data->Iopb->TargetFileObject,
		&fm,
		&status);

	//
	//	Here we can inspect the result of FLockFltReadFirstMeta(..) and errors in 'status'.
	// 	I decided to omit that code here.
	//

	//
	//	If we have calculated hash for the file path to whom user wants receive an access,
	//	save in cache information about presence of FLock meta among file's EAs.
	//
	//	flocks_cache[hash_of(file_path)] = readFLockMetaSuccessfully;
	//

	if (hasHash)
	{
		if (gTraceFlags & PTDBG_TRACE_ROUTINES)
		{
			FLockPrintMeta(&fm);
		}

		PT_DBG_PRINT(PTGBG_FLOCK_CACHE,
			("FLock!%s: add to cache - %wZ, vol %d.\n",
			__FUNCTION__,
			&Data->Iopb->TargetFileObject->FileName,
			volumeOpenRequest));

		FLockCacheAddEntryOneCall(hash, readFLockMetaSuccessfully);
	}

	//
	//	Update context only if timestamp is stale.
	//	Save the same information which was earlier saved in cache.
	//

	if (contextAcquired && contextIsStale)
	{
		flockContext->hasMetaInfo = readFLockMetaSuccessfully;
		FLockStampGenerate(&flockContext->timeStamp);

		PT_DBG_PRINT(PTGBG_TRACE_CONTEXT,
			("FLock!%s: Ctx. Is stale, update. Name %wZ, has meta - %d, vol %d, stamp is %lld.\n",
			__FUNCTION__,
			&Data->Iopb->TargetFileObject->FileName,
			readFLockMetaSuccessfully,
			volumeOpenRequest,
			flockContext->timeStamp.stamp.QuadPart));

		//
		//	Here we can free early acquired context. It helps to improve common system performance.
		//
		
		FltReleasePushLock(&flockContext->resource);
		//KeLeaveCriticalRegion();
		FltReleaseContext(flockContext);

		contextAcquired = FALSE;
	}
	else if (contextAcquired && !contextIsStale)
	{
		if ( flockContext->hasMetaInfo != readFLockMetaSuccessfully)
		{
			//
			//	Update context only if early saved info not equal to real file state info.
			//	Actually we should not have this situation in reality, but I prefer to be prepared.
			//

			flockContext->hasMetaInfo = readFLockMetaSuccessfully;
			FLockStampGenerate(&flockContext->timeStamp);
		}
	}

	if (readFLockMetaSuccessfully) // We found FLock-meta.
	{
		//
		//	Well, FLock-meta is present, verify an access policy and make a decision.
		//

		BOOLEAN lockAccessPolicy = FLockStorageVerifyLock( (PFLOCK_ID)&fm.uniqueId[0] );

		if (lockAccessPolicy)
		{
			//
			//	Query file name to print more details.
			//

			UNICODE_STRING filepath = { 0 };
			FLockFltGetPath(
				g_flockData.filterHandle,
				Data->Iopb->TargetInstance,
				Data,
				&filepath,
				&status);

			if (filepath.Buffer != NULL)
			{
				PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: Flock found! Require to protect - %wZ.\n", __FUNCTION__, &filepath));

				ExFreePool(filepath.Buffer);
				RtlZeroMemory(&filepath, sizeof(filepath));
			}
			else
			{
				PT_DBG_PRINT(PTDBG_TRACE_ERRORS, ("FLock!%s: error - couldn't find file path.\n", __FUNCTION__));
			}

			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: Success - an access was locked\n", __FUNCTION__));

			//
			// 	FltCancelFileOpen must be called before any handles are created for the file.
			// 	Callers can check the Flags member of the FILE_OBJECT structure that the FileObject parameter points to.
			// 	If the FO_HANDLE_CREATED flag is set, this means that one or more handles have been created for the file, so it is not safe to call FltCancelFileOpen.
			//

			//
			//	Callers of FltCancelFileOpen must be running at IRQL PASSIVE_LEVEL. However, it is safe for minifilter drivers
			//	to call this routine from a post - create callback routine, because post - create callback routines are guaranteed
			//	to be called at IRQL PASSIVE_LEVEL, in the context of the thread that originated the IRP_MJ_CREATE request.
			//
			// * https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/fltkernel/nf-fltkernel-fltcancelfileopen
			//

			Data->IoStatus.Status = STATUS_ACCESS_DENIED;

			FltCancelFileOpen(Data->Iopb->TargetInstance, Data->Iopb->TargetFileObject);
			FltIsCallbackDataDirty(Data);
		}
	}

complete_handling:
	if (contextAcquired)
	{
		FLockContextRelease(flockContext);
	}

	return finalResult; // FLT_POSTOP_FINISHED_PROCESSING;
}
