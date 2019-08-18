//
// Author:
//
//		Burlutsky Stas
//		burluckij@gmail.com
//

#include "FLock.h"

extern ULONG gTraceFlags;


VOID
FLockContextCleanup(
	_In_ PFLT_CONTEXT Context,
	_In_ FLT_CONTEXT_TYPE ContextType
)
{
	switch (ContextType)
	{
	case FLT_FILE_CONTEXT:
		PT_DBG_PRINT(PTGBG_TRACE_CONTEXT, ("FLock!%s: Ctx. Cleanup file.\n", __FUNCTION__));
		break;

	case FLT_VOLUME_CONTEXT:
		PT_DBG_PRINT(PTGBG_TRACE_CONTEXT, ("FLock!%s: Ctx. Cleanup volume.\n", __FUNCTION__));
		break;

	case FLT_INSTANCE_CONTEXT:
	case FLT_STREAM_CONTEXT:
	case FLT_STREAMHANDLE_CONTEXT:
		break;
	}

	if (Context)
	{
		PFLOCK_FLT_CONTEXT pContext = (PFLOCK_FLT_CONTEXT)Context;
		FltDeletePushLock(&pContext->resource);
	}
}

void FLockInitContext(
	__in PFLOCK_FLT_CONTEXT _context
	)
{
	RtlZeroMemory(_context, sizeof(FLOCK_FLT_CONTEXT));
	FLockStampGenerate(&_context->timeStamp);
	FltInitializePushLock(&_context->resource);

	//
	//	Here is one important thing we should know!
	//	By default, we assume that a file for which we create a context
	//	really has a flock-meta information among EAs.
	//

	_context->hasMetaInfo = TRUE;
	_context->hasHiddenObject = TRUE;
}


NTSTATUS FLockCreateVolumeContext(
	_Outptr_ PFLOCK_FLT_CONTEXT *_context
	)
{
	PFLOCK_FLT_CONTEXT volumeContext = NULL;

	NTSTATUS status = FltAllocateContext(FLockData()->filterHandle,
		FLT_VOLUME_CONTEXT,
		sizeof(FLOCK_FLT_CONTEXT),
		NonPagedPool, // Only non-paged memory for FLT_VOLUME_CONTEXT!
		&volumeContext);

	if (!NT_SUCCESS(status))
	{
		PT_DBG_PRINT(PTDBG_TRACE_ERRORS,
			("FLock!%s: Failed to allocate ctx with status 0x%x.\n", __FUNCTION__, status));

		return status;
	}

	FLockInitContext(volumeContext);
	*_context = volumeContext;

	return STATUS_SUCCESS;
}


NTSTATUS FLockCreateFileContext(
	_Outptr_ PFLOCK_FLT_CONTEXT *_fileContext
	)
{
	PFLOCK_FLT_CONTEXT fileContext = NULL;

	NTSTATUS status = FltAllocateContext(
		FLockData()->filterHandle,
		FLT_FILE_CONTEXT,
		sizeof(FLOCK_FLT_CONTEXT),
		NonPagedPool,
		&fileContext);

	if (!NT_SUCCESS(status))
	{
		PT_DBG_PRINT(PTDBG_TRACE_ERRORS,
			("FLock!%s: Failed to allocate ctx with status 0x%x.\n", __FUNCTION__, status));

		return status;
	}

	FLockInitContext(fileContext);
	*_fileContext = fileContext;

	return STATUS_SUCCESS;
}


NTSTATUS FLockFindOrCreateFileContext(
	_In_ PFLT_CALLBACK_DATA _cbd,
	_In_ BOOLEAN _createIfNotFound,
	_Outptr_ PFLOCK_FLT_CONTEXT *_fileContext,
	_Out_opt_ PBOOLEAN _contextCreated
	)
{
	NTSTATUS status;
	PFLOCK_FLT_CONTEXT fileContext = NULL;
	PFLOCK_FLT_CONTEXT oldFileContext = NULL;

	*_fileContext = NULL;

	SETPTR(_contextCreated, FALSE);

	//
	//  First try to get the file context.
	//

	status = FltGetFileContext(
		_cbd->Iopb->TargetInstance,
		_cbd->Iopb->TargetFileObject,
		&fileContext);

	//
	//  If the call failed because the context does not exist and
	//	the user wants to create a new one, the create a new context.
	//

	if (!NT_SUCCESS(status) && (status == STATUS_NOT_FOUND) && _createIfNotFound)
	{
		//
		//  Create a file context.
		//

		status = FLockCreateFileContext(&fileContext);

		if (!NT_SUCCESS(status))
		{
			PT_DBG_PRINT(PTDBG_TRACE_ERRORS,
				("FLock!%s: Failed to create file ctx with status 0x%x. (FileObject = %p, Instance = %p)\n",
				__FUNCTION__,
				status,
				_cbd->Iopb->TargetFileObject,
				_cbd->Iopb->TargetInstance));

			return status;
		}

		//
		//  Set the new context we just allocated on the file object.
		//

		status = FltSetFileContext(
			_cbd->Iopb->TargetInstance,
			_cbd->Iopb->TargetFileObject,
			FLT_SET_CONTEXT_KEEP_IF_EXISTS,
			fileContext,
			&oldFileContext);

		if (!NT_SUCCESS(status))
		{
			//
			// Handle - STATUS_FLT_CONTEXT_ALREADY_DEFINED
			//

			PT_DBG_PRINT(PTDBG_TRACE_ERRORS,
				("FLock!%s: Failed to set file ctx with status 0x%x. (FileObject = %p, Instance = %p)\n",
				__FUNCTION__,
				status,
				_cbd->Iopb->TargetFileObject,
				_cbd->Iopb->TargetInstance));

			//
			//  We release the context here because FltSetFileContext failed.
			//
			//  If FltSetFileContext succeeded then the context will be returned to the caller.
			//	The caller will use the context and then release it when he is done with the context.
			//

			FltReleaseContext(fileContext);

			if (status != STATUS_FLT_CONTEXT_ALREADY_DEFINED)
			{
				//
				//  FltSetFileContext failed for a reason other than the context already existing on the file.
				//	So the object now does not have any context set on it. So we return failure to the caller.
				//

				PT_DBG_PRINT(PTDBG_TRACE_ERRORS,
					("FLock!%s: Failed to set file ctx with status 0x%x != STATUS_FLT_CONTEXT_ALREADY_DEFINED. (FileObject = %p, Instance = %p)\n",
					__FUNCTION__,
					status,
					_cbd->Iopb->TargetFileObject,
					_cbd->Iopb->TargetInstance));

				return status;
			}

			//
			//  Race condition. Someone has set a context after we queried it.
			//  Use the already set context instead.
			//
			//  Return the existing context. Note that the new context that we allocated has already been released above.
			//

			fileContext = oldFileContext;
			status = STATUS_SUCCESS;
		}
		else
		{
			SETPTR(_contextCreated, TRUE);
		}
	}

	*_fileContext = fileContext;

	return status;
}


NTSTATUS FLockFindOrCreateVolumeContext(
	_In_ PCFLT_RELATED_OBJECTS _fltRelated,
	_In_ BOOLEAN _createIfNotFound,
	_Outptr_ PFLOCK_FLT_CONTEXT *_volumeContext,
	_Out_opt_ PBOOLEAN _contextCreated
	)
{
	NTSTATUS status;
	PFLOCK_FLT_CONTEXT volumeContext = NULL;
	PFLOCK_FLT_CONTEXT oldContext = NULL;

	*_volumeContext = NULL;
	SETPTR(_contextCreated, FALSE);

	status = FltGetVolumeContext(
		_fltRelated->Filter,
		_fltRelated->Volume,
		&volumeContext);

// 	if (!NT_SUCCESS(status))
// 	{
// 		PT_DBG_PRINT(PTDBG_TRACE_ERRORS,
// 			("FLock!%s: Failed to get vol ctx 0x%x.\n",
// 			__FUNCTION__,
// 			status));
// 
// 		return status;
// 	}

	if (!NT_SUCCESS(status) && (status == STATUS_NOT_FOUND) && _createIfNotFound)
	{
		status = FLockCreateVolumeContext(&volumeContext);

		if (!NT_SUCCESS(status) )
		{
			PT_DBG_PRINT(PTDBG_TRACE_ERRORS,
				("FLock!%s: Failed to create file ctx with status 0x%x.\n",
				__FUNCTION__,
				status));

			return status;
		}

		status = FltSetVolumeContext(
			_fltRelated->Volume,
			FLT_SET_CONTEXT_KEEP_IF_EXISTS,
			volumeContext,
			&oldContext);

		if (!NT_SUCCESS(status))
		{
			PT_DBG_PRINT(PTDBG_TRACE_ERRORS,
				("FLock!%s: Failed to set ctx with status 0x%x.\n",
				__FUNCTION__,
				status));

			FltReleaseContext(volumeContext);

			if (status != STATUS_FLT_CONTEXT_ALREADY_DEFINED)
			{
				PT_DBG_PRINT(PTDBG_TRACE_ERRORS,
					("FLock!%s: Failed to set volume ctx with status 0x%x != STATUS_FLT_CONTEXT_ALREADY_DEFINED.\n",
					__FUNCTION__,
					status));

				return status;
			}

			volumeContext = oldContext;
			status = STATUS_SUCCESS;
		}
		else
		{
			SETPTR(_contextCreated, TRUE);
		}
	}

	*_volumeContext = volumeContext;

	return status;
}


NTSTATUS FLockContextProcess(
	__in	PCFLT_RELATED_OBJECTS _fltObjects,
	_In_	PFLT_CALLBACK_DATA _cbd,
	__in	PFLOCK_FLT_CONTEXT* _flockContext,
	__in	BOOLEAN _thisIsVolumeRequest,
	__out	PBOOLEAN _contextCreated,
	__out	PBOOLEAN _contextAcquired,
	__out	PBOOLEAN _contextIsStale
	)
{
	NTSTATUS contextStatus;

	*_contextIsStale = TRUE;
	(*_contextAcquired) = FALSE;

	if (_thisIsVolumeRequest)
	{
		contextStatus = FLockFindOrCreateVolumeContext(_fltObjects, TRUE, _flockContext, _contextCreated);
	}
	else
	{
		contextStatus = FLockFindOrCreateFileContext(_cbd, TRUE, _flockContext, _contextCreated);
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

		FltAcquirePushLockExclusive(&(*_flockContext)->resource);
		(*_contextAcquired) = TRUE;
	}

	//
	//	Do verifications - how old information we have in flock's context?
	//	If information we have is in actual state - we can use it freely,
	//	otherwise if information we have is stale - we should update it!
	//

	if (*_contextAcquired)
	{
		if (*_contextCreated)
		{
			//
			//	If it is a newly created context we should consider it as a context with a stale information.
			//	Because we do not know real state of the file, cache can help us not to do additional disk operation.
			//	Also here we should re-acquire the same resource exclusively.
			//

			PT_DBG_PRINT(PTGBG_TRACE_CONTEXT,
				("FLock!%s: Ctx. Created - %wZ, vol %d, stamp is %lld.\n",
				__FUNCTION__,
				&_fltObjects->FileObject->FileName,
				_thisIsVolumeRequest,
				(*_flockContext)->timeStamp.stamp.QuadPart));

			(*_contextIsStale) = TRUE;
		}
		else
		{
			if ((*_contextIsStale) = FLockStampIsStale(&((*_flockContext)->timeStamp)))
			{
				//
				//	Information we have is stale. Update it.
				//
			}
			else
			{
				if ((*_flockContext)->hasMetaInfo)
				{
					//
					//	Just opened file has flock's meta attributes.
					//	Now we should try to find information in our internal cache or read from disk in case we fail to find them in memory.
					//

					PT_DBG_PRINT(PTGBG_TRACE_CONTEXT,
						("FLock!%s: Ctx. Has meta - %wZ, vol %d, stamp %lld.\n",
						__FUNCTION__,
						&_fltObjects->FileObject->FileName,
						_thisIsVolumeRequest,
						(*_flockContext)->timeStamp.stamp.QuadPart));
				}
				else
				{
					//
					//	Target file has no any flock meta information, ignore any handling.
					//	Do not touch FlockCache at all! (Now I'm not sure in that actions. Leave it for later.)
					//

					PT_DBG_PRINT(PTGBG_TRACE_CONTEXT,
						("FLock!%s: Ctx. Ignore - %wZ, vol %d, stamp %lld.\n",
						__FUNCTION__,
						&_fltObjects->FileObject->FileName,
						_thisIsVolumeRequest,
						(*_flockContext)->timeStamp.stamp.QuadPart));
				}
			}
		}
	}

	return contextStatus;
}

VOID	FLockContextRelease(
	PFLOCK_FLT_CONTEXT _context
	)
{
	FltReleasePushLock(&_context->resource);
	FltReleaseContext(_context);
}
