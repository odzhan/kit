/*!
 *
 * ROGUE
 *
 * GuidePoint Security LLC
 *
 * Threat and Attack Simulation Team
 *
!*/

#include "Common.h"

typedef struct
{
	D_API( NtQueryInformationProcess );
	D_API( NtGetNextProcess );
	D_API( RtlAllocateHeap );
	D_API( RtlFreeHeap );
	D_API( NtClose );
} API ;

/* API Hashes */
#define H_API_NTQUERYINFORMATIONPROCESS		0x8cdc5dc2 /* NtQueryInformationProcess */
#define H_API_NTGETNEXTPROCESS			0x0963c3a5 /* NtGetNextProcess */
#define H_API_RTLALLOCATEHEAP			0x3be94c5a /* RtlAllocateHeap */
#define H_API_RTLFREEHEAP			0x73a9e4d7 /* RtlFreeHeap */
#define H_API_NTCLOSE				0x40d6e69d /* NtClose */

/* LIB Hashes */
#define H_LIB_NTDLL				0x1edab0ed /* ntdll.dll */

/*!
 *
 * Purpose:
 *
 * Prints a list of running process's and info about them.
 *
!*/
D_SEC( A ) DWORD ProcessListNative( PROGUE_API Rogue, PVOID Context, PVOID Buffer, UINT32 Length, PBUFFER Output )
{
	API				Api;
	UNICODE_STRING			Uni;
	PROCESS_BASIC_INFORMATION	Pbi;

	DWORD				Ret = 0;
	SIZE_T				Len = 0;

	PVOID				Nxt = NULL;
	PVOID				Cur = NULL;
	PBUFFER				Out = NULL;
	PUNICODE_STRING			Exe = NULL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Uni, sizeof( Uni ) );
	RtlSecureZeroMemory( &Pbi, sizeof( Pbi ) );

	Api.NtQueryInformationProcess = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTQUERYINFORMATIONPROCESS );
	Api.NtGetNextProcess          = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTGETNEXTPROCESS );
	Api.RtlAllocateHeap           = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLALLOCATEHEAP );
	Api.RtlFreeHeap               = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLFREEHEAP );
	Api.NtClose                   = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTCLOSE );

	/* Create output buffer */
	if ( ( Out = BufferCreate() ) != NULL ) {

		/* Loop through every process that I can open with PROCESS_QUERY_LIMITED_INFORMATION */
		while ( NT_SUCCESS( Api.NtGetNextProcess( Cur, PROCESS_QUERY_LIMITED_INFORMATION, 0, 0, &Nxt ) ) ) {
			if ( Cur != NULL ) {
				Api.NtClose( Cur );
			};
			/* Set next pointer */
			Cur = C_PTR( Nxt );

			/* Query the current process image path name */
			if ( NT_SUCCESS( Api.NtQueryInformationProcess( Cur, ProcessBasicInformation, &Pbi, sizeof( Pbi ), NULL ) ) ) {
				/* Extract the executable name ! */
				if ( ! NT_SUCCESS( Api.NtQueryInformationProcess( Cur, ProcessImageFileName, NULL, 0, &Len ) ) ) {
					/* Create the pool to hold the buffer */
					if ( ( Exe = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, Len ) ) != NULL ) {
						if ( NT_SUCCESS( Api.NtQueryInformationProcess( Cur, ProcessImageFileName, Exe, Len, &Len ) ) ) {
							/* Extract the executable name from the path */
							for ( USHORT Idx = ( Exe->Length / sizeof( WCHAR ) ) - 1 ; Idx != 0 ; --Idx ) {
								if ( Exe->Buffer[ Idx ] == L'\\' || Exe->Buffer[ Idx ] == L'/' ) {
									Uni.Buffer = & Exe->Buffer[ Idx + 1 ];
									Uni.Length = Exe->Length - ( Idx + 1 ) * sizeof( WCHAR );
									Uni.MaximumLength = Exe->MaximumLength - ( Idx + 1 ) * sizeof( WCHAR );
									break;
								};
							};
							/* Add print formatted buffer */
							BufferPrintf( Out, C_PTR( G_PTR( "%S %hu %hu" ) ), Exe->Buffer, Pbi.UniqueProcessId, Pbi.InheritedFromUniqueProcessId );
						};
						/* Cleanup */
						Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Exe );
						Exe = NULL;
					};
				};
			};
		};
		/* Insert into buffer ! */
		if ( Out->Buffer != NULL && Out->Length != 0 ) {
			BufferAddRaw( Output, Out->Buffer, Out->Length );
		};

		/* Cleanup! */
		Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Out->Buffer );
		Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Out );
		Out = NULL;

		if ( Cur != NULL ) {
			Api.NtClose( Cur );
		};
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Uni, sizeof( Uni ) );
	RtlSecureZeroMemory( &Pbi, sizeof( Pbi ) );
};
