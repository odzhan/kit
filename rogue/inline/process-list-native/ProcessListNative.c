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
	D_API( NtQuerySystemInformation );
	D_API( RtlAllocateHeap );
	D_API( RtlFreeHeap );
} API ;

/* API Hashes */
#define H_API_NTQUERYSYSTEMINFORMATION		0x7bc23928 /* NtQuerySystemInformation */
#define H_API_RTLALLOCATEHEAP			0x3be94c5a /* RtlAllocateHeap */
#define H_API_RTLFREEHEAP			0x73a9e4d7 /* RtlFreeHeap */

/* LIB Hashes */
#define H_LIB_NTDLL				0x1edab0ed /* ntdll.dll */

/*!
 *
 * Purpose:
 *
 * Prints a list of running process's and info about them.
 *
!*/
D_SEC( A ) DWORD ProcessListNative( PROGUE_API Rogue, PVOID Context, USHORT Uid, PVOID Buffer, UINT32 Length, PBUFFER Output )
{
	API				Api;

	DWORD				Ret = ROGUE_RETURN_FAILURE;
	SIZE_T				Len = 0;

	PBUFFER				Out = NULL;
	PSYSTEM_PROCESS_INFORMATION	Tmp = NULL;
	PSYSTEM_PROCESS_INFORMATION	Spi = NULL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );

	Api.NtQuerySystemInformation = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTQUERYSYSTEMINFORMATION );
	Api.RtlAllocateHeap          = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLALLOCATEHEAP );
	Api.RtlFreeHeap              = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLFREEHEAP );

	/* Create output buffer */
	if ( ( Out = BufferCreate() ) != NULL ) {

		/* Query the total size required for the information */
		if ( ! NT_SUCCESS( Api.NtQuerySystemInformation( SystemProcessInformation, NULL, 0, &Len ) ) ) {
			/* Allocate a buffer to hold this information safelyt */
			if ( ( Spi = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, Len ) ) != NULL ) {
				if ( NT_SUCCESS( Api.NtQuerySystemInformation( SystemProcessInformation, Spi, Len, &Len ) ) ) {
					Tmp = C_PTR( Spi );

					/* Enumerate the process info */
					while ( Tmp->NextEntryOffset != 0 ) {
						/* Print out the buffer to the message */
						BufferPrintf( Out, C_PTR( G_PTR( "%S\t%hu\t%hu\n" ) ), Tmp->ImageName.Buffer, Tmp->UniqueProcessId, Tmp->InheritedFromUniqueProcessId );

						/* Increment to the next entry! */
						Tmp = C_PTR( U_PTR( Tmp ) + Tmp->NextEntryOffset );
					};
				};
				/* Cleanup! */
				Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Spi );
			};
		};
		if ( Out->Buffer != NULL && Out->Length != 0 ) {
			/* Did we succeed? */
			Ret = BufferAddRaw( Output, Out->Buffer, Out->Length ) != TRUE ? ROGUE_RETURN_FAILURE : ROGUE_RETURN_SUCCESS;
		};

		/* Cleanup! */
		Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Out->Buffer );
		Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Out );
		Out = NULL;
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );

	/* Return */
	return Ret;
};
