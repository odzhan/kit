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

#if defined( _WIN64 )

/*!
 *
 * Purpose:
 *
 * Goes to sleep and avoids the DelayExecutin period.
 *
!*/
D_SEC( D ) VOID WINAPI Sleep_Hook( _In_ DWORD DelayTime )
{
	LARGE_INTEGER	Del;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Del, sizeof( Del ) );

	/* Set the time to delay for. */
	Del.QuadPart = -10000LL * DelayTime;

	/* Wait on the current thread for the delay period */
	if ( NT_SUCCESS( ObfNtWaitForSingleObject( NtCurrentThread(), FALSE, &Del ) ) ) {
		/* Do Nothing: But shows we get the return value ! */
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Del, sizeof( Del ) );
};

#endif
