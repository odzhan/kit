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
	D_API( RtlFreeHeap ); 
} API ;

/*!
 *
 * Purpose:
 *
 * Requests a AS-REP response from the KDC and
 * prints the session key back to the caller.
 *
 * With this, we can create a working TGS and
 * acquire a TGT along with it through a socks
 * proxy.
 *
!*/
VOID KrbTgsGo( _In_ PVOID Argv, _In_ INT Argc )
{
	API	Api;

	PCHAR	Spn = NULL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
};
