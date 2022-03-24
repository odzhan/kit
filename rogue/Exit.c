/*!
 *
 * ROGUE
 *
 * GuidePoint Security LLC
 *
 * Threat and Attack Simulation Team
 *
!*/

#include "Common.h"

typedef struct
{
	D_API( NtUnmapViewOfSection );
	D_API( NtQueryVirtualMemory );
	D_API( NtFreeVirtualMemory );
} API ;

/*!
 *
 * Purpose:
 *
 * Exits the current thread. If it is injected code, it will
 * also attempt to free itself from memory before exiting 
 * from memory.
 *
 * If not, it just calls ExitThread and does not bother with
 * trying to free itself.
 *
!*/
D_SEC( B ) VOID ExitFreeThread( VOID )
{
	API				Api;
	MEMORY_BASIC_INFORMATION	Mbi;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Mbi, sizeof( Mbi ) );
};
