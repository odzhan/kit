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

/*!
 *
 * Purpose:
 *
 * Print information about the current host.
 *
!*/
D_SEC( A ) DWORD RoguePrintTest( PROGUE_API Rogue, PVOID Context, PVOID Buffer, UINT32 Length, PBUFFER Output )
{
	Rogue->RoguePrintf( Context, C_PTR( G_PTR( "========================" ) ) );
	Rogue->RoguePrintf( Context, C_PTR( G_PTR( "Currently in memory @ %p" ) ), C_PTR( G_PTR( RoguePrintTest ) ) );
	Rogue->RoguePrintf( Context, C_PTR( G_PTR( "========================" ) ) );

	BufferPrintf( Output, C_PTR( G_PTR( "%s" ) ) );
}
