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
D_SEC( A ) DWORD RoguePrintTest( PROGUE_API Rogue, PROGUE_CTX Context, USHORT Uid, PVOID Buffer, UINT32 Length, PBUFFER Output )
{
	Rogue->RoguePrintf( Context, Uid, C_PTR( G_PTR( "========================" ) ) );
	Rogue->RoguePrintf( Context, Uid, C_PTR( G_PTR( "Currently in memory @ %p" ) ), C_PTR( G_PTR( RoguePrintTest ) ) );
	Rogue->RoguePrintf( Context, Uid, C_PTR( G_PTR( "========================" ) ) );

	/* Return No Error! */
	return ROGUE_RETURN_SUCCESS;
}
