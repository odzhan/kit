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

/*!
 *
 * Purpose:
 *
 * Locks exclusive access. Blocks until the region is
 * unlocked.
 *
!*/
D_SEC( E ) VOID LockAccess( _In_ PVOID Variable )
{
	/* Block until region is unlocked */
	while ( InterlockedExchangeAdd( Variable, 0 ) );

	/* Increment usage */
	InterlockedIncrement( Variable );
};

/*!
 *
 * Purpose:
 *
 * Unlocks exclsuvie access. 
 *
!*/
D_SEC( E ) VOID UnlockAccess( _In_ PVOID Variable )
{
	InterlockedDecrement( Variable );
};
