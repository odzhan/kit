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
D_SEC( E ) VOID LockAccess( _In_ PVOID Variable );

/*!
 *
 * Purpose:
 *
 * Unlocks exclsuvie access. 
 *
!*/
D_SEC( E ) VOID UnlockAccess( _In_ PVOID Variable );
