/*!
 *
 * KERNELDOOR
 *
 * GuidePoint Security LLC
 *
 * Threat and Attack Simulation Team
 *
!*/

#pragma once

/*!
 *
 * Purpose:
 *
 * Converts an input buffer into a unique
 * DJB2 hash. If no length is provided it
 * assumes its a null terminated string.
 *
!*/
D_SEC( D ) ULONG HashString( PVOID Buffer, ULONG Length );
