/*!
 *
 * ROGUE
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
 * Returns a random string of the specified 
 * length.
 *
!*/
D_SEC( B ) VOID RandomString( _In_ PCHAR Buffer, _In_ UINT32 Length );

/*!
 *
 * Purpose:
 *
 * Returns a random integer between UINT16_MAX
 * and UINT16_MIN
 *
!*/
D_SEC( B ) UINT16 RandomInt16( VOID );
