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
 * Requests implant and host information. Ignores
 * Buffer and Length as it is not needed.
 *
!*/
D_SEC( B ) BOOL TaskHello( _In_ PVOID Buffer, _In_ UINT32 Length, _In_ PBUFFER Output );
