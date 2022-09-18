/*!
 *
 * ICMP
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
 * Find a export in a PE.
 *
!*/
D_SEC( B ) PVOID PeGetFuncEat( _In_ PVOID ImageBase, _In_ UINT32 FunctionHash );
