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
 * Find a module loaded in memory.
 *
!*/
D_SEC( B ) PVOID PebGetModule( _In_ UINT32 ModuleHash );
