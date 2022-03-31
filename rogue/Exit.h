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
 * Freees the current region of memory and
 * exits the current thread.
 *
!*/
D_SEC( B ) VOID NTAPI ExitFreeThread( _In_ NTSTATUS Status );
