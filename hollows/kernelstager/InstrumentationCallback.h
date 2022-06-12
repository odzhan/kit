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
 * Prepares the custom usermode code for execution by
 * creating a thread. Fakes the start address to try
 * and avoid Get-InjectedThread.
 *
!*/
D_SEC( D ) VOID NTAPI InstrumentationCallbackEnt( VOID );
