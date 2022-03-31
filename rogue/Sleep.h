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
 * Sets up a temporary stack for the call to avoid
 * using up too much memory. Leverages Sleep_Fiber
 * to obfuscate the current thread and set it to
 * R/W
 *
!*/
D_SEC( B ) VOID WINAPI SleepObfuscate( _In_ ULONG Timeout );
