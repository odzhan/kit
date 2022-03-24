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
 * Exits the current thread. If it is injected code, it will
 * also attempt to free itself from memory before exiting 
 * from memory.
 *
 * If not, it just calls ExitThread and does not bother with
 * trying to free itself.
 *
!*/
D_SEC( B ) VOID ExitFreeThread( VOID );
