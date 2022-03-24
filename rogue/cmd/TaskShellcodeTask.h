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
 * Executes a custom inline task and return its output.
 *
!*/
D_SEC( B ) DWORD TaskShellcodeTask( _In_ PROGUE_CTX Context, _In_ PVOID Buffer, _In_ UINT32 Length, _In_ PBUFFER Output );
