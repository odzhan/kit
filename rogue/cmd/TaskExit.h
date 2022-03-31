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
 * Sets the exit mode and sets the established
 * connection to FALSE for Rogue.
 *
!*/
D_SEC( B ) DWORD TaskExit( _In_ PROGUE_CTX Context, _In_ USHORT Uid, _In_ PVOID Buffer, _In_ ULONG Length, _In_ PBUFFER Output );
