/*!
 *
 * ARTIFACT
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
 * Hooks the specified function in the import address
 * table of the specified PE.
 *
!*/
BOOL LdrHookImport( _In_ PVOID ImageBase, _In_ UINT32 ImportHash, _In_ PVOID ImportHook );
