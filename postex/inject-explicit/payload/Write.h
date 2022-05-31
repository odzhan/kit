/*!
 *
 * PostEx
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
 * Creates a thread in the target process to write memory
 * using an APC queue to RtlFillMemory, overwriting the
 * target region. Does not verify if the write completed
 * successfully.
 *
 * Requires PROCESS_CREATE_THREAD access
 *
!*/
D_SEC( B ) VOID WriteRemoteMemory( _In_ HANDLE Process, _In_ PVOID Address, _In_ PVOID Buffer, _In_ SIZE_T Length );
