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
 * Creates a thread in the target process to read memory
 * using an APC queue to RtlCopyMemory, overwriting the
 * UniqueThread value of Teb->ClientId.UniqueThread. As
 * soon as the APC callback completes, it uses the thread
 * ThreadTebInformation to read the value using a call
 * to NtQueryInformationThread.
 *
 * Requires PROCESS_CREATE_THREAD | PROCESS_DUP_HANDLE
 * access.
 *
!*/
D_SEC( B ) VOID ReadRemoteMemory( _In_ HANDLE Process, _In_ PVOID Address, _In_ PVOID Buffer, _In_ SIZE_T Length );
