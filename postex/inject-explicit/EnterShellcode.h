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
 * Executes the process architecture specific shellcode
 * so that we can execute code in the same architecture
 * process.
 *
!*/
DWORD EnterShellcode( _In_ PVOID Function, _In_ DWORD Pid, DWORD Offset, PVOID Buffer, _In_ DWORD Length );
