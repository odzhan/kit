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
 * Executes the provided system call ID in an unhooked
 * region of NTDLL. Uses HDE64 to locate an unused seg
 * containing a syscall instructions, and directs the
 * execution to it.
 *
 * Uses the 'shadow space' inside of the function to
 * insert a return address to adjust RSP and properly
 * return in the external 'SystemCallReturn' if args
 * are greater than 5.
 *
!*/
D_SEC( B ) NTSTATUS NTAPI ExecuteSystemCall( _In_ UINT32 Id, _In_ UINT32 Argc, ... );
