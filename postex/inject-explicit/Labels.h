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

static ULONG_PTR Payload64( VOID );
static ULONG_PTR Payload32( VOID );

/* x86 -> x64 */
static VOID __cdecl EnterShellcode64(
	DWORD64, 
	DWORD64, 
	DWORD64, 
	DWORD64,
	DWORD64, 
	DWORD64, 
	DWORD64, 
	PDWORD
);
