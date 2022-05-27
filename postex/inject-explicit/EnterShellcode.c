/*!
 *
 * PostEx
 *
 * GuidePoint Security LLC
 *
 * Threat and Attack Simulation Team
 *
!*/

#include "Common.h"

/*!
 *
 * Purpose:
 *
 * Executes the process architecture specific shellcode
 * so that we can execute code in the same architecture
 * process.
 *
!*/
VOID EnterShellcode( _In_ PVOID Function, _In_ DWORD Pid, DWORD Offset, PVOID Buffer, _In_ DWORD Length, _Out_ DWORD* Return )
{
	/* Are we null? No! */
	if ( Function != NULL ) {
		/* Executes the embedded shellcodes as __cdecl */
		( ( VOID __cdecl ( * )( DWORD, DWORD, PVOID, DWORD, PDWORD ) ) Function )( Pid, Offset, Buffer, Length, Return );
	};
};
