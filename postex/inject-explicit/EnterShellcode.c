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
DWORD EnterShellcode( _In_ PVOID Function, _In_ DWORD Pid, DWORD Offset, PVOID Buffer, _In_ DWORD Length )
{
	/* Are we null? No! */
	if ( Function != NULL ) {
		/* Executes the embedded shellcodes as __cdecl */
		return ( ( DWORD __cdecl ( * )( DWORD, DWORD, PVOID, DWORD ) ) Function )( 
				Pid, 
				Offset, 
				Buffer, 
				Length 
		);
	};
	/* None */
	return 0;
};
