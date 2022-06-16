/*!
 *
 * PostEx Lateral Movement
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
 * Injects a shellcode into the current process
 * and returns FALSE to prevent the DLL from
 * being loaded.
 *
!*/
D_SEC( A ) BOOL WINAPI Entry( _In_ HINSTANCE Instance, _In_ DWORD Reason, _In_ LPVOID Parameter )
{
	/* Did we recieve the attach event */
	if ( Reason == DLL_PROCESS_ATTACH ) {
		/* Inject shellcode! */
	};
	/* Notify Failure! */
	return FALSE;
};
