/*!
 *
 * SSHOCKS
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
 * Entrypoint for the DLL image. Initializes the
 * WSA library for the sockets.
 *
!*/
BOOL WINAPI DllMain( _In_ HINSTANCE Instance, _In_ DWORD Reason, _In_ LPVOID Parameter ) 
{
	BOOL	Ret = FALSE;
	WSADATA	Wsd;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Wsd, sizeof( Wsd ) );

	switch ( Reason ) {
		case DLL_PROCESS_ATTACH:
			/* Init WSA Socket Library */
			Ret = WSAStartup( MAKEWORD( 2, 2 ), &Wsd ) != 0 ? FALSE : TRUE;
			break;
		case DLL_PROCESS_DETACH:
			/* Free WSA Socket Library */
			Ret = WSACleanup( ) != 0 ? FALSE : TRUE;
			break;
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Wsd, sizeof( Wsd ) );

	/* Return Status */
	return Ret;
};
