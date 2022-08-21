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
 * Executable main designed for testing the
 * application for errors or other issues
 * that may arrise.
 *
!*/
int main( int argc, char **argv ) {

	WSADATA	Wsd;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Wsd, sizeof( Wsd ) );

	if ( ! WSAStartup( MAKEWORD( 2, 2 ), &Wsd ) ) {
		TunnelInit( );
		WSACleanup( );
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Wsd, sizeof( Wsd ) );
};
