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
	D_API( RpcBindingFromStringBindingW );
	D_API( RpcStringBindingComposeW );
	D_API( RtlAllocateHeap );
	D_API( RpcStringFreeW );
	D_API( RpcBindingFree );
	D_API( RtlFreeHeap );
} API ;

/*!
 *
 * Purpose:
 *
 * Acts as an replacement for STRING_HANDLE_bind
 *
!*/
handle_t __RPC_USER STRING_HANDLE_bind( STRING_HANDLE lpStr )
{
	API		Api;

	HANDLE		Rpc = NULL;
	handle_t	Hnd = NULL;
	RPC_WSTR	Str = NULL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );

	/* Reference rpcrt4.dll */
	Rpc = LoadLibraryA( "rpcrt4.dll" );

	if ( Rpc != NULL ) {

		/* Build Stack API Table */
		Api.RpcBindingFromStringBindingW = C_PTR( GetProcAddress( Rpc, "RpcBindingFromStringBindingW" ) );
		Api.RpcStringBindingComposeW     = C_PTR( GetProcAddress( Rpc, "RpcStringBindingComposeW" ) );
		Api.RpcStringFreeW               = C_PTR( GetProcAddress( Rpc, "RpcStringFreeW" ) );

		/* Create a 'binding' to SpoolSS */
		if ( Api.RpcStringBindingComposeW( L"12345678-1234-ABCD-EF00-0123456789AB", L"ncacn_np", lpStr, L"\\pipe\\spoolss", NULL, &Str ) == RPC_S_OK ) {
			/* Create a binding from the RPC_WSTR */
			if ( Api.RpcBindingFromStringBindingW( Str, &Hnd ) == RPC_S_OK ) {
				/* Success! */
			};
			Api.RpcStringFreeW( &Str );
		};

		/* Dereference */
		FreeLibrary( Rpc );
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );

	/* Return binding handle */
	return Hnd;
};

/*!
 *
 * Purpose:
 *
 * Acts as a replacement for STRING_HANDLE_unbind
 *
!*/
void __RPC_USER STRING_HANDLE_unbind( STRING_HANDLE lpStr, handle_t BindingHandle )
{
	API	Api;
	HANDLE	Rpc = NULL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );

	/* Reference rpcrt4.dll */
	Rpc = LoadLibraryA( "rpcrt4.dll" );

	if ( Rpc != NULL ) {

		/* Reference and call address */
		Api.RpcBindingFree = C_PTR( GetProcAddress( Rpc, "RpcBindingFree" ) );
		Api.RpcBindingFree( BindingHandle );

		/* Dereference */
		FreeLibrary( Rpc );
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
};

/*!
 *
 * Purpose:
 *
 * Acts as a replacement for MIDL_USER_allocate
 *
!*/
void __RPC_FAR * __RPC_USER midl_user_allocate( size_t length )
{
	API	Api;
	LPVOID	Ptr = NULL;
	HANDLE	Ntl = NULL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );

	/* Reference NTDLL.DLL */
	Ntl = LoadLibraryA( "ntdll.dll" );

	if ( Ntl != NULL ) {

		/* Reference and call address */
		Api.RtlAllocateHeap = C_PTR( GetProcAddress( Ntl, "RtlAllocateHeap" ) );
		Ptr = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, length );

		/* Dereference */
		FreeLibrary( Ntl );
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );

	/* Return Buffer */
	return C_PTR( Ptr );
};

/*!
 *
 * Purpose:
 *
 * As as a replacement for MIDL_USER_free
 *
!*/
void __RPC_USER midl_user_free( void __RPC_FAR * p )
{
	API	Api;
	HANDLE	Ntl = NULL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );

	/* Reference NTDLL.DLL */
	Ntl = LoadLibraryA( "ntdll.dll" );

	if ( Ntl != NULL ) {

		/* Reference and call address */
		Api.RtlFreeHeap = C_PTR( GetProcAddress( Ntl, "RtlFreeHeap" ) );
		Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, p );
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
};
