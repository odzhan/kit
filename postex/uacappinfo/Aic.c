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
	D_API( RtlFreeHeap );
} API ;

/*!
 *
 * Purpose:
 *
 * Creates a binding handle to RAILaunchAdminProcess
 *
!*/
RPC_STATUS AicCreateHandle( VOID )
{
	API	Api;

	HANDLE	Bnd = NULL;
	HANDLE	Rpc = NULL;
	HANDLE	Ntl = NULL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );

	Ntl = LoadLibraryA( "ntdll.dll" );

	if ( Ntl != NULL ) {

		Api.RtlAllocateHeap = C_PTR( GetProcAddress( Ntl, "RtlAllocateHeap" ) );
		Api.RtlFreeHeap     = C_PTR( GetProcAddress( Ntl, "RtlFreeHeap" ) );

		/* Reference Rpcrt4.dll */
		Rpc = LoadLibraryA( "rpcrt4.dll" );

		if ( Rpc != NULL ) {

			/* Build Stack API Table */
			Api.RpcBindingFromStringBindingW = C_PTR( GetProcAddress( Rpc, "RpcbindingFromStringBindingW" ) );
			Api.RpcStringBindingComposeW     = C_PTR( GetProcAddress( Rpc, "RpcStringBindingComposeW" ) );
			Api.RpcStringFreeW               = C_PTR( GetProcAddress( Rpc, "RpcStringFreeW" ) );

			/* Dereference */
			FreeLibrary( Rpc );
		};

		/* Dereference */
		FreeLibrary( Ntl );
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
};
