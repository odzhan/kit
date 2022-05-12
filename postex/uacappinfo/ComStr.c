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
	D_API( RtlAllocateHeap );
	D_API( RtlFreeHeap );
} API ;

/*!
 *
 * Purpose:
 *
 * Replaces SysAllocString to reduce the use of 
 * the OLEAUT32 import requirement for RPC.
 *
!*/
PVOID WINAPI ComCreateString( _In_ PCHAR Buffer )
{
	API	Api;

	UINT32	Len = 0;
	PCHAR	Str = NULL;
	HANDLE	Ntl = NULL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );

	/* Reference ntdll.dll */
	Ntl = LoadLibraryA( "ntdll.dll" );

	if ( Ntl != NULL ) {

		/* Build Stack API Table */
		Api.RtlAllocateHeap = C_PTR( GetProcAddress( Ntl, "RtlAllocateHeap" ) );

		if ( Api.RtlAllocateHeap != NULL ) 
		{
			/* Get length of string */
			Len = __builtin_strlen( Buffer );

			/* Allocate a buffer to hold it + the null byte */
			if ( ( Str = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, Len + 1 ) ) != NULL ) 
			{
				/* Copy over the buffer! */
				__builtin_memcpy( C_PTR( Str ), Buffer, Len );
			};
		};

		/* Dererence */
		FreeLibrary( Ntl );
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );

	/* Return Pointer */
	return C_PTR( Str );
};

/*!
 *
 * Purpose:
 *
 * Reaplces SysFreeString to reduce the use of
 * the OLEAUT32 import requirement for RPC.
 *
!*/
VOID WINAPI ComFreeString( _In_ PCHAR Buffer ) 
{
	API	Api;

	HANDLE	Ntl = NULL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );

	if ( Buffer != NULL ) 
	{
		/* Reference ntdll.dll */
		Ntl = LoadLibraryA( "ntdll.dll" );

		if ( Ntl != NULL ) 
		{
			/* Build Stack API Table */
			Api.RtlFreeHeap = C_PTR( GetProcAddress( Ntl, "RtlFreeHeap" ) );

			if ( Api.RtlFreeHeap != NULL ) 
			{
				Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Buffer );
			};

			/* Dereference */
			FreeLibrary( Ntl );
		};
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
};
