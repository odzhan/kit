/*!
 *
 * ROGUE
 *
 * GuidePoint Security LLC
 *
 * Threat and Attack Simulation Team
 *
!*/

#include "Common.h"

/* Definition */
ULONG
NTAPI
RtlRandomEx(
	_In_ PUINT32 Seed
);

typedef struct
{
	D_API( RtlAllocateHeap );
	D_API( RtlRandomEx );
} API ;

/* API Hashes */
#define H_API_RTLALLOCATEHEAP	0x3be94c5a /* RtlAllocateHeap */
#define H_API_RTLRANDOMEX	0x7f1224f5 /* RtlRandomEx */

/* LIB Hashes */
#define H_LIB_NTDLL		0x1edab0ed /* ntdll.dll */

/*!
 *
 * Purpose:
 *
 * Returns a random string of the specified 
 * length.
 *
!*/
D_SEC( B ) VOID RandomString( _In_ PCHAR Buffer, _In_ UINT32 Length )
{
	API	Api;

	PCHAR	Alp = C_PTR( G_PTR( "ABCDEFGHIJKLMNOPQRSTUVWXYZ" ) );
	UINT32	Val = 0;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );

	/* Init API */
	Api.RtlAllocateHeap = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLALLOCATEHEAP );
	Api.RtlRandomEx     = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLRANDOMEX );

	/* Create buffer to hold the random string */
	for ( INT Idx = 0 ; Idx < Length ; ++Idx ) {
		/* Generate random index */
		Val = NtGetTickCount();
		Val = Api.RtlRandomEx( &Val );
		Val = Api.RtlRandomEx( &Val );
		Val = Val % 26;

		/* Set character */
		Buffer[ Idx ] = Alp[ Val ];
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
};

/*!
 *
 * Purpose:
 *
 * Returns a random integer between UINT16_MAX
 * and UINT16_MIN
 *
!*/
D_SEC( B ) UINT16 RandomInt16( VOID )
{
	API	Api;

	UINT16	Ret = 0;
	UINT32	Val = 0;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );

	/* Init API */
	Api.RtlAllocateHeap = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLALLOCATEHEAP ); 
	Api.RtlRandomEx     = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLRANDOMEX );

	/* Set the current random value */
	Val = NtGetTickCount();
	Val = Api.RtlRandomEx( &Val );
	Val = Api.RtlRandomEx( &Val );

	/* Return Value In Bounds */
	Ret = ( UINT16 )( Val % ( UINT16_MAX + 1 ) );

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );

	/* Return */
	return Ret;
};
