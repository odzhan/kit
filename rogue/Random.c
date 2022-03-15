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
	D_API( RtlRandomEx );
} API ;

/* API Hashes */
#define H_API_RTLRANDOMEX	0x7f1224f5 /* RtlRandomEx */

/* LIB Hashes */
#define H_LIB_NTDLL		0x1edab0ed /* ntdll.dll */

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

	/* Set the current random value */
	Api.RtlRandomEx = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLRANDOMEX );
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
