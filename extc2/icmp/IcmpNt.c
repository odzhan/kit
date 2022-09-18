/*!
 *
 * ICMP
 *
 * GuidePoint Security LLC
 *
 * Threat and Attack Simulation Team
 *
!*/

#include "Common.h"

typedef struct
{
	IPAddr	Address;
	UINT32	Timeout;
	UINT16	DataOffset;
	UINT16	DataSize;
	UINT8	HasOptions;
	UINT8	Ttl;
	UINT8	Tos;
	UINT8	Flags;
	UINT16	OptionsOffset;
	UINT8	OptionsSize;
	UINT8	Padding;
} ICMP_ECHO_REQUEST, *PICMP_ECHO_REQUEST ;

typedef struct
{
	D_API( RtlInitUnicodeString );
	D_API( RtlAllocateHeap );
	D_API( NtCreateFile );
	D_API( NtClose );
} API ;

/* API Hashes */
#define H_API_RTLINITUNICODESTRING	0xef52b589 /* RtlInitUnicodeString */
#define H_API_RTLALLOCATEHEAP		0x3be94c5a /* RtlAllocateHeap */
#define H_API_NTCREATEFILE		0x66163fbb /* NtCreateFile */
#define H_API_NTCLOSE			0x40d6e69d /* NtClose */

/* LIB Hashes */
#define H_LIB_NTDLL			0x1edab0ed /* ntdll.dll */

/*!
 *
 * Purpose:
 *
 * Sends an ICMP request over the \Device\Ip driver. Mimics
 * the behavior of IcmpSendEcho to avoid confliction issues
 *
!*/
D_SEC( B ) DWORD IcmpNtSendEcho
(
	_In_ 		HANDLE			IcmpHandle,
	_In_ 		IPAddr			DestinationAddress,
	_In_ 		LPVOID			RequestData,
	_In_		WORD			RequestSize,
	_Out_		LPVOID			ReplyBuffer,
	_In_		DWORD			ReplySize,
	_In_		DWORD			Timeout
)
{
	API			Api;
	UNICODE_STRING		Uni;
	IO_STATUS_BLOCK		Isb;
	OBJECT_ATTRIBUTES	Att;

	HANDLE			Ipd = NULL;
	PICMP_ECHO_REQUEST	Irq = NULL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Uni, sizeof( Uni ) );
	RtlSecureZeroMemory( &Isb, sizeof( Isb ) );
	RtlSecureZeroMemory( &Att, sizeof( Att ) );

	Api.RtlInitUnicodeString = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLINITUNICODESTRING );
	Api.RtlAllocateHeap      = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLALLOCATEHEAP );
	Api.NtCreateFile         = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTCREATEFILE );
	Api.NtClose              = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTCLOSE );

	Api.RtlInitUnicodeString( &Uni, C_PTR( G_SYM( L"\\Device\\Ip" ) ) );
	InitializeObjectAttributes( &Att, &Uni, OBJ_CASE_INSENSITIVE, NULL, NULL );

	/* Open a handle to the \Device\Ip driver, a needed action like IcmpCreateFile */
	if ( NT_SUCCESS( Api.NtCreateFile( &Ipd, GENERIC_EXECUTE, &Att, &Isb, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_IF, 0, NULL, 0 ) ) ) {
		/* Close the \Device\Ip driver */
		Api.NtClose( Ipd );
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Uni, sizeof( Uni ) );
	RtlSecureZeroMemory( &Isb, sizeof( Isb ) );
	RtlSecureZeroMemory( &Att, sizeof( Att ) );
};
