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
	D_API( NtDeviceIoControlFile );
	D_API( NtWaitForSingleObject );
	D_API( RtlNtStatusToDosError );
	D_API( RtlInitUnicodeString );
	D_API( RtlAllocateHeap );
	D_API( NtCreateEvent );
	D_API( NtCreateFile );
	D_API( RtlFreeHeap );
	D_API( NtClose );
} API ;

/* API Hashes */
#define H_API_NTDEVICEIOCONTROLFILE	0x05d57dd0 /* NtDeviceIoControlFile */
#define H_API_NTWAITFORSINGLEOBJECT	0xe8ac0c3c /* NtWaitForSingleObject */	
#define H_API_RTLNTSTATUSTODOSERROR	0x39d7c890 /* RtlNtStatusToDosError */
#define H_API_RTLINITUNICODESTRING	0xef52b589 /* RtlInitUnicodeString */
#define H_API_RTLALLOCATEHEAP		0x3be94c5a /* RtlAllocateHeap */
#define H_API_NTCREATEEVENT		0x28d3233d /* NtCreateEvent */
#define H_API_NTCREATEFILE		0x66163fbb /* NtCreateFile */
#define H_API_RTLFREEHEAP		0x73a9e4d7 /* RtlFreeHeap */
#define H_API_NTCLOSE			0x40d6e69d /* NtClose */

/* LIB Hashes */
#define H_LIB_NTDLL			0x1edab0ed /* ntdll.dll */

/* CTL Codes */
#ifndef IOCTL_ICMP_ECHO_REQUEST
#define IOCTL_ICMP_ECHO_REQUEST		CTL_CODE( FILE_DEVICE_NETWORK, 0, METHOD_BUFFERED, FILE_ANY_ACCESS )
#endif

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

	ULONG			Len = 0;
	DWORD			Nrp = 0;
	NTSTATUS		Nst = STATUS_UNSUCCESSFUL;

	HANDLE			Ipd = NULL;
	HANDLE			Evt = NULL;
	PICMP_ECHO_REPLY	Ier = NULL;
	PICMP_ECHO_REQUEST	Irq = NULL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Uni, sizeof( Uni ) );
	RtlSecureZeroMemory( &Isb, sizeof( Isb ) );
	RtlSecureZeroMemory( &Att, sizeof( Att ) );

	Api.NtDeviceIoControlFile = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTDEVICEIOCONTROLFILE );
	Api.NtWaitForSingleObject = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTWAITFORSINGLEOBJECT );
	Api.RtlNtStatusToDosError = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLNTSTATUSTODOSERROR );
	Api.RtlInitUnicodeString  = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLINITUNICODESTRING );
	Api.RtlAllocateHeap       = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLALLOCATEHEAP );
	Api.NtCreateEvent         = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTCREATEEVENT );
	Api.NtCreateFile          = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTCREATEFILE );
	Api.RtlFreeHeap           = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLFREEHEAP );
	Api.NtClose               = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTCLOSE );

	Api.RtlInitUnicodeString( &Uni, C_PTR( G_SYM( L"\\Device\\Ip" ) ) );
	InitializeObjectAttributes( &Att, &Uni, OBJ_CASE_INSENSITIVE, NULL, NULL );

	/* Open a handle to the \Device\Ip driver, a needed action like IcmpCreateFile */
	if ( NT_SUCCESS( ( Nst = Api.NtCreateFile( &Ipd, GENERIC_EXECUTE, &Att, &Isb, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_IF, 0, NULL, 0 ) ) ) ) {

		do 
		{
			/* Invalid timeout */
			if ( Timeout <= 0 ) {
				Nst = STATUS_INVALID_PARAMETER;
				break;
			};
			/* Not able to hold a full ICMP_ECHO_REPYL? */
			if ( ReplySize < sizeof( ICMP_ECHO_REPLY ) ) {
				Nst = STATUS_INVALID_BUFFER_SIZE;
				break;
			};
			/* Not able to hold a full ICMP_ECHO_REPLY and same request size? */
			if ( ReplySize < RequestSize + sizeof( ICMP_ECHO_REPLY ) ) {
				Nst = STATUS_INVALID_PARAMETER;
				break;
			};

			/* Set the length and adjust if too small */
			Len = sizeof( ICMP_ECHO_REQUEST ) + RequestSize;
			if ( Len < ReplySize ) {
				Len = ReplySize;
			};

			/* Allocate a buffer for ICMP_ECHO_REQUEST */
			if ( ( Irq = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, Len ) ) != NULL ) {

				/* Set the header values and copy over the buffer */
				Irq->Address = DestinationAddress;
				Irq->Timeout = Timeout;
				Irq->OptionsOffset = sizeof( ICMP_ECHO_REQUEST );
				Irq->DataOffset = sizeof( ICMP_ECHO_REQUEST );

				if ( RequestSize > 0 ) {
					/* Is the matching size */
					Irq->DataSize = RequestSize;

					/* Copy over the buffer to the request */
					__builtin_memcpy( C_PTR( Irq ) + Irq->DataOffset, RequestData, RequestSize );
				};

				if ( NT_SUCCESS( ( Nst = Api.NtCreateEvent( &Evt, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE ) ) ) ) {
					Nst = Api.NtDeviceIoControlFile( Ipd, Evt, NULL, NULL, &Isb, IOCTL_ICMP_ECHO_REQUEST, Irq, Len, ReplyBuffer, ReplySize );
					if ( Nst == STATUS_PENDING ) {
						Nst = Api.NtWaitForSingleObject( Evt, FALSE, NULL );

						if ( NT_SUCCESS( Nst ) ) {
							Nst = Isb.Status;
						};
					};
				};
			} else
			{
				Nst = STATUS_INSUFFICIENT_RESOURCES;
				break;
			};
		} while ( 0 );

		if ( Irq != NULL ) {
			Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Irq );
		};
		if ( Evt != NULL ) {
			Api.NtClose( Evt );
		};
		Api.NtClose( Ipd );
	};

	/* Notify of any general failure */
	if ( ! NT_SUCCESS( Nst ) ) {
		NtCurrentTeb()->LastErrorValue = Api.RtlNtStatusToDosError( Nst );
	} 
	else {
		/* Gather reply information */
		Ier = C_PTR( ReplyBuffer );
		Nrp = Ier->Reserved;
		Ier->Reserved = 0;

		/* Set the actual error status */
		if ( Ier->Status != IP_SUCCESS ) {
			NtCurrentTeb()->LastErrorValue = Ier->Status;
		};
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Uni, sizeof( Uni ) );
	RtlSecureZeroMemory( &Isb, sizeof( Isb ) );
	RtlSecureZeroMemory( &Att, sizeof( Att ) );

	/* Return */
	return Nrp;
};
