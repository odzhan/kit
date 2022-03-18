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
	D_API( RtlInitUnicodeString );
	D_API( GetComputerNameExA );
	D_API( RtlReAllocateHeap );
	D_API( RtlAllocateHeap );
	D_API( LdrUnloadDll );
	D_API( RtlFreeHeap );
	D_API( LdrLoadDll );
} API ;

/* API Hashes */
#define H_API_RTLINITUNICODESTRING	0xef52b589 /* RtlInitUnicodeString */
#define H_API_GETCOMPUTERNAMEEXA	0xec725c53 /* GetComputerNameExA */
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
 * Returns a pointer to the machine name. 
 *
!*/
D_SEC( B ) PVOID OsMachineName( VOID )
{
	API		Api;
	UNICODE_STRING	Uni;

	ULONG		Len = 0;

	PVOID		K32 = NULL;
	PVOID		Ptr = NULL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Uni, sizeof( Uni ) );
	
	/* Init API */
	Api.RtlInitUnicodeString = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLINITUNICODESTRING );
	Api.RtlReAllocateHeap    = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLREALLOCATEHEAP );
	Api.RtlAllocateHeap      = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLALLOCATEHEAP );
	Api.LdrUnloadDll         = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_LDRUNLOADDLL );
	Api.RtlFreeHeap          = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLFREEHEAP );
	Api.LdrLoadDll           = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_LDRLOADDLL );

	/* Load kernel32.dll if its not loaded already */
	Api.RtlInitUnicodeString( &Uni, C_PTR( G_PTR( L"kernel32.dll" ) ) );

	if ( NT_SUCCESS( Api.LdrLoadDll( NULL, 0, &Uni, &K32 ) ) ) {
		/* Extract the computername */
		Api.GetComputerNameExA = PeGetFuncEat( K32, H_API_GETCOMPUTERNAMEEXA );

		/* Create the initial buffer to hold the computer name */
		if ( ! Api.GetComputerNameExA( ComputerNameDnsDomain, NULL, &Len ) ) {
			/* Create a buffer big enough to hold memory */
			if ( ( Ptr = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, Len + 1 ) ) != NULL ) {
				/* Did we succeed?: If not, free and set to NULL */
				if ( ! Api.GetComputerNameExA( ComputerNameDnsDomain, Ptr, &Len ) ) {
					Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Ptr );
					Ptr = NULL;
				};
			};
		};
		/* Dereference */
		Api.LdrUnloadDll( K32 );
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Uni, sizeof( Uni ) );

	/* Success? */
	return C_PTR( Ptr );
};
