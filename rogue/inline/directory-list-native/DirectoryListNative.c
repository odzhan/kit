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
	D_API( NtQueryDirectoryFile );
	D_API( RtlAllocateHeap );
	D_API( RtlFreeHeap );
	D_API( NtOpenFile );
	D_API( NtClose );
} API ;

/* API Hashes */
#define H_API_NTQUERYDIRECTORYFILE	0x8b951172 /* NtQueryDirectoryFile */
#define H_API_RTLALLOCATEHEAP		0x3be94c5a /* RtlAllocateHeap */
#define H_API_RTLFREEHEAP		0x73a9e4d7 /* RtlFreeHeap */
#define H_API_NTOPENFILE		0x46dde739 /* NtOpenFile */
#define H_API_NTCLOSE			0x40d6e69d /* NtClose */

/* LIB Hashes */
#define H_LIB_NTDLL			0x1edab0ed /* ntdll.dll */

/*!
 *
 * Purpose:
 *
 * Lists a requested directory using NT.
 *
!*/
D_SEC( A ) DWORD DirectoryListNative( _In_ PROGUE_API Rogue, _In_ PVOID Context, _In_ USHORT Uid, _In_ PVOID Buffer, _In_ ULONG Length, PBUFFER Output )
{
	API		Api;
	UNICODE_STRING	Uni;

	DWORD		Ret = ROGUE_RETURN_FAILURE;

	PBUFFER		Out = NULL;
	PBUFFER		Str = NULL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Uni, sizeof( Uni ) );

	Api.NtQueryDirectoryFile = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTQUERYDIRECTORYFILE );
	Api.RtlAllocateHeap      = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLALLOCATEHEAP );
	Api.RtlFreeHeap          = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLFREEHEAP );
	Api.NtOpenFile           = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTOPENFILE );
	Api.NtClose              = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTCLOSE );

	/* Do we have an input directory argument? */
	if ( Buffer != NULL && Length != 0 ) {
		/* Create a buffer to hold our string */
		if ( ( Str = BufferCreate() ) != NULL ) { 
			/* Attempt to create a path \\??\\DRIVE:\PATH\TO\DIRECTORY */
			if ( BufferPrintfW( Str, C_PTR( G_PTR( L"\\??\\%*.*s" ) ), Length, Length, Buffer ) ) {
				/* Open the directory! */
			};
			Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Str->Buffer );
			Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Str );
			Str = NULL;
		};
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Uni, sizeof( Uni ) );

	/* Return */
	return Ret;
};
