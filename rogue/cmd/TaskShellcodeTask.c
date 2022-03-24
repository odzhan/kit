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
	UINT32	Length;
	UCHAR	Buffer[0];
} SHELLCODE_TASK, *PSHELLCODE_TASK ;

typedef struct
{
	D_API( NtAllocateVirtualMemory );
	D_API( NtFreeVirtualMemory );
} API ;

typedef struct
{
	D_API( BufferAddInt4 );
	D_API( BufferAddInt2 );
	D_API( BufferAddInt1 );
	D_API( BufferPrintf );
	D_API( BufferExtend );
	D_API( BufferAddRaw );
	D_API( BufferCreate );
} ROGUE_API ;

/*!
 *
 * Purpose:
 *
 * Executes a custom inline task and return its output.
 *
!*/
D_SEC( B ) DWORD TaskShellcodeTask( _In_ PROGUE_CTX Context, _In_ PVOID Buffer, _In_ UINT32 Length, _In_ PBUFFER Output )
{
	API		Api;
	ROGUE_API	Rpi;

	DWORD		Ret = 0;
	SIZE_T		Len = 0;

	PVOID		Mem = NULL;
	PSHELLCODE_TASK	Tsk = NULL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Rpi, sizeof( Rpi ) );

	Api.NtAllocateVirtualMemory = NULL;
	Api.NtFreeVirtualMemory     = NULL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Rpi, sizeof( Rpi ) );
};
