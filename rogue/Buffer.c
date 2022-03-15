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
	D_API( RtlReAllocateHeap );
	D_API( RtlAllocateHeap );
	D_API( RtlFreeHeap );
	D_API( _vsnprintf );
} API ;

/* API Hashes */
#define H_API_RTLREALLOCATEHEAP		0xaf740371 /* RtlReAllocateHeap */
#define H_API_RTLALLOCATEHEAP		0x3be94c5a /* RtlAllocateHeap */
#define H_API_RTLFREEHEAP		0x73a9e4d7 /* RtlFreeHeap */
#define H_API_VSNPRINTF			0xa59022ce /* _vsnprintf */

/* LIB Hashes */
#define H_LIB_NTDLL			0x1edab0ed /* ntdll.dll */

/*!
 *
 * Purpose:
 *
 * Creates a "buffer" object to use. The "buffer"
 * pointer of the structure points to the payload
 * being appended to.
 *
!*/
D_SEC( B ) PBUFFER BufferCreate( VOID )
{
	API	Api;

	PBUFFER	Buf = NULL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	Api.RtlReAllocateHeap = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLREALLOCATEHEAP );
	Api.RtlAllocateHeap   = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLALLOCATEHEAP );
	Api.RtlFreeHeap       = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLFREEHEAP );
	Api._vsnprintf        = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_VSNPRINTF );

	/* Create buffer Object */
	if ( ( Buf = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, sizeof( BUFFER ) ) ) != NULL ) {

		/* Initialize Struct */
		Buf->Length = 0; Buf->Buffer = NULL; 
		return C_PTR( Buf );
	};
	
	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );

	/* Abort! */
	return NULL;
};

/*!
 *
 * Purpose:
 *
 * Insert a UINT32 integer type.
 *
!*/
D_SEC( B ) BOOL BufferAddInt4( _In_ PBUFFER Buffer, _In_ UINT32 Value )
{
	API	Api;
	BUFFER	Buf;

	BOOL	Ret = FALSE;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Buf, sizeof( Buf ) );

	Api.RtlReAllocateHeap = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLREALLOCATEHEAP );
	Api.RtlAllocateHeap   = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLALLOCATEHEAP );
	Api.RtlFreeHeap       = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLFREEHEAP );
	Api._vsnprintf        = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_VSNPRINTF );

	/* Create a buffer to hold our integer */
	if ( Buffer->Buffer != NULL ) {
		Buf.Buffer = Api.RtlReAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, Buffer->Buffer, Buffer->Length + sizeof( UINT32 ) );
	} else {
		Buf.Buffer = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, Buffer->Length + sizeof( UINT32 ) );
	};
	
	/* Success? */
	if ( Buf.Buffer != NULL ) {
		/* Set new pointer */
		Buffer->Buffer = C_PTR( Buf.Buffer );

		/* Copy over our integer value */
		__builtin_memcpy( C_PTR( U_PTR( Buffer->Buffer ) + Buffer->Length ), &Value, sizeof( UINT32 ) );

		/* Set new length */
		Buffer->Length = Buffer->Length + sizeof( UINT32 );

		/* Status */
		Ret = TRUE;
	};
	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Buf, sizeof( Buf ) );

	/* Did our allocation succeed? */
	return Ret;
};

/*!
 *
 * Purpose:
 *
 * Insert a UINT16 integer type.
 *
!*/
D_SEC( B ) BOOL BufferAddInt2( _In_ PBUFFER Buffer, _In_ UINT16 Value )
{
	API	Api;
	BUFFER	Buf;

	BOOL	Ret = FALSE;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Buf, sizeof( Buf ) );

	Api.RtlReAllocateHeap = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLREALLOCATEHEAP );
	Api.RtlAllocateHeap   = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLALLOCATEHEAP );
	Api.RtlFreeHeap       = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLFREEHEAP );
	Api._vsnprintf        = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_VSNPRINTF );

	/* Create a buffer to hold our integer */
	if ( Buffer->Buffer != NULL ) {
		Buf.Buffer = Api.RtlReAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, Buffer->Buffer, Buffer->Length + sizeof( UINT16 ) );
	} else {
		Buf.Buffer = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, Buffer->Length + sizeof( UINT16 ) );
	};

	/* Success? */
	if ( Buf.Buffer != NULL ) {
		/* Set new pointer */
		Buffer->Buffer = C_PTR( Buf.Buffer );

		/* Copy over our integer value */
		__builtin_memcpy( C_PTR( U_PTR( Buffer->Buffer ) + Buffer->Length ), &Value, sizeof( UINT16 ) );

		/* Set new length */
		Buffer->Length = Buffer->Length + sizeof( UINT16 );

		/* Status */
		Ret = TRUE;
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Buf, sizeof( Buf ) );

	/* Did our alllocation succeed? */
	return Ret;
};

/*!
 *
 * Purpose:
 *
 * Insert a UINT8 integer type.
 *
!*/
D_SEC( B ) BOOL BufferAddInt1( _In_ PBUFFER Buffer, _In_ UINT8 Value )
{
	API	Api;
	BUFFER	Buf;

	BOOL	Ret = FALSE;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Buf, sizeof( Buf ) );

	Api.RtlReAllocateHeap = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLREALLOCATEHEAP );
	Api.RtlAllocateHeap   = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLALLOCATEHEAP );
	Api.RtlFreeHeap       = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLFREEHEAP );
	Api._vsnprintf        = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_VSNPRINTF );

	/* Create a buffer to hold our integer */
	if ( Buffer->Buffer != NULL ) {
		Buf.Buffer = Api.RtlReAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, Buffer->Buffer, Buffer->Length + sizeof( UINT8 ) );
	} else {
		Buf.Buffer = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, Buffer->Length + sizeof( UINT8 ) );
	};

	/* Success? */
	if ( Buf.Buffer != NULL ) {
		/* Set new pointer */
		Buffer->Buffer = C_PTR( Buf.Buffer );

		/* Copy over our integer value */
		__builtin_memcpy( C_PTR( U_PTR( Buffer->Buffer ) + Buffer->Length ), &Value, sizeof( UINT8 ) );

		/* Set new length */
		Buffer->Length = Buffer->Length + sizeof( UINT8 );

		/* Status */
		Ret = TRUE;
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Buf, sizeof( Buf ) );

	/* Did our allocation succeed? */
	return Ret;
};

/*!
 *
 * Purpose:
 *
 * Insert a raw buffer type.
 *
!*/
D_SEC( B ) BOOL BufferAddRawB( _In_ PBUFFER Buffer, _In_ PVOID Value, _In_ ULONG Length )
{
	API	Api;
	BUFFER	Buf;

	BOOL	Ret = FALSE;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Buf, sizeof( Buf ) );

	Api.RtlReAllocateHeap = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLREALLOCATEHEAP );
	Api.RtlAllocateHeap   = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLALLOCATEHEAP );
	Api.RtlFreeHeap       = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLFREEHEAP );
	Api._vsnprintf        = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_VSNPRINTF );

	/* Create a bufffer to hold the input */
	if ( Buffer->Buffer != NULL ) {
		Buf.Buffer = Api.RtlReAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, Buffer->Buffer, Buffer->Length + Length );
	} else {
		Buf.Buffer = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, Buffer->Length + Length );
	};

	/* Success? */
	if ( Buf.Buffer != NULL ) {
		/* Set new pointer */
		Buffer->Buffer = C_PTR( Buf.Buffer );

		/* Copr over our buffer */
		__builtin_memcpy( C_PTR( U_PTR( Buffer->Buffer ) + Buffer->Length ), Value, Length );

		/* Set new length */
		Buffer->Length = Buffer->Length + Length;

		/* Status */
		Ret = TRUE;
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Buf, sizeof( Buf ) );

	/* Did our allocation succeed? */
	return Ret;
};

/*!
 *
 * Purpose:
 *
 * Extends a buffer to a specific size.
 *
!*/
D_SEC( B ) BOOL BufferExtend( _In_ PBUFFER Buffer, _In_ ULONG Length )
{
	API	Api;
	BUFFER	Buf;

	BOOL	Ret = FALSE;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Buf, sizeof( Buf ) );

	Api.RtlReAllocateHeap = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLREALLOCATEHEAP );
	Api.RtlAllocateHeap   = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLALLOCATEHEAP );
	Api.RtlFreeHeap       = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLFREEHEAP );
	Api._vsnprintf        = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_VSNPRINTF );

	/* Create a buffer */
	if ( Buffer->Buffer != NULL ) {
		Buf.Buffer = Api.RtlReAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, Buffer->Buffer, Buffer->Length + Length );
	} else {
		Buf.Buffer = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, Buffer->Length + Length );
	};

	if ( Buf.Buffer != NULL ) {
		/* Set new pointer */
		Buffer->Buffer = C_PTR( Buf.Buffer );

		/* Set new length */
		Buffer->Length = Buffer->Length + Length;

		/* Status */
		Ret = TRUE;
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Buf, sizeof( Buf ) );

	/* Did our allocation succeed? */
	return Ret;
};

/*!
 *
 * Purpose:
 *
 * Appends a formated string to a buffer.
 *
!*/
D_SEC( B ) BOOL BufferPrintf( _In_ PBUFFER Buffer, _In_ PCHAR Format, ... )
{
	API	Api;
	BUFFER	Buf;
	va_list	Lst;

	INT	Len = 0;
	BOOL	Ret = FALSE;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Buf, sizeof( Buf ) );
	RtlSecureZeroMemory( &Lst, sizeof( Lst ) );

	Api.RtlReAllocateHeap = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLREALLOCATEHEAP );
	Api.RtlAllocateHeap   = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLALLOCATEHEAP );
	Api.RtlFreeHeap       = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLFREEHEAP );
	Api._vsnprintf        = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_VSNPRINTF );

	/* Get length of buffer */
	va_start( Lst, Format );
	Len = Api._vsnprintf( NULL, 0, Format, Lst );
	va_end( Lst );

	/* Create a buffer */
	if ( Buffer->Buffer != NULL ) {
		Buf.Buffer = Api.RtlReAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, Buffer->Buffer, Buffer->Length + Len );
	} else {
		Buf.Buffer = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, Buffer->Length + Len );
	};

	if ( Buf.Buffer != NULL ) {
		/* Set new pointer */
		Buffer->Buffer = C_PTR( Buf.Buffer );

		/* Copy over our buffer */
		va_start( Lst, Format );
		Len = Api._vsnprintf( C_PTR( U_PTR( Buffer->Buffer ) + Buffer->Length ), Len, Format, Lst );
		va_end( Lst );

		/* Set new length */
		Buffer->Length = Buffer->Length + Len;

		/* Status */
		Ret = TRUE;
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Buf, sizeof( Buf ) );
	RtlSecureZeroMemory( &Lst, sizeof( Lst ) );

	/* Did our allocation succeed? */
	return Ret;
};
