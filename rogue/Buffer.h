/*!
 *
 * ROGUE
 *
 * GuidePoint Security LLC
 *
 * Threat and Attack Simulation Team
 *
!*/

#pragma once

typedef struct
{
	ULONG	Length;
	PVOID	Buffer;
} BUFFER, *PBUFFER;

/*!
 *
 * Purpose:
 *
 * Creates a "buffer" object to use. The "buffer"
 * pointer of the structure points to the payload
 * being appended to.
 *
!*/
D_SEC( B ) PBUFFER BufferCreate( VOID );

/*!
 *
 * Purpose:
 *
 * Insert a UINT32 integer type.
 *
!*/
D_SEC( B ) BOOL BufferAddInt4( _In_ PBUFFER Buffer, _In_ UINT32 Value );

/*!
 *
 * Purpose:
 *
 * Insert a UINT16 integer type.
 *
!*/
D_SEC( B ) BOOL BufferAddInt2( _In_ PBUFFER Buffer, _In_ UINT16 Value );

/*!
 *
 * Purpose:
 *
 * Insert a UINT8 integer type.
 *
!*/
D_SEC( B ) BOOL BufferAddInt1( _In_ PBUFFER Buffer, _In_ UINT8 Value );

/*!
 *
 * Purpose:
 *
 * Insert a raw buffer type.
 *
!*/
D_SEC( B ) BOOL BufferAddRawB( _In_ PBUFFER Buffer, _In_ PVOID Value, _In_ ULONG Length );

/*!
 *
 * Purpose:
 *
 * Extends a buffer to a specific size.
 *
!*/
D_SEC( B ) BOOL BufferExtend( _In_ PBUFFER Buffer, _In_ ULONG Length );

/*!
 *
 * Purpose:
 *
 * Appends a formated string to a buffer.
 *
!*/
D_SEC( B ) BOOL BufferPrintf( _In_ PBUFFER Buffer, _In_ PCHAR Format, ... );
