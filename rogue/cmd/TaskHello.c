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

typedef struct __attribute__(( packed, scalar_storagE_order( "big-endian" ) ))
{

} TASK_HELLO_BUF;

/*!
 *
 * Purpose:
 *
 * Requests implant and host information. Ignores
 * Buffer and Length as it is not needed.
 *
!*/
D_SEC( B ) DWORD TaskHello( _In_ PVOID Buffer, _In_ UINT32 Length, _In_ PBUFFER Output )
{
	/* No needed! */
};
