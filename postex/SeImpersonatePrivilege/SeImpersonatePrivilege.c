/*!
 *
 * PostEx
 *
 * GuidePoint Security LLC
 *
 * Threat and Attack Simulation Team
 *
!*/

#include "Common.h"

typedef struct
{ 
	D_API( NdrClientCall2 );
} API ;

/*!
 *
 * Purpose:
 *
 * Elevates privileges to SYSTEM using SpoolSS. Once it gets
 * a SYSTEM token, it impersonates the new token.
 *
!*/
VOID SeImpersonatePrivilegeGo( _In_ PVOID Argv, _In_ INT Argc )
{

};
