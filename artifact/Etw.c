/*!
 *
 * ARTIFACT
 *
 * GuidePoint Security LLC
 *
 * Threat and Attack Simulation Team
 *
!*/

#include "Common.h"

/*!
 *
 * Purpose:
 *
 * Acts as a hook for advapi32!EventWrite.
 *
!*/
ULONG EVNTAPI EventWriteHook( _In_ REGHANDLE RegHandle, _In_ PCEVENT_DESCRIPTOR EventDescriptor, ULONG UserDataCount, PEVENT_DATA_DESCRIPTOR UserData )
{
	/* Arbitrary return 'success' */
	return ERROR_SUCCESS;
};
