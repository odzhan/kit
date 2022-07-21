/*!
 *
 * ARTIFACT
 *
 * GuidePoint Security LLC
 *
 * Threat and Attack Simulation Team
 *
!*/

#pragma once

/*!
 *
 * Purpose:
 *
 * Acts as a hook for advapi32!EventWrite.
 *
!*/
ULONG EVNTAPI EventWriteHook( _In_ REGHANDLE RegHandle, _In_ PCEVENT_DESCRIPTOR EventDescriptor, ULONG UserDataCount, PEVENT_DATA_DESCRIPTOR UserData );
