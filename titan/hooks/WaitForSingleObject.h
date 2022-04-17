/**
 *
 * Reflective Loader
 *
 * GuidePoint Security LLC
 *
 * Threat and Attack SimulatioN
 *
**/

#pragma once

/*!
 *
 * Purpose:
 *
 * Awaits an object to be signaled before returning
 * a result.
 *
!*/
D_SEC( D ) DWORD WINAPI WaitForSingleObject_Hook( _In_ HANDLE Handle, _In_ DWORD Timeout );
