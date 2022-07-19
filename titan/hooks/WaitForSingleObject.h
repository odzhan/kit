/**
 *
 * Reflective Loader
 *
 * GuidePoint Security LLC
 *
 * Threat and Attack Simulation
 *
**/

#pragma once

/*!
 *
 * Purpose:
 *
 * Obfuscates Beacon when it calls WaitForSingleObject
 *
!*/
D_SEC( D ) DWORD WINAPI WaitForSingleObject_Hook( _In_ HANDLE hHandle, _In_ DWORD Milliseconds );
