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
 * Obfuscates while waiting for a data to be read
 * from a named pipe, or a file. Returns a success
 * status if completed.
 *
!*/
D_SEC( D ) BOOL WINAPI ReadFile_Hook( _In_ HANDLE hFile, _In_ LPVOID lpBuffer, _In_ DWORD nNumberOfBytes, _Out_ LPDWORD lpNumberOfBytes, _Inout_ LPOVERLAPPED lpOverlapped );
