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
 * Awaits for a connection for a SMB Beacon, and
 * creates a ROP chain to hide itself from any
 * memory scans.
 *
!*/
D_SEC( D ) BOOL WINAPI ConnectNamedPipe_Hook( _In_ HANDLE hNamedPipe, _Inout_ LPOVERLAPPED lpOverlapped );
