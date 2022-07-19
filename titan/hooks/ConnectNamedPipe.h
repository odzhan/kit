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
D_SEC( D ) BOOLEAN WINAPI ConnectNamedPipe_Hook( _In_ HANDLE hNamedPipe, _In_ LPOVERLAPPED lpOverlapped );
