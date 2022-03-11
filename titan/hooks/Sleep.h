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
 * Blocks the input for a specified period of time,
 * and obfuscates Beacon as well as attempts to
 * spoof the thread stack.
 *
!*/

D_SEC( D ) VOID WINAPI Sleep_Hook( _In_ ULONG WaitTime );
