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
 * Sets up a temporary stack for the call to avoid
 * using up too much memory. Leverages ObjectFiber
 * to obfuscate the current memory, and hide the
 * thread stack while awaiting the functions
 * completion.
 *
!*/
D_SEC( E ) NTSTATUS NTAPI NtWaitForSingleObjectObf( _In_ HANDLE Handle, _In_ BOOLEAN Alertable, _In_ PLARGE_INTEGER Timeout );
