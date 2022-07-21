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
 * Hashes an input buffer. ANSI strings do not 
 * need a length if they are null terminated.
 * Unicode string requires the complete length
 *
!*/
UINT32 HashString( _In_ PVOID Buffer, _In_ UINT32 Length );
