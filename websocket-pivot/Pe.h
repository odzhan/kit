/*!
 *
 * A reimplementation of the Lastenzug code from
 * codewhitesec / f-link. Makes it much cleaner,
 * easier to read, and adds a 'cleanup' feature
 * to avoid detection.
 *
 * Furthermore, does not limit the number of the
 * clients that can be used, and permits a number
 * of connections that can be sent over at a given
 * time.
 *
 * @codewhitesec
 * @flink
 * @secidiot
 *
!*/

#pragma once

/*!
 *
 * Purpose:
 *
 * Searches for an export in the given PE.
 *
!*/
D_SEC( B ) PVOID PeGetFuncEat( _In_ PVOID ImageBase, _In_ UINT32 ExportHash );
