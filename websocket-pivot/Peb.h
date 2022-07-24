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
 * Locates a module already loaded in memory.
 *
!*/
D_SEC( B ) PVOID PebGetModule( _In_ UINT32 ModuleHash );
