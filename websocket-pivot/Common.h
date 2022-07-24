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

#include <windows.h>
#include <ntstatus.h>
#include "Native.h"
#include "Macros.h"
#include "Hash.h"
#include "Peb.h"
#include "Pe.h"
