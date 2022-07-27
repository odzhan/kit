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

/* Include core defs */
#include <windows.h>
#include <wininet.h>
#include <windns.h>
#include <oleauto.h>
#include <wtypes.h>
#include <ntstatus.h>
#include <winioctl.h>
#include "Native.h"
#include "Macros.h"
#include "Config.h"
#include "Arc4.h"

/* Include Library */
#include "HeapList.h"
#include "PreMain.h"
#include "Labels.h"
#include "Random.h"
#include "Titan.h"
#include "Table.h"
#include "Hash.h"
#include "Heap.h"
#include "Peb.h"
#include "Hde.h"
#include "Ldr.h"
#include "Pe.h"

/* Include Hooks! */
#include "hooks/NtMapViewOfSection.h"
#include "hooks/WriteProcessMemory.h"
#include "hooks/ReadProcessMemory.h"
#include "hooks/VirtualProtectEx.h"
#include "hooks/NtQueueApcThread.h"
#include "hooks/SetThreadContext.h"
#include "hooks/GetProcAddress.h"
#include "hooks/VirtualAllocEx.h"
#include "hooks/CreateThread.h"
#include "hooks/HeapReAlloc.h"
#include "hooks/DnsQuery_A.h"
#include "hooks/ExitThread.h"
#include "hooks/HeapAlloc.h"
#include "hooks/HeapFree.h"
