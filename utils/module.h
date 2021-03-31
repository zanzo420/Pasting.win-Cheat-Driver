#pragma once
#include <ntifs.h>
#include <ntstrsafe.h>

#include "defines.h"

PVOID GetKernelRoutineAddress(LPCWSTR RoutineName);
PVOID GetKernelModuleExport(LPCWSTR ModuleName, LPCSTR RoutineName);
PVOID GetKernelModuleBase(LPCWSTR ModuleName);
PVOID GetKernelBase();