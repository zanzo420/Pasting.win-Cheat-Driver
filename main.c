#include "utils/module.h"

#include <ntddk.h>

DRIVER_INITIALIZE DriverEntry;
#pragma alloc_text(INIT, DriverEntry)

__declspec(dllexport) UINT_PTR DriverControl(ULONG uCode, UINT_PTR uParam1, UINT_PTR uParam2, UINT_PTR uParam3)
{
	UNREFERENCED_PARAMETER(uParam1);
	UNREFERENCED_PARAMETER(uParam2);
	UNREFERENCED_PARAMETER(uParam3);

	DbgPrint("control code: %d\n", uCode);

	// Main switch struct

	/*
	switch (uCode)
	{
	case ID_READ_PROCESS_MEMORY:
		return read_virtual_memory(
			reinterpret_cast<PMEMORY_STRUCT>(uParam1));

	case ID_READ_KERNEL_MEMORY:
		return read_kernel_memory(
			reinterpret_cast<PVOID>(uParam1), // address
			reinterpret_cast<PVOID>(uParam2), // buffer
			uParam3); // size

	case ID_WRITE_PROCESS_MEMORY:
		return write_virtual_memory(
			reinterpret_cast<PMEMORY_STRUCT>(uParam1));

	case ID_GET_PROCESS:
		return reinterpret_cast<UINT_PTR>(get_process(
			reinterpret_cast<HANDLE>(uParam1))); // process id

	case ID_GET_PROCESS_BASE:
		return reinterpret_cast<UINT_PTR>(get_process_base(
			reinterpret_cast<HANDLE>(uParam1))); // process id

	case ID_GET_PROCESS_MODULE:
		return reinterpret_cast<UINT_PTR>(
			get_process_module_base(
				reinterpret_cast<HANDLE>(uParam1), // process id
				L"kernel32.dll" // module name
			));

	default:
		break;
	}
	*/

	return 0;
}

NTSTATUS DriverEntry(
    _In_  struct _DRIVER_OBJECT *DriverObject,
    _In_  PUNICODE_STRING RegistryPath
)
{
    /* This parameters are invalid due to nonstandard way of loading and should not be used. */
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    UINT_PTR HookFunction = GetKernelModuleExport(L"win32kbase.sys", "NtGdiGetCertificateSizeByHandle");

	DbgPrint("> HookFunction %llx\n", HookFunction);

	if (!HookFunction)
		return -1;

    UINT_PTR HookPointer = *(DWORD*)(HookFunction + 7);
    HookPointer += 0xB;
    HookPointer += HookFunction;

	DbgPrint("> HookPointer offset %llx\n", HookPointer);

	memcpy((HookPointer), &DriverControl, sizeof(PVOID));

	DbgPrint("> hook applied\n");

    return STATUS_SUCCESS;
}
