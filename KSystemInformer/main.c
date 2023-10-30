/*
 * Copyright (c) 2022 Winsider Seminars & Solutions, Inc.  All rights reserved.
 *
 * This file is part of System Informer.
 *
 * Authors:
 *
 *     wj32    2010-2016
 *     jxy-s   2021-2022
 *
 */

#include <kph.h>
#include <dyndata.h>
#include <informer.h>

#include <trace.h>

PDRIVER_OBJECT KphDriverObject = NULL;
KPH_INFORMER_SETTINGS KphInformerSettings = { 0 };
KPH_PROTECTED_DATA_SECTION_PUSH();
static BYTE KphpProtectedSection = 0;
RTL_OSVERSIONINFOEXW KphOsVersionInfo = { 0 };
KPH_FILE_VERSION KphKernelVersion = { 0 };
BOOLEAN KphIgnoreProtectionsSuppressed = FALSE;
BOOLEAN KphIgnoreTestSigningEnabled = FALSE;
SYSTEM_SECUREBOOT_INFORMATION KphSecureBootInfo = { 0 };
SYSTEM_CODEINTEGRITY_INFORMATION KphCodeIntegrityInfo = { 0 };
KPH_PROTECTED_DATA_SECTION_POP();
KPH_PROTECTED_DATA_SECTION_RO_PUSH();
static const BYTE KphpProtectedSectionReadOnly = 0;
KPH_PROTECTED_DATA_SECTION_RO_POP();

PAGED_FILE();

/**
 * \brief Protects select sections.
 */
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID KphpProtectSections(
    VOID
    )
{
    NTSTATUS status;

    PAGED_CODE();

    if (!KphDynMmProtectDriverSection)
    {
        KphTracePrint(TRACE_LEVEL_VERBOSE,
                      GENERAL,
                      "MmProtectDriverSection not found");

        return;
    }

    status = KphDynMmProtectDriverSection(&KphpProtectedSection,
                                          0,
                                          MM_PROTECT_DRIVER_SECTION_ALLOW_UNLOAD);

    KphTracePrint(TRACE_LEVEL_VERBOSE,
                  GENERAL,
                  "MmProtectDriverSection %!STATUS!",
                  status);

    status = KphDynMmProtectDriverSection((PVOID)&KphpProtectedSectionReadOnly,
                                          0,
                                          MM_PROTECT_DRIVER_SECTION_ALLOW_UNLOAD);

    KphTracePrint(TRACE_LEVEL_VERBOSE,
                  GENERAL,
                  "MmProtectDriverSection %!STATUS!",
                  status);
}

/**
 * \brief Cleans up the driver state.
 */
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID KphpDriverCleanup(
    VOID
    )
{
    PAGED_CODE_PASSIVE();

    KphObjectInformerStop();
    KphDebugInformerStop();
    KphImageInformerStop();
    KphCidMarkPopulated();
    KphThreadInformerStop();
    KphProcessInformerStop();
    KphFltUnregister();
    KphCidCleanup();
    KphCleanupSigning();
    KphDynamicDataCleanup();
    KphCleanupHashing();
    KphCleanupVerify();
    KphCleanupSocket();
}

/**
 * \brief Driver unload routine.
 *
 * \param[in] DriverObject Driver object of this driver.
 */
_Function_class_(DRIVER_UNLOAD)
_IRQL_requires_(PASSIVE_LEVEL)
_IRQL_requires_same_
VOID DriverUnload(
    _In_ PDRIVER_OBJECT DriverObject
    )
{
    PAGED_CODE_PASSIVE();

    KphTracePrint(TRACE_LEVEL_INFORMATION, GENERAL, "Driver Unloading...");

    KphpDriverCleanup();

    KphTracePrint(TRACE_LEVEL_INFORMATION, GENERAL, "Driver Unloaded");

    WPP_CLEANUP(DriverObject);
}

/**
 * \brief Driver entry point.
 *
 * \param[in] DriverObject Driver object for this driver.
 * \param[in] RegistryPath Registry path for this driver.
 *
 * \return Successful or errant status.
 */
_Function_class_(DRIVER_INITIALIZE)
_IRQL_requires_(PASSIVE_LEVEL)
_IRQL_requires_same_
NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS status;

    PAGED_CODE_PASSIVE();

    WPP_INIT_TRACING(DriverObject, RegistryPath);

    KphTracePrint(TRACE_LEVEL_INFORMATION, GENERAL, "Driver Loading...");

    KphDriverObject = DriverObject;
    KphDriverObject->DriverUnload = DriverUnload;

    ExInitializeDriverRuntime(DrvRtPoolNxOptIn);

    KphOsVersionInfo.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOEXW);
    status = RtlGetVersion((PRTL_OSVERSIONINFOW)&KphOsVersionInfo);
    if (!NT_SUCCESS(status))
    {
        KphTracePrint(TRACE_LEVEL_ERROR,
                      GENERAL,
                      "RtlGetVersion failed: %!STATUS!",
                      status);

        goto Exit;
    }

    if (!NT_SUCCESS(ZwQuerySystemInformation(SystemSecureBootInformation,
                                             &KphSecureBootInfo,
                                             sizeof(KphSecureBootInfo),
                                             NULL)))
    {
        RtlZeroMemory(&KphSecureBootInfo, sizeof(KphSecureBootInfo));
    }

    KphCodeIntegrityInfo.Length = sizeof(KphCodeIntegrityInfo);
    if (!NT_SUCCESS(ZwQuerySystemInformation(SystemCodeIntegrityInformation,
                                             &KphCodeIntegrityInfo,
                                             sizeof(KphCodeIntegrityInfo),
                                             NULL)))
    {
        RtlZeroMemory(&KphCodeIntegrityInfo, sizeof(KphCodeIntegrityInfo));
    }

    if (KphInDeveloperMode())
    {
        KphTracePrint(TRACE_LEVEL_INFORMATION, GENERAL, "Developer Mode");
    }

    status = KphInitializeAlloc(RegistryPath);
    if (!NT_SUCCESS(status))
    {
        KphTracePrint(TRACE_LEVEL_ERROR,
                      GENERAL,
                      "KphInitializeAlloc failed: %!STATUS!",
                      status);

        goto Exit;
    }

    KphDynamicImport();

    status = KphInitializeKnownDll();
    if (!NT_SUCCESS(status))
    {
        KphTracePrint(TRACE_LEVEL_ERROR,
                      GENERAL,
                      "KphInitializeKnownDll failed: %!STATUS!",
                      status);

        goto Exit;
    }

    status = KphGetKernelVersion(&KphKernelVersion);
    if (!NT_SUCCESS(status))
    {
        KphTracePrint(TRACE_LEVEL_ERROR,
                      GENERAL,
                      "KphLocateKernelRevision failed: %!STATUS!",
                      status);

        goto Exit;
    }

    KphTracePrint(TRACE_LEVEL_INFORMATION,
                  GENERAL,
                  "Windows %lu.%lu.%lu Kernel %lu.%lu.%lu.%lu",
                  KphOsVersionInfo.dwMajorVersion,
                  KphOsVersionInfo.dwMinorVersion,
                  KphOsVersionInfo.dwBuildNumber,
                  KphKernelVersion.MajorVersion,
                  KphKernelVersion.MinorVersion,
                  KphKernelVersion.BuildNumber,
                  KphKernelVersion.Revision);

    status = KphInitializeSocket();
    if (!NT_SUCCESS(status))
    {
        KphTracePrint(TRACE_LEVEL_ERROR,
                      GENERAL,
                      "KphInitializeSocket failed: %!STATUS!",
                      status);

        goto Exit;
    }

    status = KphInitializeVerify();
    if (!NT_SUCCESS(status))
    {
        KphTracePrint(TRACE_LEVEL_ERROR,
                      GENERAL,
                      "Failed to initialize signing: %!STATUS!",
                      status);

        goto Exit;
    }

    status = KphInitializeHashing();
    if (!NT_SUCCESS(status))
    {
        KphTracePrint(TRACE_LEVEL_ERROR,
                      GENERAL,
                      "Failed to initialize hashing: %!STATUS!",
                      status);

        goto Exit;
    }

    status = KphDynamicDataInitialization(RegistryPath);
    if (!NT_SUCCESS(status))
    {
        KphTracePrint(TRACE_LEVEL_ERROR,
                      GENERAL,
                      "Dynamic data initialization failed: %!STATUS!",
                      status);
        goto Exit;
    }

    status = KphInitializeStackBackTrace();
    if (!NT_SUCCESS(status))
    {
        KphTracePrint(TRACE_LEVEL_ERROR,
                      GENERAL,
                      "Failed to initialize stack back trace: %!STATUS!",
                      status);

        goto Exit;
    }

    KphpProtectSections();

    KphInitializeProtection();

    status = KphInitializeSigning();
    if (!NT_SUCCESS(status))
    {
        KphTracePrint(TRACE_LEVEL_ERROR,
                      GENERAL,
                      "Failed to initialize signing: %!STATUS!",
                      status);

        goto Exit;
    }

    status = KphFltRegister(DriverObject, RegistryPath);
    if (!NT_SUCCESS(status))
    {
        KphTracePrint(TRACE_LEVEL_ERROR,
                      GENERAL,
                      "Failed to register mini-filter: %!STATUS!",
                      status);
        goto Exit;
    }

    status = KphCidInitialize();
    if (!NT_SUCCESS(status))
    {
        KphTracePrint(TRACE_LEVEL_ERROR,
                      GENERAL,
                      "Failed to initialize CID tracking: %!STATUS!",
                      status);
        goto Exit;
    }

    status = KphProcessInformerStart();
    if (!NT_SUCCESS(status))
    {
        KphTracePrint(TRACE_LEVEL_ERROR,
                      GENERAL,
                      "Failed to start process informer: %!STATUS!",
                      status);
        goto Exit;
    }

    status = KphThreadInformerStart();
    if (!NT_SUCCESS(status))
    {
        KphTracePrint(TRACE_LEVEL_ERROR,
                      GENERAL,
                      "Failed to start thread informer: %!STATUS!",
                      status);
        goto Exit;
    }

    status = KphCidPopulate();
    if (!NT_SUCCESS(status))
    {
        KphTracePrint(TRACE_LEVEL_ERROR,
                      GENERAL,
                      "Failed to populate CID tracking: %!STATUS!",
                      status);
        goto Exit;
    }

    KphCidMarkPopulated();

    status = KphFltInformerStart();
    if (!NT_SUCCESS(status))
    {
        KphTracePrint(TRACE_LEVEL_ERROR,
                      GENERAL,
                      "Failed to start mini-filter informer: %!STATUS!",
                      status);
        goto Exit;
    }

    status = KphImageInformerStart();
    if (!NT_SUCCESS(status))
    {
        KphTracePrint(TRACE_LEVEL_ERROR,
                      GENERAL,
                      "Failed to start image informer: %!STATUS!",
                      status);
        goto Exit;
    }

    status = KphDebugInformerStart();
    if (!NT_SUCCESS(status))
    {
        KphTracePrint(TRACE_LEVEL_ERROR,
                      GENERAL,
                      "Failed to start debug informer: %!STATUS!",
                      status);
        goto Exit;
    }

    status = KphObjectInformerStart();
    if (!NT_SUCCESS(status))
    {
        KphTracePrint(TRACE_LEVEL_ERROR,
                      GENERAL,
                      "Failed to start object informer: %!STATUS!",
                      status);
        goto Exit;
    }

Exit:

    if (NT_SUCCESS(status))
    {
        KphTracePrint(TRACE_LEVEL_INFORMATION, GENERAL, "Driver Loaded");
    }
    else
    {
        KphpDriverCleanup();

        KphTracePrint(TRACE_LEVEL_ERROR,
                      GENERAL,
                      "Driver Load Failed: %!STATUS!",
                      status);

        WPP_CLEANUP(DriverObject);
    }

    return status;
}
