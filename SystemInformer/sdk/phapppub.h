#ifndef _PH_PHAPPPUB_H
#define _PH_PHAPPPUB_H

// This file was automatically generated. Do not edit.

#ifdef __cplusplus
extern "C" {
#endif

//
// phfwddef
//

// phlib

typedef struct _PH_SYMBOL_PROVIDER *PPH_SYMBOL_PROVIDER;

// Providers

typedef struct _PH_PROCESS_ITEM *PPH_PROCESS_ITEM;
typedef struct _PH_PROCESS_RECORD *PPH_PROCESS_RECORD;
typedef struct _PH_SERVICE_ITEM *PPH_SERVICE_ITEM;
typedef struct _PH_NETWORK_ITEM *PPH_NETWORK_ITEM;
typedef struct _PH_MODULE_ITEM *PPH_MODULE_ITEM;
typedef struct _PH_MODULE_PROVIDER *PPH_MODULE_PROVIDER;
typedef struct _PH_THREAD_ITEM *PPH_THREAD_ITEM;
typedef struct _PH_THREAD_PROVIDER *PPH_THREAD_PROVIDER;
typedef struct _PH_HANDLE_ITEM *PPH_HANDLE_ITEM;
typedef struct _PH_HANDLE_PROVIDER *PPH_HANDLE_PROVIDER;
typedef struct _PH_MEMORY_ITEM *PPH_MEMORY_ITEM;
typedef struct _PH_MEMORY_ITEM_LIST *PPH_MEMORY_ITEM_LIST;

// uimodels

typedef struct _PH_PROCESS_NODE *PPH_PROCESS_NODE;
typedef struct _PH_SERVICE_NODE *PPH_SERVICE_NODE;
typedef struct _PH_NETWORK_NODE *PPH_NETWORK_NODE;
typedef struct _PH_MODULE_NODE *PPH_MODULE_NODE;
typedef struct _PH_THREAD_NODE *PPH_THREAD_NODE;
typedef struct _PH_HANDLE_NODE *PPH_HANDLE_NODE;
typedef struct _PH_MEMORY_NODE *PPH_MEMORY_NODE;

// procprv

typedef struct _PH_PROCESS_PROPCONTEXT *PPH_PROCESS_PROPCONTEXT;

//
// appsup
//

PHAPPAPI
BOOLEAN
NTAPI
PhGetProcessIsSuspended(
    _In_ PSYSTEM_PROCESS_INFORMATION Process
    );

PHAPPAPI
BOOLEAN
NTAPI
PhIsProcessSuspended(
    _In_ HANDLE ProcessId
    );

BOOLEAN
NTAPI
PhIsProcessBackground(
    _In_ ULONG PriorityClass
    );

PHAPPAPI
PPH_STRINGREF
NTAPI
PhGetProcessPriorityClassString(
    _In_ ULONG PriorityClass
    );

typedef enum _PH_KNOWN_PROCESS_TYPE
{
    UnknownProcessType,
    SystemProcessType, // ntoskrnl/ntkrnlpa/...
    SessionManagerProcessType, // smss
    WindowsSubsystemProcessType, // csrss
    WindowsStartupProcessType, // wininit
    ServiceControlManagerProcessType, // services
    LocalSecurityAuthorityProcessType, // lsass
    LocalSessionManagerProcessType, // lsm
    WindowsLogonProcessType, // winlogon
    ServiceHostProcessType, // svchost
    RunDllAsAppProcessType, // rundll32
    ComSurrogateProcessType, // dllhost
    TaskHostProcessType, // taskeng, taskhost, taskhostex
    ExplorerProcessType, // explorer
    UmdfHostProcessType, // wudfhost
    NtVdmHostProcessType, // ntvdm
    //EdgeProcessType, // Microsoft Edge
    WmiProviderHostType,
    MaximumProcessType,
    KnownProcessTypeMask = 0xffff,

    KnownProcessWow64 = 0x20000
} PH_KNOWN_PROCESS_TYPE;

PHAPPAPI
NTSTATUS
NTAPI
PhGetProcessKnownType(
    _In_ HANDLE ProcessHandle,
    _Out_ PH_KNOWN_PROCESS_TYPE *KnownProcessType
    );

PHAPPAPI
PH_KNOWN_PROCESS_TYPE
NTAPI
PhGetProcessKnownTypeEx(
    _In_opt_ HANDLE ProcessId,
    _In_ PPH_STRING FileName
    );

typedef union _PH_KNOWN_PROCESS_COMMAND_LINE
{
    struct
    {
        PPH_STRING GroupName;
    } ServiceHost;
    struct
    {
        PPH_STRING FileName;
        PPH_STRING ProcedureName;
    } RunDllAsApp;
    struct
    {
        GUID Guid;
        PPH_STRING Name; // optional
        PPH_STRING FileName; // optional
    } ComSurrogate;
} PH_KNOWN_PROCESS_COMMAND_LINE, *PPH_KNOWN_PROCESS_COMMAND_LINE;

PHAPPAPI
_Success_(return)
BOOLEAN
NTAPI
PhaGetProcessKnownCommandLine(
    _In_ PPH_STRING CommandLine,
    _In_ PH_KNOWN_PROCESS_TYPE KnownProcessType,
    _Out_ PPH_KNOWN_PROCESS_COMMAND_LINE KnownCommandLine
    );

PHAPPAPI
VOID
NTAPI
PhSearchOnlineString(
    _In_ HWND WindowHandle,
    _In_ PWSTR String
    );

PHAPPAPI
VOID
NTAPI
PhShellExecuteUserString(
    _In_ HWND WindowHandle,
    _In_ PWSTR Setting,
    _In_ PWSTR String,
    _In_ BOOLEAN UseShellExecute,
    _In_opt_ PWSTR ErrorMessage
    );

PHAPPAPI
VOID
NTAPI
PhLoadSymbolProviderOptions(
    _Inout_ PPH_SYMBOL_PROVIDER SymbolProvider
    );

PHAPPAPI
VOID
NTAPI
PhCopyListViewInfoTip(
    _Inout_ LPNMLVGETINFOTIP GetInfoTip,
    _In_ PPH_STRINGREF Tip
    );

PHAPPAPI
VOID
NTAPI
PhCopyListView(
    _In_ HWND ListViewHandle
    );

PHAPPAPI
VOID
NTAPI
PhHandleListViewNotifyForCopy(
    _In_ LPARAM lParam,
    _In_ HWND ListViewHandle
    );

#define PH_LIST_VIEW_CTRL_C_BEHAVIOR 0x1
#define PH_LIST_VIEW_CTRL_A_BEHAVIOR 0x2
#define PH_LIST_VIEW_DEFAULT_1_BEHAVIORS (PH_LIST_VIEW_CTRL_C_BEHAVIOR | PH_LIST_VIEW_CTRL_A_BEHAVIOR)

PHAPPAPI
VOID
NTAPI
PhHandleListViewNotifyBehaviors(
    _In_ LPARAM lParam,
    _In_ HWND ListViewHandle,
    _In_ ULONG Behaviors
    );

PHAPPAPI
BOOLEAN
NTAPI
PhGetListViewContextMenuPoint(
    _In_ HWND ListViewHandle,
    _Out_ PPOINT Point
    );

PHAPPAPI
PPH_STRING
NTAPI
PhGetPhVersion(
    VOID
    );

PHAPPAPI
VOID
NTAPI
PhGetPhVersionNumbers(
    _Out_opt_ PULONG MajorVersion,
    _Out_opt_ PULONG MinorVersion,
    _Out_opt_ PULONG BuildNumber,
    _Out_opt_ PULONG RevisionNumber
    );

PHAPPAPI
PPH_STRING
NTAPI
PhGetPhVersionHash(
    VOID
    );

PHAPPAPI
VOID
NTAPI
PhWritePhTextHeader(
    _Inout_ PPH_FILE_STREAM FileStream
    );

#define PH_SHELL_APP_PROPAGATE_PARAMETERS 0x1
#define PH_SHELL_APP_PROPAGATE_PARAMETERS_IGNORE_VISIBILITY 0x2

PHAPPAPI
BOOLEAN
NTAPI
PhShellProcessHacker(
    _In_opt_ HWND WindowHandle,
    _In_opt_ PWSTR Parameters,
    _In_ ULONG ShowWindowType,
    _In_ ULONG Flags,
    _In_ ULONG AppFlags,
    _In_opt_ ULONG Timeout,
    _Out_opt_ PHANDLE ProcessHandle
    );

typedef struct _PH_EMENU_ITEM* PPH_EMENU_ITEM;

typedef struct _PH_TN_COLUMN_MENU_DATA
{
    HWND TreeNewHandle;
    PPH_TREENEW_HEADER_MOUSE_EVENT MouseEvent;
    ULONG DefaultSortColumn;
    PH_SORT_ORDER DefaultSortOrder;

    PPH_EMENU_ITEM Menu;
    PPH_EMENU_ITEM Selection;
    ULONG ProcessedId;
} PH_TN_COLUMN_MENU_DATA, *PPH_TN_COLUMN_MENU_DATA;

#define PH_TN_COLUMN_MENU_HIDE_COLUMN_ID ((ULONG)-1)
#define PH_TN_COLUMN_MENU_CHOOSE_COLUMNS_ID ((ULONG)-2)
#define PH_TN_COLUMN_MENU_SIZE_COLUMN_TO_FIT_ID ((ULONG)-3)
#define PH_TN_COLUMN_MENU_SIZE_ALL_COLUMNS_TO_FIT_ID ((ULONG)-4)
#define PH_TN_COLUMN_MENU_RESET_SORT_ID ((ULONG)-5)

PHAPPAPI
VOID
NTAPI
PhInitializeTreeNewColumnMenu(
    _Inout_ PPH_TN_COLUMN_MENU_DATA Data
    );

#define PH_TN_COLUMN_MENU_NO_VISIBILITY 0x1
#define PH_TN_COLUMN_MENU_SHOW_RESET_SORT 0x2

PHAPPAPI
VOID
NTAPI
PhInitializeTreeNewColumnMenuEx(
    _Inout_ PPH_TN_COLUMN_MENU_DATA Data,
    _In_ ULONG Flags
    );

PHAPPAPI
BOOLEAN
NTAPI
PhHandleTreeNewColumnMenu(
    _Inout_ PPH_TN_COLUMN_MENU_DATA Data
    );

PHAPPAPI
VOID
NTAPI
PhDeleteTreeNewColumnMenu(
    _In_ PPH_TN_COLUMN_MENU_DATA Data
    );

typedef struct _PH_TN_FILTER_SUPPORT
{
    PPH_LIST FilterList;
    HWND TreeNewHandle;
    PPH_LIST NodeList;
} PH_TN_FILTER_SUPPORT, *PPH_TN_FILTER_SUPPORT;

typedef BOOLEAN (NTAPI *PPH_TN_FILTER_FUNCTION)(
    _In_ PPH_TREENEW_NODE Node,
    _In_opt_ PVOID Context
    );

typedef struct _PH_TN_FILTER_ENTRY
{
    PPH_TN_FILTER_FUNCTION Filter;
    PVOID Context;
} PH_TN_FILTER_ENTRY, *PPH_TN_FILTER_ENTRY;

PHAPPAPI
VOID
NTAPI
PhInitializeTreeNewFilterSupport(
    _Out_ PPH_TN_FILTER_SUPPORT Support,
    _In_ HWND TreeNewHandle,
    _In_ PPH_LIST NodeList
    );

PHAPPAPI
VOID
NTAPI
PhDeleteTreeNewFilterSupport(
    _In_ PPH_TN_FILTER_SUPPORT Support
    );

PHAPPAPI
PPH_TN_FILTER_ENTRY
NTAPI
PhAddTreeNewFilter(
    _In_ PPH_TN_FILTER_SUPPORT Support,
    _In_ PPH_TN_FILTER_FUNCTION Filter,
    _In_opt_ PVOID Context
    );

PHAPPAPI
VOID
NTAPI
PhRemoveTreeNewFilter(
    _In_ PPH_TN_FILTER_SUPPORT Support,
    _In_ PPH_TN_FILTER_ENTRY Entry
    );

PHAPPAPI
BOOLEAN
NTAPI
PhApplyTreeNewFiltersToNode(
    _In_ PPH_TN_FILTER_SUPPORT Support,
    _In_ PPH_TREENEW_NODE Node
    );

PHAPPAPI
VOID
NTAPI
PhApplyTreeNewFilters(
    _In_ PPH_TN_FILTER_SUPPORT Support
    );

typedef struct _PH_COPY_CELL_CONTEXT
{
    HWND TreeNewHandle;
    ULONG Id; // column ID
    PPH_STRING MenuItemText;
} PH_COPY_CELL_CONTEXT, *PPH_COPY_CELL_CONTEXT;

PHAPPAPI
BOOLEAN
NTAPI
PhInsertCopyCellEMenuItem(
    _In_ PPH_EMENU_ITEM Menu,
    _In_ ULONG InsertAfterId,
    _In_ HWND TreeNewHandle,
    _In_ PPH_TREENEW_COLUMN Column
    );

PHAPPAPI
BOOLEAN
NTAPI
PhHandleCopyCellEMenuItem(
    _In_ PPH_EMENU_ITEM SelectedItem
    );

typedef struct _PH_COPY_ITEM_CONTEXT
{
    HWND ListViewHandle;
    ULONG Id;
    ULONG SubId;
    PPH_STRING MenuItemText;
} PH_COPY_ITEM_CONTEXT, *PPH_COPY_ITEM_CONTEXT;

PHAPPAPI
BOOLEAN
NTAPI
PhInsertCopyListViewEMenuItem(
    _In_ PPH_EMENU_ITEM Menu,
    _In_ ULONG InsertAfterId,
    _In_ HWND ListViewHandle
    );

PHAPPAPI
BOOLEAN
NTAPI
PhHandleCopyListViewEMenuItem(
    _In_ PPH_EMENU_ITEM SelectedItem
    );

PHAPPAPI
VOID
NTAPI
PhShellOpenKey(
    _In_ HWND WindowHandle,
    _In_ PPH_STRING KeyName
    );

PHAPPAPI
BOOLEAN
NTAPI
PhShellOpenKey2(
    _In_ HWND WindowHandle,
    _In_ PPH_STRING KeyName
    );

PHAPPAPI
HBITMAP
NTAPI
PhGetShieldBitmap(
    _In_ LONG WindowDpi,
    _In_opt_ LONG Width,
    _In_opt_ LONG Height
    );

PHAPPAPI
HICON
NTAPI
PhGetApplicationIcon(
    _In_ BOOLEAN SmallIcon
    );

PHAPPAPI
HICON
NTAPI
PhGetApplicationIconEx(
    _In_ BOOLEAN SmallIcon,
    _In_opt_ LONG WindowDpi
    );

PHAPPAPI
VOID
NTAPI
PhSetApplicationWindowIcon(
    _In_ HWND WindowHandle
    );

PHAPPAPI
VOID
NTAPI
PhSetApplicationWindowIconEx(
    _In_ HWND WindowHandle,
    _In_opt_ LONG WindowDpi
    );

PHAPPAPI
VOID
NTAPI
PhSetWindowIcon(
    _In_ HWND WindowHandle,
    _In_opt_ HICON SmallIcon,
    _In_opt_ HICON LargeIcon,
    _In_ BOOLEAN CleanupIcon
    );

PHAPPAPI
VOID
NTAPI
PhDestroyWindowIcon(
    _In_ HWND WindowHandle
    );

PHAPPAPI
VOID
NTAPI
PhSetStaticWindowIcon(
    _In_ HWND WindowHandle,
    _In_opt_ LONG WindowDpi
    );

PHAPPAPI
VOID
NTAPI
PhDeleteStaticWindowIcon(
    _In_ HWND WindowHandle
    );

PHAPPAPI
BOOLEAN
NTAPI
PhWordMatchStringRef(
    _In_ PPH_STRINGREF SearchText,
    _In_ PPH_STRINGREF Text
    );

FORCEINLINE
BOOLEAN
NTAPI
PhWordMatchStringZ(
    _In_ PPH_STRING SearchText,
    _In_ PWSTR Text
    )
{
    PH_STRINGREF text;

    PhInitializeStringRef(&text, Text);

    return PhWordMatchStringRef(&SearchText->sr, &text);
}

FORCEINLINE
BOOLEAN
NTAPI
PhWordMatchStringLongHintZ(
    _In_ PPH_STRING SearchText,
    _In_ PWSTR Text
    )
{
    PH_STRINGREF text;

    PhInitializeStringRefLongHint(&text, Text);

    return PhWordMatchStringRef(&SearchText->sr, &text);
}

PHAPPAPI
PVOID
NTAPI
PhCreateKsiSettingsBlob( // ksisup.c
    VOID
    );

#define PH_LOAD_SHARED_ICON_SMALL(BaseAddress, Name, dpiValue) PhLoadIcon(BaseAddress, (Name), PH_LOAD_ICON_SHARED | PH_LOAD_ICON_SIZE_SMALL, 0, 0, dpiValue) // phapppub
#define PH_LOAD_SHARED_ICON_LARGE(BaseAddress, Name, dpiValue) PhLoadIcon(BaseAddress, (Name), PH_LOAD_ICON_SHARED | PH_LOAD_ICON_SIZE_LARGE, 0, 0, dpiValue) // phapppub

//
// phapp
//

PHAPPAPI
VOID
NTAPI
PhRegisterDialog(
    _In_ HWND DialogWindowHandle
    );

PHAPPAPI
VOID
NTAPI
PhUnregisterDialog(
    _In_ HWND DialogWindowHandle
    );

typedef BOOLEAN (NTAPI *PPH_MESSAGE_LOOP_FILTER)(
    _In_ PMSG Message,
    _In_ PVOID Context
    );

typedef struct _PH_MESSAGE_LOOP_FILTER_ENTRY
{
    PPH_MESSAGE_LOOP_FILTER Filter;
    PVOID Context;
} PH_MESSAGE_LOOP_FILTER_ENTRY, *PPH_MESSAGE_LOOP_FILTER_ENTRY;

PHAPPAPI
PPH_MESSAGE_LOOP_FILTER_ENTRY
NTAPI
PhRegisterMessageLoopFilter(
    _In_ PPH_MESSAGE_LOOP_FILTER Filter,
    _In_opt_ PVOID Context
    );

PHAPPAPI
VOID
NTAPI
PhUnregisterMessageLoopFilter(
    _In_ PPH_MESSAGE_LOOP_FILTER_ENTRY FilterEntry
    );

#define PH_LOG_ENTRY_MESSAGE 100 // phapppub

typedef struct _PH_LOG_ENTRY *PPH_LOG_ENTRY; // phapppub

PHAPPAPI
VOID
NTAPI
PhLogMessageEntry(
    _In_ UCHAR Type,
    _In_ PPH_STRING Message
    );

PHAPPAPI
PPH_STRING
NTAPI
PhFormatLogEntry(
    _In_ PPH_LOG_ENTRY Entry
    );

_Success_(return)
PHAPPAPI
BOOLEAN
NTAPI
PhShowProcessAffinityDialog2(
    _In_ HWND ParentWindowHandle,
    _In_ PPH_PROCESS_ITEM ProcessItem,
    _Out_ PKAFFINITY NewAffinityMask
    );

PHAPPAPI
NTSTATUS
NTAPI
PhSetProcessItemAffinityMask(
    _In_ PPH_PROCESS_ITEM ProcessItem,
    _In_ KAFFINITY AffinityMask
    );

PHAPPAPI
NTSTATUS
NTAPI
PhSetProcessItemPagePriority(
    _In_ PPH_PROCESS_ITEM ProcessItem,
    _In_ ULONG PagePriority
    );

PHAPPAPI
NTSTATUS
NTAPI
PhSetProcessItemIoPriority(
    _In_ PPH_PROCESS_ITEM ProcessItem,
    _In_ IO_PRIORITY_HINT IoPriority
    );

PHAPPAPI
NTSTATUS
NTAPI
PhSetProcessItemPriority(
    _In_ PPH_PROCESS_ITEM ProcessItem,
    _In_ UCHAR PriorityClass
    );

PHAPPAPI
NTSTATUS
NTAPI
PhSetProcessItemPriorityBoost(
    _In_ PPH_PROCESS_ITEM ProcessItem,
    _In_ BOOLEAN PriorityBoost
    );

PHAPPAPI
NTSTATUS
NTAPI
PhSetProcessItemThrottlingState(
    _In_ PPH_PROCESS_ITEM ProcessItem,
    _In_ BOOLEAN ThrottlingState
    );

#define PH_CHOICE_DIALOG_SAVED_CHOICES 10

#define PH_CHOICE_DIALOG_CHOICE 0x0
#define PH_CHOICE_DIALOG_USER_CHOICE 0x1
#define PH_CHOICE_DIALOG_PASSWORD 0x2
#define PH_CHOICE_DIALOG_TYPE_MASK 0x3

PHAPPAPI
BOOLEAN
NTAPI
PhaChoiceDialog(
    _In_ HWND ParentWindowHandle,
    _In_ PWSTR Title,
    _In_ PWSTR Message,
    _In_opt_ PWSTR *Choices,
    _In_opt_ ULONG NumberOfChoices,
    _In_opt_ PWSTR Option,
    _In_ ULONG Flags,
    _Inout_ PPH_STRING *SelectedChoice,
    _Inout_opt_ PBOOLEAN SelectedOption,
    _In_opt_ PWSTR SavedChoicesSettingName
    );

_Success_(return)
PHAPPAPI
BOOLEAN
NTAPI
PhShowChooseProcessDialog(
    _In_ HWND ParentWindowHandle,
    _In_ PWSTR Message,
    _Out_ PHANDLE ProcessId
    );

PHAPPAPI
VOID
NTAPI
PhShowProcessRecordDialog(
    _In_ HWND ParentWindowHandle,
    _In_ PPH_PROCESS_RECORD Record
    );

PHLIBAPI
BOOLEAN
NTAPI
PhShowRunFileDialog(
    _In_ HWND ParentWindowHandle
    );

PHAPPAPI
NTSTATUS
NTAPI
PhExecuteRunAsCommand2(
    _In_ HWND hWnd,
    _In_ PWSTR Program,
    _In_opt_ PWSTR UserName,
    _In_opt_ PWSTR Password,
    _In_opt_ ULONG LogonType,
    _In_opt_ HANDLE ProcessIdWithToken,
    _In_ ULONG SessionId,
    _In_ PWSTR DesktopName,
    _In_ BOOLEAN UseLinkedToken
    );

PHAPPAPI
VOID
NTAPI
PhCreateSearchControl(
    _In_ HWND Parent,
    _In_ HWND WindowHandle,
    _In_opt_ PWSTR BannerText
    );

#define WM_PH_SET_LIST_VIEW_SETTINGS (WM_APP + 701)

PHAPPAPI
HWND
NTAPI
PhCreateServiceListControl(
    _In_ HWND ParentWindowHandle,
    _In_ PPH_SERVICE_ITEM *Services,
    _In_ ULONG NumberOfServices
    );

//
// procprv
//

#define DPCS_PROCESS_ID ((HANDLE)(LONG_PTR)-2)
#define INTERRUPTS_PROCESS_ID ((HANDLE)(LONG_PTR)-3)

// DPCs, Interrupts and System Idle Process are not real.
// Non-"real" processes can never be opened.
#define PH_IS_REAL_PROCESS_ID(ProcessId) ((LONG_PTR)(ProcessId) > 0)

// DPCs and Interrupts are fake, but System Idle Process is not.
#define PH_IS_FAKE_PROCESS_ID(ProcessId) ((LONG_PTR)(ProcessId) < 0)

// The process item has been removed.
#define PH_PROCESS_ITEM_REMOVED 0x1

typedef enum _VERIFY_RESULT VERIFY_RESULT;
typedef struct _PH_PROCESS_RECORD *PPH_PROCESS_RECORD;

typedef struct _PH_IMAGELIST_ITEM
{
    PPH_STRING FileName;
    ULONG LargeIconIndex;
    ULONG SmallIconIndex;
} PH_IMAGELIST_ITEM, *PPH_IMAGELIST_ITEM;

typedef struct _PH_PROCESS_ITEM
{
    PH_HASH_ENTRY HashEntry;
    ULONG State;
    PPH_PROCESS_RECORD Record;

    // Basic

    HANDLE ProcessId;
    HANDLE ParentProcessId;
    PPH_STRING ProcessName;
    ULONG SessionId;

    LARGE_INTEGER CreateTime;

    // Handles

    HANDLE QueryHandle;

    // Parameters

    PPH_STRING FileNameWin32;
    PPH_STRING FileName;
    PPH_STRING CommandLine;

    // File

    ULONG_PTR SmallIconIndex;
    ULONG_PTR LargeIconIndex;
    PH_IMAGE_VERSION_INFO VersionInfo;

    // Security

    PSID Sid;
    TOKEN_ELEVATION_TYPE ElevationType;
    MANDATORY_LEVEL IntegrityLevel;
    PWSTR IntegrityString;

    // Other

    HANDLE ConsoleHostProcessId;

    // Signature, Packed

    VERIFY_RESULT VerifyResult;
    PPH_STRING VerifySignerName;
    ULONG ImportFunctions;
    ULONG ImportModules;

    // Flags

    union
    {
        ULONG Flags;
        struct
        {
            ULONG UpdateIsDotNet : 1;
            ULONG IsBeingDebugged : 1;
            ULONG IsDotNet : 1;
            ULONG IsElevated : 1;
            ULONG IsInJob : 1;
            ULONG IsInSignificantJob : 1;
            ULONG IsPacked : 1;
            ULONG IsHandleValid : 1;
            ULONG IsSuspended : 1;
            ULONG IsWow64 : 1;
            ULONG IsImmersive : 1;
            ULONG IsPartiallySuspended : 1;
            ULONG IsProtectedHandle : 1;
            ULONG IsProtectedProcess : 1;
            ULONG IsSecureProcess : 1;
            ULONG IsSubsystemProcess : 1;
            ULONG IsPackagedProcess : 1;
            ULONG IsUIAccessEnabled : 1;
            ULONG IsControlFlowGuardEnabled : 1;
            ULONG IsCetEnabled : 1;
            ULONG IsXfgEnabled : 1;
            ULONG IsXfgAuditEnabled : 1;
            ULONG Spare : 10;
        };
    };

    // Misc.

    volatile LONG JustProcessed;
    PH_EVENT Stage1Event;

    PPH_POINTER_LIST ServiceList;
    PH_QUEUED_LOCK ServiceListLock;

    WCHAR ProcessIdString[PH_INT32_STR_LEN_1];
    //WCHAR ParentProcessIdString[PH_INT32_STR_LEN_1];
    //WCHAR SessionIdString[PH_INT32_STR_LEN_1];
    WCHAR LxssProcessIdString[PH_INT32_STR_LEN_1];

    // Dynamic

    KPRIORITY BasePriority;
    ULONG PriorityClass;
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    ULONG NumberOfHandles;
    ULONG NumberOfThreads;

    FLOAT CpuUsage; // Below Windows 7, sum of kernel and user CPU usage; above Windows 7, cycle-based CPU usage.
    FLOAT CpuKernelUsage;
    FLOAT CpuUserUsage;
    FLOAT CpuAverageUsage;

    PH_UINT64_DELTA CpuKernelDelta;
    PH_UINT64_DELTA CpuUserDelta;
    PH_UINT64_DELTA IoReadDelta;
    PH_UINT64_DELTA IoWriteDelta;
    PH_UINT64_DELTA IoOtherDelta;
    PH_UINT64_DELTA IoReadCountDelta;
    PH_UINT64_DELTA IoWriteCountDelta;
    PH_UINT64_DELTA IoOtherCountDelta;
    PH_UINT64_DELTA ContextSwitchesDelta;
    PH_UINT32_DELTA PageFaultsDelta;
    PH_UINT32_DELTA HardFaultsDelta;
    PH_UINT64_DELTA CycleTimeDelta; // since WIN7

    VM_COUNTERS_EX VmCounters;
    IO_COUNTERS IoCounters;
    SIZE_T WorkingSetPrivateSize; // since VISTA
    ULONG PeakNumberOfThreads; // since WIN7
    ULONG HardFaultCount; // since WIN7

    ULONG TimeSequenceNumber;
    PH_CIRCULAR_BUFFER_FLOAT CpuKernelHistory;
    PH_CIRCULAR_BUFFER_FLOAT CpuUserHistory;
    PH_CIRCULAR_BUFFER_ULONG64 IoReadHistory;
    PH_CIRCULAR_BUFFER_ULONG64 IoWriteHistory;
    PH_CIRCULAR_BUFFER_ULONG64 IoOtherHistory;
    PH_CIRCULAR_BUFFER_SIZE_T PrivateBytesHistory;
    //PH_CIRCULAR_BUFFER_SIZE_T WorkingSetHistory;

    // New fields
    PH_UINTPTR_DELTA PrivateBytesDelta;
    PPH_STRING PackageFullName;
    PPH_STRING UserName;

    PROCESS_DISK_COUNTERS DiskCounters;
    ULONGLONG ContextSwitches;

    ULONGLONG ProcessSequenceNumber;
    PH_KNOWN_PROCESS_TYPE KnownProcessType;
    PS_PROTECTION Protection;
    ULONG JobObjectId;
    SIZE_T SharedCommitCharge;

    PPH_IMAGELIST_ITEM IconEntry;

    NTSTATUS ImageCoherencyStatus;
    FLOAT ImageCoherency;

    ULONG LxssProcessId;

} PH_PROCESS_ITEM, *PPH_PROCESS_ITEM;

// The process itself is dead.
#define PH_PROCESS_RECORD_DEAD 0x1
// An extra reference has been added to the process record for the statistics system.
#define PH_PROCESS_RECORD_STAT_REF 0x2

typedef struct _PH_PROCESS_RECORD
{
    LIST_ENTRY ListEntry;
    LONG RefCount;
    ULONG Flags;

    HANDLE ProcessId;
    HANDLE ParentProcessId;
    ULONG SessionId;
    ULONGLONG ProcessSequenceNumber;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER ExitTime;

    PPH_STRING ProcessName;
    PPH_STRING FileName;
    PPH_STRING CommandLine;
    /*PPH_STRING UserName;*/
} PH_PROCESS_RECORD, *PPH_PROCESS_RECORD;

PHAPPAPI
PPH_STRING
NTAPI
PhGetClientIdName(
    _In_ PCLIENT_ID ClientId
    );

PHAPPAPI
PPH_STRING
NTAPI
PhGetClientIdNameEx(
    _In_ PCLIENT_ID ClientId,
    _In_opt_ PPH_STRING ProcessName
    );

PHAPPAPI
PPH_PROCESS_ITEM
NTAPI
PhReferenceProcessItem(
    _In_opt_ HANDLE ProcessId
    );

PHAPPAPI
VOID
NTAPI
PhEnumProcessItems(
    _Out_opt_ PPH_PROCESS_ITEM **ProcessItems,
    _Out_ PULONG NumberOfProcessItems
    );

PHAPPAPI
_Success_(return)
BOOLEAN
NTAPI
PhGetStatisticsTime(
    _In_opt_ PPH_PROCESS_ITEM ProcessItem,
    _In_ ULONG Index,
    _Out_ PLARGE_INTEGER Time
    );

PHAPPAPI
PPH_STRING
NTAPI
PhGetStatisticsTimeString(
    _In_opt_ PPH_PROCESS_ITEM ProcessItem,
    _In_ ULONG Index
    );

PHAPPAPI
VOID
NTAPI
PhReferenceProcessRecord(
    _In_ PPH_PROCESS_RECORD ProcessRecord
    );

PHAPPAPI
BOOLEAN
NTAPI
PhReferenceProcessRecordSafe(
    _In_ PPH_PROCESS_RECORD ProcessRecord
    );

PHAPPAPI
VOID
NTAPI
PhReferenceProcessRecordForStatistics(
    _In_ PPH_PROCESS_RECORD ProcessRecord
    );

PHAPPAPI
VOID
NTAPI
PhDereferenceProcessRecord(
    _In_ PPH_PROCESS_RECORD ProcessRecord
    );

PHAPPAPI
PPH_PROCESS_RECORD
NTAPI
PhFindProcessRecord(
    _In_opt_ HANDLE ProcessId,
    _In_ PLARGE_INTEGER Time
    );

PHAPPAPI
PPH_PROCESS_ITEM
NTAPI
PhReferenceProcessItemForParent(
    _In_ PPH_PROCESS_ITEM ProcessItem
    );

PHAPPAPI
PPH_PROCESS_ITEM
NTAPI
PhReferenceProcessItemForRecord(
    _In_ PPH_PROCESS_RECORD Record
    );

PHAPPAPI
VOID
NTAPI
PhProcessImageListInitialization(
    _In_ HWND WindowHandle,
    _In_ LONG WindowDpi
    );

PHAPPAPI
PPH_IMAGELIST_ITEM
NTAPI
PhImageListExtractIcon(
    _In_ PPH_STRING FileName,
    _In_ BOOLEAN NativeFileName,
    _In_opt_ HANDLE ProcessId,
    _In_opt_ PPH_STRING PackageFullName,
    _In_ LONG SystemDpi
    );

PHAPPAPI
VOID
NTAPI
PhImageListFlushCache(
    VOID
    );

PHAPPAPI
HICON
NTAPI
PhGetImageListIcon(
    _In_ ULONG_PTR Index,
    _In_ BOOLEAN Large
    );

PHAPPAPI
HIMAGELIST
NTAPI
PhGetProcessSmallImageList(
    VOID
    );

// Note: Can only be called from same thread as process provider. (dmex)
PHAPPAPI
BOOLEAN
NTAPI
PhDuplicateProcessInformation(
    _Out_ PPVOID ProcessInformation
    );

//
// srvprv
//

typedef enum _VERIFY_RESULT VERIFY_RESULT;
typedef struct _PH_IMAGELIST_ITEM* PPH_IMAGELIST_ITEM;

typedef struct _PH_SERVICE_ITEM
{
    PH_STRINGREF Key; // points to Name
    PPH_STRING Name;
    PPH_STRING DisplayName;
    PPH_STRING FileName;

    PPH_IMAGELIST_ITEM IconEntry;
    volatile LONG JustProcessed;

    // State
    ULONG Type;
    ULONG State;
    ULONG ControlsAccepted;
    ULONG Flags; // e.g. SERVICE_RUNS_IN_SYSTEM_PROCESS
    HANDLE ProcessId;

    // Config
    ULONG StartType;
    ULONG ErrorControl;

    // Signature
    VERIFY_RESULT VerifyResult;
    PPH_STRING VerifySignerName;

    WCHAR ProcessIdString[PH_INT32_STR_LEN_1];


} PH_SERVICE_ITEM, *PPH_SERVICE_ITEM;

typedef struct _PH_SERVICE_MODIFIED_DATA
{
    PPH_SERVICE_ITEM ServiceItem;
    PH_SERVICE_ITEM OldService;
} PH_SERVICE_MODIFIED_DATA, *PPH_SERVICE_MODIFIED_DATA;

typedef enum _PH_SERVICE_CHANGE
{
    ServiceNone,
    ServiceStarted,
    ServiceContinued,
    ServicePaused,
    ServiceStopped,
    ServiceModified,
} PH_SERVICE_CHANGE, *PPH_SERVICE_CHANGE;

PHAPPAPI
PPH_SERVICE_ITEM
NTAPI
PhReferenceServiceItem(
    _In_ PWSTR Name
    );

PHAPPAPI
PH_SERVICE_CHANGE
NTAPI
PhGetServiceChange(
    _In_ PPH_SERVICE_MODIFIED_DATA Data
    );

//
// netprv
//

#define PH_NETWORK_OWNER_INFO_SIZE 16

typedef struct _PH_NETWORK_ITEM
{
    ULONG ProtocolType;
    PH_IP_ENDPOINT LocalEndpoint;
    PH_IP_ENDPOINT RemoteEndpoint;
    MIB_TCP_STATE State;
    HANDLE ProcessId;

    PPH_STRING ProcessName;
    ULONG_PTR ProcessIconIndex;
    BOOLEAN ProcessIconValid;
    PPH_STRING OwnerName;

    volatile LONG JustResolved;

    ULONG LocalAddressStringLength;
    ULONG RemoteAddressStringLength;
    WCHAR LocalAddressString[INET6_ADDRSTRLEN];
    WCHAR LocalPortString[PH_INT32_STR_LEN_1];
    WCHAR RemoteAddressString[INET6_ADDRSTRLEN];
    WCHAR RemotePortString[PH_INT32_STR_LEN_1];
    PPH_STRING LocalHostString;
    PPH_STRING RemoteHostString;

    LARGE_INTEGER CreateTime;
    ULONG LocalScopeId;
    ULONG RemoteScopeId;

    union
    {
        ULONG Flags;
        struct
        {
            ULONG UnknownProcess : 1;
            ULONG SubsystemProcess : 1;
            ULONG Spare : 27;
            ULONG InvalidateHostname : 1;
            ULONG LocalHostnameResolved : 1;
            ULONG RemoteHostnameResolved : 1;
        };
    };

    PPH_PROCESS_ITEM ProcessItem;
} PH_NETWORK_ITEM, *PPH_NETWORK_ITEM;

PHAPPAPI
PPH_NETWORK_ITEM
NTAPI
PhReferenceNetworkItem(
    _In_ ULONG ProtocolType,
    _In_ PPH_IP_ENDPOINT LocalEndpoint,
    _In_ PPH_IP_ENDPOINT RemoteEndpoint,
    _In_ HANDLE ProcessId
    );

PHAPPAPI
VOID
NTAPI
PhEnumNetworkItems(
    _Out_opt_ PPH_NETWORK_ITEM** NetworkItems,
    _Out_ PULONG NumberOfNetworkItems
    );

PHAPPAPI
VOID
NTAPI
PhEnumNetworkItemsByProcessId(
    _In_opt_ HANDLE ProcessId,
    _Out_opt_ PPH_NETWORK_ITEM** NetworkItems,
    _Out_ PULONG NumberOfNetworkItems
    );

PHAPPAPI
PPH_STRINGREF
NTAPI
PhGetProtocolTypeName(
    _In_ ULONG ProtocolType
    );

PHAPPAPI
PPH_STRINGREF
NTAPI
PhGetTcpStateName(
    _In_ ULONG State
    );

//
// modprv
//

typedef struct _PH_MODULE_ITEM
{
    PVOID BaseAddress;
    PVOID ParentBaseAddress;
    PVOID EntryPoint;
    ULONG Size;
    ULONG Flags;
    ULONG Type;
    USHORT LoadReason;
    USHORT LoadCount;
    PPH_STRING Name;
    PPH_STRING FileName;
    PH_IMAGE_VERSION_INFO VersionInfo;
    ULONG EnclaveType;
    PVOID EnclaveBaseAddress;
    SIZE_T EnclaveSize;

    union
    {
        BOOLEAN StateFlags;
        struct
        {
            BOOLEAN JustProcessed : 1;
            BOOLEAN IsFirst : 1;
            BOOLEAN ImageNotAtBase : 1;
            BOOLEAN ImageKnownDll : 1;
            BOOLEAN Spare : 4;
        };
    };

    enum _VERIFY_RESULT VerifyResult;
    PPH_STRING VerifySignerName;

    ULONG ImageTimeDateStamp;
    USHORT ImageCharacteristics;
    USHORT ImageDllCharacteristics;
    ULONG ImageDllCharacteristicsEx;
    ULONG GuardFlags;

    LARGE_INTEGER LoadTime;
    LARGE_INTEGER FileLastWriteTime;
    LARGE_INTEGER FileEndOfFile;

    NTSTATUS ImageCoherencyStatus;
    FLOAT ImageCoherency;

    WCHAR BaseAddressString[PH_PTR_STR_LEN_1];
    WCHAR ParentBaseAddressString[PH_PTR_STR_LEN_1];
    WCHAR EntryPointAddressString[PH_PTR_STR_LEN_1];
    WCHAR EnclaveBaseAddressString[PH_PTR_STR_LEN_1];
} PH_MODULE_ITEM, *PPH_MODULE_ITEM;

typedef struct _PH_MODULE_PROVIDER
{
    PPH_HASHTABLE ModuleHashtable;
    PH_FAST_LOCK ModuleHashtableLock;
    PH_CALLBACK ModuleAddedEvent;
    PH_CALLBACK ModuleModifiedEvent;
    PH_CALLBACK ModuleRemovedEvent;
    PH_CALLBACK UpdatedEvent;

    HANDLE ProcessId;
    HANDLE ProcessHandle;
    PPH_STRING ProcessFileName;
    PPH_STRING PackageFullName;
    SLIST_HEADER QueryListHead;
    NTSTATUS RunStatus;

    union
    {
        BOOLEAN Flags;
        struct
        {
            BOOLEAN HaveFirst : 1;
            BOOLEAN IsHandleValid : 1;
            BOOLEAN IsSubsystemProcess : 1;
            BOOLEAN ControlFlowGuardEnabled : 1;
            BOOLEAN CetEnabled : 1;
            BOOLEAN CetStrictModeEnabled : 1;
            BOOLEAN ZeroPadAddresses : 1;
            BOOLEAN Spare : 1;
        };
    };
    UCHAR ImageCoherencyScanLevel;
} PH_MODULE_PROVIDER, *PPH_MODULE_PROVIDER;

//
// thrdprv
//

typedef struct _PH_THREAD_ITEM
{
    HANDLE ThreadId;

    LARGE_INTEGER CreateTime;
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    PH_UINT64_DELTA CpuKernelDelta;
    PH_UINT64_DELTA CpuUserDelta;
    PH_UINT32_DELTA ContextSwitchesDelta;
    PH_UINT64_DELTA CyclesDelta;

    FLOAT CpuUsage;
    FLOAT CpuKernelUsage;
    FLOAT CpuUserUsage;

    KPRIORITY Priority;
    KPRIORITY BasePriority;
    ULONG WaitTime;
    KTHREAD_STATE State;
    KWAIT_REASON WaitReason;
    KPRIORITY BasePriorityIncrement;

    HANDLE ThreadHandle;

    PPH_STRING ServiceName;

    ULONG64 StartAddress;
    PPH_STRING StartAddressString;
    PPH_STRING StartAddressFileName;
    enum _PH_SYMBOL_RESOLVE_LEVEL StartAddressResolveLevel;

    BOOLEAN IsGuiThread;
    BOOLEAN JustResolved;
    WCHAR ThreadIdString[PH_INT32_STR_LEN_1];
    WCHAR LxssThreadIdString[PH_INT32_STR_LEN_1];

    IO_COUNTERS IoCounters;

    ULONG LxssThreadId;
} PH_THREAD_ITEM, *PPH_THREAD_ITEM;

typedef enum _PH_KNOWN_PROCESS_TYPE PH_KNOWN_PROCESS_TYPE;

typedef struct _PH_THREAD_PROVIDER
{
    PPH_HASHTABLE ThreadHashtable;
    PH_FAST_LOCK ThreadHashtableLock;
    PH_CALLBACK ThreadAddedEvent;
    PH_CALLBACK ThreadModifiedEvent;
    PH_CALLBACK ThreadRemovedEvent;
    PH_CALLBACK UpdatedEvent;
    PH_CALLBACK LoadingStateChangedEvent;

    HANDLE ProcessId;
    HANDLE ProcessHandle;

    union
    {
        BOOLEAN Flags;
        struct
        {
            BOOLEAN HasServices : 1;
            BOOLEAN HasServicesKnown : 1;
            BOOLEAN Terminating : 1;
            BOOLEAN Spare : 5;
        };
    };

    struct _PH_SYMBOL_PROVIDER *SymbolProvider;

    SLIST_HEADER QueryListHead;
    PH_QUEUED_LOCK LoadSymbolsLock;
    LONG SymbolsLoading;
    ULONG64 RunId;
    ULONG64 SymbolsLoadedRunId;
} PH_THREAD_PROVIDER, *PPH_THREAD_PROVIDER;

//
// hndlprv
//

#define PH_HANDLE_FILE_SHARED_READ 0x1
#define PH_HANDLE_FILE_SHARED_WRITE 0x2
#define PH_HANDLE_FILE_SHARED_DELETE 0x4
#define PH_HANDLE_FILE_SHARED_MASK 0x7

typedef struct _PH_HANDLE_ITEM
{
    PH_HASH_ENTRY HashEntry;

    HANDLE Handle;
    PVOID Object;
    ULONG Attributes;
    ACCESS_MASK GrantedAccess;
    ULONG TypeIndex;
    ULONG FileFlags;

    PPH_STRING TypeName;
    PPH_STRING ObjectName;
    PPH_STRING BestObjectName;

    WCHAR HandleString[PH_PTR_STR_LEN_1];
    WCHAR GrantedAccessString[PH_PTR_STR_LEN_1];
    WCHAR ObjectString[PH_PTR_STR_LEN_1];
} PH_HANDLE_ITEM, *PPH_HANDLE_ITEM;

typedef struct _PH_HANDLE_PROVIDER
{
    PPH_HASH_ENTRY *HandleHashSet;
    ULONG HandleHashSetSize;
    ULONG HandleHashSetCount;
    PH_QUEUED_LOCK HandleHashSetLock;

    PH_CALLBACK HandleAddedEvent;
    PH_CALLBACK HandleModifiedEvent;
    PH_CALLBACK HandleRemovedEvent;
    PH_CALLBACK HandleUpdatedEvent;

    HANDLE ProcessId;
    HANDLE ProcessHandle;

    PPH_HASHTABLE TempListHashtable;
    NTSTATUS RunStatus;
} PH_HANDLE_PROVIDER, *PPH_HANDLE_PROVIDER;

//
// memprv
//

typedef enum _PH_MEMORY_REGION_TYPE
{
    UnknownRegion,
    CustomRegion,
    UnusableRegion,
    MappedFileRegion,
    UserSharedDataRegion,
    PebRegion,
    Peb32Region,
    TebRegion,
    Teb32Region, // Not used
    StackRegion,
    Stack32Region,
    HeapRegion,
    Heap32Region,
    HeapSegmentRegion,
    HeapSegment32Region,
    CfgBitmapRegion,
    CfgBitmap32Region,
    ApiSetMapRegion,
    HypervisorSharedDataRegion,
    ReadOnlySharedMemoryRegion,
    CodePageDataRegion,
    GdiSharedHandleTableRegion,
    ShimDataRegion,
    ActivationContextDataRegion,
    SystemDefaultActivationContextDataRegion
} PH_MEMORY_REGION_TYPE;

typedef struct _PH_MEMORY_ITEM
{
    LIST_ENTRY ListEntry;
    PH_AVL_LINKS Links;

    union
    {
        MEMORY_BASIC_INFORMATION BasicInfo;
        struct
        {
            PVOID BaseAddress;
            PVOID AllocationBase;
            ULONG AllocationProtect;
            SIZE_T RegionSize;
            ULONG State;
            ULONG Protect;
            ULONG Type;
        };
    };

    union
    {
        BOOLEAN Attributes;
        struct
        {
            BOOLEAN Valid : 1;
            BOOLEAN Bad : 1;
            BOOLEAN Spare : 6;
        };
    };
    union
    {
        ULONG RegionTypeEx;
        struct
        {
            ULONG Private : 1;
            ULONG MappedDataFile : 1;
            ULONG MappedImage : 1;
            ULONG MappedPageFile : 1;
            ULONG MappedPhysical : 1;
            ULONG DirectMapped : 1;
            ULONG SoftwareEnclave : 1; // REDSTONE3
            ULONG PageSize64K : 1;
            ULONG PlaceholderReservation : 1; // REDSTONE4
            ULONG MappedAwe : 1; // 21H1
            ULONG MappedWriteWatch : 1;
            ULONG PageSizeLarge : 1;
            ULONG PageSizeHuge : 1;
            ULONG Reserved : 19; // Sync with MemoryRegionInformationEx (dmex)
        };
    };

    WCHAR BaseAddressString[PH_PTR_STR_LEN_1];

    struct _PH_MEMORY_ITEM *AllocationBaseItem;

    SIZE_T CommittedSize;
    SIZE_T PrivateSize;

    SIZE_T TotalWorkingSetPages;
    SIZE_T PrivateWorkingSetPages;
    SIZE_T SharedWorkingSetPages;
    SIZE_T ShareableWorkingSetPages;
    SIZE_T LockedWorkingSetPages;

    SIZE_T SharedOriginalPages;
    SIZE_T Priority;

    PH_MEMORY_REGION_TYPE RegionType;

    union
    {
        struct
        {
            PPH_STRING Text;
            BOOLEAN PropertyOfAllocationBase;
        } Custom;
        struct
        {
            PPH_STRING FileName;
            BOOLEAN SigningLevelValid;
            SE_SIGNING_LEVEL SigningLevel;
        } MappedFile;
        struct
        {
            HANDLE ThreadId;
        } Teb;
        struct
        {
            HANDLE ThreadId;
        } Stack;
        struct
        {
            ULONG Index;
            BOOLEAN ClassValid;
            ULONG Class;
        } Heap;
        struct
        {
            struct _PH_MEMORY_ITEM *HeapItem;
        } HeapSegment;
    } u;
} PH_MEMORY_ITEM, *PPH_MEMORY_ITEM;

typedef struct _PH_MEMORY_ITEM_LIST
{
    HANDLE ProcessId;
    PH_AVL_TREE Set;
    LIST_ENTRY ListHead;
} PH_MEMORY_ITEM_LIST, *PPH_MEMORY_ITEM_LIST;

PHAPPAPI
VOID
NTAPI
PhDeleteMemoryItemList(
    _In_ PPH_MEMORY_ITEM_LIST List
    );

PHAPPAPI
PPH_MEMORY_ITEM
NTAPI
PhLookupMemoryItemList(
    _In_ PPH_MEMORY_ITEM_LIST List,
    _In_ PVOID Address
    );

#define PH_QUERY_MEMORY_IGNORE_FREE        0x1
#define PH_QUERY_MEMORY_REGION_TYPE        0x2
#define PH_QUERY_MEMORY_WS_COUNTERS        0x4
#define PH_QUERY_MEMORY_ZERO_PAD_ADDRESSES 0x8

PHAPPAPI
NTSTATUS
NTAPI
PhQueryMemoryItemList(
    _In_ HANDLE ProcessId,
    _In_ ULONG Flags,
    _Out_ PPH_MEMORY_ITEM_LIST List
    );

//
// devprv
//

extern PPH_OBJECT_TYPE PhDeviceTreeType;
extern PPH_OBJECT_TYPE PhDeviceItemType;
extern PPH_OBJECT_TYPE PhDeviceNotifyType;

typedef enum _PH_DEVICE_PROPERTY_CLASS
{
    PhDevicePropertyName,
    PhDevicePropertyManufacturer,
    PhDevicePropertyService,
    PhDevicePropertyClass,
    PhDevicePropertyEnumeratorName,
    PhDevicePropertyInstallDate,

    PhDevicePropertyFirstInstallDate,
    PhDevicePropertyLastArrivalDate,
    PhDevicePropertyLastRemovalDate,
    PhDevicePropertyDeviceDesc,
    PhDevicePropertyFriendlyName,
    PhDevicePropertyInstanceId,
    PhDevicePropertyParentInstanceId,
    PhDevicePropertyPDOName,
    PhDevicePropertyLocationInfo,
    PhDevicePropertyClassGuid,
    PhDevicePropertyDriver,
    PhDevicePropertyDriverVersion,
    PhDevicePropertyDriverDate,
    PhDevicePropertyFirmwareDate,
    PhDevicePropertyFirmwareVersion,
    PhDevicePropertyFirmwareRevision,
    PhDevicePropertyHasProblem,
    PhDevicePropertyProblemCode,
    PhDevicePropertyProblemStatus,
    PhDevicePropertyDevNodeStatus,
    PhDevicePropertyDevCapabilities,
    PhDevicePropertyUpperFilters,
    PhDevicePropertyLowerFilters,
    PhDevicePropertyHardwareIds,
    PhDevicePropertyCompatibleIds,
    PhDevicePropertyConfigFlags,
    PhDevicePropertyUINumber,
    PhDevicePropertyBusTypeGuid,
    PhDevicePropertyLegacyBusType,
    PhDevicePropertyBusNumber,
    PhDevicePropertySecurity,
    PhDevicePropertySecuritySDS,
    PhDevicePropertyDevType,
    PhDevicePropertyExclusive,
    PhDevicePropertyCharacteristics,
    PhDevicePropertyAddress,
    PhDevicePropertyPowerData,
    PhDevicePropertyRemovalPolicy,
    PhDevicePropertyRemovalPolicyDefault,
    PhDevicePropertyRemovalPolicyOverride,
    PhDevicePropertyInstallState,
    PhDevicePropertyLocationPaths,
    PhDevicePropertyBaseContainerId,
    PhDevicePropertyEjectionRelations,
    PhDevicePropertyRemovalRelations,
    PhDevicePropertyPowerRelations,
    PhDevicePropertyBusRelations,
    PhDevicePropertyChildren,
    PhDevicePropertySiblings,
    PhDevicePropertyTransportRelations,
    PhDevicePropertyReported,
    PhDevicePropertyLegacy,
    PhDevicePropertyContainerId,
    PhDevicePropertyInLocalMachineContainer,
    PhDevicePropertyModel,
    PhDevicePropertyModelId,
    PhDevicePropertyFriendlyNameAttributes,
    PhDevicePropertyManufacturerAttributes,
    PhDevicePropertyPresenceNotForDevice,
    PhDevicePropertySignalStrength,
    PhDevicePropertyIsAssociateableByUserAction,
    PhDevicePropertyShowInUninstallUI,
    PhDevicePropertyNumaProximityDomain,
    PhDevicePropertyDHPRebalancePolicy,
    PhDevicePropertyNumaNode,
    PhDevicePropertyBusReportedDeviceDesc,
    PhDevicePropertyIsPresent,
    PhDevicePropertyConfigurationId,
    PhDevicePropertyReportedDeviceIdsHash,
    PhDevicePropertyPhysicalDeviceLocation,
    PhDevicePropertyBiosDeviceName,
    PhDevicePropertyDriverProblemDesc,
    PhDevicePropertyDebuggerSafe,
    PhDevicePropertyPostInstallInProgress,
    PhDevicePropertyStack,
    PhDevicePropertyExtendedConfigurationIds,
    PhDevicePropertyIsRebootRequired,
    PhDevicePropertyDependencyProviders,
    PhDevicePropertyDependencyDependents,
    PhDevicePropertySoftRestartSupported,
    PhDevicePropertyExtendedAddress,
    PhDevicePropertyAssignedToGuest,
    PhDevicePropertyCreatorProcessId,
    PhDevicePropertyFirmwareVendor,
    PhDevicePropertySessionId,
    PhDevicePropertyDriverDesc,
    PhDevicePropertyDriverInfPath,
    PhDevicePropertyDriverInfSection,
    PhDevicePropertyDriverInfSectionExt,
    PhDevicePropertyMatchingDeviceId,
    PhDevicePropertyDriverProvider,
    PhDevicePropertyDriverPropPageProvider,
    PhDevicePropertyDriverCoInstallers,
    PhDevicePropertyResourcePickerTags,
    PhDevicePropertyResourcePickerExceptions,
    PhDevicePropertyDriverRank,
    PhDevicePropertyDriverLogoLevel,
    PhDevicePropertyNoConnectSound,
    PhDevicePropertyGenericDriverInstalled,
    PhDevicePropertyAdditionalSoftwareRequested,
    PhDevicePropertySafeRemovalRequired,
    PhDevicePropertySafeRemovalRequiredOverride,

    PhDevicePropertyPkgModel,
    PhDevicePropertyPkgVendorWebSite,
    PhDevicePropertyPkgDetailedDescription,
    PhDevicePropertyPkgDocumentationLink,
    PhDevicePropertyPkgIcon,
    PhDevicePropertyPkgBrandingIcon,

    PhDevicePropertyClassUpperFilters,
    PhDevicePropertyClassLowerFilters,
    PhDevicePropertyClassSecurity,
    PhDevicePropertyClassSecuritySDS,
    PhDevicePropertyClassDevType,
    PhDevicePropertyClassExclusive,
    PhDevicePropertyClassCharacteristics,
    PhDevicePropertyClassName,
    PhDevicePropertyClassClassName,
    PhDevicePropertyClassIcon,
    PhDevicePropertyClassClassInstaller,
    PhDevicePropertyClassPropPageProvider,
    PhDevicePropertyClassNoInstallClass,
    PhDevicePropertyClassNoDisplayClass,
    PhDevicePropertyClassSilentInstall,
    PhDevicePropertyClassNoUseClass,
    PhDevicePropertyClassDefaultService,
    PhDevicePropertyClassIconPath,
    PhDevicePropertyClassDHPRebalanceOptOut,
    PhDevicePropertyClassClassCoInstallers,

    PhDevicePropertyInterfaceFriendlyName,
    PhDevicePropertyInterfaceEnabled,
    PhDevicePropertyInterfaceClassGuid,
    PhDevicePropertyInterfaceReferenceString,
    PhDevicePropertyInterfaceRestricted,
    PhDevicePropertyInterfaceUnrestrictedAppCapabilities,
    PhDevicePropertyInterfaceSchematicName,

    PhDevicePropertyInterfaceClassDefaultInterface,
    PhDevicePropertyInterfaceClassName,

    PhDevicePropertyContainerAddress,
    PhDevicePropertyContainerDiscoveryMethod,
    PhDevicePropertyContainerIsEncrypted,
    PhDevicePropertyContainerIsAuthenticated,
    PhDevicePropertyContainerIsConnected,
    PhDevicePropertyContainerIsPaired,
    PhDevicePropertyContainerIcon,
    PhDevicePropertyContainerVersion,
    PhDevicePropertyContainerLastSeen,
    PhDevicePropertyContainerLastConnected,
    PhDevicePropertyContainerIsShowInDisconnectedState,
    PhDevicePropertyContainerIsLocalMachine,
    PhDevicePropertyContainerMetadataPath,
    PhDevicePropertyContainerIsMetadataSearchInProgress,
    PhDevicePropertyContainerIsMetadataChecksum,
    PhDevicePropertyContainerIsNotInterestingForDisplay,
    PhDevicePropertyContainerLaunchDeviceStageOnDeviceConnect,
    PhDevicePropertyContainerLaunchDeviceStageFromExplorer,
    PhDevicePropertyContainerBaselineExperienceId,
    PhDevicePropertyContainerIsDeviceUniquelyIdentifiable,
    PhDevicePropertyContainerAssociationArray,
    PhDevicePropertyContainerDeviceDescription1,
    PhDevicePropertyContainerDeviceDescription2,
    PhDevicePropertyContainerHasProblem,
    PhDevicePropertyContainerIsSharedDevice,
    PhDevicePropertyContainerIsNetworkDevice,
    PhDevicePropertyContainerIsDefaultDevice,
    PhDevicePropertyContainerMetadataCabinet,
    PhDevicePropertyContainerRequiresPairingElevation,
    PhDevicePropertyContainerExperienceId,
    PhDevicePropertyContainerCategory,
    PhDevicePropertyContainerCategoryDescSingular,
    PhDevicePropertyContainerCategoryDescPlural,
    PhDevicePropertyContainerCategoryIcon,
    PhDevicePropertyContainerCategoryGroupDesc,
    PhDevicePropertyContainerCategoryGroupIcon,
    PhDevicePropertyContainerPrimaryCategory,
    PhDevicePropertyContainerUnpairUninstall,
    PhDevicePropertyContainerRequiresUninstallElevation,
    PhDevicePropertyContainerDeviceFunctionSubRank,
    PhDevicePropertyContainerAlwaysShowDeviceAsConnected,
    PhDevicePropertyContainerConfigFlags,
    PhDevicePropertyContainerPrivilegedPackageFamilyNames,
    PhDevicePropertyContainerCustomPrivilegedPackageFamilyNames,
    PhDevicePropertyContainerIsRebootRequired,
    PhDevicePropertyContainerFriendlyName,
    PhDevicePropertyContainerManufacturer,
    PhDevicePropertyContainerModelName,
    PhDevicePropertyContainerModelNumber,
    PhDevicePropertyContainerInstallInProgress,

    PhDevicePropertyObjectType,

    PhDevicePropertyPciInterruptSupport,
    PhDevicePropertyPciExpressCapabilityControl,
    PhDevicePropertyPciNativeExpressControl,
    PhDevicePropertyPciSystemMsiSupport,

    PhDevicePropertyStoragePortable,
    PhDevicePropertyStorageRemovableMedia,
    PhDevicePropertyStorageSystemCritical,
    PhDevicePropertyStorageDiskNumber,
    PhDevicePropertyStoragePartitionNumber,

    PhMaxDeviceProperty
} PH_DEVICE_PROPERTY_CLASS, *PPH_DEVICE_PROPERTY_CLASS;

typedef enum _PH_DEVICE_PROPERTY_TYPE
{
    PhDevicePropertyTypeString,
    PhDevicePropertyTypeUInt64,
    PhDevicePropertyTypeUInt32,
    PhDevicePropertyTypeInt32,
    PhDevicePropertyTypeNTSTATUS,
    PhDevicePropertyTypeGUID,
    PhDevicePropertyTypeBoolean,
    PhDevicePropertyTypeTimeStamp,
    PhDevicePropertyTypeStringList,
    PhDevicePropertyTypeBinary,

    PhMaxDevicePropertyType
} PH_DEVICE_PROPERTY_TYPE, PPH_DEVICE_PROPERTY_TYPE;
C_ASSERT(PhMaxDevicePropertyType <= MAXSHORT);

typedef struct _PH_DEVICE_PROPERTY
{
    union
    {
        struct
        {
            ULONG Type : 16; // PH_DEVICE_PROPERTY_TYPE
            ULONG Spare : 14;
            ULONG Initialized : 1;
            ULONG Valid : 1;
        };
        ULONG State;
    };

    union
    {
        PPH_STRING String;
        ULONG64 UInt64;
        ULONG UInt32;
        LONG Int32;
        NTSTATUS Status;
        GUID Guid;
        BOOLEAN Boolean;
        LARGE_INTEGER TimeStamp;
        PPH_LIST StringList;
        struct
        {
            ULONG Size;
            PBYTE Buffer;
        } Binary;
    };

    PPH_STRING AsString;
} PH_DEVICE_PROPERTY, *PPH_DEVICE_PROPERTY;



typedef struct _PH_DEVICE_ITEM
{
    struct _PH_DEVICE_TREE* Tree;
    struct _PH_DEVICE_ITEM* Parent;
    struct _PH_DEVICE_ITEM* Sibling;
    struct _PH_DEVICE_ITEM* Child;

    GUID ClassGuid;
    ULONG InstanceIdHash;
    PPH_STRING InstanceId;
    PPH_STRING ParentInstanceId;
    ULONG ProblemCode;
    ULONG DevNodeStatus;
    ULONG Capabilities;
    ULONG ChildrenCount;
    ULONG InterfaceCount;

    union
    {
        struct
        {
            ULONG HasUpperFilters : 1;
            ULONG HasLowerFilters : 1;
            ULONG DeviceInterface : 1;
            ULONG Spare : 29;
        };
        ULONG Flags;
    };

    PH_DEVICE_PROPERTY Properties[PhMaxDeviceProperty];

} PH_DEVICE_ITEM, *PPH_DEVICE_ITEM;

typedef struct _PH_DEVICE_TREE
{
    PPH_DEVICE_ITEM Root;
    PPH_LIST DeviceList;
    PPH_LIST DeviceInterfaceList;
} PH_DEVICE_TREE, *PPH_DEVICE_TREE;

PHAPPAPI
PPH_DEVICE_PROPERTY
NTAPI
PhGetDeviceProperty(
    _In_ PPH_DEVICE_ITEM Item,
    _In_ PH_DEVICE_PROPERTY_CLASS Class
    );

PHAPPAPI
BOOLEAN
NTAPI
PhLookupDevicePropertyClass(
    _In_ const DEVPROPKEY* Key,
    _Out_ PPH_DEVICE_PROPERTY_CLASS Class
    );

PHAPPAPI
HICON
NTAPI
PhGetDeviceIcon(
    _In_ PPH_DEVICE_ITEM Item,
    _In_ PPH_INTEGER_PAIR IconSize
    );

PHAPPAPI
PPH_DEVICE_TREE
NTAPI
PhReferenceDeviceTree(
    VOID
    );

PHAPPAPI
PPH_DEVICE_TREE
NTAPI
PhReferenceDeviceTreeEx(
    _In_ BOOLEAN ForceRefresh
    );

PHAPPAPI
_Success_(return != NULL)
_Must_inspect_result_
PPH_DEVICE_ITEM
NTAPI
PhLookupDeviceItemByHash(
    _In_ PPH_DEVICE_TREE Tree,
    _In_ ULONG InstanceIdHash
    );

PHAPPAPI
_Success_(return != NULL)
_Must_inspect_result_
PPH_DEVICE_ITEM
NTAPI
PhLookupDeviceItem(
    _In_ PPH_DEVICE_TREE Tree,
    _In_ PPH_STRINGREF InstanceId
    );

PHAPPAPI
_Success_(return != NULL)
_Must_inspect_result_
PPH_DEVICE_ITEM
NTAPI
PhReferenceDeviceItemByHash(
    _In_ PPH_DEVICE_TREE Tree,
    _In_ ULONG InstanceIdHash
    );

PHAPPAPI
_Success_(return != NULL)
_Must_inspect_result_
PPH_DEVICE_ITEM
NTAPI
PhReferenceDeviceItem(
    _In_ PPH_DEVICE_TREE Tree,
    _In_ PPH_STRINGREF InstanceId
    );

PHAPPAPI
_Success_(return != NULL)
_Must_inspect_result_
PPH_DEVICE_ITEM
NTAPI
PhReferenceDeviceItem2(
    _In_ PPH_STRINGREF InstanceId
    );

typedef enum _PH_DEVICE_NOTIFY_ACTION
{
    PhDeviceNotifyInterfaceArrival,
    PhDeviceNotifyInterfaceRemoval,
    PhDeviceNotifyInstanceEnumerated,
    PhDeviceNotifyInstanceStarted,
    PhDeviceNotifyInstanceRemoved,
} PH_DEVICE_NOTIFY_ACTION, *PPH_DEVICE_NOTIFY_ACTION;

typedef struct _PH_DEVICE_NOTIFY
{
    PH_DEVICE_NOTIFY_ACTION Action;

    union
    {
        struct
        {
            GUID ClassGuid;
        } DeviceInterface; // PhDeviceNotifyInterface...

        struct
        {
            PPH_STRING InstanceId;
        } DeviceInstance; // PhDeviceNotifyInstance...
    };

} PH_DEVICE_NOTIFY, *PPH_DEVICE_NOTIFY;

PHAPPAPI
BOOLEAN
NTAPI
PhDeviceProviderInitialization(
    VOID
    );


//
// phuisup
//

// Common state highlighting support

typedef struct _PH_SH_STATE
{
    PH_ITEM_STATE State;
    HANDLE StateListHandle;
    ULONG64 TickCount;
} PH_SH_STATE, *PPH_SH_STATE;

FORCEINLINE VOID PhChangeShStateTn(
    _Inout_ PPH_TREENEW_NODE Node,
    _Inout_ PPH_SH_STATE ShState,
    _Inout_ PPH_POINTER_LIST *StateList,
    _In_ PH_ITEM_STATE NewState,
    _In_ COLORREF NewTempBackColor,
    _In_opt_ HWND TreeNewHandleForUpdate
    )
{
    if (!*StateList)
        *StateList = PhCreatePointerList(4);

    if (ShState->State == NormalItemState)
        ShState->StateListHandle = PhAddItemPointerList(*StateList, Node);

    ShState->TickCount = NtGetTickCount64();
    ShState->State = NewState;

    Node->UseTempBackColor = TRUE;
    Node->TempBackColor = NewTempBackColor;

    if (TreeNewHandleForUpdate)
        TreeNew_InvalidateNode(TreeNewHandleForUpdate, Node);
}

#define PH_TICK_SH_STATE_TN(NodeType, ShStateFieldName, StateList, RemoveFunction, HighlightingDuration, TreeNewHandleForUpdate, Invalidate, FullyInvalidated, Context) \
    do { \
        NodeType *node; \
        ULONG enumerationKey = 0; \
        ULONG64 tickCount; \
        BOOLEAN preferFullInvalidate; \
        HANDLE stateListHandle; \
        BOOLEAN needsFullInvalidate = FALSE; \
\
        if (!StateList || StateList->Count == 0) \
            break; \
\
        tickCount = NtGetTickCount64(); \
        preferFullInvalidate = StateList->Count > 8; \
\
        while (PhEnumPointerList(StateList, &enumerationKey, &node)) \
        { \
            if (PhRoundNumber(tickCount - node->ShStateFieldName.TickCount, 100) < (HighlightingDuration)) \
                continue; \
\
            stateListHandle = node->ShStateFieldName.StateListHandle; \
\
            if (node->ShStateFieldName.State == NewItemState) \
            { \
                node->ShStateFieldName.State = NormalItemState; \
                ((PPH_TREENEW_NODE)node)->UseTempBackColor = FALSE; \
                if (Invalidate) \
                { \
                    if (preferFullInvalidate) \
                    { \
                        needsFullInvalidate = TRUE; \
                    } \
                    else \
                    { \
                        if (TreeNewHandleForUpdate) \
                            TreeNew_InvalidateNode((TreeNewHandleForUpdate), node); \
                    } \
                } \
            } \
            else if (node->ShStateFieldName.State == RemovingItemState) \
            { \
                RemoveFunction(node, Context); \
                needsFullInvalidate = TRUE; \
            } \
\
            PhRemoveItemPointerList(StateList, stateListHandle); \
        } \
\
        if (TreeNewHandleForUpdate) \
        { \
            if (needsFullInvalidate) \
            { \
                InvalidateRect((TreeNewHandleForUpdate), NULL, FALSE); \
                if (FullyInvalidated) \
                    *((PBOOLEAN)FullyInvalidated) = TRUE; \
            } \
        } \
    } while (0)

// Provider event queues

typedef enum _PH_PROVIDER_EVENT_TYPE
{
    ProviderAddedEvent = 1,
    ProviderModifiedEvent = 2,
    ProviderRemovedEvent = 3
} PH_PROVIDER_EVENT_TYPE;

typedef struct _PH_PROVIDER_EVENT
{
    ULONG_PTR TypeAndObject;
    ULONG RunId;
} PH_PROVIDER_EVENT, *PPH_PROVIDER_EVENT;

#define PH_PROVIDER_EVENT_TYPE_MASK 0x3
#define PH_PROVIDER_EVENT_OBJECT_MASK (~(ULONG_PTR)0x3)
#define PH_PROVIDER_EVENT_TYPE(Event) ((ULONG)(Event).TypeAndObject & PH_PROVIDER_EVENT_TYPE_MASK)
#define PH_PROVIDER_EVENT_OBJECT(Event) ((PVOID)((Event).TypeAndObject & PH_PROVIDER_EVENT_OBJECT_MASK))

typedef struct _PH_PROVIDER_EVENT_QUEUE
{
    PH_ARRAY Array;
    PH_QUEUED_LOCK Lock;
} PH_PROVIDER_EVENT_QUEUE, *PPH_PROVIDER_EVENT_QUEUE;

FORCEINLINE VOID PhInitializeProviderEventQueue(
    _Out_ PPH_PROVIDER_EVENT_QUEUE EventQueue,
    _In_ SIZE_T InitialCapacity
    )
{
    PhInitializeArray(&EventQueue->Array, sizeof(PH_PROVIDER_EVENT), InitialCapacity);
    PhInitializeQueuedLock(&EventQueue->Lock);
}

FORCEINLINE VOID PhDeleteProviderEventQueue(
    _Inout_ PPH_PROVIDER_EVENT_QUEUE EventQueue
    )
{
    PPH_PROVIDER_EVENT events;
    SIZE_T i;

    events = (PPH_PROVIDER_EVENT)EventQueue->Array.Items;

    for (i = 0; i < EventQueue->Array.Count; i++)
    {
        if (PH_PROVIDER_EVENT_TYPE(events[i]) == ProviderAddedEvent)
            PhDereferenceObject(PH_PROVIDER_EVENT_OBJECT(events[i]));
    }

    PhDeleteArray(&EventQueue->Array);
}

FORCEINLINE VOID PhPushProviderEventQueue(
    _Inout_ PPH_PROVIDER_EVENT_QUEUE EventQueue,
    _In_ PH_PROVIDER_EVENT_TYPE Type,
    _In_opt_ PVOID Object,
    _In_ ULONG RunId
    )
{
    PH_PROVIDER_EVENT event;

    assert(!(PtrToUlong(Object) & PH_PROVIDER_EVENT_TYPE_MASK));
    event.TypeAndObject = (ULONG_PTR)Object | Type;
    event.RunId = RunId;

    PhAcquireQueuedLockExclusive(&EventQueue->Lock);
    PhAddItemArray(&EventQueue->Array, &event);
    PhReleaseQueuedLockExclusive(&EventQueue->Lock);
}

FORCEINLINE PPH_PROVIDER_EVENT PhFlushProviderEventQueue(
    _Inout_ PPH_PROVIDER_EVENT_QUEUE EventQueue,
    _In_ ULONG UpToRunId,
    _Out_ PULONG Count
    )
{
    PPH_PROVIDER_EVENT availableEvents;
    PPH_PROVIDER_EVENT events = NULL;
    SIZE_T count;

    PhAcquireQueuedLockExclusive(&EventQueue->Lock);
    availableEvents = (PPH_PROVIDER_EVENT)EventQueue->Array.Items;

    for (count = 0; count < EventQueue->Array.Count; count++)
    {
        if ((LONG)(UpToRunId - availableEvents[count].RunId) < 0)
            break;
    }

    if (count != 0)
    {
        events = (PPH_PROVIDER_EVENT)PhAllocateCopy(availableEvents, count * sizeof(PH_PROVIDER_EVENT));
        PhRemoveItemsArray(&EventQueue->Array, 0, count);
    }

    PhReleaseQueuedLockExclusive(&EventQueue->Lock);

    *Count = (ULONG)count;

    return events;
}

//
// colmgr
//

typedef LONG (NTAPI *PPH_CM_POST_SORT_FUNCTION)(
    _In_ LONG Result,
    _In_ PVOID Node1,
    _In_ PVOID Node2,
    _In_ PH_SORT_ORDER SortOrder
    );

PHAPPAPI
BOOLEAN
NTAPI
PhCmLoadSettings(
    _In_ HWND TreeNewHandle,
    _In_ PPH_STRINGREF Settings
    );

PHAPPAPI
PPH_STRING
NTAPI
PhCmSaveSettings(
    _In_ HWND TreeNewHandle
    );

//
// proctree
//

typedef struct _PH_PROCESS_NODE
{
    PH_TREENEW_NODE Node;

    PH_HASH_ENTRY HashEntry;

    PH_SH_STATE ShState;

    HANDLE ProcessId;
    PPH_PROCESS_ITEM ProcessItem;

    struct _PH_PROCESS_NODE *Parent;
    PPH_LIST Children;

} PH_PROCESS_NODE, *PPH_PROCESS_NODE;

PHAPPAPI
struct _PH_TN_FILTER_SUPPORT *
NTAPI
PhGetFilterSupportProcessTreeList(
    VOID
    );

PHAPPAPI
PPH_PROCESS_NODE
NTAPI
PhFindProcessNode(
    _In_ HANDLE ProcessId
    );

PHAPPAPI
VOID
NTAPI
PhUpdateProcessNode(
    _In_ PPH_PROCESS_NODE ProcessNode
    );

PHAPPAPI
PPH_PROCESS_ITEM
NTAPI
PhGetSelectedProcessItem(
    VOID
    );

PHAPPAPI
VOID
NTAPI
PhGetSelectedProcessItems(
    _Out_ PPH_PROCESS_ITEM **Processes,
    _Out_ PULONG NumberOfProcesses
    );

PHAPPAPI
VOID
NTAPI
PhGetSelectedProcessNodes(
    _Out_ PPH_PROCESS_NODE** Nodes,
    _Out_ PULONG NumberOfNodes
    );

PHAPPAPI
VOID
NTAPI
PhGetSelectedAndPropagateProcessItems(
    _Out_ PPH_PROCESS_ITEM** Processes,
    _Out_ PULONG NumberOfProcesses
    );

PHAPPAPI
VOID
NTAPI
PhDeselectAllProcessNodes(
    VOID
    );

PHAPPAPI
VOID
NTAPI
PhExpandAllProcessNodes(
    _In_ BOOLEAN Expand
    );

PHAPPAPI
VOID
NTAPI
PhInvalidateAllProcessNodes(
    VOID
    );

PHAPPAPI
VOID
NTAPI
PhSelectAndEnsureVisibleProcessNode(
    _In_ PPH_PROCESS_NODE ProcessNode
    );

PHAPPAPI
PPH_LIST
NTAPI
PhDuplicateProcessNodeList(
    VOID
    );

//
// srvlist
//

typedef struct _PH_SERVICE_NODE
{
    PH_TREENEW_NODE Node;

    PH_SH_STATE ShState;

    PPH_SERVICE_ITEM ServiceItem;

    WCHAR StartTypeText[12 + 24 + 1];
    // Config
    PPH_STRING BinaryPath;
    PPH_STRING LoadOrderGroup;
    // Description
    PPH_STRING Description;
    // Key
    LARGE_INTEGER KeyLastWriteTime;
    PPH_STRING KeyModifiedTimeText;
} PH_SERVICE_NODE, *PPH_SERVICE_NODE;

PHAPPAPI
struct _PH_TN_FILTER_SUPPORT *
NTAPI
PhGetFilterSupportServiceTreeList(
    VOID
    );

PHAPPAPI
PPH_SERVICE_NODE
NTAPI
PhFindServiceNode(
    _In_ PPH_SERVICE_ITEM ServiceItem
    );

PHAPPAPI
VOID
NTAPI
PhUpdateServiceNode(
    _In_ PPH_SERVICE_NODE ServiceNode
    );

PHAPPAPI
PPH_SERVICE_ITEM
NTAPI
PhGetSelectedServiceItem(
    VOID
    );

PHAPPAPI
VOID
NTAPI
PhGetSelectedServiceItems(
    _Out_ PPH_SERVICE_ITEM **Services,
    _Out_ PULONG NumberOfServices
    );

PHAPPAPI
VOID
NTAPI
PhDeselectAllServiceNodes(
    VOID
    );

PHAPPAPI
VOID
NTAPI
PhSelectAndEnsureVisibleServiceNode(
    _In_ PPH_SERVICE_NODE ServiceNode
    );

//
// netlist
//

typedef struct _PH_NETWORK_NODE
{
    PH_TREENEW_NODE Node;

    PH_SH_STATE ShState;

    PPH_NETWORK_ITEM NetworkItem;

    PPH_STRING ProcessNameText;
    PPH_STRING TimeStampText;
    WCHAR ProcessIdString[PH_INT32_STR_LEN_1];

} PH_NETWORK_NODE, *PPH_NETWORK_NODE;

PHAPPAPI
PPH_TN_FILTER_SUPPORT
NTAPI
PhGetFilterSupportNetworkTreeList(
    VOID
    );

PHAPPAPI
PPH_NETWORK_NODE
NTAPI
PhFindNetworkNode(
    _In_ PPH_NETWORK_ITEM NetworkItem
    );

//
// thrdlist
//

typedef struct _PH_THREAD_NODE
{
    PH_TREENEW_NODE Node;

    PH_SH_STATE ShState;

    HANDLE ThreadId;
    PPH_THREAD_ITEM ThreadItem;

} PH_THREAD_NODE, *PPH_THREAD_NODE;

//
// modlist
//

typedef struct _PH_MODULE_NODE
{
    PH_TREENEW_NODE Node;

    PH_SH_STATE ShState;

    PPH_MODULE_ITEM ModuleItem;

} PH_MODULE_NODE, *PPH_MODULE_NODE;

//
// hndllist
//

typedef enum _PH_HANDLE_TREE_MENUITEM
{
    PH_HANDLE_TREE_MENUITEM_NONE,

    PH_HANDLE_TREE_MENUITEM_HIDE_PROTECTED_HANDLES,
    PH_HANDLE_TREE_MENUITEM_HIDE_INHERIT_HANDLES,
    PH_HANDLE_TREE_MENUITEM_HIDE_UNNAMED_HANDLES,
    PH_HANDLE_TREE_MENUITEM_HIDE_ETW_HANDLES,

    PH_HANDLE_TREE_MENUITEM_HIGHLIGHT_PROTECTED_HANDLES,
    PH_HANDLE_TREE_MENUITEM_HIGHLIGHT_INHERIT_HANDLES,

    PH_HANDLE_TREE_MENUITEM_HANDLESTATS,
    PH_HANDLE_TREE_MENUITEM_MAXIMUM
} PH_HANDLE_TREE_MENUITEM;

typedef struct _PH_HANDLE_NODE
{
    PH_TREENEW_NODE Node;

    PH_SH_STATE ShState;

    HANDLE Handle;
    PPH_HANDLE_ITEM HandleItem;

} PH_HANDLE_NODE, *PPH_HANDLE_NODE;

//
// memlist
//

typedef struct _PH_MEMORY_NODE
{
    PH_TREENEW_NODE Node;

    BOOLEAN IsAllocationBase;
    BOOLEAN Reserved1;
    USHORT Reserved2;
    PPH_MEMORY_ITEM MemoryItem;

    struct _PH_MEMORY_NODE *Parent;
    PPH_LIST Children;

} PH_MEMORY_NODE, *PPH_MEMORY_NODE;

//
// extmgr
//

typedef enum _PH_EM_OBJECT_TYPE
{
    EmProcessItemType,
    EmProcessNodeType,
    EmServiceItemType,
    EmServiceNodeType,
    EmNetworkItemType,
    EmNetworkNodeType,
    EmThreadItemType,
    EmThreadNodeType,
    EmModuleItemType,
    EmModuleNodeType,
    EmHandleItemType,
    EmHandleNodeType,
    EmThreadsContextType,
    EmModulesContextType,
    EmHandlesContextType,
    EmThreadProviderType,
    EmModuleProviderType,
    EmHandleProviderType,
    EmMemoryNodeType,
    EmMemoryContextType,
    EmMaximumObjectType
} PH_EM_OBJECT_TYPE;

typedef enum _PH_EM_OBJECT_OPERATION
{
    EmObjectCreate,
    EmObjectDelete,
    EmMaximumObjectOperation
} PH_EM_OBJECT_OPERATION;

typedef VOID (NTAPI *PPH_EM_OBJECT_CALLBACK)(
    _In_ PVOID Object,
    _In_ PH_EM_OBJECT_TYPE ObjectType,
    _In_ PVOID Extension
    );

//
// mainwnd
//

PHAPPAPI extern HWND PhMainWndHandle; // phapppub

#define WM_PH_FIRST (WM_APP + 99)
#define WM_PH_ACTIVATE (WM_APP + 99)
#define WM_PH_SHOW_DIALOG (WM_APP + 100) // unused (plugins only)
#define WM_PH_UPDATE_DIALOG (WM_APP + 101) // unused (plugins only)
#define PH_ACTIVATE_REPLY 0x1119
#define WM_PH_NOTIFY_ICON_MESSAGE (WM_APP + 126)
#define WM_PH_UPDATE_FONT (WM_APP + 136)

typedef enum _PH_MAINWINDOW_CALLBACK_TYPE
{
    PH_MAINWINDOW_CALLBACK_TYPE_DESTROY,
    PH_MAINWINDOW_CALLBACK_TYPE_SHOW_PROPERTIES,
    PH_MAINWINDOW_CALLBACK_TYPE_SAVE_ALL_SETTINGS,
    PH_MAINWINDOW_CALLBACK_TYPE_PREPARE_FOR_EARLY_SHUTDOWN,
    PH_MAINWINDOW_CALLBACK_TYPE_CANCEL_EARLY_SHUTDOWN,
    PH_MAINWINDOW_CALLBACK_TYPE_TOGGLE_VISIBLE,
    PH_MAINWINDOW_CALLBACK_TYPE_SHOW_MEMORY_EDITOR,
    PH_MAINWINDOW_CALLBACK_TYPE_SHOW_MEMORY_RESULTS,
    PH_MAINWINDOW_CALLBACK_TYPE_SELECT_TAB_PAGE,
    PH_MAINWINDOW_CALLBACK_TYPE_GET_CALLBACK_LAYOUT_PADDING,
    PH_MAINWINDOW_CALLBACK_TYPE_INVALIDATE_LAYOUT_PADDING,
    PH_MAINWINDOW_CALLBACK_TYPE_SELECT_PROCESS_NODE,
    PH_MAINWINDOW_CALLBACK_TYPE_SELECT_SERVICE_ITEM,
    PH_MAINWINDOW_CALLBACK_TYPE_SELECT_NETWORK_ITEM,
    PH_MAINWINDOW_CALLBACK_TYPE_UPDATE_FONT,
    PH_MAINWINDOW_CALLBACK_TYPE_GET_FONT,
    PH_MAINWINDOW_CALLBACK_TYPE_INVOKE,
    PH_MAINWINDOW_CALLBACK_TYPE_REFRESH,
    PH_MAINWINDOW_CALLBACK_TYPE_CREATE_TAB_PAGE,
    PH_MAINWINDOW_CALLBACK_TYPE_GET_UPDATE_AUTOMATICALLY,
    PH_MAINWINDOW_CALLBACK_TYPE_SET_UPDATE_AUTOMATICALLY,
    PH_MAINWINDOW_CALLBACK_TYPE_ICON_CLICK,
    PH_MAINWINDOW_CALLBACK_TYPE_WINDOW_BASE,
    PH_MAINWINDOW_CALLBACK_TYPE_WINDOW_PROCEDURE,
    PH_MAINWINDOW_CALLBACK_TYPE_WINDOW_HANDLE,
    PH_MAINWINDOW_CALLBACK_TYPE_VERSION,
    PH_MAINWINDOW_CALLBACK_TYPE_PORTABLE,
    PH_MAINWINDOW_CALLBACK_TYPE_MAXIMUM
} PH_MAINWINDOW_CALLBACK_TYPE;

PHAPPAPI
PVOID
NTAPI
PhPluginInvokeWindowCallback(
    _In_ PH_MAINWINDOW_CALLBACK_TYPE Event,
    _In_opt_ PVOID wparam,
    _In_opt_ PVOID lparam
    );

#define ProcessHacker_Destroy() \
    PhPluginInvokeWindowCallback(PH_MAINWINDOW_CALLBACK_TYPE_DESTROY, 0, 0)
#define ProcessHacker_ShowProcessProperties(ProcessItem) \
    PhPluginInvokeWindowCallback(PH_MAINWINDOW_CALLBACK_TYPE_SHOW_PROPERTIES, 0, (PVOID)(ULONG_PTR)(ProcessItem))
#define ProcessHacker_SaveAllSettings() \
    PhPluginInvokeWindowCallback(PH_MAINWINDOW_CALLBACK_TYPE_SAVE_ALL_SETTINGS, 0, 0)
#define ProcessHacker_PrepareForEarlyShutdown() \
    PhPluginInvokeWindowCallback(PH_MAINWINDOW_CALLBACK_TYPE_PREPARE_FOR_EARLY_SHUTDOWN, 0, 0)
#define ProcessHacker_CancelEarlyShutdown() \
    PhPluginInvokeWindowCallback(PH_MAINWINDOW_CALLBACK_TYPE_CANCEL_EARLY_SHUTDOWN, 0, 0)
#define ProcessHacker_ToggleVisible(AlwaysShow) \
    PhPluginInvokeWindowCallback(PH_MAINWINDOW_CALLBACK_TYPE_TOGGLE_VISIBLE, (PVOID)(ULONG_PTR)(AlwaysShow), 0)
#define ProcessHacker_ShowMemoryEditor(ShowMemoryEditor) \
    PhPluginInvokeWindowCallback(PH_MAINWINDOW_CALLBACK_TYPE_SHOW_MEMORY_EDITOR, 0, (PVOID)(ULONG_PTR)(ShowMemoryEditor))
#define ProcessHacker_ShowMemoryResults(ShowMemoryResults) \
    PhPluginInvokeWindowCallback(PH_MAINWINDOW_CALLBACK_TYPE_SHOW_MEMORY_RESULTS, 0, (PVOID)(ULONG_PTR)(ShowMemoryResults))
#define ProcessHacker_SelectTabPage(Index) \
    PhPluginInvokeWindowCallback(PH_MAINWINDOW_CALLBACK_TYPE_SELECT_TAB_PAGE, (PVOID)(ULONG_PTR)(Index), 0)
#define ProcessHacker_GetCallbackLayoutPadding() \
    ((PPH_CALLBACK)PhPluginInvokeWindowCallback(PH_MAINWINDOW_CALLBACK_TYPE_GET_CALLBACK_LAYOUT_PADDING, 0, 0))
#define ProcessHacker_InvalidateLayoutPadding() \
    PhPluginInvokeWindowCallback(PH_MAINWINDOW_CALLBACK_TYPE_INVALIDATE_LAYOUT_PADDING, 0, 0)
#define ProcessHacker_SelectProcessNode(ProcessNode) \
    PhPluginInvokeWindowCallback(PH_MAINWINDOW_CALLBACK_TYPE_SELECT_PROCESS_NODE, 0, (PVOID)(ULONG_PTR)(ProcessNode))
#define ProcessHacker_SelectServiceItem(ServiceItem) \
    PhPluginInvokeWindowCallback(PH_MAINWINDOW_CALLBACK_TYPE_SELECT_SERVICE_ITEM, 0, (PVOID)(ULONG_PTR)(ServiceItem))
#define ProcessHacker_SelectNetworkItem(NetworkItem) \
    PhPluginInvokeWindowCallback(PH_MAINWINDOW_CALLBACK_TYPE_SELECT_NETWORK_ITEM, 0, (PVOID)(ULONG_PTR)(NetworkItem))
#define ProcessHacker_UpdateFont() \
    PhPluginInvokeWindowCallback(PH_MAINWINDOW_CALLBACK_TYPE_UPDATE_FONT, 0, 0)
#define ProcessHacker_GetFont() \
    ((HFONT)PhPluginInvokeWindowCallback(PH_MAINWINDOW_CALLBACK_TYPE_GET_FONT, 0, 0))
#define ProcessHacker_Invoke(Function, Parameter) \
    PhPluginInvokeWindowCallback(PH_MAINWINDOW_CALLBACK_TYPE_INVOKE, (PVOID)(ULONG_PTR)(Parameter), (PVOID)(ULONG_PTR)(Function))
//#define ProcessHacker_CreateTabPage(Template) \
//    PhPluginInvokeWindowCallback(PH_MAINWINDOW_CALLBACK_TYPE_CREATE_TAB_PAGE, 0, (PVOID)(ULONG_PTR)(Template))
#define ProcessHacker_Refresh() \
    PhPluginInvokeWindowCallback(PH_MAINWINDOW_CALLBACK_TYPE_REFRESH, 0, 0)
#define ProcessHacker_GetUpdateAutomatically() \
    ((BOOLEAN)PtrToUlong(PhPluginInvokeWindowCallback(PH_MAINWINDOW_CALLBACK_TYPE_GET_UPDATE_AUTOMATICALLY, 0, 0)))
#define ProcessHacker_SetUpdateAutomatically(Value) \
    PhPluginInvokeWindowCallback(PH_MAINWINDOW_CALLBACK_TYPE_SET_UPDATE_AUTOMATICALLY, (PVOID)(ULONG_PTR)(Value), 0)
#define ProcessHacker_IconClick() \
    PhPluginInvokeWindowCallback(PH_MAINWINDOW_CALLBACK_TYPE_ICON_CLICK, 0, 0)
#define ProcessHacker_GetInstanceHandle() \
    ((PVOID)PhPluginInvokeWindowCallback(PH_MAINWINDOW_CALLBACK_TYPE_WINDOW_BASE, 0, 0))
#define ProcessHacker_GetWindowProcedure() \
    ((WNDPROC)PhPluginInvokeWindowCallback(PH_MAINWINDOW_CALLBACK_TYPE_WINDOW_PROCEDURE, 0, 0))
#define ProcessHacker_GetWindowHandle() \
    ((HWND)PhPluginInvokeWindowCallback(PH_MAINWINDOW_CALLBACK_TYPE_WINDOW_HANDLE, 0, 0))
#define ProcessHacker_GetWindowsVersion() \
    (PtrToUlong(PhPluginInvokeWindowCallback(PH_MAINWINDOW_CALLBACK_TYPE_VERSION, 0, 0)))
#define ProcessHacker_IsPortableMode() \
    ((BOOLEAN)PtrToUlong(PhPluginInvokeWindowCallback(PH_MAINWINDOW_CALLBACK_TYPE_PORTABLE, 0, 0)))

#define PhWindowsVersion ProcessHacker_GetWindowsVersion() // Temporary backwards compat (dmex)
#define PhMainWindowHandle ProcessHacker_GetWindowHandle() // Temporary backwards compat (dmex)

PHAPPAPI
PVOID
NTAPI
PhPluginCreateTabPage(
    _In_ PVOID Page
    );

typedef struct _PH_LAYOUT_PADDING_DATA
{
    RECT Padding;
} PH_LAYOUT_PADDING_DATA, *PPH_LAYOUT_PADDING_DATA;

typedef enum _PH_MAIN_TAB_PAGE_MESSAGE
{
    MainTabPageCreate,
    MainTabPageDestroy,
    MainTabPageCreateWindow, // HWND *Parameter1 (WindowHandle), HWND Parameter2 (ParentWindow)
    MainTabPageSelected, // BOOLEAN Parameter1 (Selected)
    MainTabPageInitializeSectionMenuItems, // PPH_MAIN_TAB_PAGE_MENU_INFORMATION Parameter1

    MainTabPageLoadSettings,
    MainTabPageSaveSettings,
    MainTabPageExportContent, // PPH_MAIN_TAB_PAGE_EXPORT_CONTENT Parameter1
    MainTabPageFontChanged, // HFONT Parameter1 (Font)
    MainTabPageUpdateAutomaticallyChanged, // BOOLEAN Parameter1 (UpdateAutomatically)
    MainTabPageDpiChanged,

    MaxMainTabPageMessage
} PH_MAIN_TAB_PAGE_MESSAGE;

typedef struct _PH_MAIN_TAB_PAGE *PPH_MAIN_TAB_PAGE;

typedef BOOLEAN (NTAPI *PPH_MAIN_TAB_PAGE_CALLBACK)(
    _In_ PPH_MAIN_TAB_PAGE Page,
    _In_ PH_MAIN_TAB_PAGE_MESSAGE Message,
    _In_opt_ PVOID Parameter1,
    _In_opt_ PVOID Parameter2
    );

typedef struct _PH_MAIN_TAB_PAGE_EXPORT_CONTENT
{
    PPH_FILE_STREAM FileStream;
    ULONG Mode;
} PH_MAIN_TAB_PAGE_EXPORT_CONTENT, *PPH_MAIN_TAB_PAGE_EXPORT_CONTENT;

typedef struct _PH_MAIN_TAB_PAGE_MENU_INFORMATION
{
    PPH_EMENU_ITEM Menu;
    ULONG StartIndex;
} PH_MAIN_TAB_PAGE_MENU_INFORMATION, *PPH_MAIN_TAB_PAGE_MENU_INFORMATION;

typedef struct _PH_MAIN_TAB_PAGE
{
    // Public

    PH_STRINGREF Name;
    ULONG Flags;
    PPH_MAIN_TAB_PAGE_CALLBACK Callback;
    PVOID Context;

    INT Index;
    union
    {
        ULONG StateFlags;
        struct
        {
            ULONG Selected : 1;
            ULONG CreateWindowCalled : 1;
            ULONG SpareStateFlags : 30;
        };
    };
    PVOID Reserved[2];

} PH_MAIN_TAB_PAGE, *PPH_MAIN_TAB_PAGE;

#define PH_NOTIFY_MINIMUM 0x1
#define PH_NOTIFY_PROCESS_CREATE 0x1
#define PH_NOTIFY_PROCESS_DELETE 0x2
#define PH_NOTIFY_SERVICE_CREATE 0x4
#define PH_NOTIFY_SERVICE_DELETE 0x8
#define PH_NOTIFY_SERVICE_START 0x10
#define PH_NOTIFY_SERVICE_STOP 0x20
#define PH_NOTIFY_SERVICE_MODIFIED 0x40
#define PH_NOTIFY_DEVICE_ARRIVED 0x80
#define PH_NOTIFY_DEVICE_REMOVED 0x100
#define PH_NOTIFY_MAXIMUM 0x200
#define PH_NOTIFY_VALID_MASK 0x1ff

PHAPPAPI
VOID
NTAPI
PhShowIconNotification(
    _In_ PWSTR Title,
    _In_ PWSTR Text
    );

//
// notifico
//

typedef struct _PH_NF_ICON PH_NF_ICON, *PPH_NF_ICON;

typedef VOID (NTAPI *PPH_NF_UPDATE_REGISTERED_ICON)(
    _In_ PPH_NF_ICON Icon
    );

typedef VOID (NTAPI *PPH_NF_BEGIN_BITMAP)(
    _Out_ PULONG Width,
    _Out_ PULONG Height,
    _Out_ HBITMAP *Bitmap,
    _Out_opt_ PVOID *Bits,
    _Out_ HDC *Hdc,
    _Out_ HBITMAP *OldBitmap
    );

typedef struct _PH_NF_POINTERS
{
    PPH_NF_BEGIN_BITMAP BeginBitmap;
} PH_NF_POINTERS, *PPH_NF_POINTERS;

#define PH_NF_UPDATE_IS_BITMAP 0x1
#define PH_NF_UPDATE_DESTROY_RESOURCE 0x2

typedef VOID (NTAPI *PPH_NF_ICON_UPDATE_CALLBACK)(
    _In_ PPH_NF_ICON Icon,
    _Out_ PVOID *NewIconOrBitmap,
    _Out_ PULONG Flags,
    _Out_ PPH_STRING *NewText,
    _In_opt_ PVOID Context
    );

typedef BOOLEAN (NTAPI *PPH_NF_ICON_MESSAGE_CALLBACK)(
    _In_ PPH_NF_ICON Icon,
    _In_ ULONG_PTR WParam,
    _In_ ULONG_PTR LParam,
    _In_opt_ PVOID Context
    );

// Special messages
// The message type is stored in LOWORD(LParam), and the message data is in WParam.

#define PH_NF_MSG_SHOWMINIINFOSECTION (WM_APP + 1)

typedef struct _PH_NF_MSG_SHOWMINIINFOSECTION_DATA
{
    PWSTR SectionName; // NULL to leave unchanged
} PH_NF_MSG_SHOWMINIINFOSECTION_DATA, *PPH_NF_MSG_SHOWMINIINFOSECTION_DATA;

// Structures and internal functions

#define PH_NF_ICON_ENABLED 0x1
#define PH_NF_ICON_UNAVAILABLE 0x2
#define PH_NF_ICON_NOSHOW_MINIINFO 0x4

typedef struct _PH_PLUGIN PH_PLUGIN, *PPH_PLUGIN;

typedef struct _PH_NF_ICON
{
    // Public

    PPH_PLUGIN Plugin;
    ULONG SubId;
    PVOID Context;
    PPH_NF_POINTERS Pointers;

} PH_NF_ICON, *PPH_NF_ICON;

// Public registration data

typedef struct _PH_NF_ICON_REGISTRATION_DATA
{
    PPH_NF_ICON_UPDATE_CALLBACK UpdateCallback;
    PPH_NF_ICON_MESSAGE_CALLBACK MessageCallback;
} PH_NF_ICON_REGISTRATION_DATA, *PPH_NF_ICON_REGISTRATION_DATA;

//
// sysinfo
//

typedef enum _PH_SYSINFO_VIEW_TYPE
{
    SysInfoSummaryView,
    SysInfoSectionView
} PH_SYSINFO_VIEW_TYPE;

typedef VOID (NTAPI *PPH_SYSINFO_COLOR_SETUP_FUNCTION)(
    _Out_ PPH_GRAPH_DRAW_INFO DrawInfo,
    _In_ COLORREF Color1,
    _In_ COLORREF Color2,
    _In_ LONG dpiValue
    );

typedef struct _PH_SYSINFO_PARAMETERS
{
    HWND SysInfoWindowHandle;
    HWND ContainerWindowHandle;

    HFONT Font;
    HFONT MediumFont;
    HFONT LargeFont;
    ULONG FontHeight;
    ULONG FontAverageWidth;
    ULONG MediumFontHeight;
    ULONG MediumFontAverageWidth;
    COLORREF GraphBackColor;
    COLORREF PanelForeColor;
    PPH_SYSINFO_COLOR_SETUP_FUNCTION ColorSetupFunction;

    ULONG MinimumGraphHeight;
    ULONG SectionViewGraphHeight;
    ULONG PanelWidth;
    LONG WindowDpi;

} PH_SYSINFO_PARAMETERS, *PPH_SYSINFO_PARAMETERS;

typedef enum _PH_SYSINFO_SECTION_MESSAGE
{
    SysInfoCreate,
    SysInfoDestroy,
    SysInfoTick,
    SysInfoViewChanging, // PH_SYSINFO_VIEW_TYPE Parameter1, PPH_SYSINFO_SECTION Parameter2
    SysInfoCreateDialog, // PPH_SYSINFO_CREATE_DIALOG Parameter1
    SysInfoGraphGetDrawInfo, // PPH_GRAPH_DRAW_INFO Parameter1
    SysInfoGraphGetTooltipText, // PPH_SYSINFO_GRAPH_GET_TOOLTIP_TEXT Parameter1
    SysInfoGraphDrawPanel, // PPH_SYSINFO_DRAW_PANEL Parameter1
    SysInfoDpiChanged, // ULONG Parameter1
    MaxSysInfoMessage
} PH_SYSINFO_SECTION_MESSAGE;

typedef struct _PH_SYSINFO_SECTION *PPH_SYSINFO_SECTION;

typedef BOOLEAN (NTAPI *PPH_SYSINFO_SECTION_CALLBACK)(
    _In_ PPH_SYSINFO_SECTION Section,
    _In_ PH_SYSINFO_SECTION_MESSAGE Message,
    _In_opt_ PVOID Parameter1,
    _In_opt_ PVOID Parameter2
    );

typedef struct _PH_SYSINFO_CREATE_DIALOG
{
    BOOLEAN CustomCreate;

    // Parameters for default create
    PVOID Instance;
    PWSTR Template;
    DLGPROC DialogProc;
    PVOID Parameter;
} PH_SYSINFO_CREATE_DIALOG, *PPH_SYSINFO_CREATE_DIALOG;

typedef struct _PH_SYSINFO_GRAPH_GET_TOOLTIP_TEXT
{
    ULONG Index;
    PH_STRINGREF Text;
} PH_SYSINFO_GRAPH_GET_TOOLTIP_TEXT, *PPH_SYSINFO_GRAPH_GET_TOOLTIP_TEXT;

typedef struct _PH_SYSINFO_DRAW_PANEL
{
    HDC hdc;
    RECT Rect;
    BOOLEAN CustomDraw;

    // Parameters for default draw
    PPH_STRING Title;
    PPH_STRING SubTitle;
    PPH_STRING SubTitleOverflow;
} PH_SYSINFO_DRAW_PANEL, *PPH_SYSINFO_DRAW_PANEL;

typedef struct _PH_SYSINFO_SECTION
{
    // Public

    // Initialization
    PH_STRINGREF Name;
    ULONG Flags;
    PPH_SYSINFO_SECTION_CALLBACK Callback;
    PVOID Context;
    PVOID Reserved[3];

    // State
    HWND GraphHandle;
    PH_GRAPH_STATE GraphState;
    PPH_SYSINFO_PARAMETERS Parameters;
    PVOID Reserved2[3];

} PH_SYSINFO_SECTION, *PPH_SYSINFO_SECTION;

PHAPPAPI
VOID
NTAPI
PhSiSetColorsGraphDrawInfo(
    _Out_ PPH_GRAPH_DRAW_INFO DrawInfo,
    _In_ COLORREF Color1,
    _In_ COLORREF Color2,
    _In_ LONG dpiValue
    );

PHAPPAPI
PPH_STRING
NTAPI
PhSiSizeLabelYFunction(
    _In_ PPH_GRAPH_DRAW_INFO DrawInfo,
    _In_ ULONG DataIndex,
    _In_ FLOAT Value,
    _In_ FLOAT Parameter
    );

PHAPPAPI
PPH_STRING
NTAPI
PhSiDoubleLabelYFunction(
    _In_ PPH_GRAPH_DRAW_INFO DrawInfo,
    _In_ ULONG DataIndex,
    _In_ FLOAT Value,
    _In_ FLOAT Parameter
    );

PHAPPAPI
PPH_STRING
NTAPI
PhSiUInt64LabelYFunction(
    _In_ PPH_GRAPH_DRAW_INFO DrawInfo,
    _In_ ULONG DataIndex,
    _In_ FLOAT Value,
    _In_ FLOAT Parameter
    );

PHAPPAPI
VOID
NTAPI
PhShowSystemInformationDialog(
    _In_opt_ PWSTR SectionName
    );

//
// procgrp
//

typedef struct _PH_PROCESS_GROUP
{
    PPH_PROCESS_ITEM Representative; // An element of Processes (no extra reference added)
    PPH_LIST Processes; // List of PPH_PROCESS_ITEM
    HWND WindowHandle; // Window handle of representative
} PH_PROCESS_GROUP, *PPH_PROCESS_GROUP;

//
// miniinfo
//

// Section

typedef VOID (NTAPI *PPH_MINIINFO_SET_SECTION_TEXT)(
    _In_ struct _PH_MINIINFO_SECTION *Section,
    _In_opt_ PPH_STRING Text
    );

typedef struct _PH_MINIINFO_PARAMETERS
{
    HWND ContainerWindowHandle;
    HWND MiniInfoWindowHandle;

    HFONT Font;
    HFONT MediumFont;
    ULONG FontHeight;
    ULONG FontAverageWidth;
    ULONG MediumFontHeight;
    ULONG MediumFontAverageWidth;

    PPH_MINIINFO_SET_SECTION_TEXT SetSectionText;
} PH_MINIINFO_PARAMETERS, *PPH_MINIINFO_PARAMETERS;

typedef enum _PH_MINIINFO_SECTION_MESSAGE
{
    MiniInfoCreate,
    MiniInfoDestroy,
    MiniInfoTick,
    MiniInfoSectionChanging, // PPH_MINIINFO_SECTION Parameter1
    MiniInfoShowing, // BOOLEAN Parameter1 (Showing)
    MiniInfoCreateDialog, // PPH_MINIINFO_CREATE_DIALOG Parameter1
    MaxMiniInfoMessage
} PH_MINIINFO_SECTION_MESSAGE;

typedef BOOLEAN (NTAPI *PPH_MINIINFO_SECTION_CALLBACK)(
    _In_ struct _PH_MINIINFO_SECTION *Section,
    _In_ PH_MINIINFO_SECTION_MESSAGE Message,
    _In_opt_ PVOID Parameter1,
    _In_opt_ PVOID Parameter2
    );

typedef struct _PH_MINIINFO_CREATE_DIALOG
{
    BOOLEAN CustomCreate;

    // Parameters for default create
    PVOID Instance;
    PWSTR Template;
    DLGPROC DialogProc;
    PVOID Parameter;
} PH_MINIINFO_CREATE_DIALOG, *PPH_MINIINFO_CREATE_DIALOG;

#define PH_MINIINFO_SECTION_NO_UPPER_MARGINS 0x1

typedef struct _PH_MINIINFO_SECTION
{
    // Public

    // Initialization
    PH_STRINGREF Name;
    ULONG Flags;
    PPH_MINIINFO_SECTION_CALLBACK Callback;
    PVOID Context;
    PVOID Reserved1[3];

    PPH_MINIINFO_PARAMETERS Parameters;
    PVOID Reserved2[3];

} PH_MINIINFO_SECTION, *PPH_MINIINFO_SECTION;

// List section

typedef enum _PH_MINIINFO_LIST_SECTION_MESSAGE
{
    MiListSectionCreate,
    MiListSectionDestroy,
    MiListSectionTick,
    MiListSectionShowing, // BOOLEAN Parameter1 (Showing)
    MiListSectionDialogCreated, // HWND Parameter1 (DialogHandle)
    MiListSectionSortProcessList, // PPH_MINIINFO_LIST_SECTION_SORT_LIST Parameter1
    MiListSectionAssignSortData, // PPH_MINIINFO_LIST_SECTION_ASSIGN_SORT_DATA Parameter1
    MiListSectionSortGroupList, // PPH_MINIINFO_LIST_SECTION_SORT_LIST Parameter1
    MiListSectionGetTitleText, // PPH_MINIINFO_LIST_SECTION_GET_TITLE_TEXT Parameter1
    MiListSectionGetUsageText, // PPH_MINIINFO_LIST_SECTION_GET_USAGE_TEXT Parameter1
    MiListSectionInitializeContextMenu, // PPH_MINIINFO_LIST_SECTION_MENU_INFORMATION Parameter1
    MiListSectionHandleContextMenu, // PPH_MINIINFO_LIST_SECTION_MENU_INFORMATION Parameter1
    MaxMiListSectionMessage
} PH_MINIINFO_LIST_SECTION_MESSAGE;

typedef BOOLEAN (NTAPI *PPH_MINIINFO_LIST_SECTION_CALLBACK)(
    _In_ struct _PH_MINIINFO_LIST_SECTION *ListSection,
    _In_ PH_MINIINFO_LIST_SECTION_MESSAGE Message,
    _In_opt_ PVOID Parameter1,
    _In_opt_ PVOID Parameter2
    );

// The list section performs the following steps when constructing the list of process groups:
// 1. MiListSectionSortProcessList is sent in order to sort the process list.
// 2. A small number of process groups is created from the first few processes in the sorted list (typically high
//    resource consumers).
// 3. MiListSectionAssignSortData is sent for each process group so that the user can assign custom sort data to
//    each process group.
// 4. MiListSectionSortGroupList is sent in order to ensure that the process groups are correctly sorted by resource
//    usage.
// The user also has access to the sort data when handling MiListSectionGetTitleText and MiListSectionGetUsageText.

typedef struct _PH_MINIINFO_LIST_SECTION_SORT_DATA
{
    PH_TREENEW_NODE DoNotModify;
    ULONGLONG UserData[4];
} PH_MINIINFO_LIST_SECTION_SORT_DATA, *PPH_MINIINFO_LIST_SECTION_SORT_DATA;

typedef struct _PH_MINIINFO_LIST_SECTION_ASSIGN_SORT_DATA
{
    PPH_PROCESS_GROUP ProcessGroup;
    PPH_MINIINFO_LIST_SECTION_SORT_DATA SortData;
} PH_MINIINFO_LIST_SECTION_ASSIGN_SORT_DATA, *PPH_MINIINFO_LIST_SECTION_ASSIGN_SORT_DATA;

typedef struct _PH_MINIINFO_LIST_SECTION_SORT_LIST
{
    // MiListSectionSortProcessList: List of PPH_PROCESS_NODE
    // MiListSectionSortGroupList: List of PPH_MINIINFO_LIST_SECTION_SORT_DATA
    PPH_LIST List;
} PH_MINIINFO_LIST_SECTION_SORT_LIST, *PPH_MINIINFO_LIST_SECTION_SORT_LIST;

typedef struct _PH_MINIINFO_LIST_SECTION_GET_TITLE_TEXT
{
    PPH_PROCESS_GROUP ProcessGroup;
    PPH_MINIINFO_LIST_SECTION_SORT_DATA SortData;
    PPH_STRING Title; // Top line (may already contain a string)
    PPH_STRING Subtitle; // Bottom line (may already contain a string)
    COLORREF TitleColor;
    COLORREF SubtitleColor;
} PH_MINIINFO_LIST_SECTION_GET_TITLE_TEXT, *PPH_MINIINFO_LIST_SECTION_GET_TITLE_TEXT;

typedef struct _PH_MINIINFO_LIST_SECTION_GET_USAGE_TEXT
{
    PPH_PROCESS_GROUP ProcessGroup;
    PPH_MINIINFO_LIST_SECTION_SORT_DATA SortData;
    PPH_STRING Line1; // Top line
    PPH_STRING Line2; // Bottom line
    COLORREF Line1Color;
    COLORREF Line2Color;
} PH_MINIINFO_LIST_SECTION_GET_USAGE_TEXT, *PPH_MINIINFO_LIST_SECTION_GET_USAGE_TEXT;

typedef struct _PH_MINIINFO_LIST_SECTION_MENU_INFORMATION
{
    PPH_PROCESS_GROUP ProcessGroup;
    PPH_MINIINFO_LIST_SECTION_SORT_DATA SortData;
    PPH_TREENEW_CONTEXT_MENU ContextMenu;
    struct _PH_EMENU_ITEM *SelectedItem;
} PH_MINIINFO_LIST_SECTION_MENU_INFORMATION, *PPH_MINIINFO_LIST_SECTION_MENU_INFORMATION;

typedef struct _PH_MINIINFO_LIST_SECTION
{
    // Public

    PPH_MINIINFO_SECTION Section; // State
    HWND DialogHandle; // State
    HWND TreeNewHandle; // State
    PVOID Context; // Initialization
    PPH_MINIINFO_LIST_SECTION_CALLBACK Callback; // Initialization

} PH_MINIINFO_LIST_SECTION, *PPH_MINIINFO_LIST_SECTION;

//
// phplug
//

// Callbacks

typedef enum _PH_GENERAL_CALLBACK
{
    GeneralCallbackMainWindowShowing = 0, // INT ShowCommand [main thread]
    GeneralCallbackProcessesUpdated = 1, // [main thread]
    GeneralCallbackGetProcessHighlightingColor = 2, // PPH_PLUGIN_GET_HIGHLIGHTING_COLOR Data [main thread]
    GeneralCallbackGetProcessTooltipText = 3, // PPH_PLUGIN_GET_TOOLTIP_TEXT Data [main thread]
    GeneralCallbackProcessPropertiesInitializing = 4, // PPH_PLUGIN_PROCESS_PROPCONTEXT Data [properties thread]
    GeneralCallbackMainMenuInitializing = 5, // PPH_PLUGIN_MENU_INFORMATION Data [main thread]
    GeneralCallbackNotifyEvent = 6, // PPH_PLUGIN_NOTIFY_EVENT Data [main thread]
    GeneralCallbackServicePropertiesInitializing = 7, // PPH_PLUGIN_OBJECT_PROPERTIES Data [properties thread]
    GeneralCallbackHandlePropertiesInitializing = 8, // PPH_PLUGIN_OBJECT_PROPERTIES Data [properties thread]
    GeneralCallbackProcessMenuInitializing = 9, // PPH_PLUGIN_MENU_INFORMATION Data [main thread]
    GeneralCallbackServiceMenuInitializing = 10, // PPH_PLUGIN_MENU_INFORMATION Data [main thread]
    GeneralCallbackNetworkMenuInitializing = 11, // PPH_PLUGIN_MENU_INFORMATION Data [main thread]
    GeneralCallbackIconMenuInitializing = 12, // PPH_PLUGIN_MENU_INFORMATION Data [main thread]
    GeneralCallbackThreadMenuInitializing = 13, // PPH_PLUGIN_MENU_INFORMATION Data [properties thread]
    GeneralCallbackModuleMenuInitializing = 14, // PPH_PLUGIN_MENU_INFORMATION Data [properties thread]
    GeneralCallbackMemoryMenuInitializing = 15, // PPH_PLUGIN_MENU_INFORMATION Data [properties thread]
    GeneralCallbackHandleMenuInitializing = 16, // PPH_PLUGIN_MENU_INFORMATION Data [properties thread]
    GeneralCallbackProcessTreeNewInitializing = 17, // PPH_PLUGIN_TREENEW_INFORMATION Data [main thread]
    GeneralCallbackServiceTreeNewInitializing = 18, // PPH_PLUGIN_TREENEW_INFORMATION Data [main thread]
    GeneralCallbackNetworkTreeNewInitializing = 19, // PPH_PLUGIN_TREENEW_INFORMATION Data [main thread]
    GeneralCallbackModuleTreeNewInitializing = 20, // PPH_PLUGIN_TREENEW_INFORMATION Data [properties thread]
    GeneralCallbackModuleTreeNewUninitializing = 21, // PPH_PLUGIN_TREENEW_INFORMATION Data [properties thread]
    GeneralCallbackThreadTreeNewInitializing = 22, // PPH_PLUGIN_TREENEW_INFORMATION Data [properties thread]
    GeneralCallbackThreadTreeNewUninitializing = 23, // PPH_PLUGIN_TREENEW_INFORMATION Data [properties thread]
    GeneralCallbackHandleTreeNewInitializing = 24, // PPH_PLUGIN_TREENEW_INFORMATION Data [properties thread]
    GeneralCallbackHandleTreeNewUninitializing = 25, // PPH_PLUGIN_TREENEW_INFORMATION Data [properties thread]
    GeneralCallbackThreadStackControl = 26, // PPH_PLUGIN_THREAD_STACK_CONTROL Data [properties thread]
    GeneralCallbackSystemInformationInitializing = 27, // PPH_PLUGIN_SYSINFO_POINTERS Data [system information thread]
    GeneralCallbackMainWindowTabChanged = 28, // INT NewIndex [main thread]
    GeneralCallbackMemoryTreeNewInitializing = 29, // PPH_PLUGIN_TREENEW_INFORMATION Data [properties thread]
    GeneralCallbackMemoryTreeNewUninitializing = 30, // PPH_PLUGIN_TREENEW_INFORMATION Data [properties thread]
    GeneralCallbackMemoryItemListControl = 31, // PPH_PLUGIN_MEMORY_ITEM_LIST_CONTROL Data [properties thread]
    GeneralCallbackMiniInformationInitializing = 32, // PPH_PLUGIN_MINIINFO_POINTERS Data [main thread]
    GeneralCallbackMiListSectionMenuInitializing = 33, // PPH_PLUGIN_MENU_INFORMATION Data [main thread]
    GeneralCallbackOptionsWindowInitializing = 34, // PPH_PLUGIN_OBJECT_PROPERTIES Data [main thread]

    GeneralCallbackProcessProviderAddedEvent, // [process provider thread]
    GeneralCallbackProcessProviderModifiedEvent, // [process provider thread]
    GeneralCallbackProcessProviderRemovedEvent, // [process provider thread]
    GeneralCallbackProcessProviderUpdatedEvent, // [process provider thread]
    GeneralCallbackServiceProviderAddedEvent, // [service provider thread]
    GeneralCallbackServiceProviderModifiedEvent, // [service provider thread]
    GeneralCallbackServiceProviderRemovedEvent, // [service provider thread]
    GeneralCallbackServiceProviderUpdatedEvent, // [service provider thread]
    GeneralCallbackNetworkProviderAddedEvent, // [network provider thread]
    GeneralCallbackNetworkProviderModifiedEvent, // [network provider thread]
    GeneralCallbackNetworkProviderRemovedEvent, // [network provider thread]
    GeneralCallbackNetworkProviderUpdatedEvent, // [network provider thread]

    GeneralCallbackLoggedEvent,
    GeneralCallbackTrayIconsInitializing,
    GeneralCallbackWindowNotifyEvent,
    GeneralCallbackProcessStatsNotifyEvent,
    GeneralCallbackSettingsUpdated,

    GeneralCallbackDeviceNotificationEvent, // [device provider thread]

    GeneralCallbackMaximum
} PH_GENERAL_CALLBACK, *PPH_GENERAL_CALLBACK;

typedef enum _PH_PLUGIN_CALLBACK
{
    PluginCallbackLoad = 0, // PPH_LIST Parameters [main thread] // list of strings, might be NULL
    PluginCallbackUnload = 1, // BOOLEAN SessionEnding [main thread]
    PluginCallbackShowOptions = 2, // HWND ParentWindowHandle [main thread]
    PluginCallbackMenuItem = 3, // PPH_PLUGIN_MENU_ITEM MenuItem [main/properties thread]
    PluginCallbackTreeNewMessage = 4, // PPH_PLUGIN_TREENEW_MESSAGE Message [main/properties thread]
    PluginCallbackPhSvcRequest = 5, // PPH_PLUGIN_PHSVC_REQUEST Message [phsvc thread]
    PluginCallbackMenuHook = 6, // PH_PLUGIN_MENU_HOOK_INFORMATION MenuHookInfo [menu thread]
    PluginCallbackMaximum
} PH_PLUGIN_CALLBACK, *PPH_PLUGIN_CALLBACK;

typedef struct _PH_PLUGIN_GET_HIGHLIGHTING_COLOR
{
    // Parameter is:
    // PPH_PROCESS_ITEM for GeneralCallbackGetProcessHighlightingColor

    PVOID Parameter;
    COLORREF BackColor;
    COLORREF ForeColor;
    BOOLEAN Handled;
    BOOLEAN Cache;
} PH_PLUGIN_GET_HIGHLIGHTING_COLOR, *PPH_PLUGIN_GET_HIGHLIGHTING_COLOR;

typedef struct _PH_PLUGIN_GET_TOOLTIP_TEXT
{
    // Parameter is:
    // PPH_PROCESS_ITEM for GeneralCallbackGetProcessTooltipText

    PVOID Parameter;
    PPH_STRING_BUILDER StringBuilder;
    ULONG ValidForMs;
} PH_PLUGIN_GET_TOOLTIP_TEXT, *PPH_PLUGIN_GET_TOOLTIP_TEXT;

typedef struct _PH_PLUGIN_PROCESS_PROPCONTEXT
{
    PPH_PROCESS_PROPCONTEXT PropContext;
    PPH_PROCESS_ITEM ProcessItem;
} PH_PLUGIN_PROCESS_PROPCONTEXT, *PPH_PLUGIN_PROCESS_PROPCONTEXT;

typedef struct _PH_PLUGIN_NOTIFY_EVENT
{
    // Parameter is:
    // PPH_PROCESS_ITEM for Type = PH_NOTIFY_PROCESS_*
    // PPH_SERVICE_ITEM for Type = PH_NOTIFY_SERVICE_*
    // PPH_DEVICE_ITEM for type = PH_NOTIFY_DEVICE_*

    ULONG Type;
    BOOLEAN Handled;
    PVOID Parameter;
} PH_PLUGIN_NOTIFY_EVENT, *PPH_PLUGIN_NOTIFY_EVENT;

typedef struct _PH_PLUGIN_OBJECT_PROPERTIES
{
    // Parameter is:
    // PPH_SERVICE_ITEM for GeneralCallbackServicePropertiesInitializing
    // PPH_PLUGIN_HANDLE_PROPERTIES_CONTEXT for GeneralCallbackHandlePropertiesInitializing

    PVOID Parameter;
    ULONG NumberOfPages;
    ULONG MaximumNumberOfPages;
    HPROPSHEETPAGE *Pages;
} PH_PLUGIN_OBJECT_PROPERTIES, *PPH_PLUGIN_OBJECT_PROPERTIES;

typedef struct _PH_PLUGIN_PROCESS_STATS_EVENT
{
    ULONG Version;
    ULONG Type;
    PPH_PROCESS_ITEM ProcessItem;
    PVOID Parameter;
} PH_PLUGIN_PROCESS_STATS_EVENT, *PPH_PLUGIN_PROCESS_STATS_EVENT;

typedef struct _PH_PLUGIN_HANDLE_PROPERTIES_CONTEXT
{
    HANDLE ProcessId;
    PPH_HANDLE_ITEM HandleItem;
} PH_PLUGIN_HANDLE_PROPERTIES_CONTEXT, *PPH_PLUGIN_HANDLE_PROPERTIES_CONTEXT;

typedef struct _PH_EMENU_ITEM *PPH_EMENU_ITEM, *PPH_EMENU;

#define PH_PLUGIN_MENU_DISALLOW_HOOKS 0x1

typedef struct _PH_PLUGIN_MENU_INFORMATION
{
    PPH_EMENU Menu;
    HWND OwnerWindow;

    union
    {
        struct
        {
            PVOID Reserved[8]; // Reserve space for future expansion of this union
        } DoNotUse;
        struct
        {
            ULONG SubMenuIndex;
        } MainMenu;
        struct
        {
            PPH_PROCESS_ITEM *Processes;
            ULONG NumberOfProcesses;
        } Process;
        struct
        {
            PPH_SERVICE_ITEM *Services;
            ULONG NumberOfServices;
        } Service;
        struct
        {
            PPH_NETWORK_ITEM *NetworkItems;
            ULONG NumberOfNetworkItems;
        } Network;
        struct
        {
            HANDLE ProcessId;
            PPH_THREAD_ITEM *Threads;
            ULONG NumberOfThreads;
        } Thread;
        struct
        {
            HANDLE ProcessId;
            PPH_MODULE_ITEM *Modules;
            ULONG NumberOfModules;
        } Module;
        struct
        {
            HANDLE ProcessId;
            PPH_MEMORY_NODE *MemoryNodes;
            ULONG NumberOfMemoryNodes;
        } Memory;
        struct
        {
            HANDLE ProcessId;
            PPH_HANDLE_ITEM *Handles;
            ULONG NumberOfHandles;
        } Handle;
        struct
        {
            PPH_STRINGREF SectionName;
            PPH_PROCESS_GROUP ProcessGroup;
        } MiListSection;
    } u;

    ULONG Flags;
    PPH_LIST PluginHookList;
} PH_PLUGIN_MENU_INFORMATION, *PPH_PLUGIN_MENU_INFORMATION;

C_ASSERT(RTL_FIELD_SIZE(PH_PLUGIN_MENU_INFORMATION, u) == RTL_FIELD_SIZE(PH_PLUGIN_MENU_INFORMATION, u.DoNotUse));

typedef struct _PH_PLUGIN_MENU_HOOK_INFORMATION
{
    PPH_PLUGIN_MENU_INFORMATION MenuInfo;
    PPH_EMENU SelectedItem;
    PVOID Context;
    BOOLEAN Handled;
} PH_PLUGIN_MENU_HOOK_INFORMATION, *PPH_PLUGIN_MENU_HOOK_INFORMATION;

typedef struct _PH_PLUGIN_TREENEW_INFORMATION
{
    HWND TreeNewHandle;
    PVOID CmData;
    PVOID SystemContext; // e.g. PPH_THREADS_CONTEXT
} PH_PLUGIN_TREENEW_INFORMATION, *PPH_PLUGIN_TREENEW_INFORMATION;

typedef enum _PH_PLUGIN_THREAD_STACK_CONTROL_TYPE
{
    PluginThreadStackInitializing,
    PluginThreadStackUninitializing,
    PluginThreadStackResolveSymbol,
    PluginThreadStackGetTooltip,
    PluginThreadStackWalkStack,
    PluginThreadStackBeginDefaultWalkStack,
    PluginThreadStackEndDefaultWalkStack,
    PluginThreadStackMaximum
} PH_PLUGIN_THREAD_STACK_CONTROL_TYPE;

typedef struct _PH_SYMBOL_PROVIDER *PPH_SYMBOL_PROVIDER;
typedef struct _PH_THREAD_STACK_FRAME *PPH_THREAD_STACK_FRAME;

typedef BOOLEAN (NTAPI *PPH_PLUGIN_WALK_THREAD_STACK_CALLBACK)(
    _In_ PPH_THREAD_STACK_FRAME StackFrame,
    _In_opt_ PVOID Context
    );

typedef struct _PH_PLUGIN_THREAD_STACK_CONTROL
{
    PH_PLUGIN_THREAD_STACK_CONTROL_TYPE Type;
    PVOID UniqueKey;

    union
    {
        struct
        {
            HANDLE ProcessId;
            HANDLE ThreadId;
            HANDLE ThreadHandle;
            HANDLE ProcessHandle;
            PPH_SYMBOL_PROVIDER SymbolProvider;
            BOOLEAN CustomWalk;
        } Initializing;
        struct
        {
            PPH_THREAD_STACK_FRAME StackFrame;
            PPH_STRING Symbol;
            PPH_STRING FileName;
        } ResolveSymbol;
        struct
        {
            PPH_THREAD_STACK_FRAME StackFrame;
            PPH_STRING_BUILDER StringBuilder;
        } GetTooltip;
        struct
        {
            NTSTATUS Status;
            HANDLE ThreadHandle;
            HANDLE ProcessHandle;
            PCLIENT_ID ClientId;
            ULONG Flags;
            PPH_PLUGIN_WALK_THREAD_STACK_CALLBACK Callback;
            PVOID CallbackContext;
        } WalkStack;
    } u;
} PH_PLUGIN_THREAD_STACK_CONTROL, *PPH_PLUGIN_THREAD_STACK_CONTROL;

typedef enum _PH_PLUGIN_MEMORY_ITEM_LIST_CONTROL_TYPE
{
    PluginMemoryItemListInitialized,
    PluginMemoryItemListMaximum
} PH_PLUGIN_MEMORY_ITEM_LIST_CONTROL_TYPE;

typedef struct _PH_PLUGIN_MEMORY_ITEM_LIST_CONTROL
{
    PH_PLUGIN_MEMORY_ITEM_LIST_CONTROL_TYPE Type;

    union
    {
        struct
        {
            PPH_MEMORY_ITEM_LIST List;
        } Initialized;
    } u;
} PH_PLUGIN_MEMORY_ITEM_LIST_CONTROL, *PPH_PLUGIN_MEMORY_ITEM_LIST_CONTROL;

typedef PPH_SYSINFO_SECTION (NTAPI *PPH_SYSINFO_CREATE_SECTION)(
    _In_ PPH_SYSINFO_SECTION Template
    );

typedef PPH_SYSINFO_SECTION (NTAPI *PPH_SYSINFO_FIND_SECTION)(
    _In_ PPH_STRINGREF Name
    );

typedef VOID (NTAPI *PPH_SYSINFO_ENTER_SECTION_VIEW)(
    _In_ PPH_SYSINFO_SECTION NewSection
    );

typedef VOID (NTAPI *PPH_SYSINFO_RESTORE_SUMMARY_VIEW)(
    VOID
    );

typedef struct _PH_PLUGIN_SYSINFO_POINTERS
{
    HWND WindowHandle;
    PPH_SYSINFO_CREATE_SECTION CreateSection;
    PPH_SYSINFO_FIND_SECTION FindSection;
    PPH_SYSINFO_ENTER_SECTION_VIEW EnterSectionView;
    PPH_SYSINFO_RESTORE_SUMMARY_VIEW RestoreSummaryView;
} PH_PLUGIN_SYSINFO_POINTERS, *PPH_PLUGIN_SYSINFO_POINTERS;

typedef PPH_MINIINFO_SECTION (NTAPI *PPH_MINIINFO_CREATE_SECTION)(
    _In_ PPH_MINIINFO_SECTION Template
    );

typedef PPH_MINIINFO_SECTION (NTAPI *PPH_MINIINFO_FIND_SECTION)(
    _In_ PPH_STRINGREF Name
    );

typedef PPH_MINIINFO_LIST_SECTION (NTAPI *PPH_MINIINFO_CREATE_LIST_SECTION)(
    _In_ PWSTR Name,
    _In_ ULONG Flags,
    _In_ PPH_MINIINFO_LIST_SECTION Template
    );

typedef struct _PH_PLUGIN_MINIINFO_POINTERS
{
    HWND WindowHandle;
    PPH_MINIINFO_CREATE_SECTION CreateSection;
    PPH_MINIINFO_FIND_SECTION FindSection;
    PPH_MINIINFO_CREATE_LIST_SECTION CreateListSection;
} PH_PLUGIN_MINIINFO_POINTERS, *PPH_PLUGIN_MINIINFO_POINTERS;

typedef struct _PH_NF_ICON_REGISTRATION_DATA *PPH_NF_ICON_REGISTRATION_DATA;
typedef struct _PH_PLUGIN *PPH_PLUGIN;

/**
 * Creates a notification icon.
 *
 * \param Plugin A plugin instance structure.
 * \param SubId An identifier for the column. This should be unique within the
 * plugin.
 * \param Guid A unique guid for this icon.
 * \param Context A user-defined value.
 * \param Text A string describing the notification icon.
 * \param Flags A combination of flags.
 * \li \c PH_NF_ICON_UNAVAILABLE The notification icon is currently unavailable.
 * \param RegistrationData A \ref PH_NF_ICON_REGISTRATION_DATA structure that
 * contains registration information.
 */
typedef PPH_PLUGIN (NTAPI *PPH_REGISTER_TRAY_ICON)(
    _In_ PPH_PLUGIN Plugin,
    _In_ ULONG SubId,
    _In_ GUID Guid,
    _In_opt_ PVOID Context,
    _In_ PWSTR Text,
    _In_ ULONG Flags,
    _In_ PPH_NF_ICON_REGISTRATION_DATA RegistrationData
    );

typedef struct _PH_TRAY_ICON_POINTERS
{
    PPH_REGISTER_TRAY_ICON RegisterTrayIcon;
} PH_TRAY_ICON_POINTERS, *PPH_TRAY_ICON_POINTERS;

typedef struct _PH_OPTIONS_SECTION
{
    PH_STRINGREF Name;

} PH_OPTIONS_SECTION, *PPH_OPTIONS_SECTION;

typedef PPH_OPTIONS_SECTION (NTAPI *PPH_OPTIONS_CREATE_SECTION)(
    _In_ PWSTR Name,
    _In_ PVOID Instance,
    _In_ PWSTR Template,
    _In_ DLGPROC DialogProc,
    _In_opt_ PVOID Parameter
    );

typedef PPH_OPTIONS_SECTION (NTAPI *PPH_OPTIONS_FIND_SECTION)(
    _In_ PPH_STRINGREF Name
    );

typedef VOID (NTAPI *PPH_OPTIONS_ENTER_SECTION_VIEW)(
    _In_ PPH_OPTIONS_SECTION NewSection
    );

typedef struct _PH_PLUGIN_OPTIONS_POINTERS
{
    HWND WindowHandle;
    PPH_OPTIONS_CREATE_SECTION CreateSection;
    PPH_OPTIONS_FIND_SECTION FindSection;
    PPH_OPTIONS_ENTER_SECTION_VIEW EnterSectionView;
} PH_PLUGIN_OPTIONS_POINTERS, *PPH_PLUGIN_OPTIONS_POINTERS;

typedef struct _PH_PLUGIN_TREENEW_MESSAGE
{
    HWND TreeNewHandle;
    PH_TREENEW_MESSAGE Message;
    PVOID Parameter1;
    PVOID Parameter2;
    ULONG SubId;
    PVOID Context;
} PH_PLUGIN_TREENEW_MESSAGE, *PPH_PLUGIN_TREENEW_MESSAGE;

typedef LONG (NTAPI *PPH_PLUGIN_TREENEW_SORT_FUNCTION)(
    _In_ PVOID Node1,
    _In_ PVOID Node2,
    _In_ ULONG SubId,
    _In_ PH_SORT_ORDER SortOrder,
    _In_ PVOID Context
    );

_Function_class_(PHSVC_SERVER_PROBE_BUFFER)
typedef NTSTATUS (NTAPI PHSVC_SERVER_PROBE_BUFFER)(
    _In_ PPH_RELATIVE_STRINGREF String,
    _In_ ULONG Alignment,
    _In_ BOOLEAN AllowNull,
    _Out_ PVOID *Pointer
    );

_Function_class_(PHSVC_SERVER_CAPTURE_BUFFER)
typedef NTSTATUS (NTAPI PHSVC_SERVER_CAPTURE_BUFFER)(
    _In_ PPH_RELATIVE_STRINGREF String,
    _In_ BOOLEAN AllowNull,
    _Out_ PVOID *CapturedBuffer
    );

_Function_class_(PHSVC_SERVER_CAPTURE_STRING)
typedef NTSTATUS (NTAPI PHSVC_SERVER_CAPTURE_STRING)(
    _In_ PPH_RELATIVE_STRINGREF String,
    _In_ BOOLEAN AllowNull,
    _Out_ PPH_STRING *CapturedString
    );

typedef PHSVC_SERVER_PROBE_BUFFER *PPHSVC_SERVER_PROBE_BUFFER;
typedef PHSVC_SERVER_CAPTURE_BUFFER *PPHSVC_SERVER_CAPTURE_BUFFER;
typedef PHSVC_SERVER_CAPTURE_STRING *PPHSVC_SERVER_CAPTURE_STRING;

typedef struct _PH_PLUGIN_PHSVC_REQUEST
{
    ULONG SubId;
    NTSTATUS ReturnStatus;
    PVOID InBuffer;
    ULONG InLength;
    PVOID OutBuffer;
    ULONG OutLength;

    PPHSVC_SERVER_PROBE_BUFFER ProbeBuffer;
    PPHSVC_SERVER_CAPTURE_BUFFER CaptureBuffer;
    PPHSVC_SERVER_CAPTURE_STRING CaptureString;
} PH_PLUGIN_PHSVC_REQUEST, *PPH_PLUGIN_PHSVC_REQUEST;

typedef VOID (NTAPI *PPHSVC_CLIENT_FREE_HEAP)(
    _In_ PVOID Memory
    );

typedef PVOID (NTAPI *PPHSVC_CLIENT_CREATE_STRING)(
    _In_opt_ PVOID String,
    _In_ SIZE_T Length,
    _Out_ PPH_RELATIVE_STRINGREF StringRef
    );

typedef struct _PH_PLUGIN_PHSVC_CLIENT
{
    HANDLE ServerProcessId;
    PPHSVC_CLIENT_FREE_HEAP FreeHeap;
    PPHSVC_CLIENT_CREATE_STRING CreateString;
} PH_PLUGIN_PHSVC_CLIENT, *PPH_PLUGIN_PHSVC_CLIENT;

// Plugin structures

typedef struct _PH_PLUGIN_INFORMATION
{
    PWSTR DisplayName;
    PWSTR Author;
    PWSTR Description;
    PWSTR Url;
    BOOLEAN HasOptions;
    BOOLEAN Reserved1[3];
    PVOID Interface;
} PH_PLUGIN_INFORMATION, *PPH_PLUGIN_INFORMATION;

#define PH_PLUGIN_FLAG_RESERVED 0x1

typedef struct _PH_PLUGIN
{
    // Public

    PH_AVL_LINKS Links;

    PVOID DllBase;

} PH_PLUGIN, *PPH_PLUGIN;

// Plugin API

PHAPPAPI
PPH_PLUGIN
NTAPI
PhRegisterPlugin(
    _In_ PWSTR Name,
    _In_ PVOID DllBase,
    _Out_opt_ PPH_PLUGIN_INFORMATION *Information
    );

PHAPPAPI
PPH_PLUGIN
NTAPI
PhFindPlugin(
    _In_ PWSTR Name
    );

PHAPPAPI
PPH_PLUGIN_INFORMATION
NTAPI
PhGetPluginInformation(
    _In_ PPH_PLUGIN Plugin
    );

PHAPPAPI
PPH_CALLBACK
NTAPI
PhGetPluginCallback(
    _In_ PPH_PLUGIN Plugin,
    _In_ PH_PLUGIN_CALLBACK Callback
    );

PHAPPAPI
PPH_CALLBACK
NTAPI
PhGetGeneralCallback(
    _In_ PH_GENERAL_CALLBACK Callback
    );

PHAPPAPI
ULONG
NTAPI
PhPluginReserveIds(
    _In_ ULONG Count
    );

typedef struct _PH_PLUGIN_MENU_ITEM *PPH_PLUGIN_MENU_ITEM;

_Function_class_(PH_PLUGIN_MENU_ITEM_DELETE_FUNCTION)
typedef VOID (NTAPI PH_PLUGIN_MENU_ITEM_DELETE_FUNCTION)(
    _In_ PPH_PLUGIN_MENU_ITEM MenuItem
    );
typedef PH_PLUGIN_MENU_ITEM_DELETE_FUNCTION *PPH_PLUGIN_MENU_ITEM_DELETE_FUNCTION;

typedef struct _PH_PLUGIN_MENU_ITEM
{
    PPH_PLUGIN Plugin;
    ULONG Id;
    ULONG Reserved1;
    PVOID Context;

    HWND OwnerWindow; // valid only when the menu item is chosen
    PVOID Reserved2;
    PVOID Reserved3;
    PPH_PLUGIN_MENU_ITEM_DELETE_FUNCTION DeleteFunction; // valid only for EMENU-based menu items
} PH_PLUGIN_MENU_ITEM, *PPH_PLUGIN_MENU_ITEM;

// Location
#define PH_MENU_ITEM_LOCATION_SYSTEM 0
#define PH_MENU_ITEM_LOCATION_VIEW 1
#define PH_MENU_ITEM_LOCATION_TOOLS 2
#define PH_MENU_ITEM_LOCATION_USERS 3
#define PH_MENU_ITEM_LOCATION_HELP 4

typedef struct _PH_PLUGIN_SYSTEM_STATISTICS
{
    PSYSTEM_PERFORMANCE_INFORMATION Performance;

    ULONG NumberOfProcesses;
    ULONG NumberOfThreads;
    ULONG NumberOfHandles;

    FLOAT CpuKernelUsage;
    FLOAT CpuUserUsage;

    PH_UINT64_DELTA IoReadDelta;
    PH_UINT64_DELTA IoWriteDelta;
    PH_UINT64_DELTA IoOtherDelta;

    ULONG CommitPages;
    ULONG PhysicalPages;

    HANDLE MaxCpuProcessId;
    HANDLE MaxIoProcessId;

    PPH_CIRCULAR_BUFFER_FLOAT CpuKernelHistory;
    PPH_CIRCULAR_BUFFER_FLOAT CpuUserHistory;
    PPH_CIRCULAR_BUFFER_FLOAT *CpusKernelHistory;
    PPH_CIRCULAR_BUFFER_FLOAT *CpusUserHistory;
    PPH_CIRCULAR_BUFFER_ULONG64 IoReadHistory;
    PPH_CIRCULAR_BUFFER_ULONG64 IoWriteHistory;
    PPH_CIRCULAR_BUFFER_ULONG64 IoOtherHistory;
    PPH_CIRCULAR_BUFFER_ULONG CommitHistory;
    PPH_CIRCULAR_BUFFER_ULONG PhysicalHistory;
    PPH_CIRCULAR_BUFFER_ULONG MaxCpuHistory; // ID of max. CPU process
    PPH_CIRCULAR_BUFFER_ULONG MaxIoHistory; // ID of max. I/O process
    PPH_CIRCULAR_BUFFER_FLOAT MaxCpuUsageHistory;
    PPH_CIRCULAR_BUFFER_ULONG64 MaxIoReadOtherHistory;
    PPH_CIRCULAR_BUFFER_ULONG64 MaxIoWriteHistory;
} PH_PLUGIN_SYSTEM_STATISTICS, *PPH_PLUGIN_SYSTEM_STATISTICS;

PHAPPAPI
VOID
NTAPI
PhPluginGetSystemStatistics(
    _Out_ PPH_PLUGIN_SYSTEM_STATISTICS Statistics
    );

PHAPPAPI
PPH_EMENU_ITEM
NTAPI
PhPluginCreateEMenuItem(
    _In_ PPH_PLUGIN Plugin,
    _In_ ULONG Flags,
    _In_ ULONG Id,
    _In_ PWSTR Text,
    _In_opt_ PVOID Context
    );

PHAPPAPI
BOOLEAN
NTAPI
PhPluginAddMenuHook(
    _Inout_ PPH_PLUGIN_MENU_INFORMATION MenuInfo,
    _In_ PPH_PLUGIN Plugin,
    _In_opt_ PVOID Context
    );

PHAPPAPI
BOOLEAN
NTAPI
PhPluginAddTreeNewColumn(
    _In_ PPH_PLUGIN Plugin,
    _In_ PVOID CmData,
    _In_ PPH_TREENEW_COLUMN Column,
    _In_ ULONG SubId,
    _In_opt_ PVOID Context,
    _In_opt_ PPH_PLUGIN_TREENEW_SORT_FUNCTION SortFunction
    );

PHAPPAPI
VOID
NTAPI
PhPluginSetObjectExtension(
    _In_ PPH_PLUGIN Plugin,
    _In_ PH_EM_OBJECT_TYPE ObjectType,
    _In_ ULONG ExtensionSize,
    _In_opt_ PPH_EM_OBJECT_CALLBACK CreateCallback,
    _In_opt_ PPH_EM_OBJECT_CALLBACK DeleteCallback
    );

PHAPPAPI
PVOID
NTAPI
PhPluginGetObjectExtension(
    _In_ PPH_PLUGIN Plugin,
    _In_ PVOID Object,
    _In_ PH_EM_OBJECT_TYPE ObjectType
    );

PHAPPAPI
VOID
NTAPI
PhPluginEnableTreeNewNotify(
    _In_ PPH_PLUGIN Plugin,
    _In_ PVOID CmData
    );

PHAPPAPI
_Success_(return)
BOOLEAN
NTAPI
PhPluginQueryPhSvc(
    _Out_ PPH_PLUGIN_PHSVC_CLIENT Client
    );

PHAPPAPI
NTSTATUS
NTAPI
PhPluginCallPhSvc(
    _In_ PPH_PLUGIN Plugin,
    _In_ ULONG SubId,
    _In_reads_bytes_opt_(InLength) PVOID InBuffer,
    _In_ ULONG InLength,
    _Out_writes_bytes_opt_(OutLength) PVOID OutBuffer,
    _In_ ULONG OutLength
    );

PHAPPAPI
PPH_STRING
NTAPI
PhGetPluginName(
    _In_ PPH_PLUGIN Plugin
    );

PHAPPAPI
PPH_STRING
NTAPI
PhGetPluginFileName(
    _In_ PPH_PLUGIN Plugin
    );

_Function_class_(PH_PLUGIN_ENUMERATE)
typedef NTSTATUS (NTAPI PH_PLUGIN_ENUMERATE)(
    _In_ PPH_PLUGIN Information,
    _In_opt_ PVOID Context
    );
typedef PH_PLUGIN_ENUMERATE *PPH_PLUGIN_ENUMERATE;

PHAPPAPI
VOID
NTAPI
PhEnumeratePlugins(
    _In_ PPH_PLUGIN_ENUMERATE Callback,
    _In_opt_ PVOID Context
    );


//
// actions
//

typedef enum _PH_PHSVC_MODE
{
    ElevatedPhSvcMode,
    Wow64PhSvcMode
} PH_PHSVC_MODE;

PHAPPAPI
BOOLEAN
NTAPI
PhUiConnectToPhSvc(
    _In_opt_ HWND hWnd,
    _In_ BOOLEAN ConnectOnly
    );

PHAPPAPI
BOOLEAN
NTAPI
PhUiConnectToPhSvcEx(
    _In_opt_ HWND hWnd,
    _In_ PH_PHSVC_MODE Mode,
    _In_ BOOLEAN ConnectOnly
    );

PHAPPAPI
VOID
NTAPI
PhUiDisconnectFromPhSvc(
    VOID
    );

PHAPPAPI
BOOLEAN
NTAPI
PhUiLockComputer(
    _In_ HWND hWnd
    );

PHAPPAPI
BOOLEAN
NTAPI
PhUiLogoffComputer(
    _In_ HWND hWnd
    );

PHAPPAPI
BOOLEAN
NTAPI
PhUiSleepComputer(
    _In_ HWND hWnd
    );

PHAPPAPI
BOOLEAN
NTAPI
PhUiHibernateComputer(
    _In_ HWND hWnd
    );

typedef enum _PH_POWERACTION_TYPE
{
    PH_POWERACTION_TYPE_NONE,
    PH_POWERACTION_TYPE_WIN32,
    PH_POWERACTION_TYPE_NATIVE,
    PH_POWERACTION_TYPE_CRITICAL,
    PH_POWERACTION_TYPE_ADVANCEDBOOT,
    PH_POWERACTION_TYPE_FIRMWAREBOOT,
    PH_POWERACTION_TYPE_UPDATE,
    PH_POWERACTION_TYPE_WDOSCAN,
    PH_POWERACTION_TYPE_MAXIMUM
} PH_POWERACTION_TYPE;

PHAPPAPI
BOOLEAN
NTAPI
PhUiRestartComputer(
    _In_ HWND WindowHandle,
    _In_ PH_POWERACTION_TYPE Action,
    _In_ ULONG Flags
    );

PHAPPAPI
BOOLEAN
NTAPI
PhUiShutdownComputer(
    _In_ HWND WindowHandle,
    _In_ PH_POWERACTION_TYPE Action,
    _In_ ULONG Flags
    );

PVOID PhUiCreateComputerBootDeviceMenu(
    _In_ BOOLEAN DelayLoadMenu
    );

PVOID PhUiCreateComputerFirmwareDeviceMenu(
    _In_ BOOLEAN DelayLoadMenu
    );

VOID PhUiHandleComputerBootApplicationMenu(
    _In_ HWND WindowHandle,
    _In_ ULONG MenuIndex
    );

VOID PhUiHandleComputerFirmwareApplicationMenu(
    _In_ HWND WindowHandle,
    _In_ ULONG MenuIndex
    );

VOID PhUiCreateSessionMenu(
    _In_ PVOID UsersMenuItem
    );

PHAPPAPI
BOOLEAN
NTAPI
PhUiConnectSession(
    _In_ HWND hWnd,
    _In_ ULONG SessionId
    );

PHAPPAPI
BOOLEAN
NTAPI
PhUiDisconnectSession(
    _In_ HWND hWnd,
    _In_ ULONG SessionId
    );

PHAPPAPI
BOOLEAN
NTAPI
PhUiLogoffSession(
    _In_ HWND hWnd,
    _In_ ULONG SessionId
    );

PHAPPAPI
BOOLEAN
NTAPI
PhUiTerminateProcesses(
    _In_ HWND hWnd,
    _In_ PPH_PROCESS_ITEM *Processes,
    _In_ ULONG NumberOfProcesses
    );

PHAPPAPI
BOOLEAN
NTAPI
PhUiTerminateTreeProcess(
    _In_ HWND hWnd,
    _In_ PPH_PROCESS_ITEM Process
    );

PHAPPAPI
BOOLEAN
NTAPI
PhUiSuspendProcesses(
    _In_ HWND hWnd,
    _In_ PPH_PROCESS_ITEM *Processes,
    _In_ ULONG NumberOfProcesses
    );

PHAPPAPI
BOOLEAN
NTAPI
PhUiSuspendTreeProcess(
    _In_ HWND hWnd,
    _In_ PPH_PROCESS_ITEM Process
    );

PHAPPAPI
BOOLEAN
NTAPI
PhUiResumeProcesses(
    _In_ HWND hWnd,
    _In_ PPH_PROCESS_ITEM *Processes,
    _In_ ULONG NumberOfProcesses
    );

PHAPPAPI
BOOLEAN
NTAPI
PhUiResumeTreeProcess(
    _In_ HWND hWnd,
    _In_ PPH_PROCESS_ITEM Process
    );

PHAPPAPI
BOOLEAN
NTAPI
PhUiFreezeTreeProcess(
    _In_ HWND WindowHandle,
    _In_ PPH_PROCESS_ITEM Process
    );

PHAPPAPI
BOOLEAN
NTAPI
PhUiThawTreeProcess(
    _In_ HWND WindowHandle,
    _In_ PPH_PROCESS_ITEM Process
    );

PHAPPAPI
BOOLEAN
NTAPI
PhUiRestartProcess(
    _In_ HWND hWnd,
    _In_ PPH_PROCESS_ITEM Process
    );

PHAPPAPI
BOOLEAN
NTAPI
PhUiDebugProcess(
    _In_ HWND hWnd,
    _In_ PPH_PROCESS_ITEM Process
    );

PHAPPAPI
BOOLEAN
NTAPI
PhUiReduceWorkingSetProcesses(
    _In_ HWND hWnd,
    _In_ PPH_PROCESS_ITEM *Processes,
    _In_ ULONG NumberOfProcesses
    );

PHAPPAPI
BOOLEAN
NTAPI
PhUiSetVirtualizationProcess(
    _In_ HWND hWnd,
    _In_ PPH_PROCESS_ITEM Process,
    _In_ BOOLEAN Enable
    );

PHAPPAPI
BOOLEAN
NTAPI
PhUiSetCriticalProcess(
    _In_ HWND WindowHandle,
    _In_ PPH_PROCESS_ITEM Process
    );

PHAPPAPI
BOOLEAN
NTAPI
PhUiSetEcoModeProcess(
    _In_ HWND WindowHandle,
    _In_ PPH_PROCESS_ITEM Process
    );

PHAPPAPI
BOOLEAN
NTAPI
PhUiDetachFromDebuggerProcess(
    _In_ HWND hWnd,
    _In_ PPH_PROCESS_ITEM Process
    );

PHAPPAPI
BOOLEAN
NTAPI
PhUiLoadDllProcess(
    _In_ HWND hWnd,
    _In_ PPH_PROCESS_ITEM Process
    );

PHAPPAPI
BOOLEAN
NTAPI
PhUiSetIoPriorityProcesses(
    _In_ HWND hWnd,
    _In_ PPH_PROCESS_ITEM *Processes,
    _In_ ULONG NumberOfProcesses,
    _In_ IO_PRIORITY_HINT IoPriority
    );

PHAPPAPI
BOOLEAN
NTAPI
PhUiSetPagePriorityProcess(
    _In_ HWND hWnd,
    _In_ PPH_PROCESS_ITEM Process,
    _In_ ULONG PagePriority
    );

PHAPPAPI
BOOLEAN
NTAPI
PhUiSetPriorityProcesses(
    _In_ HWND hWnd,
    _In_ PPH_PROCESS_ITEM *Processes,
    _In_ ULONG NumberOfProcesses,
    _In_ ULONG PriorityClass
    );

PHAPPAPI
BOOLEAN
NTAPI
PhUiSetBoostPriorityProcesses(
    _In_ HWND WindowHandle,
    _In_ PPH_PROCESS_ITEM* Processes,
    _In_ ULONG NumberOfProcesses,
    _In_ BOOLEAN PriorityBoost
    );

PHAPPAPI
BOOLEAN
NTAPI
PhUiSetBoostPriorityProcess(
    _In_ HWND hWnd,
    _In_ PPH_PROCESS_ITEM Process,
    _In_ BOOLEAN PriorityBoost
    );

PHAPPAPI
BOOLEAN
NTAPI
PhUiStartServices(
    _In_ HWND WindowHandle,
    _In_ PPH_SERVICE_ITEM* Services,
    _In_ ULONG NumberOfServices
    );

PHAPPAPI
BOOLEAN
NTAPI
PhUiStartService(
    _In_ HWND hWnd,
    _In_ PPH_SERVICE_ITEM Service
    );

PHAPPAPI
BOOLEAN
NTAPI
PhUiContinueServices(
    _In_ HWND WindowHandle,
    _In_ PPH_SERVICE_ITEM* Services,
    _In_ ULONG NumberOfServices
    );

PHAPPAPI
BOOLEAN
NTAPI
PhUiContinueService(
    _In_ HWND hWnd,
    _In_ PPH_SERVICE_ITEM Service
    );

PHAPPAPI
BOOLEAN
NTAPI
PhUiPauseServices(
    _In_ HWND WindowHandle,
    _In_ PPH_SERVICE_ITEM* Services,
    _In_ ULONG NumberOfServices
    );

PHAPPAPI
BOOLEAN
NTAPI
PhUiPauseService(
    _In_ HWND hWnd,
    _In_ PPH_SERVICE_ITEM Service
    );

PHAPPAPI
BOOLEAN
NTAPI
PhUiStopServices(
    _In_ HWND WindowHandle,
    _In_ PPH_SERVICE_ITEM* Services,
    _In_ ULONG NumberOfServices
    );

PHAPPAPI
BOOLEAN
NTAPI
PhUiStopService(
    _In_ HWND hWnd,
    _In_ PPH_SERVICE_ITEM Service
    );

PHAPPAPI
BOOLEAN
NTAPI
PhUiDeleteService(
    _In_ HWND hWnd,
    _In_ PPH_SERVICE_ITEM Service
    );

PHAPPAPI
BOOLEAN
NTAPI
PhUiCloseConnections(
    _In_ HWND hWnd,
    _In_ PPH_NETWORK_ITEM *Connections,
    _In_ ULONG NumberOfConnections
    );

PHAPPAPI
BOOLEAN
NTAPI
PhUiTerminateThreads(
    _In_ HWND hWnd,
    _In_ PPH_THREAD_ITEM *Threads,
    _In_ ULONG NumberOfThreads
    );

PHAPPAPI
BOOLEAN
NTAPI
PhUiSuspendThreads(
    _In_ HWND hWnd,
    _In_ PPH_THREAD_ITEM *Threads,
    _In_ ULONG NumberOfThreads
    );

PHAPPAPI
BOOLEAN
NTAPI
PhUiResumeThreads(
    _In_ HWND hWnd,
    _In_ PPH_THREAD_ITEM *Threads,
    _In_ ULONG NumberOfThreads
    );

PHAPPAPI
BOOLEAN
NTAPI
PhUiSetBoostPriorityThreads(
    _In_ HWND WindowHandle,
    _In_ PPH_THREAD_ITEM* Threads,
    _In_ ULONG NumberOfThreads,
    _In_ BOOLEAN PriorityBoost
    );

PHAPPAPI
BOOLEAN
NTAPI
PhUiSetBoostPriorityThread(
    _In_ HWND hWnd,
    _In_ PPH_THREAD_ITEM Thread,
    _In_ BOOLEAN PriorityBoost
    );

PHAPPAPI
BOOLEAN
NTAPI
PhUiSetPriorityThreads(
    _In_ HWND WindowHandle,
    _In_ PPH_THREAD_ITEM* Threads,
    _In_ ULONG NumberOfThreads,
    _In_ LONG Increment
    );

PHAPPAPI
BOOLEAN
NTAPI
PhUiSetPriorityThread(
    _In_ HWND hWnd,
    _In_ PPH_THREAD_ITEM Thread,
    _In_ LONG Increment
    );

PHAPPAPI
BOOLEAN
NTAPI
PhUiSetIoPriorityThread(
    _In_ HWND hWnd,
    _In_ PPH_THREAD_ITEM Thread,
    _In_ IO_PRIORITY_HINT IoPriority
    );

PHAPPAPI
BOOLEAN
NTAPI
PhUiSetPagePriorityThread(
    _In_ HWND hWnd,
    _In_ PPH_THREAD_ITEM Thread,
    _In_ ULONG PagePriority
    );

PHAPPAPI
BOOLEAN
NTAPI
PhUiUnloadModule(
    _In_ HWND hWnd,
    _In_ HANDLE ProcessId,
    _In_ PPH_MODULE_ITEM Module
    );

PHAPPAPI
BOOLEAN
NTAPI
PhUiFreeMemory(
    _In_ HWND hWnd,
    _In_ HANDLE ProcessId,
    _In_ PPH_MEMORY_ITEM MemoryItem,
    _In_ BOOLEAN Free
    );

PHAPPAPI
BOOLEAN
NTAPI
PhUiCloseHandles(
    _In_ HWND hWnd,
    _In_ HANDLE ProcessId,
    _In_ PPH_HANDLE_ITEM *Handles,
    _In_ ULONG NumberOfHandles,
    _In_ BOOLEAN Warn
    );

PHAPPAPI
BOOLEAN
NTAPI
PhUiSetAttributesHandle(
    _In_ HWND hWnd,
    _In_ HANDLE ProcessId,
    _In_ PPH_HANDLE_ITEM Handle,
    _In_ ULONG Attributes
    );

//
// procprp
//

typedef struct _PH_PROCESS_PROPPAGECONTEXT
{
    PPH_PROCESS_PROPCONTEXT PropContext;
    PVOID Context;
    PROPSHEETPAGE PropSheetPage;

    BOOLEAN LayoutInitialized;
} PH_PROCESS_PROPPAGECONTEXT, *PPH_PROCESS_PROPPAGECONTEXT;

PHAPPAPI
PPH_PROCESS_PROPCONTEXT
NTAPI
PhCreateProcessPropContext(
    _In_opt_ HWND ParentWindowHandle,
    _In_ PPH_PROCESS_ITEM ProcessItem
    );

PHAPPAPI
VOID
NTAPI
PhSetSelectThreadIdProcessPropContext(
    _Inout_ PPH_PROCESS_PROPCONTEXT PropContext,
    _In_ HANDLE ThreadId
    );

PHAPPAPI
BOOLEAN
NTAPI
PhAddProcessPropPage(
    _Inout_ PPH_PROCESS_PROPCONTEXT PropContext,
    _In_ _Assume_refs_(1) PPH_PROCESS_PROPPAGECONTEXT PropPageContext
    );

PHAPPAPI
BOOLEAN
NTAPI
PhAddProcessPropPage2(
    _Inout_ PPH_PROCESS_PROPCONTEXT PropContext,
    _In_ HPROPSHEETPAGE PropSheetPageHandle
    );

PHAPPAPI
PPH_PROCESS_PROPPAGECONTEXT
NTAPI
PhCreateProcessPropPageContext(
    _In_ LPCWSTR Template,
    _In_ DLGPROC DlgProc,
    _In_opt_ PVOID Context
    );

PHAPPAPI
PPH_PROCESS_PROPPAGECONTEXT
NTAPI
PhCreateProcessPropPageContextEx(
    _In_opt_ PVOID InstanceHandle,
    _In_ LPCWSTR Template,
    _In_ DLGPROC DlgProc,
    _In_opt_ PVOID Context
    );

_Success_(return)
PHAPPAPI
BOOLEAN
NTAPI
PhPropPageDlgProcHeader(
    _In_ HWND hwndDlg,
    _In_ UINT uMsg,
    _In_ LPARAM lParam,
    _Out_opt_ LPPROPSHEETPAGE *PropSheetPage,
    _Out_opt_ PPH_PROCESS_PROPPAGECONTEXT *PropPageContext,
    _Out_opt_ PPH_PROCESS_ITEM *ProcessItem
    );

#define PH_PROP_PAGE_TAB_CONTROL_PARENT ((PPH_LAYOUT_ITEM)0x1)

PHAPPAPI
PPH_LAYOUT_ITEM
NTAPI
PhAddPropPageLayoutItem(
    _In_ HWND hwnd,
    _In_ HWND Handle,
    _In_ PPH_LAYOUT_ITEM ParentItem,
    _In_ ULONG Anchor
    );

PHAPPAPI
VOID
NTAPI
PhDoPropPageLayout(
    _In_ HWND hwnd
    );

FORCEINLINE
PPH_LAYOUT_ITEM
PhBeginPropPageLayout(
    _In_ HWND hwndDlg,
    _In_ PPH_PROCESS_PROPPAGECONTEXT PropPageContext
    )
{
    if (!PropPageContext->LayoutInitialized)
    {
        return PhAddPropPageLayoutItem(hwndDlg, hwndDlg,
            PH_PROP_PAGE_TAB_CONTROL_PARENT, PH_ANCHOR_ALL);
    }
    else
    {
        return NULL;
    }
}

FORCEINLINE
VOID
PhEndPropPageLayout(
    _In_ HWND hwndDlg,
    _In_ PPH_PROCESS_PROPPAGECONTEXT PropPageContext
    )
{
    PhDoPropPageLayout(hwndDlg);
    PropPageContext->LayoutInitialized = TRUE;
}

PHAPPAPI
VOID
NTAPI
PhShowProcessProperties(
    _In_ PPH_PROCESS_PROPCONTEXT Context
    );

//
// procprpp
//

typedef struct _PH_THREADS_CONTEXT
{
    PPH_THREAD_PROVIDER Provider;
    PH_CALLBACK_REGISTRATION ProviderRegistration;
    PH_CALLBACK_REGISTRATION AddedEventRegistration;
    PH_CALLBACK_REGISTRATION ModifiedEventRegistration;
    PH_CALLBACK_REGISTRATION RemovedEventRegistration;
    PH_CALLBACK_REGISTRATION UpdatedEventRegistration;
    PH_CALLBACK_REGISTRATION LoadingStateChangedEventRegistration;

    HWND WindowHandle;
            HWND Private; // phapppub
            HWND TreeNewHandle; // phapppub

} PH_THREADS_CONTEXT, *PPH_THREADS_CONTEXT;

typedef struct _PH_MODULES_CONTEXT
{
    PPH_MODULE_PROVIDER Provider;
    PH_PROVIDER_REGISTRATION ProviderRegistration;
    PH_CALLBACK_REGISTRATION AddedEventRegistration;
    PH_CALLBACK_REGISTRATION ModifiedEventRegistration;
    PH_CALLBACK_REGISTRATION RemovedEventRegistration;
    PH_CALLBACK_REGISTRATION UpdatedEventRegistration;

    HWND WindowHandle;
            HWND Private; // phapppub
            HWND TreeNewHandle; // phapppub
} PH_MODULES_CONTEXT, *PPH_MODULES_CONTEXT;

typedef struct _PH_HANDLES_CONTEXT
{
    PPH_HANDLE_PROVIDER Provider;
    PH_PROVIDER_REGISTRATION ProviderRegistration;
    PH_CALLBACK_REGISTRATION AddedEventRegistration;
    PH_CALLBACK_REGISTRATION ModifiedEventRegistration;
    PH_CALLBACK_REGISTRATION RemovedEventRegistration;
    PH_CALLBACK_REGISTRATION UpdatedEventRegistration;

    HWND WindowHandle;

            HWND Private; // phapppub
            HWND TreeNewHandle; // phapppub

} PH_HANDLES_CONTEXT, *PPH_HANDLES_CONTEXT;

typedef struct _PH_MEMORY_CONTEXT
{
    HANDLE ProcessId;
    HWND WindowHandle;

            HWND Private; // phapppub
            HWND TreeNewHandle; // phapppub

} PH_MEMORY_CONTEXT, *PPH_MEMORY_CONTEXT;

//
// phsvccl
//

PHAPPAPI
NTSTATUS PhSvcCallChangeServiceConfig(
    _In_ PWSTR ServiceName,
    _In_ ULONG ServiceType,
    _In_ ULONG StartType,
    _In_ ULONG ErrorControl,
    _In_opt_ PWSTR BinaryPathName,
    _In_opt_ PWSTR LoadOrderGroup,
    _Out_opt_ PULONG TagId,
    _In_opt_ PWSTR Dependencies,
    _In_opt_ PWSTR ServiceStartName,
    _In_opt_ PWSTR Password,
    _In_opt_ PWSTR DisplayName
    );

PHAPPAPI
NTSTATUS PhSvcCallChangeServiceConfig2(
    _In_ PWSTR ServiceName,
    _In_ ULONG InfoLevel,
    _In_ PVOID Info
    );

PHAPPAPI
NTSTATUS PhSvcCallPostMessage(
    _In_opt_ HWND hWnd,
    _In_ UINT Msg,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam
    );

PHAPPAPI
NTSTATUS PhSvcCallSendMessage(
    _In_opt_ HWND hWnd,
    _In_ UINT Msg,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam
    );

#ifdef __cplusplus
}
#endif

#endif
