#ifndef _TOOLSTATUSINTF_H
#define _TOOLSTATUSINTF_H

#define TOOLSTATUS_PLUGIN_NAME L"ProcessHacker.ToolStatus"
#define TOOLSTATUS_INTERFACE_VERSION 1

typedef PPH_STRING (NTAPI *PTOOLSTATUS_GET_SEARCHBOX_TEXT)(
    VOID
    );

typedef BOOLEAN (NTAPI *PTOOLSTATUS_WORD_MATCH)(
    _In_ PPH_STRINGREF Text
    );

typedef VOID (NTAPI *PTOOLSTATUS_REGISTER_TAB_SEARCH)(
    _In_ INT TabIndex,
    _In_ PWSTR BannerText
    );

typedef VOID (NTAPI *PTOOLSTATUS_TAB_ACTIVATE_CONTENT)(
    _In_ BOOLEAN Select
    );

typedef HWND (NTAPI *PTOOLSTATUS_GET_TREENEW_HANDLE)(
    VOID
    );

typedef struct _TOOLSTATUS_TAB_INFO
{
    PWSTR BannerText;
    PTOOLSTATUS_TAB_ACTIVATE_CONTENT ActivateContent;
    PTOOLSTATUS_GET_TREENEW_HANDLE GetTreeNewHandle;
} TOOLSTATUS_TAB_INFO, *PTOOLSTATUS_TAB_INFO;

typedef PTOOLSTATUS_TAB_INFO (NTAPI *PTOOLSTATUS_REGISTER_TAB_INFO)(
    _In_ INT TabIndex
    );

#define TOOLSTATUS_GRAPH_ENABLED 0x1
#define TOOLSTATUS_GRAPH_UNAVAILABLE 0x2

typedef struct _PH_TOOLBAR_GRAPH* PPH_TOOLBAR_GRAPH;
typedef struct _PH_PLUGIN* PPH_PLUGIN;

#define TOOLSTATUS_GRAPH_MESSAGE_CALLBACK_DECLARE(ToolStatusGraphCallbackName) \
VOID ToolStatusGraphCallbackName( \
    _In_ PPH_TOOLBAR_GRAPH Graph, \
    _In_ HWND GraphHandle, \
    _In_ PPH_GRAPH_STATE GraphState, \
    _In_ LPNMHDR Header, \
    _In_ PVOID Context \
    )

typedef VOID (NTAPI *PTOOLSTATUS_GRAPH_MESSAGE_CALLBACK)(
    _In_ PPH_TOOLBAR_GRAPH Graph,
    _In_ HWND GraphHandle,
    _In_ PPH_GRAPH_STATE GraphState,
    _In_ LPNMHDR Header,
    _In_opt_ PVOID Context
    );

typedef VOID (NTAPI *PTOOLSTATUS_REGISTER_TOOLBAR_GRAPH)(
    _In_ PPH_PLUGIN Plugin,
    _In_ ULONG Id,
    _In_ PWSTR Text,
    _In_ ULONG Flags,
    _In_opt_ PVOID Context,
    _In_opt_ PTOOLSTATUS_GRAPH_MESSAGE_CALLBACK MessageCallback
    );

typedef struct _TOOLSTATUS_INTERFACE
{
    ULONG Version;
    PTOOLSTATUS_GET_SEARCHBOX_TEXT GetSearchboxText;
    PTOOLSTATUS_WORD_MATCH WordMatch;
    PTOOLSTATUS_REGISTER_TAB_SEARCH RegisterTabSearchDeprecated;
    PPH_CALLBACK SearchChangedEvent;
    PTOOLSTATUS_REGISTER_TAB_INFO RegisterTabInfo;
    PTOOLSTATUS_REGISTER_TOOLBAR_GRAPH RegisterToolbarGraph;
} TOOLSTATUS_INTERFACE, *PTOOLSTATUS_INTERFACE;

#endif
