/*
 * Copyright (c) 2022 Winsider Seminars & Solutions, Inc.  All rights reserved.
 *
 * This file is part of System Informer.
 *
 * Authors:
 *
 *     wj32    2016
 *     dmex    2015-2023
 *
 */

#include "devices.h"

VOID NetAdapterUpdateGraph(
    _Inout_ PDV_NETADAPTER_SYSINFO_CONTEXT Context
    )
{
    Context->GraphState.Valid = FALSE;
    Context->GraphState.TooltipIndex = ULONG_MAX;
    Graph_MoveGrid(Context->GraphHandle, 1);
    Graph_Draw(Context->GraphHandle);
    Graph_UpdateTooltip(Context->GraphHandle);
    InvalidateRect(Context->GraphHandle, NULL, FALSE);
}

VOID NetAdapterUpdatePanel(
    _Inout_ PDV_NETADAPTER_SYSINFO_CONTEXT Context
    )
{
    ULONG64 linkSpeedValue = 0;
    NDIS_MEDIA_CONNECT_STATE mediaState = MediaConnectStateUnknown;
    HANDLE deviceHandle = NULL;
    PH_FORMAT format[2];
    WCHAR formatBuffer[256];

    if (NetAdapterEnableNdis)
    {
        if (NT_SUCCESS(PhCreateFile(
            &deviceHandle,
            &Context->AdapterEntry->AdapterId.InterfacePath->sr,
            FILE_GENERIC_READ,
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT
            )))
        {
            if (!Context->AdapterEntry->CheckedDeviceSupport)
            {
                if (NetworkAdapterQuerySupported(deviceHandle))
                {
                    Context->AdapterEntry->DeviceSupported = TRUE;
                }

                Context->AdapterEntry->CheckedDeviceSupport = TRUE;
            }

            if (!Context->AdapterEntry->DeviceSupported)
            {
                NtClose(deviceHandle);
                deviceHandle = NULL;
            }
        }
    }

    if (deviceHandle)
    {
        NDIS_LINK_STATE interfaceState;

        if (NT_SUCCESS(NetworkAdapterQueryLinkState(deviceHandle, &interfaceState)))
        {
            mediaState = interfaceState.MediaConnectState;
            linkSpeedValue = interfaceState.XmitLinkSpeed;
        }
        else
        {
            NetworkAdapterQueryLinkSpeed(deviceHandle, &linkSpeedValue);
        }

        NtClose(deviceHandle);
    }
    else
    {
        MIB_IF_ROW2 interfaceRow;

        if (NetworkAdapterQueryInterfaceRow(&Context->AdapterEntry->AdapterId, MibIfEntryNormal, &interfaceRow))
        {
            mediaState = interfaceRow.MediaConnectState;
            linkSpeedValue = interfaceRow.TransmitLinkSpeed;
        }
    }

    PhInitFormatSize(&format[0], Context->AdapterEntry->NetworkSendDelta.Value);

    if (PhFormatToBuffer(format, 1, formatBuffer, sizeof(formatBuffer), NULL))
        PhSetWindowText(Context->NetAdapterPanelSentLabel, formatBuffer);
    else
        PhSetWindowText(Context->NetAdapterPanelSentLabel, PhaFormatSize(Context->AdapterEntry->NetworkSendDelta.Value, ULONG_MAX)->Buffer);

    PhInitFormatSize(&format[0], Context->AdapterEntry->NetworkReceiveDelta.Value);

    if (PhFormatToBuffer(format, 1, formatBuffer, sizeof(formatBuffer), NULL))
        PhSetWindowText(Context->NetAdapterPanelReceivedLabel, formatBuffer);
    else
        PhSetWindowText(Context->NetAdapterPanelReceivedLabel, PhaFormatSize(Context->AdapterEntry->NetworkReceiveDelta.Value, ULONG_MAX)->Buffer);

    PhInitFormatSize(&format[0], Context->AdapterEntry->NetworkReceiveDelta.Value + Context->AdapterEntry->NetworkSendDelta.Value);

    if (PhFormatToBuffer(format, 1, formatBuffer, sizeof(formatBuffer), NULL))
        PhSetWindowText(Context->NetAdapterPanelTotalLabel, formatBuffer);
    else
        PhSetWindowText(Context->NetAdapterPanelTotalLabel, PhaFormatSize(Context->AdapterEntry->NetworkReceiveDelta.Value + Context->AdapterEntry->NetworkSendDelta.Value, ULONG_MAX)->Buffer);

    if (mediaState == MediaConnectStateConnected)
    {
        PhSetWindowText(Context->NetAdapterPanelStateLabel, L"Connected");

        //PhInitFormatSR(&format[0], PH_AUTO_T(PH_STRING, NetAdapterFormatBitratePrefix(linkSpeedValue))->sr);
        PhInitFormatSize(&format[0], linkSpeedValue / BITS_IN_ONE_BYTE);
        PhInitFormatS(&format[1], L"/s");

        if (PhFormatToBuffer(format, 2, formatBuffer, sizeof(formatBuffer), NULL))
            PhSetWindowText(Context->NetAdapterPanelSpeedLabel, formatBuffer);
        else
        {
            PhSetWindowText(Context->NetAdapterPanelSpeedLabel, PhaConcatStrings2(
                PhaFormatSize(linkSpeedValue / BITS_IN_ONE_BYTE, ULONG_MAX)->Buffer,
                L"/s"
                )->Buffer);
            //PhSetWindowText(Context->NetAdapterPanelSpeedLabel, PH_AUTO_T(PH_STRING, NetAdapterFormatBitratePrefix(linkSpeedValue))->Buffer);
        }
    }
    else
    {
        PhSetWindowText(Context->NetAdapterPanelStateLabel, L"Disconnected");
        PhSetWindowText(Context->NetAdapterPanelSpeedLabel, L"N/A");
    }

    //PhInitFormatSR(&format[0], PH_AUTO_T(PH_STRING, NetAdapterFormatBitratePrefix((Context->AdapterEntry->CurrentNetworkReceive + Context->AdapterEntry->CurrentNetworkSend) * BITS_IN_ONE_BYTE))->sr);
    PhInitFormatSize(&format[0], Context->AdapterEntry->CurrentNetworkReceive + Context->AdapterEntry->CurrentNetworkSend);
    PhInitFormatS(&format[1], L"/s");

    if (PhFormatToBuffer(format, 2, formatBuffer, sizeof(formatBuffer), NULL))
        PhSetWindowText(Context->NetAdapterPanelBytesLabel, formatBuffer);
    else
    {
        PhSetWindowText(Context->NetAdapterPanelBytesLabel, PhaFormatString(
            L"%s/s",
            PhaFormatSize(Context->AdapterEntry->CurrentNetworkReceive + Context->AdapterEntry->CurrentNetworkSend, ULONG_MAX)->Buffer)->Buffer
            );
        //PhSetWindowText(Context->NetAdapterPanelBytesLabel, PH_AUTO_T(PH_STRING, NetAdapterFormatBitratePrefix((Context->AdapterEntry->CurrentNetworkReceive + Context->AdapterEntry->CurrentNetworkSend)* BITS_IN_ONE_BYTE))->Buffer);
    }
}

VOID NetAdapterUpdateTitle(
    _In_ PDV_NETADAPTER_SYSINFO_CONTEXT Context
    )
{
    if (Context->AdapterEntry->PendingQuery)
    {
        if (Context->AdapterTextLabel)
            PhSetWindowText(Context->AdapterTextLabel, L"Pending...");
        if (Context->AdapterNameLabel)
            PhSetWindowText(Context->AdapterNameLabel, L"Pending...");
    }
    else
    {
        if (Context->AdapterTextLabel)
            PhSetWindowText(Context->AdapterTextLabel, PhGetStringOrDefault(Context->AdapterEntry->AdapterAlias, L"Unknown network adapter"));
        if (Context->AdapterNameLabel)
            PhSetWindowText(Context->AdapterNameLabel, PhGetStringOrDefault(Context->AdapterEntry->AdapterName, L"Unknown network adapter"));
    }
}

VOID NetAdapterUpdateAdapterNameText(
    _In_ PDV_NETADAPTER_ENTRY AdapterEntry
    )
{
    NetAdapterUpdateDeviceInfo(NULL, AdapterEntry);
}

INT_PTR CALLBACK NetAdapterPanelDialogProc(
    _In_ HWND hwndDlg,
    _In_ UINT uMsg,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam
    )
{
    PDV_NETADAPTER_SYSINFO_CONTEXT context = NULL;

    if (uMsg == WM_INITDIALOG)
    {
        context = (PDV_NETADAPTER_SYSINFO_CONTEXT)lParam;

        PhSetWindowContext(hwndDlg, PH_WINDOW_CONTEXT_DEFAULT, context);
    }
    else
    {
        context = PhGetWindowContext(hwndDlg, PH_WINDOW_CONTEXT_DEFAULT);
    }

    if (context == NULL)
        return FALSE;

    switch (uMsg)
    {
    case WM_INITDIALOG:
        {
            context->NetAdapterPanelSentLabel = GetDlgItem(hwndDlg, IDC_STAT_BSENT);
            context->NetAdapterPanelReceivedLabel = GetDlgItem(hwndDlg, IDC_STAT_BRECEIVED);
            context->NetAdapterPanelTotalLabel = GetDlgItem(hwndDlg, IDC_STAT_BTOTAL);
            context->NetAdapterPanelStateLabel = GetDlgItem(hwndDlg, IDC_LINK_STATE);
            context->NetAdapterPanelSpeedLabel = GetDlgItem(hwndDlg, IDC_LINK_SPEED);
            context->NetAdapterPanelBytesLabel = GetDlgItem(hwndDlg, IDC_STAT_BYTESDELTA);
        }
        break;
    case WM_NCDESTROY:
        {
            PhRemoveWindowContext(hwndDlg, PH_WINDOW_CONTEXT_DEFAULT);
        }
        break;
    case WM_COMMAND:
        {
            switch (GET_WM_COMMAND_ID(wParam, lParam))
            {
            case IDC_DETAILS:
                ShowNetAdapterDetailsDialog(context);
                break;
            }
        }
        break;
    case WM_CTLCOLORBTN:
        return HANDLE_WM_CTLCOLORBTN(hwndDlg, wParam, lParam, PhWindowThemeControlColor);
    case WM_CTLCOLORDLG:
        return HANDLE_WM_CTLCOLORDLG(hwndDlg, wParam, lParam, PhWindowThemeControlColor);
    case WM_CTLCOLORSTATIC:
        return HANDLE_WM_CTLCOLORSTATIC(hwndDlg, wParam, lParam, PhWindowThemeControlColor);
    }

    return FALSE;
}

VOID NetAdapterCreateGraph(
    _Inout_ PDV_NETADAPTER_SYSINFO_CONTEXT Context
    )
{
    Context->GraphHandle = CreateWindow(
        PH_GRAPH_CLASSNAME,
        NULL,
        WS_VISIBLE | WS_CHILD | WS_BORDER,
        0,
        0,
        3,
        3,
        Context->WindowHandle,
        NULL,
        NULL,
        NULL
        );
    Graph_SetTooltip(Context->GraphHandle, TRUE);

    PhAddLayoutItemEx(&Context->LayoutManager, Context->GraphHandle, NULL, PH_ANCHOR_ALL, Context->GraphMargin);
}

VOID NetAdapterTickDialog(
    _Inout_ PDV_NETADAPTER_SYSINFO_CONTEXT Context
    )
{
    NetAdapterUpdateGraph(Context);
    NetAdapterUpdatePanel(Context);
}

INT_PTR CALLBACK NetAdapterDialogProc(
    _In_ HWND hwndDlg,
    _In_ UINT uMsg,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam
    )
{
    PDV_NETADAPTER_SYSINFO_CONTEXT context = NULL;

    if (uMsg == WM_INITDIALOG)
    {
        context = (PDV_NETADAPTER_SYSINFO_CONTEXT)lParam;
        PhSetWindowContext(hwndDlg, PH_WINDOW_CONTEXT_DEFAULT, context);
    }
    else
    {
        context = PhGetWindowContext(hwndDlg, PH_WINDOW_CONTEXT_DEFAULT);
    }

    if (context == NULL)
        return FALSE;

    switch (uMsg)
    {
    case WM_INITDIALOG:
        {
            PPH_LAYOUT_ITEM graphItem;
            PPH_LAYOUT_ITEM panelItem;
            RECT margin;

            context->WindowHandle = hwndDlg;
            context->AdapterTextLabel = GetDlgItem(hwndDlg, IDC_ADAPTERTEXT);
            context->AdapterNameLabel = GetDlgItem(hwndDlg, IDC_ADAPTERNAME);

            PhInitializeGraphState(&context->GraphState);
            PhInitializeLayoutManager(&context->LayoutManager, hwndDlg);

            PhAddLayoutItem(&context->LayoutManager, context->AdapterTextLabel, NULL, PH_ANCHOR_LEFT | PH_ANCHOR_TOP | PH_ANCHOR_RIGHT | PH_LAYOUT_FORCE_INVALIDATE);
            PhAddLayoutItem(&context->LayoutManager, context->AdapterNameLabel, NULL, PH_ANCHOR_TOP | PH_ANCHOR_RIGHT | PH_LAYOUT_FORCE_INVALIDATE);
            graphItem = PhAddLayoutItem(&context->LayoutManager, GetDlgItem(hwndDlg, IDC_GRAPH_LAYOUT), NULL, PH_ANCHOR_ALL);
            panelItem = PhAddLayoutItem(&context->LayoutManager, GetDlgItem(hwndDlg, IDC_LAYOUT), NULL, PH_ANCHOR_LEFT | PH_ANCHOR_RIGHT | PH_ANCHOR_BOTTOM);
            context->GraphMargin = graphItem->Margin;
            PhGetSizeDpiValue(&context->GraphMargin, context->SysinfoSection->Parameters->WindowDpi, TRUE);

            SetWindowFont(context->AdapterTextLabel, context->SysinfoSection->Parameters->LargeFont, FALSE);
            SetWindowFont(context->AdapterNameLabel, context->SysinfoSection->Parameters->MediumFont, FALSE);

            context->PanelWindowHandle = PhCreateDialog(PluginInstance->DllBase, MAKEINTRESOURCE(IDD_NETADAPTER_PANEL), hwndDlg, NetAdapterPanelDialogProc, context);
            ShowWindow(context->PanelWindowHandle, SW_SHOW);

            margin = panelItem->Margin;
            PhGetSizeDpiValue(&margin, context->SysinfoSection->Parameters->WindowDpi, TRUE);
            PhAddLayoutItemEx(&context->LayoutManager, context->PanelWindowHandle, NULL, PH_ANCHOR_LEFT | PH_ANCHOR_RIGHT | PH_ANCHOR_BOTTOM, margin);

            NetAdapterUpdateTitle(context);
            NetAdapterCreateGraph(context);
            NetAdapterUpdateGraph(context);
            NetAdapterUpdatePanel(context);
        }
        break;
    case WM_DESTROY:
        {
            PhDeleteLayoutManager(&context->LayoutManager);
            PhDeleteGraphState(&context->GraphState);

            if (context->GraphHandle)
                DestroyWindow(context->GraphHandle);
            if (context->PanelWindowHandle)
                DestroyWindow(context->PanelWindowHandle);
        }
        break;
    case WM_NCDESTROY:
        {
            PhRemoveWindowContext(hwndDlg, PH_WINDOW_CONTEXT_DEFAULT);
        }
        break;
    case WM_DPICHANGED_AFTERPARENT:
        {
            if (context->SysinfoSection->Parameters->LargeFont)
            {
                SetWindowFont(context->AdapterTextLabel, context->SysinfoSection->Parameters->LargeFont, FALSE);
            }

            if (context->SysinfoSection->Parameters->MediumFont)
            {
                SetWindowFont(context->AdapterNameLabel, context->SysinfoSection->Parameters->MediumFont, FALSE);
            }

            context->GraphState.Valid = FALSE;
            context->GraphState.TooltipIndex = ULONG_MAX;
            PhLayoutManagerLayout(&context->LayoutManager);
        }
        break;
    case WM_SIZE:
        {
            context->GraphState.Valid = FALSE;
            context->GraphState.TooltipIndex = ULONG_MAX;
            PhLayoutManagerLayout(&context->LayoutManager);
        }
        break;
    case WM_NOTIFY:
        {
            NMHDR* header = (NMHDR*)lParam;

            if (header->hwndFrom == context->GraphHandle)
            {
                switch (header->code)
                {
                case GCN_GETDRAWINFO:
                    {
                        PPH_GRAPH_GETDRAWINFO getDrawInfo = (PPH_GRAPH_GETDRAWINFO)header;
                        PPH_GRAPH_DRAW_INFO drawInfo = getDrawInfo->DrawInfo;

                        drawInfo->Flags = PH_GRAPH_USE_GRID_X | PH_GRAPH_USE_GRID_Y | PH_GRAPH_LABEL_MAX_Y | PH_GRAPH_USE_LINE_2;
                        context->SysinfoSection->Parameters->ColorSetupFunction(drawInfo, PhGetIntegerSetting(L"ColorIoReadOther"), PhGetIntegerSetting(L"ColorIoWrite"), context->SysinfoSection->Parameters->WindowDpi);

                        PhGraphStateGetDrawInfo(
                            &context->GraphState,
                            getDrawInfo,
                            context->AdapterEntry->InboundBuffer.Count
                            );

                        if (!context->GraphState.Valid)
                        {
                            ULONG i;
                            FLOAT max = 4 * 1024; // Minimum scaling 4KB

                            for (i = 0; i < drawInfo->LineDataCount; i++)
                            {
                                FLOAT data1;
                                FLOAT data2;

                                context->GraphState.Data1[i] = data1 = (FLOAT)PhGetItemCircularBuffer_ULONG64(&context->AdapterEntry->InboundBuffer, i);
                                context->GraphState.Data2[i] = data2 = (FLOAT)PhGetItemCircularBuffer_ULONG64(&context->AdapterEntry->OutboundBuffer, i);

                                if (max < data1 + data2)
                                    max = data1 + data2;
                            }

                            if (max != 0)
                            {
                                // Scale the data.

                                PhDivideSinglesBySingle(
                                    context->GraphState.Data1,
                                    max,
                                    drawInfo->LineDataCount
                                    );
                                PhDivideSinglesBySingle(
                                    context->GraphState.Data2,
                                    max,
                                    drawInfo->LineDataCount
                                    );
                            }

                            drawInfo->LabelYFunction = PhSiSizeLabelYFunction;
                            drawInfo->LabelYFunctionParameter = max;

                            context->GraphState.Valid = TRUE;
                        }
                    }
                    break;
                case GCN_GETTOOLTIPTEXT:
                    {
                        PPH_GRAPH_GETTOOLTIPTEXT getTooltipText = (PPH_GRAPH_GETTOOLTIPTEXT)header;

                        if (getTooltipText->Index < getTooltipText->TotalCount)
                        {
                            if (context->GraphState.TooltipIndex != getTooltipText->Index)
                            {
                                ULONG64 adapterInboundValue;
                                ULONG64 adapterOutboundValue;
                                PH_FORMAT format[6];

                                adapterInboundValue = PhGetItemCircularBuffer_ULONG64(
                                    &context->AdapterEntry->InboundBuffer,
                                    getTooltipText->Index
                                    );

                                adapterOutboundValue = PhGetItemCircularBuffer_ULONG64(
                                    &context->AdapterEntry->OutboundBuffer,
                                    getTooltipText->Index
                                    );

                                // R: %s\nS: %s\n%s
                                PhInitFormatS(&format[0], L"R: ");
                                PhInitFormatSize(&format[1], adapterInboundValue);
                                PhInitFormatS(&format[2], L"\nS: ");
                                PhInitFormatSize(&format[3], adapterOutboundValue);
                                PhInitFormatC(&format[4], L'\n');
                                PhInitFormatSR(&format[5], PH_AUTO_T(PH_STRING, PhGetStatisticsTimeString(NULL, getTooltipText->Index))->sr);

                                PhMoveReference(&context->GraphState.TooltipText, PhFormat(format, RTL_NUMBER_OF(format), 0));
                            }

                            getTooltipText->Text = PhGetStringRef(context->GraphState.TooltipText);
                        }
                    }
                    break;
                }
            }
        }
        break;
    case WM_CTLCOLORBTN:
        return HANDLE_WM_CTLCOLORBTN(hwndDlg, wParam, lParam, PhWindowThemeControlColor);
    case WM_CTLCOLORDLG:
        return HANDLE_WM_CTLCOLORDLG(hwndDlg, wParam, lParam, PhWindowThemeControlColor);
    case WM_CTLCOLORSTATIC:
        return HANDLE_WM_CTLCOLORSTATIC(hwndDlg, wParam, lParam, PhWindowThemeControlColor);
    }

    return FALSE;
}

NTSTATUS NetAdapterQueryNameWorkQueueItem(
    _In_ PDV_NETADAPTER_ENTRY AdapterEntry
    )
{
    // Update the adapter aliases, index and guids (dmex)
    NetAdapterUpdateAdapterNameText(AdapterEntry);

#ifdef FORCE_DELAY_LABEL_WORKQUEUE
    PhDelayExecution(4000);
#endif

    InterlockedExchange(&AdapterEntry->JustProcessed, TRUE);
    AdapterEntry->PendingQuery = FALSE;

    PhDereferenceObject(AdapterEntry);
    return STATUS_SUCCESS;
}

VOID NetAdapterQueueNameUpdate(
    _In_ PDV_NETADAPTER_ENTRY AdapterEntry
    )
{
    AdapterEntry->PendingQuery = TRUE;

    PhReferenceObject(AdapterEntry);
    PhQueueItemWorkQueue(PhGetGlobalWorkQueue(), NetAdapterQueryNameWorkQueueItem, AdapterEntry);
}

BOOLEAN NetAdapterSectionCallback(
    _In_ PPH_SYSINFO_SECTION Section,
    _In_ PH_SYSINFO_SECTION_MESSAGE Message,
    _In_ PVOID Parameter1,
    _In_ PVOID Parameter2
    )
{
    PDV_NETADAPTER_SYSINFO_CONTEXT context = (PDV_NETADAPTER_SYSINFO_CONTEXT)Section->Context;

    switch (Message)
    {
    case SysInfoCreate:
        {
            NetAdapterQueueNameUpdate(context->AdapterEntry);
        }
        return TRUE;
    case SysInfoDestroy:
        {
            PhDereferenceObject(context->AdapterEntry);
            PhFree(context);
        }
        return TRUE;
    case SysInfoTick:
        {
            if (context->WindowHandle)
            {
                if (context->AdapterEntry->JustProcessed)
                {
                    NetAdapterUpdateTitle(context);
                    InterlockedExchange(&context->AdapterEntry->JustProcessed, FALSE);
                }

                NetAdapterTickDialog(context);
            }
        }
        return TRUE;
    case SysInfoViewChanging:
        {
            PH_SYSINFO_VIEW_TYPE view = (PH_SYSINFO_VIEW_TYPE)PtrToUlong(Parameter1);
            PPH_SYSINFO_SECTION section = (PPH_SYSINFO_SECTION)Parameter2;

            if (view == SysInfoSummaryView || section != Section)
                return TRUE;

            if (context->GraphHandle)
            {
                context->GraphState.Valid = FALSE;
                context->GraphState.TooltipIndex = ULONG_MAX;
                Graph_Draw(context->GraphHandle);
            }
        }
        return TRUE;
    case SysInfoCreateDialog:
        {
            PPH_SYSINFO_CREATE_DIALOG createDialog = (PPH_SYSINFO_CREATE_DIALOG)Parameter1;

            createDialog->Instance = PluginInstance->DllBase;
            createDialog->Template = MAKEINTRESOURCE(IDD_NETADAPTER_DIALOG);
            createDialog->DialogProc = NetAdapterDialogProc;
            createDialog->Parameter = context;
        }
        return TRUE;
    case SysInfoGraphGetDrawInfo:
        {
            PPH_GRAPH_DRAW_INFO drawInfo = (PPH_GRAPH_DRAW_INFO)Parameter1;

            drawInfo->Flags = PH_GRAPH_USE_GRID_X | PH_GRAPH_USE_GRID_Y | PH_GRAPH_LABEL_MAX_Y | PH_GRAPH_USE_LINE_2;
            Section->Parameters->ColorSetupFunction(drawInfo, PhGetIntegerSetting(L"ColorIoReadOther"), PhGetIntegerSetting(L"ColorIoWrite"), Section->Parameters->WindowDpi);
            PhGetDrawInfoGraphBuffers(&Section->GraphState.Buffers, drawInfo, context->AdapterEntry->InboundBuffer.Count);

            if (!Section->GraphState.Valid)
            {
                FLOAT max = 4 * 1024; // Minimum scaling 4KB

                for (ULONG i = 0; i < drawInfo->LineDataCount; i++)
                {
                    FLOAT data1;
                    FLOAT data2;

                    Section->GraphState.Data1[i] = data1 = (FLOAT)PhGetItemCircularBuffer_ULONG64(&context->AdapterEntry->InboundBuffer, i);
                    Section->GraphState.Data2[i] = data2 = (FLOAT)PhGetItemCircularBuffer_ULONG64(&context->AdapterEntry->OutboundBuffer, i);

                    if (max < data1 + data2)
                        max = data1 + data2;
                }

                if (max != 0)
                {
                    // Scale the data.

                    PhDivideSinglesBySingle(
                        Section->GraphState.Data1,
                        max,
                        drawInfo->LineDataCount
                        );
                    PhDivideSinglesBySingle(
                        Section->GraphState.Data2,
                        max,
                        drawInfo->LineDataCount
                        );
                }

                drawInfo->LabelYFunction = PhSiSizeLabelYFunction;
                drawInfo->LabelYFunctionParameter = max;

                Section->GraphState.Valid = TRUE;
            }
        }
        return TRUE;
    case SysInfoGraphGetTooltipText:
        {
            PPH_SYSINFO_GRAPH_GET_TOOLTIP_TEXT getTooltipText = (PPH_SYSINFO_GRAPH_GET_TOOLTIP_TEXT)Parameter1;
            ULONG64 adapterInboundValue;
            ULONG64 adapterOutboundValue;
            PH_FORMAT format[6];

            adapterInboundValue = PhGetItemCircularBuffer_ULONG64(
                &context->AdapterEntry->InboundBuffer,
                getTooltipText->Index
                );

            adapterOutboundValue = PhGetItemCircularBuffer_ULONG64(
                &context->AdapterEntry->OutboundBuffer,
                getTooltipText->Index
                );

            // R: %s\nS: %s\n%s
            PhInitFormatS(&format[0], L"R: ");
            PhInitFormatSize(&format[1], adapterInboundValue);
            PhInitFormatS(&format[2], L"\nS: ");
            PhInitFormatSize(&format[3], adapterOutboundValue);
            PhInitFormatC(&format[4], L'\n');
            PhInitFormatSR(&format[5], PH_AUTO_T(PH_STRING, PhGetStatisticsTimeString(NULL, getTooltipText->Index))->sr);

            PhMoveReference(&Section->GraphState.TooltipText, PhFormat(format, RTL_NUMBER_OF(format), 0));
            getTooltipText->Text = PhGetStringRef(Section->GraphState.TooltipText);
        }
        return TRUE;
    case SysInfoGraphDrawPanel:
        {
            PPH_SYSINFO_DRAW_PANEL drawPanel = (PPH_SYSINFO_DRAW_PANEL)Parameter1;
            PH_FORMAT format[4];

            if (context->AdapterEntry->PendingQuery)
                PhMoveReference(&drawPanel->Title, PhCreateString(L"Pending..."));
            else
            {
                if (context->AdapterEntry->AdapterAlias)
                    PhSetReference(&drawPanel->Title, context->AdapterEntry->AdapterAlias);
                else
                    PhSetReference(&drawPanel->Title, context->AdapterEntry->AdapterName);
            }

            if (!drawPanel->Title)
                drawPanel->Title = PhCreateString(L"Unknown network adapter");

            // R: %s\nS: %s
            PhInitFormatS(&format[0], L"R: ");
            PhInitFormatSize(&format[1], context->AdapterEntry->CurrentNetworkReceive);
            PhInitFormatS(&format[2], L"\nS: ");
            PhInitFormatSize(&format[3], context->AdapterEntry->CurrentNetworkSend);

            drawPanel->SubTitle = PhFormat(format, RTL_NUMBER_OF(format), 0);
        }
        return TRUE;
    }

    return FALSE;
}

VOID NetAdapterSysInfoInitializing(
    _In_ PPH_PLUGIN_SYSINFO_POINTERS Pointers,
    _In_ _Assume_refs_(1) PDV_NETADAPTER_ENTRY AdapterEntry
    )
{
    PDV_NETADAPTER_SYSINFO_CONTEXT context;
    PH_SYSINFO_SECTION section;

    context = PhAllocateZero(sizeof(DV_NETADAPTER_SYSINFO_CONTEXT));
    context->AdapterEntry = PhReferenceObject(AdapterEntry);
    context->AdapterEntry->PendingQuery = TRUE;

    memset(&section, 0, sizeof(PH_SYSINFO_SECTION));
    section.Context = context;
    section.Callback = NetAdapterSectionCallback;
    PhInitializeStringRef(&section.Name, L"NetAdapter");

    context->SysinfoSection = Pointers->CreateSection(&section);
}
