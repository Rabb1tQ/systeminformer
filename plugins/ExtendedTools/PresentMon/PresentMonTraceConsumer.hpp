// Copyright (C) 2017-2021 Intel Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include "TraceConsumer.hpp"

enum class PresentMode
{
    Unknown = 0,
    Hardware_Legacy_Flip = 1,
    Hardware_Legacy_Copy_To_Front_Buffer = 2,
    Hardware_Independent_Flip = 3,
    Composed_Flip = 4,
    Composed_Copy_GPU_GDI = 5,
    Composed_Copy_CPU_GDI = 6,
    /*
    Composed_Composition_Atlas = 7,
    */
    Hardware_Composed_Independent_Flip = 8,
};

enum class PresentResult
{
    Unknown = 0,
    Presented = 1,
    Discarded = 2,
};

enum class Runtime
{
    Other = 0,
    DXGI = 1,
    D3D9 = 2,
};

struct PresentEvent
{
    ULONGLONG PresentStartTime;       // QPC value of the first event related to the Present (D3D9, DXGI, or DXGK Present_Start)
    ULONG ProcessId;     // ID of the process that presented
    ULONG ThreadId;      // ID of the thread that presented
    ULONGLONG PresentStopTime;     // QPC duration between runtime present start and end
    ULONGLONG ReadyTime;     // QPC value when the last GPU commands completed prior to presentation
    ULONGLONG ScreenTime;    // QPC value when the present was displayed on screen

    // Extra present parameters obtained through DXGI or D3D9 present
    ULONGLONG SwapChainAddress;
    LONG SyncInterval;
    ULONG PresentFlags;

    // Keys used to index into PMTraceConsumer's tracking data structures:
    ULONGLONG CompositionSurfaceLuid;      // mPresentByWin32KPresentHistoryToken
    ULONGLONG Win32KPresentCount;          // mPresentByWin32KPresentHistoryToken
    ULONGLONG Win32KBindId;                // mPresentByWin32KPresentHistoryToken
    ULONGLONG DxgkPresentHistoryToken;     // mPresentByDxgkPresentHistoryToken
    ULONGLONG DxgkPresentHistoryTokenData; // mPresentByDxgkPresentHistoryTokenData
    ULONGLONG DxgkContext;                 // mPresentByDxgkContext
    ULONGLONG Hwnd;                        // mLastPresentByWindow
    ULONG QueueSubmitSequence;         // mPresentBySubmitSequence
    ULONG mAllPresentsTrackingIndex;   // mAllPresents.
    // Note: the following index tracking structures as well but are defined elsewhere:
    //       ProcessId                 -> mOrderedPresentsByProcessId
    //       ThreadId, DriverThreadId  -> mPresentByThreadId
    //       PresentInDwmWaitingStruct -> mPresentsWaitingForDWM

    // How many PresentStop events from the thread to wait for before
    // enqueueing this present.
    ULONG DeferredCompletionWaitCount;

    // Properties deduced by watching events through present pipeline
    ULONG DestWidth;
    ULONG DestHeight;
    ULONG DriverThreadId;    // If the present is deferred by the driver, this will hold the

    Runtime Runtime;
    PresentMode PresentMode;
    PresentResult FinalState;

    union
    {
        ULONG Flags;
        struct
        {
            ULONG SupportsTearing : 1;
            ULONG WaitForFlipEvent : 1;
            ULONG WaitForMPOFlipEvent : 1;
            ULONG SeenDxgkPresent : 1;
            ULONG SeenWin32KEvents : 1;
            ULONG DwmNotified : 1;
            ULONG SeenInFrameEvent : 1;          // This present has gotten a Win32k TokenStateChanged event into InFrame state
            ULONG IsCompleted : 1;               // All expected events have been observed
            ULONG IsLost : 1;                    // This PresentEvent was found in an unexpected state or is too old
            ULONG PresentInDwmWaitingStruct : 1; // Whether this PresentEvent is currently stored in PMTraceConsumer::mPresentsWaitingForDWM
            ULONG Spare : 22;
        };
    };

    // Additional transient tracking state
    std::deque<std::shared_ptr<PresentEvent>> DependentPresents;

    PresentEvent();

private:
    PresentEvent(PresentEvent const& copy); // dne
};

using OrderedPresents = std::map<ULONGLONG, std::shared_ptr<PresentEvent>>;

struct DeferredCompletions
{
    OrderedPresents mOrderedPresents;
    ULONGLONG mLastEnqueuedQpcTime = 0;
};

// A high-level description of the sequence of events for each present type,
// ignoring runtime end:
//
// Hardware Legacy Flip:
//   Runtime PresentStart -> Flip (by thread/process, for classification) -> QueueSubmit (by thread, for submit sequence) ->
//   MMIOFlip (by submit sequence, for ready time and immediate flags) [-> VSyncDPC (by submit sequence, for screen time)]
//
// Composed Flip (FLIP_SEQUENTIAL, FLIP_DISCARD, FlipEx):
//   Runtime PresentStart -> TokenCompositionSurfaceObject (by thread/process, for classification and token key) ->
//   PresentHistoryDetailed (by thread, for token ptr) -> QueueSubmit (by thread, for submit sequence) ->
//   DxgKrnl_PresentHistory (by token ptr, for ready time) and TokenStateChanged (by token key, for discard status and intent to present) ->
//   DWM Present (consumes most recent present per hWnd, marks DWM thread ID) ->
//   A fullscreen present is issued by DWM, and when it completes, this present is on screen
//
// Hardware Direct Flip:
//   N/A, not currently uniquely detectable (follows the same path as composed flip)
//
// Hardware Independent Flip:
//   Follows composed flip, TokenStateChanged indicates IndependentFlip -> MMIOFlip (by submit sequence, for immediate flags)
//   [-> VSyncDPC or HSyncDPC (by submit sequence, for screen time)]
//
// Hardware Composed Independent Flip:
//   Identical to hardware independent flip, but VSyncDPCMPO and HSyncDPCMPO contains more than one valid plane and SubmitSequence.
//
// Composed Copy with GPU GDI (a.k.a. Win7 Blit):
//   Runtime PresentStart -> DxgKrnl_Blit (by thread/process, for classification) ->
//   DxgKrnl_PresentHistoryDetailed (by thread, for token ptr and classification) -> DxgKrnl_Present (by thread, for hWnd) ->
//   DxgKrnl_PresentHistory (by token ptr, for ready time) -> DWM UpdateWindow (by hWnd, marks hWnd active for composition) ->
//   DWM Present (consumes most recent present per hWnd, marks DWM thread ID) ->
//   A fullscreen present is issued by DWM, and when it completes, this present is on screen
//
// Hardware Copy to front buffer:
//   Runtime PresentStart -> DxgKrnl_Blit (by thread/process, for classification) -> QueueSubmit (by thread, for submit sequence) ->
//   QueueComplete (by submit sequence, indicates ready and screen time)
//   Distinction between FS and windowed blt is done by LACK of other events
//
// Composed Copy with CPU GDI (a.k.a. Vista Blit):
//   Runtime PresentStart -> DxgKrnl_Blit (by thread/process, for classification) ->
//   SubmitPresentHistory (by thread, for token ptr, legacy blit token, and classification) ->
//   DxgKrnl_PresentHistory (by token ptr, for ready time) ->
//   DWM FlipChain (by legacy blit token, for hWnd and marks hWnd active for composition) ->
//   Follows the Windowed_Blit path for tracking to screen
//
// Composed Composition Atlas (DirectComposition):
//   SubmitPresentHistory (use model field for classification, get token ptr) -> DxgKrnl_PresentHistory (by token ptr) ->
//   Assume DWM will compose this buffer on next present (missing InFrame event), follow windowed blit paths to screen time

void HandleDxgkBlt(EVENT_HEADER const& hdr, uint64_t hwnd, bool redirectedPresent);
void HandleDxgkFlip(EVENT_HEADER const& hdr, int32_t flipInterval, bool isMMIOFlip, bool isMPOFlip);
void HandleDxgkQueueSubmit(EVENT_HEADER const& hdr, uint64_t hContext, uint32_t submitSequence, uint32_t packetType, bool isPresentPacket, bool isWin7);
void HandleDxgkQueueComplete(uint64_t timestamp, uint64_t hContext, uint32_t submitSequence);
void HandleDxgkMMIOFlip(uint64_t timestamp, uint32_t submitSequence, uint32_t flags);
void HandleDxgkSyncDPC(uint64_t timestamp, uint32_t submitSequence);
void HandleDxgkSyncDPCMPO(EVENT_HEADER const& hdr, uint32_t flipSubmitSequence, bool isMultiplane);
void HandleDxgkPresentHistory(EVENT_HEADER const& hdr, uint64_t token, uint64_t tokenData, uint32_t presentModel);
void HandleDxgkPresentHistoryInfo(EVENT_HEADER const& hdr, uint64_t token);

void CompletePresent(std::shared_ptr<PresentEvent> const& p);
void CompletePresentHelper(std::shared_ptr<PresentEvent> const& p);
void EnqueueDeferredCompletions(DeferredCompletions* deferredCompletions);
void EnqueueDeferredPresent(std::shared_ptr<PresentEvent> const& p);
void TrackPresent(std::shared_ptr<PresentEvent> const& present, OrderedPresents* presentsByThisProcess);
void RemoveLostPresent(std::shared_ptr<PresentEvent> present);
void RemovePresentFromTemporaryTrackingCollections(std::shared_ptr<PresentEvent> const& present);
void RemovePresentFromSubmitSequenceIdTracking(std::shared_ptr<PresentEvent> const& present);
void RuntimePresentStart(Runtime runtime, EVENT_HEADER const& hdr, uint64_t swapchainAddr, uint32_t dxgiPresentFlags, int32_t syncInterval);
void RuntimePresentStop(Runtime runtime, EVENT_HEADER const& hdr, uint32_t result);

//void HandleNTProcessEvent(EVENT_RECORD* pEventRecord);
void HandleDXGIEvent(EVENT_RECORD* pEventRecord);
void HandleD3D9Event(EVENT_RECORD* pEventRecord);
void HandleDXGKEvent(EVENT_RECORD* pEventRecord);
void HandleWin32kEvent(EVENT_RECORD* pEventRecord);
void HandleDWMEvent(EVENT_RECORD* pEventRecord);
void HandleMetadataEvent(EVENT_RECORD* pEventRecord);

void HandleWin7DxgkBlt(EVENT_RECORD* pEventRecord);
void HandleWin7DxgkFlip(EVENT_RECORD* pEventRecord);
void HandleWin7DxgkPresentHistory(EVENT_RECORD* pEventRecord);
void HandleWin7DxgkQueuePacket(EVENT_RECORD* pEventRecord);
void HandleWin7DxgkVSyncDPC(EVENT_RECORD* pEventRecord);
void HandleWin7DxgkMMIOFlip(EVENT_RECORD* pEventRecord);

void DequeuePresentEvents(std::vector<std::shared_ptr<PresentEvent>>& outPresentEvents);
//void DequeueLostPresentEvents(std::vector<std::shared_ptr<PresentEvent>>& outPresentEvents);

void SetThreadPresent(uint32_t threadId, std::shared_ptr<PresentEvent> const& present);
std::shared_ptr<PresentEvent> FindThreadPresent(uint32_t threadId);
std::shared_ptr<PresentEvent> FindOrCreatePresent(EVENT_HEADER const& hdr);
std::shared_ptr<PresentEvent> FindPresentBySubmitSequence(uint32_t submitSequence);
