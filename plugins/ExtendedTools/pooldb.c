/*
 * Copyright (c) 2022 Winsider Seminars & Solutions, Inc.  All rights reserved.
 *
 * This file is part of System Informer.
 *
 * Authors:
 *
 *     dmex    2016-2023
 *
 */

#include "exttools.h"
#include "poolmon.h"

PPH_STRING TrimString(
    _In_ PPH_STRING String
    )
{
    static PH_STRINGREF whitespace = PH_STRINGREF_INIT(L" \t");
    return PhCreateString3(&String->sr, 0, &whitespace);
}

PPH_STRING FindPoolTagFilePath(
    VOID
    )
{
    static struct
    {
        PH_STRINGREF AppendPath;
    } locations[] =
    {
#ifdef _WIN64
        { PH_STRINGREF_INIT(L"%ProgramFiles(x86)%\\Windows Kits\\10\\Debuggers\\x64\\") },
        { PH_STRINGREF_INIT(L"%ProgramFiles(x86)%\\Windows Kits\\8.1\\Debuggers\\x64\\") },
        { PH_STRINGREF_INIT(L"%ProgramFiles(x86)%\\Windows Kits\\8.0\\Debuggers\\x64\\") },
        { PH_STRINGREF_INIT(L"%ProgramFiles%\\Debugging Tools for Windows (x64)\\") }
#else
        { PH_STRINGREF_INIT(L"%ProgramFiles%\\Windows Kits\\10\\Debuggers\\x86\\") },
        { PH_STRINGREF_INIT(L"%ProgramFiles%\\Windows Kits\\8.1\\Debuggers\\x86\\") },
        { PH_STRINGREF_INIT(L"%ProgramFiles%\\Windows Kits\\8.0\\Debuggers\\x86\\") },
        { PH_STRINGREF_INIT(L"%ProgramFiles%\\Debugging Tools for Windows (x86)\\") }
#endif
    };

    for (ULONG i = 0; i < RTL_NUMBER_OF(locations); i++)
    {
        PPH_STRING path = PhExpandEnvironmentStrings(&locations[i].AppendPath);

        if (path)
        {
            PhMoveReference(&path, PhConcatStringRef2(&PhNtDosDevicesPrefix, &path->sr));
            PhMoveReference(&path, PhConcatStringRefZ(&path->sr, L"triage\\pooltag.txt"));

            if (PhDoesFileExist(&path->sr))
                return path;

            PhDereferenceObject(path);
        }
    }

    {
        PPH_STRING path = PhGetApplicationDirectoryFileNameZ(L"pooltag.txt", TRUE);

        if (PhDoesFileExist(&path->sr))
            return path;

        PhDereferenceObject(path);
    }

    return NULL;
}

BOOLEAN EtPoolTagListHashtableEqualFunction(
    _In_ PVOID Entry1,
    _In_ PVOID Entry2
    )
{
    PPOOL_TAG_LIST_ENTRY poolTagNode1 = *(PPOOL_TAG_LIST_ENTRY *)Entry1;
    PPOOL_TAG_LIST_ENTRY poolTagNode2 = *(PPOOL_TAG_LIST_ENTRY *)Entry2;

    return poolTagNode1->TagUlong == poolTagNode2->TagUlong;
}

ULONG EtPoolTagListHashtableHashFunction(
    _In_ PVOID Entry
    )
{
    return PhHashInt32((*(PPOOL_TAG_LIST_ENTRY*)Entry)->TagUlong);
}

PPOOL_TAG_LIST_ENTRY EtFindPoolTagListEntry(
    _In_ PPOOLTAG_CONTEXT Context,
    _In_ ULONG PoolTag
    )
{
    POOL_TAG_LIST_ENTRY lookupNode;
    PPOOL_TAG_LIST_ENTRY lookupNodePtr = &lookupNode;
    PPOOL_TAG_LIST_ENTRY *node;

    lookupNode.TagUlong = PoolTag;

    node = (PPOOL_TAG_LIST_ENTRY*)PhFindEntryHashtable(
        Context->PoolTagDbHashtable,
        &lookupNodePtr
        );

    if (node)
        return *node;
    else
        return NULL;
}

VOID EtLoadPoolTagDatabase(
    _In_ PPOOLTAG_CONTEXT Context
    )
{
    static PH_STRINGREF skipPoolTagFileHeader = PH_STRINGREF_INIT(L"\r\n\r\n");
    static PH_STRINGREF skipPoolTagFileLine = PH_STRINGREF_INIT(L"\r\n");
    PPH_STRING poolTagFilePath;
    HANDLE fileHandle = NULL;
    LARGE_INTEGER fileSize;
    SIZE_T stringBufferLength;
    PSTR stringBuffer;
    PPH_STRING utf16StringBuffer = NULL;
    IO_STATUS_BLOCK isb;

    Context->PoolTagDbList = PhCreateList(100);
    Context->PoolTagDbHashtable = PhCreateHashtable(
        sizeof(PPOOL_TAG_LIST_ENTRY),
        EtPoolTagListHashtableEqualFunction,
        EtPoolTagListHashtableHashFunction,
        100
        );

    if (poolTagFilePath = FindPoolTagFilePath())
    {
        if (!NT_SUCCESS(PhCreateFile(
            &fileHandle,
            &poolTagFilePath->sr,
            FILE_GENERIC_READ,
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_DELETE,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT
            )))
        {
            PhDereferenceObject(poolTagFilePath);
            return;
        }

        if (!NT_SUCCESS(PhGetFileSize(fileHandle, &fileSize)))
        {
            NtClose(fileHandle);
            PhDereferenceObject(poolTagFilePath);
            return;
        }

        if (fileSize.QuadPart == 0)
        {
            NtClose(fileHandle);
            PhDereferenceObject(poolTagFilePath);
            return;
        }

        stringBufferLength = (SIZE_T)fileSize.QuadPart + 1;
        stringBuffer = PhAllocateZero(stringBufferLength);

        if (NT_SUCCESS(NtReadFile(
            fileHandle,
            NULL,
            NULL,
            NULL,
            &isb,
            stringBuffer,
            (ULONG)fileSize.QuadPart,
            NULL,
            NULL
            )))
        {
            utf16StringBuffer = PhZeroExtendToUtf16Ex(stringBuffer, (SIZE_T)fileSize.QuadPart);
        }

        PhFree(stringBuffer);
        NtClose(fileHandle);
        PhDereferenceObject(poolTagFilePath);
    }

    if (utf16StringBuffer)
    {
        PH_STRINGREF firstPart;
        PH_STRINGREF remainingPart;
        PH_STRINGREF poolTagPart;
        PH_STRINGREF binaryNamePart;
        PH_STRINGREF descriptionPart;

        remainingPart = PhGetStringRef(utf16StringBuffer);

        PhSplitStringRefAtString(&remainingPart, &skipPoolTagFileHeader, TRUE, &firstPart, &remainingPart);

        while (remainingPart.Length != 0)
        {
            PhSplitStringRefAtString(&remainingPart, &skipPoolTagFileLine, TRUE, &firstPart, &remainingPart);

            if (firstPart.Length != 0)
            {
                PPOOL_TAG_LIST_ENTRY entry;
                PPH_STRING poolTagString;
                PPH_STRING poolTag;
                PPH_STRING binaryName;
                PPH_STRING description;

                if (!PhSplitStringRefAtChar(&firstPart, '-', &poolTagPart, &firstPart))
                    continue;
                if (!PhSplitStringRefAtChar(&firstPart, '-', &binaryNamePart, &firstPart))
                    continue;
                // Note: Some entries don't have descriptions
                PhSplitStringRefAtChar(&firstPart, '-', &descriptionPart, &firstPart);

                poolTag = PhCreateString2(&poolTagPart);
                binaryName = PhCreateString2(&binaryNamePart);
                description = PhCreateString2(&descriptionPart);

                entry = PhAllocateZero(sizeof(POOL_TAG_LIST_ENTRY));
                entry->BinaryNameString = TrimString(binaryName);
                entry->DescriptionString = TrimString(description);

                // Convert the poolTagString to ULONG
                poolTagString = TrimString(poolTag);
                PhConvertUtf16ToUtf8Buffer(
                    entry->Tag,
                    sizeof(entry->Tag),
                    NULL,
                    poolTagString->Buffer,
                    poolTagString->Length
                    );

                PhAcquireQueuedLockExclusive(&Context->PoolTagListLock);
                PhAddEntryHashtable(Context->PoolTagDbHashtable, &entry);
                PhAddItemList(Context->PoolTagDbList, entry);
                PhReleaseQueuedLockExclusive(&Context->PoolTagListLock);

                PhDereferenceObject(description);
                PhDereferenceObject(binaryName);
                PhDereferenceObject(poolTag);
                PhDereferenceObject(poolTagString);
            }
        }

        PhDereferenceObject(utf16StringBuffer);
    }
}

VOID EtFreePoolTagDatabase(
    _In_ PPOOLTAG_CONTEXT Context
    )
{
    PhAcquireQueuedLockExclusive(&Context->PoolTagListLock);

    for (ULONG i = 0; i < Context->PoolTagDbList->Count; i++)
    {
        PPOOL_TAG_LIST_ENTRY entry = Context->PoolTagDbList->Items[i];

        PhDereferenceObject(entry->DescriptionString);
        PhDereferenceObject(entry->BinaryNameString);
        PhFree(entry);
    }

    PhClearHashtable(Context->PoolTagDbHashtable);
    PhClearList(Context->PoolTagDbList);

    PhReleaseQueuedLockExclusive(&Context->PoolTagListLock);
}

VOID EtUpdatePoolTagBinaryName(
    _In_ PPOOLTAG_CONTEXT Context,
    _In_ PPOOL_ITEM PoolEntry,
    _In_ ULONG TagUlong
    )
{
    PPOOL_TAG_LIST_ENTRY client;

    if (client = EtFindPoolTagListEntry(Context, TagUlong))
    {
        PoolEntry->BinaryNameString = client->BinaryNameString;
        PoolEntry->DescriptionString = client->DescriptionString;

        //if (PhStartsWithString2(PoolEntry->BinaryNameString, L"nt!", FALSE))
        //    PoolEntry->Type = TPOOLTAG_TREE_ITEM_TYPE_OBJECT;
        //if (PhEndsWithString2(PoolEntry->BinaryNameString, L".sys", FALSE))
        //    PoolEntry->Type = TPOOLTAG_TREE_ITEM_TYPE_DRIVER;
    }
}
