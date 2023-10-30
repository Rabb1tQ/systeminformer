#include "tests.h"

static VOID Test_rectangle(
    VOID
    )
{
    PH_RECTANGLE r1;
    PH_RECTANGLE r2;

    r1.Left = 0;
    r1.Top = 0;
    r1.Width = 1024;
    r1.Height = 1024;

    r2.Width = 100;
    r2.Height = 100;

    r2.Left = -10;
    r2.Top = -10;
    PhAdjustRectangleToBounds(&r2, &r1);
    assert(r2.Left == 0 && r2.Top == 0 && r2.Width == 100 && r2.Height == 100);

    r2.Left = 1100;
    r2.Top = 1100;
    PhAdjustRectangleToBounds(&r2, &r1);
    assert(r2.Left == 924 && r2.Top == 924 && r2.Width == 100 && r2.Height == 100);

    PhCenterRectangle(&r2, &r1);
    assert(r2.Left == 462 && r2.Top == 462 && r2.Width == 100 && r2.Height == 100);
}

static BOOLEAN AreGuidsEqual(
    _In_ PGUID Guid1,
    _In_ PWSTR Guid2
    )
{
    GUID guid2;
    UNICODE_STRING us;

    RtlInitUnicodeString(&us, Guid2);
    RtlGUIDFromString(&us, &guid2);

    return memcmp(Guid1, &guid2, sizeof(GUID)) == 0;
}

static VOID Test_guid(
    VOID
    )
{
    GUID guid;
    GUID ns;
    UNICODE_STRING dnsNamespace = RTL_CONSTANT_STRING(L"{6ba7b810-9dad-11d1-80b4-00c04fd430c8}");
    UNICODE_STRING urlNamespace = RTL_CONSTANT_STRING(L"{6ba7b811-9dad-11d1-80b4-00c04fd430c8}");
    UNICODE_STRING oidNamespace = RTL_CONSTANT_STRING(L"{6ba7b812-9dad-11d1-80b4-00c04fd430c8}");
    UNICODE_STRING x500Namespace = RTL_CONSTANT_STRING(L"{6ba7b814-9dad-11d1-80b4-00c04fd430c8}");

    // Taken from http://svn.python.org/projects/python/branches/py3k/Lib/test/test_uuid.py

    RtlGUIDFromString(&dnsNamespace, &ns);
    PhGenerateGuidFromName(&guid, &ns, "python.org", 10, GUID_VERSION_MD5);
    assert(AreGuidsEqual(&guid, L"{6fa459ea-ee8a-3ca4-894e-db77e160355e}"));

    RtlGUIDFromString(&urlNamespace, &ns);
    PhGenerateGuidFromName(&guid, &ns, "http://python.org/", 18, GUID_VERSION_MD5);
    assert(AreGuidsEqual(&guid, L"{9fe8e8c4-aaa8-32a9-a55c-4535a88b748d}"));

    RtlGUIDFromString(&oidNamespace, &ns);
    PhGenerateGuidFromName(&guid, &ns, "1.3.6.1", 7, GUID_VERSION_SHA1);
    assert(AreGuidsEqual(&guid, L"{1447fa61-5277-5fef-a9b3-fbc6e44f4af3}"));

    RtlGUIDFromString(&x500Namespace, &ns);
    PhGenerateGuidFromName(&guid, &ns, "c=ca", 4, GUID_VERSION_SHA1);
    assert(AreGuidsEqual(&guid, L"{cc957dd1-a972-5349-98cd-874190002798}"));
}

static VOID Test_ellipsis(
    VOID
    )
{
    PPH_STRING input;
    PPH_STRING output;

    // Normal

    input = PhCreateString(L"asdf 1234");

    output = PhEllipsisString(input, 9);
    assert(wcscmp(output->Buffer, L"asdf 1234") == 0);
    output = PhEllipsisString(input, 999);
    assert(wcscmp(output->Buffer, L"asdf 1234") == 0);
    output = PhEllipsisString(input, 8);
    assert(wcscmp(output->Buffer, L"asdf ...") == 0);
    output = PhEllipsisString(input, 7);
    assert(wcscmp(output->Buffer, L"asdf...") == 0);
    output = PhEllipsisString(input, 5);
    assert(wcscmp(output->Buffer, L"as...") == 0);
    output = PhEllipsisString(input, 4);
    assert(wcscmp(output->Buffer, L"a...") == 0);
    output = PhEllipsisString(input, 3);
    assert(wcscmp(output->Buffer, L"...") == 0);
    output = PhEllipsisString(input, 2);
    assert(wcscmp(output->Buffer, L"asdf 1234") == 0);
    output = PhEllipsisString(input, 1);
    assert(wcscmp(output->Buffer, L"asdf 1234") == 0);
    output = PhEllipsisString(input, 0);
    assert(wcscmp(output->Buffer, L"asdf 1234") == 0);

    // Path

    input = PhCreateString(L"C:\\abcdef\\1234.abc");

    output = PhEllipsisStringPath(input, 18);
    assert(wcscmp(output->Buffer, L"C:\\abcdef\\1234.abc") == 0);
    output = PhEllipsisStringPath(input, 999);
    assert(wcscmp(output->Buffer, L"C:\\abcdef\\1234.abc") == 0);
    output = PhEllipsisStringPath(input, 17);
    assert(wcscmp(output->Buffer, L"C:\\ab...\\1234.abc") == 0); // last part is kept
    output = PhEllipsisStringPath(input, 16);
    assert(wcscmp(output->Buffer, L"C:\\a...\\1234.abc") == 0);
    output = PhEllipsisStringPath(input, 15);
    assert(wcscmp(output->Buffer, L"C:\\...\\1234.abc") == 0);
    output = PhEllipsisStringPath(input, 14);
    assert(wcscmp(output->Buffer, L"C:...\\1234.abc") == 0);
    output = PhEllipsisStringPath(input, 13);
    assert(wcscmp(output->Buffer, L"C...\\1234.abc") == 0);
    output = PhEllipsisStringPath(input, 12);
    assert(wcscmp(output->Buffer, L"...\\1234.abc") == 0);
    output = PhEllipsisStringPath(input, 11);
    assert(wcscmp(output->Buffer, L"C:\\a....abc") == 0); // the two sides are split as evenly as possible
    output = PhEllipsisStringPath(input, 10);
    assert(wcscmp(output->Buffer, L"C:\\....abc") == 0);
    output = PhEllipsisStringPath(input, 9);
    assert(wcscmp(output->Buffer, L"C:\\...abc") == 0);
    output = PhEllipsisStringPath(input, 8);
    assert(wcscmp(output->Buffer, L"C:...abc") == 0);
    output = PhEllipsisStringPath(input, 7);
    assert(wcscmp(output->Buffer, L"C:...bc") == 0);
    output = PhEllipsisStringPath(input, 6);
    assert(wcscmp(output->Buffer, L"C...bc") == 0);
    output = PhEllipsisStringPath(input, 5);
    assert(wcscmp(output->Buffer, L"C...c") == 0);
    output = PhEllipsisStringPath(input, 4);
    assert(wcscmp(output->Buffer, L"...c") == 0);
    output = PhEllipsisStringPath(input, 3);
    assert(wcscmp(output->Buffer, L"...") == 0);
    output = PhEllipsisStringPath(input, 2);
    assert(wcscmp(output->Buffer, L"C:\\abcdef\\1234.abc") == 0);
    output = PhEllipsisStringPath(input, 1);
    assert(wcscmp(output->Buffer, L"C:\\abcdef\\1234.abc") == 0);
    output = PhEllipsisStringPath(input, 0);
    assert(wcscmp(output->Buffer, L"C:\\abcdef\\1234.abc") == 0);
}

VOID Test_compareignoremenuprefix(
    VOID
    )
{
    assert(PhCompareUnicodeStringZIgnoreMenuPrefix(L"", L"", FALSE, FALSE) == 0);
    assert(PhCompareUnicodeStringZIgnoreMenuPrefix(L"asdf", L"asdf", FALSE, FALSE) == 0);
    assert(PhCompareUnicodeStringZIgnoreMenuPrefix(L"asdf", L"asDF", FALSE, FALSE) > 0);
    assert(PhCompareUnicodeStringZIgnoreMenuPrefix(L"asdf", L"asDF", TRUE, FALSE) == 0);
    assert(PhCompareUnicodeStringZIgnoreMenuPrefix(L"asdf", L"asdff", FALSE, FALSE) < 0);
    assert(PhCompareUnicodeStringZIgnoreMenuPrefix(L"asdfff", L"asdff", FALSE, FALSE) > 0);

    assert(PhCompareUnicodeStringZIgnoreMenuPrefix(L"&asdf", L"asdf", FALSE, FALSE) == 0);
    assert(PhCompareUnicodeStringZIgnoreMenuPrefix(L"&asdf", L"&asdf", FALSE, FALSE) == 0);
    assert(PhCompareUnicodeStringZIgnoreMenuPrefix(L"&&asdf", L"&asdf", FALSE, FALSE) != 0);
    assert(PhCompareUnicodeStringZIgnoreMenuPrefix(L"&&asdf", L"&&asdf", FALSE, FALSE) == 0);
    assert(PhCompareUnicodeStringZIgnoreMenuPrefix(L"&&&asdf", L"&&asdf", FALSE, FALSE) == 0);
    assert(PhCompareUnicodeStringZIgnoreMenuPrefix(L"&&&&asdf", L"&&asdf", FALSE, FALSE) != 0);
    assert(PhCompareUnicodeStringZIgnoreMenuPrefix(L"AAA&&asdf", L"aaa&&&asdf", TRUE, FALSE) == 0);
    assert(PhCompareUnicodeStringZIgnoreMenuPrefix(L"AAA&&&&asdf", L"aaa&&&&asdf", TRUE, FALSE) == 0);

    assert(PhCompareUnicodeStringZIgnoreMenuPrefix(L"", L"", FALSE, TRUE) == 0);
    assert(PhCompareUnicodeStringZIgnoreMenuPrefix(L"asdf", L"asdf", FALSE, TRUE) == 0);
    assert(PhCompareUnicodeStringZIgnoreMenuPrefix(L"asdf", L"asDF", FALSE, TRUE) > 0);
    assert(PhCompareUnicodeStringZIgnoreMenuPrefix(L"asdf", L"asDF", TRUE, TRUE) == 0);
    assert(PhCompareUnicodeStringZIgnoreMenuPrefix(L"asdf", L"asdff", FALSE, TRUE) == 0);
    assert(PhCompareUnicodeStringZIgnoreMenuPrefix(L"asdfff", L"asdff", FALSE, TRUE) != 0);

    assert(PhCompareUnicodeStringZIgnoreMenuPrefix(L"&asdf", L"asdf", FALSE, TRUE) == 0);
    assert(PhCompareUnicodeStringZIgnoreMenuPrefix(L"&asdf", L"&asdf", FALSE, TRUE) == 0);
    assert(PhCompareUnicodeStringZIgnoreMenuPrefix(L"&&asdf", L"&asdf", FALSE, TRUE) != 0);
    assert(PhCompareUnicodeStringZIgnoreMenuPrefix(L"&&asdf", L"&&asdf&", FALSE, TRUE) == 0);
    assert(PhCompareUnicodeStringZIgnoreMenuPrefix(L"&&asdf", L"&&asdf&&", FALSE, TRUE) == 0);
    assert(PhCompareUnicodeStringZIgnoreMenuPrefix(L"&&asdf&", L"&&asdf", FALSE, TRUE) == 0);
    assert(PhCompareUnicodeStringZIgnoreMenuPrefix(L"&&asdf&&", L"&&asdf", FALSE, TRUE) != 0);
    assert(PhCompareUnicodeStringZIgnoreMenuPrefix(L"&&&asdf", L"&&asdf", FALSE, TRUE) == 0);
    assert(PhCompareUnicodeStringZIgnoreMenuPrefix(L"&&&&asdf", L"&&asdf&&", FALSE, TRUE) != 0);
    assert(PhCompareUnicodeStringZIgnoreMenuPrefix(L"AAA&&asdf", L"aaa&&&asdf&&", TRUE, TRUE) == 0);
    assert(PhCompareUnicodeStringZIgnoreMenuPrefix(L"AAA&&&&asdf", L"aaa&&&&asdf&&", TRUE, TRUE) == 0);
}

static VOID Test_wildcards(
    VOID
    )
{
    static WCHAR *testCases[][3] =
    {
        { L"", L"", L"true" },
        { L"", L"a", L"false" },
        { L"a", L"a", L"true" },
        { L"a", L"b", L"false" },
        { L"?", L"b", L"true" },
        { L"??", L"bc", L"true" },
        { L"?c", L"bc", L"true" },
        { L"b?", L"bc", L"true" },
        { L"*", L"a", L"true" },
        { L"**", L"a", L"true" },
        { L"*", L"", L"true" },
        { L"*bc*hij", L"abcdfghij", L"true" },
        { L"*b*a*", L"b", L"false" },
        { L"*bc*hik", L"abcdfghij", L"false" },
        { L"abc*", L"abc", L"true" },
        { L"abc**", L"abc", L"true" },
        { L"*???", L"abc", L"true" },
        { L"*???", L"ab", L"false" },
        { L"*???", L"abcd", L"true" },
        { L"*?*", L"abcd", L"true" },
        { L"*bc", L"abc", L"true" },
        { L"*cc", L"abc", L"false" },
        { L"*a*", L"de", L"false" },
        { L"*???*", L"123", L"true" },
        { L"a*bc", L"abbc", L"true" },
        { L"a*b", L"a", L"false" },
        { L"a*?b", L"axb", L"true" },
        { L"a**b", L"axb", L"true" }
    };

    ULONG i;
    BOOLEAN r;
    BOOLEAN fail;

    for (i = 0; i < sizeof(testCases) / sizeof(WCHAR *[3]); i++)
    {
        r = PhMatchWildcards(testCases[i][0], testCases[i][1], TRUE);
        fail = r != PhEqualStringZ(testCases[i][2], L"true", FALSE);

        if (fail)
        {
            wprintf(L"pattern '%s' against '%s': %s (%s expected)\n",
                testCases[i][0], testCases[i][1], r ? L"true" : L"false", testCases[i][2]);
            assert(FALSE);
        }
    }
}

VOID Test_util(
    VOID
    )
{
    Test_rectangle();
    Test_guid();
    Test_ellipsis();
    Test_compareignoremenuprefix();
    Test_wildcards();
}
