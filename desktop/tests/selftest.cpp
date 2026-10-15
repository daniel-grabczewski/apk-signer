// Console harness that drives the app's own code, for testing without clicking through the UI.
//
//   selftest sign    <in.apk> <out.apk>   the whole job: sign, check the result, save
//   selftest copy    <in.apk> <out.apk> [--at yyyy-mm-ddThh:mm:ss] [--name <name>]
//                                         the same as a separate copy, made now or at that time
//   selftest slug    <name>...            the package name part each copy name gives
//   selftest verify  <signed.apk>         the v2 signature and alignment check, on any APK
//   selftest inspect <file>               the check made when a file is picked

#define APK_SIGNER_NO_WINMAIN
#include "../apk_signer.cpp"

#include <fcntl.h>
#include <io.h>

int wmain(int argc, wchar_t** argv) {
    _setmode(_fileno(stdout), _O_U8TEXT);
    const std::wstring command = argc > 1 ? argv[1] : L"";
    std::wstring problem;
    if (command == L"sign" && argc == 4) {
        const Outcome outcome = SignApk(argv[2], argv[3]);
        if (!outcome.ok) problem = outcome.problem + L" " + outcome.details;
    } else if (command == L"copy" && argc >= 4) {
        CopyRequest request;
        GetLocalTime(&request.at);
        for (int i = 4; i < argc; i += 2) {
            const std::wstring option = argv[i];
            bool ok = i + 1 < argc;
            if (ok && option == L"--name")
                request.name = argv[i + 1];
            else if (ok && option == L"--at")
                ok = swscanf_s(argv[i + 1], L"%hu-%hu-%huT%hu:%hu:%hu", &request.at.wYear, &request.at.wMonth, &request.at.wDay,
                               &request.at.wHour, &request.at.wMinute, &request.at.wSecond) == 6;
            else
                ok = false;
            if (!ok) {
                wprintf(L"usage: selftest copy <in.apk> <out.apk> [--at yyyy-mm-ddThh:mm:ss] [--name <name>]\n");
                return 2;
            }
        }
        const Outcome outcome = SignApk(argv[2], argv[3], &request);
        if (outcome.ok)
            wprintf(L"%ls  \"%ls\"\n", outcome.copy.packageName.c_str(), outcome.copy.label.c_str());
        else
            problem = outcome.problem + L" " + outcome.details;
    } else if (command == L"slug" && argc >= 3) {
        for (int i = 2; i < argc; ++i) wprintf(L"%ls\t%ls\n", NormalizeCopyName(argv[i]).c_str(), CopyNameSlug(argv[i]).c_str());
        return 0;
    } else if (command == L"verify" && argc == 3) {
        problem = VerifyApkFile(argv[2]);
    } else if (command == L"inspect" && argc == 3) {
        uint64_t size = 0;
        problem = InspectApk(argv[2], size);
    } else {
        wprintf(L"usage: selftest sign|copy|slug|verify|inspect <arguments>\n");
        return 2;
    }
    wprintf(L"%ls\n", problem.empty() ? L"OK" : (L"FAIL " + problem).c_str());
    return problem.empty() ? 0 : 1;
}
