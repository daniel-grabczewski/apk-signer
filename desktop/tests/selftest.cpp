// Console harness that drives the app's own code, for testing without clicking through the UI.
//
//   selftest sign    <in.apk> <out.apk>   the whole job: sign, check the result, save
//   selftest copy    <in.apk> <out.apk> [yyyy-mm-ddThh:mm:ss]
//                                         the same as a separate copy, made now or at that time
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
    } else if (command == L"copy" && (argc == 4 || argc == 5)) {
        SYSTEMTIME when{};
        GetLocalTime(&when);
        if (argc == 5 && swscanf_s(argv[4], L"%hu-%hu-%huT%hu:%hu:%hu", &when.wYear, &when.wMonth, &when.wDay,
                                   &when.wHour, &when.wMinute, &when.wSecond) != 6) {
            wprintf(L"usage: selftest copy <in.apk> <out.apk> [yyyy-mm-ddThh:mm:ss]\n");
            return 2;
        }
        const Outcome outcome = SignApk(argv[2], argv[3], &when);
        if (outcome.ok)
            wprintf(L"%ls  \"%ls\"\n", outcome.copy.packageName.c_str(), outcome.copy.label.c_str());
        else
            problem = outcome.problem + L" " + outcome.details;
    } else if (command == L"verify" && argc == 3) {
        problem = VerifyApkFile(argv[2]);
    } else if (command == L"inspect" && argc == 3) {
        uint64_t size = 0;
        problem = InspectApk(argv[2], size);
    } else {
        wprintf(L"usage: selftest sign|copy|verify|inspect <files>\n");
        return 2;
    }
    wprintf(L"%ls\n", problem.empty() ? L"OK" : (L"FAIL " + problem).c_str());
    return problem.empty() ? 0 : 1;
}
