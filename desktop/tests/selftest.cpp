// Console harness that drives the app's own code, for testing without clicking through the UI.
//
//   selftest sign    <in.apk> <out.apk>   the whole job: sign, check the result, save
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
    } else if (command == L"verify" && argc == 3) {
        problem = VerifyApkFile(argv[2]);
    } else if (command == L"inspect" && argc == 3) {
        uint64_t size = 0;
        problem = InspectApk(argv[2], size);
    } else {
        wprintf(L"usage: selftest sign|verify|inspect <files>\n");
        return 2;
    }
    wprintf(L"%ls\n", problem.empty() ? L"OK" : (L"FAIL " + problem).c_str());
    return problem.empty() ? 0 : 1;
}
