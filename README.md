# APK Signer

Sign an Android APK with the Android debug key, in two forms:

- **Web:** [apk-signer.pages.dev](https://apk-signer.pages.dev). Drop an APK on the page, press
  **Sign**, and the signed APK downloads. It runs entirely in your browser; the APK is never
  uploaded anywhere.
- **Windows:** [`APK-Signer.exe`](https://github.com/daniel-grabczewski/apk-signer/releases/latest),
  one native file of about 350 KB with no installer and no runtimes. Drop an APK on the window,
  press **Sign**, and choose where to save.

Either way the signed file is named `<name>-SIGNED.apk`. Tick **Separate copy** first to get an APK
that installs alongside the original instead of over it, and give the copy a name if you want to
update it with later builds (see [Separate copies](#separate-copies)).

## What it writes

The same as Google's `apksigner` with v1 and v2 enabled:

- a JAR signature (`META-INF/MANIFEST.MF`, `CERT.SF`, `CERT.RSA`), which Android 6 and older check,
- an APK Signature Scheme v2 block, which Android 7 and newer check,
- zip alignment: 4 bytes for uncompressed files and 16 KB for uncompressed native libraries.

Everything else in the APK is kept byte for byte, `META-INF` included. Only old signature files
are replaced, so an APK that is already signed simply gets re-signed. (A separate copy also changes
`AndroidManifest.xml` and `resources.arsc`, as described below.) Every result is checked before you
get it: the v2 signature must verify with the expected certificate, and the file must be
zip-aligned.

Both versions were tested against Google's `apksig` verifier on real-world APKs up to 122 MB,
including apps with a minimum SDK of 21 (v1 and v2 both verified) and apps with uncompressed
native libraries.

## Separate copies

Android tells apps apart by their package name, not by their signature. An APK signed with a
different key still counts as the same app, so Android refuses to install it while the original is
installed. To run two or more copies of one app on the same device, each copy needs its own package
name.

With **Separate copy** ticked, the signer also:

- gives the app a new package name (see below),
- renames what Android requires to be unique per app: content provider authorities and the app's
  own permissions that start with the old package name,
- adds the time it was made to the app's name, for example `My App 11:47:48 16 Oct`, so the copies
  can be told apart. The time comes first because launchers cut long names at the end,
- records the new package name in `resources.arsc`.

Class names are left alone, so the code runs unchanged. A copy can be unnamed or named:

- **Unnamed** (the name box left empty): every copy is a new app with its own data. Its package is
  `<package>.c<yyyyMMddHHmmss>` and its file `<name>-COPY-<yyyyMMdd>-<HHmmss>-SIGNED.apk`.
- **Named**, for example `Alex's phone`: the name goes into the app's name, between the original
  name and the time (`My App Alex's phone 12:04:57 16 Oct`), and the package is made from the name
  instead of the time (`<package>.copy_alexs_phone`). Signing another build as a copy with the
  same name therefore gives the same package, which Android installs as an update of that copy: its
  data is kept and its name shows the new time. Its file is
  `<name>-COPY-alexs_phone-<yyyyMMdd>-<HHmmss>-SIGNED.apk`.

Names match loosely: case, apostrophes, spaces and punctuation do not matter, so `Alex's phone` and
`alexs phone` are the same copy. Both versions remember the names you have used: the web version in
your browser, the Windows version under `HKCU\Software\APK Signer`.

A named copy's version code is set from the time it was made, so the build you sign last always
installs over the one before, whatever version codes the builds themselves carry. That includes an
older build over a newer one's data, which Android would otherwise refuse. The version name the app
shows is unchanged. An APK that is already a copy is not copied again: make copies from the
original.

An app that checks its own package name at run time, or relies on a service registered to its
package name (Google sign-in, Firebase, push notifications, map keys), may not work fully as a
copy.

## The key

`keys/debug.keystore` is the debug keystore bundled with
[uber-apk-signer](https://github.com/patrickfav/uber-apk-signer): alias `androiddebugkey`,
password `android`, CN=Android Debug, certificate SHA-256
`1E:08:A9:03:AE:F9:C3:A7:21:51:0B:64:EC:76:4D:01:D3:D0:94:EB:95:41:61:B6:25:44:EA:8F:18:7B:59:53`.
APKs signed here install over APKs that uber-apk-signer signed with its default key.

It is a public debug key, which is why it can ship inside a web page. Use it for testing and
sideloading, never for a store release.

## Windows

Download `APK-Signer.exe` from
[Releases](https://github.com/daniel-grabczewski/apk-signer/releases/latest). It is not
code-signed, so the first time you run it Windows SmartScreen may say "Windows protected your PC":
choose **More info**, then **Run anyway**.

To build it yourself, run `desktop\build.cmd` (Visual Studio 2022 or later with the C++ desktop
tools). It produces `desktop\build\APK-Signer.exe` and `desktop\build\selftest.exe`, a console
harness that runs the same code:

```
selftest sign    <in.apk> <out.apk>
selftest copy    <in.apk> <out.apk> [--at yyyy-mm-ddThh:mm:ss] [--name <name>]
selftest slug    <name>...
selftest verify  <signed.apk>
selftest inspect <file>
```

## Web

`web/` is a static site with no build step. Signing uses the browser's own WebCrypto and
`DecompressionStream`, so it works in current Chrome, Edge, Firefox and Safari.

- **Preview:** `python tools/dev_server.py`, then open http://localhost:8253.
- **Cloudflare Pages:** connect this repository with no build command. `wrangler.jsonc` tells
  Pages to publish `web/`, and `web/_headers` adds a strict Content-Security-Policy.

## Changing the key

Replace `keys/debug.keystore` (JKS), then run `java tools/ExtractKey.java [alias] [password]`
from the repository root. That regenerates `desktop/res/debug.pk8`, `desktop/res/debug.cer` and
`web/debug-key.js`. Rebuild and redeploy afterwards.

## Licence

MIT, see [LICENSE](LICENSE). Third-party parts are listed in
[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
