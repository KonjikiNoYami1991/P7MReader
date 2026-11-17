<p align="center">
  <img src="docs/social-preview.png" alt="P7MReader" width="100%">
</p>

<p align="center">
  <a href="README.md">Italiano</a> · <b>English</b>
</p>

# P7MReader

**Digital signature verification and document extraction from `.p7m` envelopes, one at a time or by the thousand.**
Checks CAdES (`.p7m`, `.p7s`), PAdES (signed PDFs) and XAdES (`.xml`, Italian FatturaPA e-invoices) signatures with a chain of trust to the **Italian AgID Trusted List (eIDAS)**, tells you *why* each signature is valid or not, and extracts the documents with a clean file name — **your files never leave your computer**.

![Signature verification](docs/screenshot-en.png)

## Download

From the **[Releases](https://github.com/KonjikiNoYami1991/P7MReader/releases/latest)** page:

| System | File | Notes |
|---|---|---|
| Windows 10/11 | `P7MReader-<version>-windows-x64.exe` | Single executable, no installation |
| macOS 12+ (Apple Silicon / Intel) | `P7MReader-<version>-macOS-arm64.dmg` / `-x86_64.dmg` | Unsigned app: on first start *right click → Open* |
| Linux x86_64 | `P7MReader-<version>-x86_64.AppImage` | `chmod +x` and run; or the `.tar.gz` with `installa-linux.sh` |

The release's `SHA256SUMS.txt` lists the fingerprints to check the downloads.

## Language

The interface is in **Italian** when the operating system is in Italian, and in **English** otherwise. It can be set manually in *Settings → Appearance → Language* (applies from the next start).

## How to use it

1. **Drag** files or folders onto the window, or use *Choose files…* / *Choose a folder…*.
2. Choose **Verify signatures** or **Extract documents**: the table fills up while the program works.
3. **Expand a row** (double click, or Enter) to see every check performed, the signer, the certificate and the document.
4. From there: open or extract the document, open/export the certificate, see the e-invoice summary, copy the report.
5. *Report* exports everything to **CSV** (Excel) or to an **HTML** page.

Files and folders passed on the command line are opened right away:

```bash
P7MReader.exe document.pdf.p7m "C:\Signed deeds"
```

### Keyboard shortcuts

| Keys | Action |
|---|---|
| `Ctrl+O` | Open files |
| `Ctrl+Shift+O` | Open folder |
| `Ctrl+F` | Go to the table filter |
| `Ctrl+1` … `Ctrl+4` | Home, Verification, Extraction, Settings |
| `Enter` / `Space` | Expand or collapse the selected row |
| `Menu` / `Shift+F10` | Row actions (open, extract, certificate, copy…) |
| `Esc` | Cancel the running operation |
| `Tab` / `Shift+Tab` | Move between controls (the highlighted border shows where you are) |

## The verification engine

For every signature (and countersignature) these checks are performed and shown:

| Check | What it verifies |
|---|---|
| **Document integrity** | Content digest and cryptographic signature (RSA, RSA-PSS, ECDSA, EdDSA). For PDFs also **changes after signing**; for XAdES references, transforms and `SignedInfo` |
| **Signature-certificate binding** | `signing-certificate` attribute (CAdES/PAdES) or `SigningCertificate` (XAdES) |
| **Timestamp** | RFC 3161 token truly verified: digest, token signature, TSA certificate. When valid, the signature is assessed **at that date**; an **eIDAS qualified** timestamp is reported as such |
| **Certificate validity** | At the timestamp date or (optionally) at the claimed signing date for expired certificates |
| **Chain of trust** | Up to a root in the AgID Trusted List, the Windows store or the CAs you added; missing intermediates are downloaded via AIA |
| **AgID Trusted List** | Status of the certification authority **at signing time**, using the list history (services later withdrawn or suspended are reported) |
| **eIDAS qualification** | Certificate QcStatements + Trusted List qualifications (QSCD, signature or seal, policy criteria): **qualified electronic signature (QES)**, qualified seal, advanced signature with qualified certificate, remote signing… |
| **Revocation** | OCSP/CRL (soft-fail: if servers do not answer the result becomes *Warning* and says so) |
| **Algorithms / key usage** | Weak algorithms (SHA-1, MD5, RSA < 2048) and whether the certificate is enabled for signing |

The result is **Verified**, **Warning** or **Invalid**, always with the reason (the first failed check).

### A Trusted List you can trust

The AgID Trusted List is downloaded at every start (with a cached copy and a copy bundled in the program for offline use) and **is not used unless it is authentic**:

1. its XAdES signature is verified;
2. the certificate that signed it must be among those the **European Commission** publishes for Italy in the *List of Trusted Lists* (LOTL);
3. an expired list (*NextUpdate* passed) is reported.

A downloaded copy with an invalid signature or an unknown signer is rejected; a tampered local copy is never loaded. The status is shown in *Settings → Trusted roots* and in the status bar.

> P7MReader is a technical verification tool: it is not a *qualified validation service* under Article 33 of the eIDAS Regulation and its results have no legal value by themselves.

## Extraction

- `.p7m` envelopes, also **nested** (double signature) or **base64/PEM**.
- **Clean name**: `.pdf (1) (1).p7m`, `.p7m (2)`, ` - Copia` are removed; the extension comes from the content (PDF, Office, ODF, images, XML…).
- Same name and same content = *Already present*; different content = `document (2).pdf`.
- Output next to the originals or in a folder of your choice; optionally deletes the `.p7m` after a successful extraction (never if the signature is invalid, always after confirmation).

## Accessibility

Designed following **WCAG 2.1 level AA**, without changing the look:

- **everything works from the keyboard** (see the shortcuts) and the **focus is always visible** when using the keyboard;
- **accessible names and descriptions** for screen readers (NVDA, Narrator, JAWS); coloured results always come with text, and check details are read in full;
- **text contrast of at least 4.5:1** in both themes (light and dark);
- text follows the **size set in Windows** (*Accessibility → Text size*);
- **animations** can be turned off and stay off when animation effects are disabled in Windows;
- the HTML report uses table headers, document language and text alternatives for symbols.

## Running from source

Requires **Python 3.12+** (tested with 3.13 and 3.15).

```bash
pip install PyQt6 pyhanko pyhanko-certvalidator asn1crypto cryptography lxml certifi
```

```bash
python P7MReader.py
```

Automatic check (modules, Trusted List, interface), exit code 0 when everything is fine:

```bash
python P7MReader.py --selftest
```

To force a language, set `P7MREADER_LANG=en` or `P7MREADER_LANG=it`.

## Building the executable

Windows (single exe with icon and version info; runs the self-test and prints the SHA-256 at the end):

```bash
build_p7mreader.bat
```

macOS and Linux (`.app` + `.dmg`, or AppImage + `.tar.gz`):

```bash
./build_p7mreader.sh
```

Releases are built automatically on GitHub Actions when a `v*` tag (e.g. `v3.1.0`) is pushed, for Windows, macOS and Linux.

## Where data is stored

| What | Where (Windows) |
|---|---|
| Settings | `%APPDATA%\P7MReader\impostazioni.json` |
| Cached AgID Trusted List and EU LOTL | `%APPDATA%\P7MReader\TSL-IT.xml`, `eu-lotl.xml` |
| Error log | `%APPDATA%\P7MReader\errori.log` |

On macOS and Linux the folder is `~/.config/P7MReader`.

**Network connections**: only to the AgID Trusted List, the European Commission LOTL and the OCSP/CRL/AIA servers named in the certificates. Documents are never sent anywhere.

## License

Released under the **GNU GPL v3.0** — see [LICENSE](LICENSE).
