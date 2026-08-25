# CheckSecBN

A static, [Narly](https://code.google.com/archive/p/narly/)/checksec-style exploit-mitigation
reporter for Binary Ninja.

The classic WinDbg extension **narly** inspected a *live* process's loaded modules and reported
`/SafeSEH`, `/GS`, DEP, and ASLR status. CheckSecBN reports the same class of information, but
statically. Straight from the PE headers and load-config directory Binary Ninja has already
loaded. No debugger session required.

## What it reports

- ASLR (Dynamic Base) / High Entropy VA
- DEP / NX
- SafeSEH (32-bit only; reported as N/A on 64-bit, which is table-based SEH and always safe)
- GS / stack cookie (heuristic, see caveat below)
- Control Flow Guard (CFG)
- Force Integrity
- AppContainer / No SEH
- Authenticode signature *presence* (not validated)

## Install

Copy the `CheckSecBN` folder into your Binary Ninja plugins directory:

| Platform | Path |
|---|---|
| Windows | `%APPDATA%\Binary Ninja\plugins\` |
| macOS   | `~/Library/Application Support/Binary Ninja/plugins/` |
| Linux   | `~/.binaryninja/plugins/` |

Restart Binary Ninja (or use the Plugin Manager's reload).

## Usage

With a PE binary loaded, run:

```
Tools > CheckSecBN > Show Mitigation Report
```

(or right-click in the disassembly/decompiler view and find it under the same submenu).

This opens a Markdown report tab with a mitigation table, and also logs a plain-text copy to the
Binary Ninja log. It works the same way when run headlessly via the Binary Ninja API:

```python
import binaryninja as bn
bv = bn.load("target.exe")
import CheckSecBN
CheckSecBN.show_checksec_report(bv)
```

## Caveats

- **GS detection is a heuristic.** It's based on whether the load-config directory's
  `SecurityCookie` field is non-zero, which is the same heuristic older checksec-style tools use.
  It is not a substitute for actually confirming a `__security_check_cookie` call sequence in the
  binary.
- **Signature presence != signature validity.** This plugin only checks whether a certificate
  blob is attached (`IMAGE_DIRECTORY_ENTRY_SECURITY`), not whether it's valid, trusted, or
  unrevoked. For real Authenticode validation, use something like
  [winchecksec](https://github.com/trailofbits/winchecksec) or Windows' own signtool/`Get-AuthenticodeSignature`.
- Only tested against standard PE32/PE32+ images. Malformed or heavily obfuscated headers
  (stomped headers, packed loaders that rewrite the PE header at runtime, etc.) may not parse
  cleanly. The plugin will log a parse error rather than guess.

## Why not just use winchecksec?

You can, and for authoritative static-mitigation results you probably should,
[winchecksec](https://github.com/trailofbits/winchecksec) is the more rigorous, actively
maintained tool for this. CheckSecBN exists for the workflow where you want the same info
without leaving Binary Ninja or shelling out to a separate tool.

## License

MIT
