# FerriteLoader
FerriteLoader is an undetected, indirect, and memory safe rust shellcode injector &amp; executor.

## Features

- **Nt-Based APIs**: FerriteLoader avoids commonly flagged APIs (`VirtualAlloc`, `VirtualProtect`, `CreateRemoteThread`, `WriteProcessMemory`) by dynamically resolving and utilizing their undocumented ntdll.dll based counterparts (`NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtProtectVirtualMemory`, `RtlCreateUserThread`). The use of these lesser-common APIs lower the threat score for the binary as a whole during most forms of analysis.

- **PEB Walking for Dynamic API Resolution**: FerriteLoader locates its most crucial syscalls by traversing the Process Environment Block (PEB) to find function addresses within `ntdll.dll`. This protects/hides its functionality from surface IAT scans, also adding a layer of obscurity during reverse analysis of the binary.

- **Encoded Shellcode Handling**: FerriteLoader uses custom encoding/decoding of the shellcode payload. The included Encode.py script applies a custom charset mapping, additive feedback loop, and XOR encoding to the raw shellcode .bin file (with a user-defined seed). The encoded shellcode is stored in a `.dat` file and embedded as a resource within the binary during compilation, allowing FerriteLoader to decode and inject it only at runtime, minimizing exposure to memory & protecting the payload during static analysis.
- **Gargoyle Technique**: Ferric uses the simple, yet extremely effective 'gargoyle' technique to evade memory scanning of the injected process. This marks the target memory mapped region from R/W/X to R/W just a couple seconds after execution.
- **Stack Strings**: Select strings are not present as contiguous literals in the binary. Instead, they're built from a stack during execution, protecting from static engine detection.
- **Encrypted Strings** Select high-risk strings utilize the goldberg_strings compilation-time protection module to encrypt strings, protecting them from static engine detection, and reverse engineering.
- **Encrypted Integers** Most integers and stored values are also protected with the goldberg_int compilation-time protection module, protecting them from reverse engineering.

## Mandiant CAPA Results
```
┍━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┯━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┑
│ Capability                                           │ Namespace                                            │
┝━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┿━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┥
│ contain obfuscated stackstrings                      │ anti-analysis/obfuscation/string/stackstring         │
│ compiled with rust                                   │ compiler/rust                                        │
│ reference Base64 string                              │ data-manipulation/encoding/base64                    │
│ encode data using XOR (4 matches)                    │ data-manipulation/encoding/xor                       │
│ encrypt data using RC4 PRGA (2 matches)              │ data-manipulation/encryption/rc4                     │
│ get common file path                                 │ host-interaction/file-system                         │
│ write file on Windows                                │ host-interaction/file-system/write                   │
│ get number of processors                             │ host-interaction/hardware/cpu                        │
│ check mutex and exit                                 │ host-interaction/mutex                               │
│ check OS version                                     │ host-interaction/os/version                          │
│ enumerate processes                                  │ host-interaction/process/list                        │
│ link many functions at runtime                       │ linking/runtime-linking                              │
│ parse PE header                                      │ load-code/pe                                         │
┕━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┷━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┙
```
## Detection Results
- [Kleenscan Results](https://kleenscan.com/scan_result/303f6dcc05bc0ce7b4d93cc37983acfcfbf90dad54920b16047ee161e35dbd49) (*0/39*)
- *Note: Obviously this code can be signatured, but I did my best to remove commonalities of shellcode injection.*

## Special Thanks
*A very large special thanks to frank2, who developed the goldberg crate. This helped protect some immediate-use strings, and ints in FerriteLoader.
