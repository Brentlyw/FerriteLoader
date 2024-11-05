# FerriteLoader
Ferrite is an undetected, indirect, and memory safe rust shellcode injector &amp; executor.

## Features

- **Nt-Based APIs**: Ferrite avoids commonly flagged APIs (`VirtualAlloc`, `VirtualProtect`, `CreateRemoteThread`, `WriteProcessMemory`) by dynamically resolving and utilizing their undocumented ntdll.dll based counterparts (`NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtProtectVirtualMemory`, `RtlCreateUserThread`). The use of these lesser-common APIs lower the threat score for the binary as a whole during most forms of analysis.

- **PEB Walking for Dynamic API Resolution**: Ferrite locates its most crucial syscalls by traversing the Process Environment Block (PEB) to find function addresses within `ntdll.dll`. This protects/hides its functionality from surface IAT scans, also adding a layer of obscurity during reverse analysis of the binary.

- **Encoded Shellcode Handling**: Ferrite uses custom encoding/decoding of the shellcode payload. The included Encode.py script applies a custom charset mapping, additive feedback loop, and XOR encoding to the raw shellcode .bin file (with a user-defined seed). The encoded shellcode is stored in a `.dat` file and embedded as a resource within the binary during compilation, allowing Ferrite to decode and inject it only at runtime, minimizing exposure to memory & protecting the payload during static analysis.

- **Stack Strings**: Strings like "NtAllocateVirtualMemory" are not present as contiguous literals in the binary. Instead, they're built from separate characters during execution, protecting from RE and static engine detection.
- **Gargoyle Technique**: Ferric uses the simple, yet extremely effective 'gargoyle' technique to evade memory scanning of the injected process. This marks the target memory mapped region from R/W/X to R/W just a couple seconds after execution.

## Future Implementation

- **Chunk-Based Injection**: To avoid storing the entire decoded shellcode in memory, Ferrite is planned to implement this technique to avoid memory-based scanning.


## Detection Status
- https://kleenscan.com/scan_result/1ffa38cf798caed38c34732464dd225a7c19420f0559b3c7290e51ac5f0fd510
- *Note: Obviously this code can be signatured, but I did my best to remove commonalities of shellcode injection.*
