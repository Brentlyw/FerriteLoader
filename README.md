# Ferrite
Ferrite is an indirect rust-based shellcode injector &amp; executor.

## Features

- **Dynamic Nt-Based API Resolution**: Ferrite avoids commonly flagged APIs by dynamically resolving and utilizing `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtProtectVirtualMemory`, and `RtlCreateUserThread`. These functions are less commonly used than their counterparts in typical injection malware.

- **PEB-Based Function Resolution with Checksum Verification**: Instead of relying on traditional imports, Ferrite locates critical & high-risk functions by traversing the Process Environment Block (PEB) to find func addresses within `ntdll.dll`. Each function is identified using custom checksum verification, removing the need for static references to them. This dynamic lookup provides strong stealth against import-based detection methods.

- **Encoded Shellcode Handling**: To bypass shellcode heurustics, Ferrite encodes shellcode using a multi-layered approach. It applies a custom charset, additive feedback loop, and XOR encoding. The encoded shellcode is stored in a `.dat` file and embedded as a resource within the binary, allowing Ferrite to decode and inject it only at runtime, minimizing exposure to memory.

- **Low-Level Memory Management**: Ferrite allocates and manages memory directly through Nt-based calls, bypassing commonly flagged functions like `VirtualAllocEx`.

## Future Implementation

- **Chunk-Based Injection**: To avoid storing the entire decoded shellcode in memory, Ferrite is planned to implement this technique to avoid memory-based scanning.
- **Gargoyle Technique**: To avoid memory scanning all together, or to avoid the risk of flagging a memory region as high-risk, Ferrite is planned to implement the gargoyle technique to mark the memory region as 'R/W' after execution.


 ## Sanity check?
 - **No**


## Detection Status
- https://kleenscan.com/scan_result/1ffa38cf798caed38c34732464dd225a7c19420f0559b3c7290e51ac5f0fd510
- *Note: Obviously this code can be signatured, but I did my best to remove commonalities of shellcode injection.*
