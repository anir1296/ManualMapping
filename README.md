
## Overview:
Manual mapped injection (also called retrospective/introspective injection)
involves mapping a dll into a target process without calling LoadLibrary in the target process

This is more evasive because some applications will hook into LoadLibrary to detect the dlls being loaded
However, it is very complicated because you have to emulate everything LoadLibrary does

Solution uses VS2022.
For a simple DLL injection demonstration, see Injector project.
For manual mapping, see ManualMappingInjector project

## Resources and Examples:
1. Complete video tutorial:
* https://www.youtube.com/watch?v=qzZTXcBu3cE&feature=emb_title
2. Manual mapped injector by Cruz:
* https://github.com/TheCruZ/Simple-Manual-Map-Injector
3. Memory module written in C:
* https://github.com/fancycode/MemoryModule/tree/master/doc
4. PE format docs:
* https://docs.microsoft.com/en-us/windows/win32/debug/pe-format
5. Blog of PE Parser:
* https://0xrick.github.io/win-internals/pe8/
