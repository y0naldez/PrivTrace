# Compatibility

- Target framework: `.NETFramework,Version=v4.0` (Full), unchanged from the supplied project.
- Output platform: `AnyCPU`; native declarations use pointer-sized handles and Unicode APIs, allowing x86 or x64 CLR execution where the underlying API is available.
- Runtime baseline: Windows 7 / Windows Server 2008 R2 or later with .NET Framework 4.x installed. Task Scheduler 2.0 and the Service Control Manager are Windows-only.
- `RegistryView.Registry32/Registry64` and `RegistryKey.OpenBaseKey` are available in .NET Framework 4.0. On 64-bit Windows, PrivTrace records both requested views; Windows may expose a shared underlying `SYSTEM` key, so findings remain deduplicated by service/path.
- Build chain verified here: Visual Studio Build Tools 2019 16.11 plus installed .NET Framework v4.0 reference assemblies.
- Visual Studio 2022 and later cannot build targets 4.0–4.5.1 according to Microsoft. Use VS/Build Tools 2019 or earlier and install the matching reference assemblies; do not silently retarget.
- Windows 10/11 and newer Server releases generally run .NET Framework 4-targeted applications through the in-place 4.x runtime, but host-specific validation remains required.
- Long paths remain subject to .NET Framework 4.0 and host API limitations; the tool does not claim modern long-path opt-in support.
- No third-party packages, PowerShell, Python, Internet connection, or administrative token are required for normal execution.

The workspace uses `PrivTrace.slnx`; the production project is `src/PrivTrace/PrivTrace.csproj` and the test project is `tests/PrivTrace.Tests/PrivTrace.Tests.csproj`.
