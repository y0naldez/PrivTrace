# Architecture

PrivTrace follows a collect, normalize, evaluate, correlate, report pipeline.

1. `TokenCollector` opens the current process token and reads groups, attributes, privileges, elevation, restrictions, and integrity with native APIs. `GroupCollector` exposes the normalized SID-based view.
2. `ServiceCollector` enumerates Win32 services through the Service Control Manager, queries configuration and security descriptors, separates executable paths from arguments, checks `SERVICE_CHANGE_CONFIG`, and evaluates executable/directory/candidate ACLs without mutation.
3. `RegistryCollector` receives only the SCM-derived service list. It reads each matching `HKLM\SYSTEM\CurrentControlSet\Services\<name>` and `Parameters` key in the relevant registry views, records owner/ACEs, evaluates registry-specific rights, and resolves `ImagePath`/`ServiceDll`; it never performs a global registry sweep.
4. `ScheduledTaskCollector` walks Task Scheduler 2.0 COM folders, reads registered actions, principals, run level, triggers, state, and task security descriptors. `SystemCollector` also reads both scopes of the AlwaysInstallElevated policy without changing the registry.
5. `AccessEvaluator` obtains binary security descriptors and calls `AccessCheck` with a duplicated impersonation token and object-specific generic-right mapping. It handles file/directory and registry masks separately. Missing paths and access failures remain `UNKNOWN`.
6. `ProcessCollector` uses a read-only Toolhelp snapshot for PID/PPID/name, opens each process with query-only rights, resolves the image with `QueryFullProcessImageName`, and reads owner and integrity from `OpenProcessToken`. Inaccessible fields remain `UNKNOWN`.
7. `ExecutionCorrelation` deduplicates observed images and configured service/task/ServiceDll references, associates services by the PID reported by SCM, and emits typed relationships. `ServiceDll` is always `CONFIGURED`; a host PID does not turn it into an observed loaded module.
8. `RuleCatalog` rejects duplicate or malformed IDs, gaps, incomplete metadata, unknown categories, category-incompatible evaluators, and malformed references.
9. `RuleEngine` uses specialized privilege, group, service, and task evaluators. PT-026 separates registry-key rights from SCM rights; PT-027 requires a privileged shared-process service, configured DLL, and effective filesystem control.
10. Reporters produce compact findings, optional process/binary/relationship views, per-collector timings in verbose mode, and structured JSON.

The central engine depends on normalized models rather than live collectors, which permits offline fixtures and deterministic tests. Rules are declarative for metadata and evaluator routing; security-sensitive multi-object conditions remain in reviewed C# evaluators.

No component contains write, service-control, task-registration, payload, persistence, or network execution logic.
