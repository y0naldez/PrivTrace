using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using PrivTrace.Models;
using PrivTrace.Security;

namespace PrivTrace.Core
{
    public static class ExecutionCorrelation
    {
        public static void Correlate(AnalysisContext context, bool evaluateLivePermissions = true)
        {
            if (context.Processes == null) context.Processes = new List<WindowsProcess>();
            if (context.Binaries == null) context.Binaries = new List<BinaryArtifact>();
            if (context.ExecutionRelationships == null) context.ExecutionRelationships = new List<ExecutionRelationship>();
            Dictionary<int, WindowsProcess> processById = context.Processes.GroupBy(p => p.ProcessId).ToDictionary(g => g.Key, g => g.First());
            foreach (WindowsService service in context.Services)
            {
                WindowsProcess process;
                if (service.ProcessId > 0 && processById.TryGetValue(service.ProcessId, out process)) AddUnique(process.ServiceNames, service.Name);
            }
            foreach (WindowsProcess process in context.Processes)
            {
                WindowsProcess parent; if (processById.TryGetValue(process.ParentProcessId, out parent)) process.ParentImagePath = parent.ImagePath;
                BinaryPathResolution resolved = BinaryPathResolver.Resolve(process.ImagePath, null, true);
                BinaryArtifact binary = Add(context, resolved, "ProcessImage");
                if (binary != null)
                {
                    AddUnique(binary.ProcessIds, process.ProcessId); binary.ObservedProcessImage = true;
                    AddUnique(binary.ExecutionIdentities, process.OwnerAccount ?? process.OwnerSid);
                    foreach (string serviceName in process.ServiceNames) AddUnique(binary.ServiceNames, serviceName);
                }
            }
            foreach (WindowsService service in context.Services)
            {
                BinaryPathResolution resolved = BinaryPathResolver.Resolve(service.ExecutablePath ?? service.BinaryPath, null, false);
                BinaryArtifact binary = Add(context, resolved, "ServiceConfiguration");
                if (binary != null)
                {
                    AddUnique(binary.ServiceNames, service.Name); AddUnique(binary.ExecutionIdentities, service.Account);
                    if (service.ProcessId > 0) AddUnique(binary.ProcessIds, service.ProcessId);
                    if (service.ExecutablePermission != null) binary.FilePermission = service.ExecutablePermission;
                    if (service.DirectoryPermission != null) binary.DirectoryPermission = service.DirectoryPermission;
                }
                WindowsProcess serviceProcess; bool exactObservedProcess = service.ProcessId > 0 && processById.TryGetValue(service.ProcessId, out serviceProcess) && BinaryPathResolver.SamePath(serviceProcess.ImagePath, resolved == null ? null : resolved.Path);
                if (resolved != null && !String.IsNullOrWhiteSpace(resolved.Path) && !context.ExecutionRelationships.Any(r => r.SourceKind == "ServiceExecutable" && String.Equals(r.SourceId, service.Name, StringComparison.OrdinalIgnoreCase)))
                    context.ExecutionRelationships.Add(new ExecutionRelationship { Classification = exactObservedProcess ? "OBSERVED" : "CONFIGURED", RelationStatus = exactObservedProcess ? "OBSERVED" : "CONFIGURED", SourceKind = "ServiceExecutable", SourceId = service.Name, TargetPath = resolved.Path, HostProcessId = exactObservedProcess ? service.ProcessId : 0, EvidenceSource = exactObservedProcess ? "ServiceCollector+ProcessCollector exact PID/path" : "ServiceCollector+QueryServiceConfig", Confidence = exactObservedProcess ? Confidence.High : Confidence.Medium, ObjectIdentity = service.Name + "|" + resolved.Path, RuleIds = new List<string> { "PT-013", "PT-016" }, Detail = exactObservedProcess ? "The configured service executable is correlated to an observed process by exact service PID and image path." : "The service executable is configured; no matching process image is inferred." });
                foreach (ServiceRegistryEvidence registry in service.RegistryEvidence ?? new List<ServiceRegistryEvidence>())
                {
                    if (String.IsNullOrWhiteSpace(registry.ServiceDllPath)) continue;
                    BinaryPathResolution dllResolution = new BinaryPathResolution { Original = registry.ServiceDll, Path = registry.ServiceDllPath, Exists = registry.ServiceDllExists, IsAmbiguous = false, ObservedImage = false, Detail = "Resolved from the service ServiceDll registry value." };
                    BinaryArtifact dll = Add(context, dllResolution, "ServiceDllConfiguration");
                    if (dll != null)
                    {
                        AddUnique(dll.ServiceNames, service.Name); AddUnique(dll.ExecutionIdentities, service.Account);
                        if (registry.ServiceDllPermission != null) dll.FilePermission = registry.ServiceDllPermission;
                        if (registry.ServiceDllDirectoryPermission != null) dll.DirectoryPermission = registry.ServiceDllDirectoryPermission;
                    }
                    if (!context.ExecutionRelationships.Any(r => r.Classification == "CONFIGURED" && r.SourceKind == "ServiceDll" && String.Equals(r.SourceId, service.Name, StringComparison.OrdinalIgnoreCase) && BinaryPathResolver.SamePath(r.TargetPath, registry.ServiceDllPath)))
                        context.ExecutionRelationships.Add(new ExecutionRelationship { Classification = "CONFIGURED", SourceKind = "ServiceDll", SourceId = service.Name, TargetPath = registry.ServiceDllPath, HostProcessId = service.ProcessId, Detail = "Registry configuration associates this DLL with the service. DLL load was not observed or inferred." });
                }
            }
            foreach (ScheduledTaskInfo task in context.Tasks)
            {
                foreach (ScheduledTaskAction action in task.Actions)
                {
                    if (String.IsNullOrWhiteSpace(action.Executable)) continue;
                    BinaryPathResolution resolved = BinaryPathResolver.Resolve(action.Executable, action.WorkingDirectory, false);
                    BinaryArtifact binary = Add(context, resolved, "ScheduledTaskConfiguration");
                    if (binary == null) continue;
                    AddUnique(binary.TaskPaths, task.Path); AddUnique(binary.ExecutionIdentities, task.Principal);
                    if (action.TargetPermission != null) binary.FilePermission = action.TargetPermission;
                }
            }
            if (evaluateLivePermissions)
            {
                AccessEvaluator access = new AccessEvaluator();
                foreach (BinaryArtifact binary in context.Binaries)
                {
                    if (binary.FilePermission == null) binary.FilePermission = access.EvaluatePath(binary.Path, false);
                    if (binary.DirectoryPermission == null)
                    {
                        string directory = null; try { directory = String.IsNullOrWhiteSpace(binary.Path) ? null : Path.GetDirectoryName(binary.Path); } catch { }
                        binary.DirectoryPermission = access.EvaluatePath(directory, true);
                    }
                }
            }
        }

        private static BinaryArtifact Add(AnalysisContext context, BinaryPathResolution resolved, string source)
        {
            if (resolved == null || String.IsNullOrWhiteSpace(resolved.Path)) return null;
            BinaryArtifact binary = context.Binaries.FirstOrDefault(b => BinaryPathResolver.SamePath(b.Path, resolved.Path));
            if (binary == null)
            {
                binary = new BinaryArtifact { Path = resolved.Path, OriginalReference = resolved.Original, Exists = resolved.Exists, IsAmbiguous = resolved.IsAmbiguous, ObservedProcessImage = resolved.ObservedImage };
                if (!String.IsNullOrWhiteSpace(resolved.Detail)) binary.Errors.Add(resolved.Detail); context.Binaries.Add(binary);
            }
            else
            {
                binary.ObservedProcessImage = binary.ObservedProcessImage || resolved.ObservedImage;
                binary.IsAmbiguous = binary.IsAmbiguous || resolved.IsAmbiguous;
                if (binary.Exists == TriState.Unknown) binary.Exists = resolved.Exists;
            }
            AddUnique(binary.Sources, source); return binary;
        }

        private static void AddUnique(List<string> values, string value) { if (!String.IsNullOrWhiteSpace(value) && !values.Contains(value, StringComparer.OrdinalIgnoreCase)) values.Add(value); }
        private static void AddUnique(List<int> values, int value) { if (!values.Contains(value)) values.Add(value); }
    }
}
