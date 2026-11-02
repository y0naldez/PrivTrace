using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Web.Script.Serialization;
using PrivTrace.Models;

namespace PrivTrace.Reporting
{
    public static class ConsoleReporter
    {
        public static void PrintBanner()
        {
            Console.WriteLine("=================================================");
            Console.WriteLine("                PrivTrace v1.0.0");
            Console.WriteLine("       Windows Privilege Escalation Analyzer");
            Console.WriteLine("=================================================");
        }

        public static void Print(AnalysisResult result, bool verbose)
        {
            PrintBanner();
            Console.WriteLine("[+] User      : " + (result.Context.Token.UserName ?? "Unknown"));
            Console.WriteLine("[+] Integrity : " + (result.Context.Token.IntegrityLevel ?? "Unknown"));
            Console.WriteLine("[+] OS        : " + result.Context.System.OsVersion + " " + result.Context.System.Architecture);
            List<Finding> all = result.Findings ?? new List<Finding>();
            int unknownCount = all.Count(f => f.Status == EvaluationStatus.Unknown);
            Console.WriteLine(); Console.WriteLine("Collection Coverage:");
            Console.WriteLine("Services: " + (result.Context.ServiceEnumerationState ?? "UNKNOWN"));
            Console.WriteLine("Tasks: " + (result.Context.TaskEnumerationState ?? "UNKNOWN"));
            if (!String.Equals(result.Context.ServiceEnumerationState, "OBSERVED", StringComparison.OrdinalIgnoreCase) || !String.Equals(result.Context.TaskEnumerationState, "OBSERVED", StringComparison.OrdinalIgnoreCase))
                Console.WriteLine("Impact: Some service/task escalation checks could not be completed; unaffected evidence remains available.");
            PrintCorrelations(result.CorrelationTraces, verbose);
            Console.WriteLine(); Console.WriteLine("================================================="); Console.WriteLine(verbose ? "FINDINGS (FULL DIAGNOSTICS)" : "ESCALATION PATHS"); Console.WriteLine("=================================================");
            HashSet<string> correlatedFindingIds = new HashSet<string>((result.CorrelationTraces ?? new List<CorrelationTrace>()).SelectMany(t => t.FindingIds), StringComparer.OrdinalIgnoreCase);
            HashSet<string> groupedServiceFindingIds = verbose ? new HashSet<string>(StringComparer.OrdinalIgnoreCase) : PrintServiceFindingGroups(result.Context.Services, all);
            IEnumerable<Finding> visible = verbose ? all : all.Where(f => !correlatedFindingIds.Contains(f.FindingId) && !groupedServiceFindingIds.Contains(f.FindingId) && IsActionable(f));
            List<Finding> visibleList = visible.OrderBy(f => Rank(f.Status)).ThenBy(f => f.Severity).ToList();
            if (!verbose && visibleList.Count == 0 && groupedServiceFindingIds.Count == 0 && !(result.CorrelationTraces ?? new List<CorrelationTrace>()).Any(t => t.Status == EvaluationStatus.Confirmed || t.Status == EvaluationStatus.Potential))
                Console.WriteLine("No actionable escalation paths verified.");
            foreach (Finding finding in visibleList)
            {
                Console.WriteLine(); Console.WriteLine("[" + finding.Severity.ToString().ToUpperInvariant() + "] " + finding.RuleId + " - " + finding.Name);
                if (!String.IsNullOrEmpty(finding.Target)) Console.WriteLine("Target: " + finding.Target);
                Console.WriteLine("Status: " + finding.Status.ToString().ToUpperInvariant() + " | Confidence: " + finding.Confidence.ToString().ToUpperInvariant());
                Console.WriteLine("Rule severity: " + finding.RuleSeverity.ToString().ToUpperInvariant() + " | Finding severity: " + finding.Severity.ToString().ToUpperInvariant());
                foreach (Evidence e in finding.Evidence) Console.WriteLine((e.Positive ? "[+] " : "[-] ") + e.Value);
                if (finding.Trace.Count > 0) { Console.WriteLine("TRACE:"); foreach (string step in finding.Trace) Console.WriteLine("  -> " + step); }
                IEnumerable<string> missingConditions = verbose ? finding.MissingConditions : finding.MissingConditions.Take(1);
                foreach (string missing in missingConditions) Console.WriteLine("[?] " + missing);
                if (!String.IsNullOrEmpty(finding.Recommendation)) Console.WriteLine("Recommendation: " + finding.Recommendation);
            }
            PrintInterestingSoftware(result.Context.Software, verbose, result.Context.EvidenceOrigin);
            if (!verbose && unknownCount > 0)
            {
                Console.WriteLine(); Console.WriteLine("Collection limitations:");
                Console.WriteLine("Services: " + (result.Context.ServiceEnumerationState ?? "UNKNOWN"));
                Console.WriteLine("Tasks: " + (result.Context.TaskEnumerationState ?? "UNKNOWN"));
                foreach (IGrouping<string, Finding> group in all.Where(f => f.Status == EvaluationStatus.Unknown).GroupBy(f => f.RuleId).OrderBy(g => g.Key))
                    Console.WriteLine(group.Key + " checks: " + group.Count() + " unresolved.");
                Console.WriteLine(); Console.WriteLine("Diagnostics: " + unknownCount + " checks unresolved.");
                Console.WriteLine("Run --verbose for details.");
            }
            Console.WriteLine(); Console.WriteLine("================================================="); Console.WriteLine("SUMMARY"); Console.WriteLine("=================================================");
            Console.WriteLine("Rules evaluated : " + result.RulesEvaluated);
            Console.WriteLine("Confirmed       : " + all.Count(f => f.Status == EvaluationStatus.Confirmed));
            Console.WriteLine("Potential       : " + all.Count(f => f.Status == EvaluationStatus.Potential && HasPositiveEvidence(f)));
            Console.WriteLine("Unknown checks  : " + unknownCount);
            Console.WriteLine("Collection Coverage: " + (unknownCount > 0 || !String.Equals(result.Context.ServiceEnumerationState, "OBSERVED", StringComparison.OrdinalIgnoreCase) || !String.Equals(result.Context.TaskEnumerationState, "OBSERVED", StringComparison.OrdinalIgnoreCase) ? "PARTIAL" : "COMPLETE"));
            if (verbose)
            {
                if (result.Context.Timings != null && result.Context.Timings.Count > 0)
                {
                    Console.WriteLine("Collector timings:");
                    foreach (CollectorTiming timing in result.Context.Timings) Console.WriteLine("  " + timing.Name + ": " + timing.ElapsedMilliseconds + " ms (" + timing.Items + " items)");
                }
                foreach (string error in result.Errors) Console.WriteLine("[!] " + error);
                foreach (CollectorDiagnostic diagnostic in result.Context.Diagnostics ?? new List<CollectorDiagnostic>())
                    Console.WriteLine("[!] " + diagnostic.Collector + "/" + diagnostic.Stage + " " + diagnostic.Api + " object=" + (diagnostic.ObjectName ?? "GLOBAL") + " access=" + (diagnostic.RequestedAccess ?? "N/A") + " win32=" + diagnostic.Win32Error + " hresult=0x" + diagnostic.HResult.ToString("X8") + " classification=" + diagnostic.Classification);
            }
        }

        public static void PrintInterestingSoftware(IEnumerable<SoftwareObservation> software, bool verbose, string evidenceOrigin)
        {
            List<SoftwareObservation> items = (software ?? Enumerable.Empty<SoftwareObservation>()).ToList();
            if (items.Count == 0) return;
            PrintSoftwareSection(items.Where(s => !String.Equals(s.SoftwareContext, "INFRASTRUCTURE", StringComparison.OrdinalIgnoreCase)).ToList(), "INTERESTING SOFTWARE", verbose, evidenceOrigin);
            PrintSoftwareSection(items.Where(s => String.Equals(s.SoftwareContext, "INFRASTRUCTURE", StringComparison.OrdinalIgnoreCase)).ToList(), "INFRASTRUCTURE SOFTWARE", verbose, evidenceOrigin);
        }

        private static void PrintSoftwareSection(IList<SoftwareObservation> items, string title, bool verbose, string evidenceOrigin)
        {
            if (items == null || items.Count == 0) return;
            Console.WriteLine(); Console.WriteLine("================================================="); Console.WriteLine(title); Console.WriteLine("=================================================");
            int index = 0;
            foreach (SoftwareObservation item in items.OrderByDescending(s => s.InvestigationPriority).ThenBy(s => s.ProductName, StringComparer.OrdinalIgnoreCase).ThenBy(s => s.InstallationRoot, StringComparer.OrdinalIgnoreCase))
            {
                SoftwareCleanSummary summary = BuildSoftwareCleanSummary(item, evidenceOrigin);
                index++; Console.WriteLine(); Console.WriteLine("[" + index + "] " + item.ProductName);
                Console.WriteLine("    Process    : " + summary.Process);
                if (item.ServiceNames.Count > 0) Console.WriteLine("    Service    : " + String.Join(", ", item.ServiceNames.ToArray()));
                Console.WriteLine("    Version    : " + summary.Version);
                Console.WriteLine("    Source     : " + summary.Source);
                Console.WriteLine("    Escalation : " + (item.ActiveRuleIds.Count > 0 ? String.Join(", ", item.ActiveRuleIds.OrderBy(r => r, StringComparer.OrdinalIgnoreCase).ToArray()) : (item.EscalationStatus ?? "NOT_VERIFIED").Replace('_', ' ')));
                if (verbose)
                {
                    if (item.ProcessPaths.Count > 1) Console.WriteLine("    Processes  : " + String.Join(", ", item.ProcessPaths.ToArray()));
                    if (item.ConfiguredExecutablePaths.Count > 0) Console.WriteLine("    Configured : " + String.Join(", ", item.ConfiguredExecutablePaths.ToArray()));
                    if (item.ServiceNames.Count > 0) Console.WriteLine("    Services   : " + String.Join(", ", item.ServiceNames.ToArray()));
                    if (item.ActiveRuleIds.Count > 0) Console.WriteLine("    Rules      : " + String.Join(", ", item.ActiveRuleIds.ToArray()) + " (see ESCALATION PATHS)");
                    Console.WriteLine("    State      : " + (item.State ?? "UNKNOWN") + (item.ObservationStates.Count > 0 ? " | Evidence states: " + String.Join(",", item.ObservationStates.ToArray()) : String.Empty));
                    Console.WriteLine("    Context    : " + (item.SoftwareContext ?? "INTERESTING") + " | Priority: " + item.InvestigationPriority);
                    Console.WriteLine("    Version source: " + (item.VersionSource ?? "UNKNOWN"));
                    Console.WriteLine("    Classification: " + item.ClassificationName + " | Identification: " + item.IdentificationStatus + " | Confidence: " + item.IdentificationConfidence.ToString().ToUpperInvariant());
                    Console.WriteLine("    Signature  : " + item.SignatureStatus.ToString().ToUpperInvariant() + (String.IsNullOrWhiteSpace(item.SignerSubject) ? String.Empty : " | " + item.SignerSubject));
                    Console.WriteLine("    PIDs       : " + String.Join(",", item.ProcessIds.Select(p => p.ToString()).ToArray()));
                    if (item.ScheduledTaskPaths.Count > 0) Console.WriteLine("    Tasks      : " + String.Join(", ", item.ScheduledTaskPaths.ToArray()));
                    foreach (SoftwareVersionEvidence version in item.VersionEvidence ?? new List<SoftwareVersionEvidence>())
                        Console.WriteLine("      [" + (version.ObservationStatus ?? "UNKNOWN") + "] Version " + (version.Product ?? "UNKNOWN") + "=" + (version.Value ?? "UNKNOWN") + " | type=" + (version.SourceType ?? "UNKNOWN") + " | field=" + (version.SourceField ?? "UNKNOWN") + " | read=" + (version.ReadStatus ?? "UNKNOWN") + " | confidence=" + version.Confidence.ToString().ToUpperInvariant() + " | origin=" + (version.EvidenceOrigin ?? "IMPORTED_UNVERIFIED") + (String.IsNullOrWhiteSpace(version.SourcePath) ? String.Empty : " | path=" + version.SourcePath) + (String.IsNullOrWhiteSpace(version.RegistryKey) ? String.Empty : " | key=" + version.RegistryKey) + (String.IsNullOrWhiteSpace(version.CollectionError) ? String.Empty : " | error=" + version.CollectionError));
                    foreach (SoftwareEvidence evidence in item.Evidence) Console.WriteLine("      [" + evidence.StateName + "] " + evidence.Kind + ": " + evidence.Value + " (" + evidence.Source + ")");
                    foreach (string pending in item.PendingConditions) Console.WriteLine("      [?] " + pending);
                    Console.WriteLine("    TRACE:"); foreach (string step in item.Trace) Console.WriteLine("      -> " + step);
                }
            }
        }

        private static SoftwareCleanSummary BuildSoftwareCleanSummary(SoftwareObservation item, string contextOrigin)
        {
            SoftwareCleanSummary summary = new SoftwareCleanSummary { Process = "UNKNOWN", Version = "UNKNOWN", Source = "UNKNOWN" };
            if (item == null) return summary;
            bool imported = String.Equals(contextOrigin, "IMPORTED_UNVERIFIED", StringComparison.OrdinalIgnoreCase);
            if (imported) { summary.Process = "UNKNOWN (IMPORTED_UNVERIFIED)"; return summary; }
            string process = (item.ProcessPaths ?? new List<string>()).FirstOrDefault(p => !String.IsNullOrWhiteSpace(p) && String.Equals(p, item.CanonicalExecutable, StringComparison.OrdinalIgnoreCase))
                ?? (item.ProcessPaths ?? new List<string>()).FirstOrDefault(p => !String.IsNullOrWhiteSpace(p));
            if (!String.IsNullOrWhiteSpace(process)) summary.Process = process;
            SoftwareVersionEvidence evidence = (item.VersionEvidence ?? new List<SoftwareVersionEvidence>()).FirstOrDefault(v =>
                !String.IsNullOrWhiteSpace(item.Version) && String.Equals(v.Value, item.Version, StringComparison.Ordinal) && String.Equals(v.SourceType, item.VersionSource, StringComparison.OrdinalIgnoreCase)
                && String.Equals(v.ObservationStatus, "OBSERVED", StringComparison.OrdinalIgnoreCase) && String.Equals(v.ReadStatus, "SUCCESS", StringComparison.OrdinalIgnoreCase)
                && (String.Equals(v.EvidenceOrigin, "LIVE_OBSERVED", StringComparison.OrdinalIgnoreCase) || String.Equals(v.EvidenceOrigin, "TEST_FIXTURE", StringComparison.OrdinalIgnoreCase)));
            if (evidence == null) return summary;
            summary.Version = evidence.Value;
            if (String.Equals(evidence.SourceType, "UNINSTALL_REGISTRY", StringComparison.OrdinalIgnoreCase) && !String.IsNullOrWhiteSpace(evidence.RegistryKey)) summary.Source = "Registry (" + evidence.RegistryKey + ")";
            else if ((String.Equals(evidence.SourceType, "PE_PRODUCT_VERSION", StringComparison.OrdinalIgnoreCase) || String.Equals(evidence.SourceType, "PE_FILE_VERSION", StringComparison.OrdinalIgnoreCase)) && !String.IsNullOrWhiteSpace(evidence.SourcePath)) summary.Source = "PE metadata (" + evidence.SourcePath + ")";
            else if (!String.IsNullOrWhiteSpace(evidence.SourcePath)) summary.Source = evidence.SourcePath;
            return summary;
        }

        private sealed class SoftwareCleanSummary
        {
            internal string Process;
            internal string Version;
            internal string Source;
        }

        private static HashSet<string> PrintServiceFindingGroups(IEnumerable<WindowsService> services, IEnumerable<Finding> findings)
        {
            HashSet<string> grouped = new HashSet<string>(StringComparer.OrdinalIgnoreCase); List<Finding> candidates = (findings ?? Enumerable.Empty<Finding>()).Where(f => (String.Equals(f.RuleId, "PT-013", StringComparison.OrdinalIgnoreCase) || String.Equals(f.RuleId, "PT-016", StringComparison.OrdinalIgnoreCase)) && !String.IsNullOrWhiteSpace(f.ServiceName) && IsActionable(f)).ToList();
            foreach (IGrouping<string, Finding> group in candidates.GroupBy(f => f.ServiceName, StringComparer.OrdinalIgnoreCase).OrderBy(g => g.Key, StringComparer.OrdinalIgnoreCase))
            {
                WindowsService service = (services ?? Enumerable.Empty<WindowsService>()).FirstOrDefault(s => String.Equals(s.Name, group.Key, StringComparison.OrdinalIgnoreCase));
                Severity severity = group.Any(f => f.Severity == Severity.Critical) ? Severity.Critical : group.Any(f => f.Severity == Severity.High) ? Severity.High : group.Any(f => f.Severity == Severity.Medium) ? Severity.Medium : Severity.Low;
                Console.WriteLine(); Console.WriteLine("[" + severity.ToString().ToUpperInvariant() + "] Service: " + group.Key);
                Console.WriteLine("    Account   : " + (service == null ? "UNKNOWN" : service.Account ?? "UNKNOWN"));
                Console.WriteLine("    Binary    : " + (service == null ? "UNKNOWN" : service.ExecutablePath ?? service.BinaryPath ?? "UNKNOWN"));
                foreach (Finding finding in group.OrderBy(f => f.RuleId, StringComparer.OrdinalIgnoreCase))
                {
                    string operation = String.IsNullOrWhiteSpace(finding.VerifiedOperation) ? finding.PermissionState ?? finding.Status.ToString().ToUpperInvariant() : finding.VerifiedOperation;
                    Console.WriteLine("    " + finding.RuleId + "    : " + operation + " (" + finding.Status.ToString().ToUpperInvariant() + ")"); if (!String.IsNullOrWhiteSpace(finding.FindingId)) grouped.Add(finding.FindingId);
                }
                Console.WriteLine("    Execution : " + (group.Select(f => f.ExecutionState).FirstOrDefault(s => !String.IsNullOrWhiteSpace(s)) ?? "CONDITIONAL_EXECUTION"));
                Console.WriteLine("    CanStart  : " + (service == null ? "UNKNOWN" : service.CanStart.ToString()));
                Console.WriteLine("    Runtime protection: " + (group.Select(f => f.RuntimeProtectionState).FirstOrDefault(s => !String.IsNullOrWhiteSpace(s)) ?? "UNKNOWN"));
            }
            return grouped;
        }

        public static bool IsActionable(Finding finding)
        {
            return finding != null && (finding.Status == EvaluationStatus.Confirmed || (finding.Status == EvaluationStatus.Potential && HasPositiveEvidence(finding)));
        }

        private static bool HasPositiveEvidence(Finding finding)
        {
            return finding.Evidence != null && finding.Evidence.Any(e => e.Positive);
        }

        public static void PrintCorrelations(IEnumerable<CorrelationTrace> correlations, bool verbose)
        {
            List<CorrelationTrace> items = (correlations ?? Enumerable.Empty<CorrelationTrace>()).ToList();
            if (items.Count == 0) return;
            Console.WriteLine(); Console.WriteLine("================================================="); Console.WriteLine("CORRELATED PATHS"); Console.WriteLine("=================================================");
            foreach (CorrelationTrace trace in items.Where(t => verbose || t.Status == EvaluationStatus.Confirmed || t.Status == EvaluationStatus.Potential).OrderBy(t => t.TraceId, StringComparer.OrdinalIgnoreCase))
            {
                Console.WriteLine(); Console.WriteLine("[" + trace.Severity.ToString().ToUpperInvariant() + "] " + trace.Name + " (support: " + String.Join(" + ", trace.SupportingRuleIds.ToArray()) + ")");
                Console.WriteLine("Detection status: " + trace.Status.ToString().ToUpperInvariant() + " | Confidence: " + trace.Confidence.ToString().ToUpperInvariant() + " | Classification: " + trace.Classification);
                if (trace.RuledOutRuleIds.Count > 0) Console.WriteLine("Ruled-out rules: " + String.Join(", ", trace.RuledOutRuleIds.ToArray()));
                foreach (string fact in trace.ConfirmedFacts) Console.WriteLine("[+] " + fact);
                foreach (string outcome in trace.ConditionalOutcomes) Console.WriteLine("[?] " + outcome);
                Console.WriteLine("Exploitation verified: NO");
                foreach (string step in trace.Trace) Console.WriteLine("  -> " + step);
                foreach (string pending in (verbose ? trace.PendingConditions : trace.PendingConditions.Take(2))) Console.WriteLine("[?] " + pending);
                if (verbose) foreach (CorrelationEdge edge in trace.Edges) Console.WriteLine("  [" + edge.State.ToString().ToUpperInvariant() + "] " + edge.SourceNodeId + " -" + edge.Relation + "-> " + edge.DestinationNodeId + " | evidence=" + edge.EvidenceId + " | provenance=" + edge.Provenance);
            }
        }

        public static void PrintHelp()
        {
            PrintBanner();
            Console.WriteLine("Usage: PrivTrace.exe [options]");
            Console.WriteLine("  --clean                   Explicit high-signal output (the default)");
            Console.WriteLine("  --verbose                 Include UNKNOWN, ruled-out findings and diagnostics");
            Console.WriteLine("  --processes               Show observed processes and exact service associations");
            Console.WriteLine("  --binaries                Show deduplicated execution paths and effective permissions");
            Console.WriteLine("  -es, --es                 Show console output in natural Spanish");
            Console.WriteLine("  --json <report.json>      Export structured JSON");
            Console.WriteLine("  --rule <PT-001>           Evaluate one rule");
            Console.WriteLine("  --rule-info <PT-001>      Show rule metadata and references");
            Console.WriteLine("  --category <name>         Filter by category");
            Console.WriteLine("  --offline-fixture <file>  Analyze fixture without live enumeration");
            Console.WriteLine("  --sanitize-report <file>  Sanitize a report offline; requires --json output");
            Console.WriteLine("  --inspect-report <file>   Validate/import a report without changing findings");
            Console.WriteLine("  --list-rules              List the local rule catalog");
            Console.WriteLine("  --help                    Show this help");
        }

        public static void PrintProcesses(IEnumerable<WindowsProcess> processes, bool verbose)
        {
            Console.WriteLine(); Console.WriteLine("================================================="); Console.WriteLine("PROCESSES"); Console.WriteLine("=================================================");
            foreach (WindowsProcess process in (processes ?? Enumerable.Empty<WindowsProcess>()).OrderBy(p => p.ProcessId))
            {
                Console.WriteLine("PID " + process.ProcessId + "  " + (process.Name ?? "Unknown") + "  [" + (process.AccessStatus ?? "UNKNOWN") + "]");
                Console.WriteLine("  Image: " + (process.ImagePath ?? "UNKNOWN") + " (source: " + (process.ImagePathSource ?? "UNKNOWN") + ")");
                Console.WriteLine("  Identity: " + (process.OwnerAccount ?? process.OwnerSid ?? "UNKNOWN") + " | Integrity: " + (process.IntegrityLevel ?? "UNKNOWN") + " | Architecture: " + (process.Architecture ?? "UNKNOWN"));
                Console.WriteLine("  Parent: " + process.ParentProcessId + " " + (process.ParentImagePath ?? "UNKNOWN"));
                if (process.ServiceNames.Count > 0) Console.WriteLine("  Services by exact PID: " + String.Join(", ", process.ServiceNames.ToArray()));
                if (verbose) foreach (string error in process.Errors) Console.WriteLine("  [?] " + error);
                if (verbose && process.FileIdentity != null)
                {
                    FileIdentityMetadata identity = process.FileIdentity;
                    Console.WriteLine("  PE: product=" + (identity.ProductName ?? "UNKNOWN") + "; productVersion=" + (identity.ProductVersion ?? "UNKNOWN") + "; fileVersion=" + (identity.FileVersion ?? "UNKNOWN") + "; company=" + (identity.CompanyName ?? "UNKNOWN") + "; original=" + (identity.OriginalFilename ?? "UNKNOWN"));
                    Console.WriteLine("  Authenticode: " + identity.SignatureStatusName + (String.IsNullOrWhiteSpace(identity.SignerSubject) ? String.Empty : "; signer=" + identity.SignerSubject) + (String.IsNullOrWhiteSpace(identity.SignatureError) ? String.Empty : "; detail=" + identity.SignatureError));
                }
            }
        }

        public static void PrintBinaries(IEnumerable<BinaryArtifact> binaries, bool verbose)
        {
            Console.WriteLine(); Console.WriteLine("================================================="); Console.WriteLine("BINARIES"); Console.WriteLine("=================================================");
            foreach (BinaryArtifact binary in (binaries ?? Enumerable.Empty<BinaryArtifact>()).OrderBy(b => b.Path, StringComparer.OrdinalIgnoreCase))
            {
                Console.WriteLine(binary.Path + "  [exists=" + binary.Exists.ToString().ToUpperInvariant() + (binary.IsAmbiguous ? ", ambiguous" : String.Empty) + "]");
                Console.WriteLine("  Sources: " + String.Join(", ", binary.Sources.ToArray()));
                if (binary.ExecutionIdentities.Count > 0) Console.WriteLine("  Execution identities: " + String.Join(", ", binary.ExecutionIdentities.ToArray()));
                if (binary.ServiceNames.Count > 0) Console.WriteLine("  Services: " + String.Join(", ", binary.ServiceNames.ToArray()));
                if (binary.TaskPaths.Count > 0) Console.WriteLine("  Tasks: " + String.Join(", ", binary.TaskPaths.ToArray()));
                if (binary.ProcessIds.Count > 0) Console.WriteLine("  Observed PIDs: " + String.Join(", ", binary.ProcessIds.Select(p => p.ToString()).ToArray()));
                if (binary.FilePermission != null) Console.WriteLine("  File rights: write=" + binary.FilePermission.CanWrite + ", delete=" + binary.FilePermission.CanDelete + ", write-DACL=" + binary.FilePermission.CanChangePermissions + ", owner=" + (binary.FilePermission.OwnerAccount ?? binary.FilePermission.OwnerSid ?? "UNKNOWN"));
                if (binary.DirectoryPermission != null) Console.WriteLine("  Directory rights: create=" + binary.DirectoryPermission.CanCreate + ", delete=" + binary.DirectoryPermission.CanDelete + ", write-DACL=" + binary.DirectoryPermission.CanChangePermissions);
                if (verbose)
                {
                    if (binary.FilePermission != null) foreach (AccessEntryEvidence ace in binary.FilePermission.AccessEntries) Console.WriteLine("  ACE " + ace.Type + " " + (ace.Account ?? ace.Sid) + " " + ace.Rights + (ace.Inherited ? " inherited" : " explicit"));
                    foreach (string error in binary.Errors) Console.WriteLine("  [?] " + error);
                }
            }
        }

        public static void PrintRelationships(IEnumerable<ExecutionRelationship> relationships)
        {
            IEnumerable<ExecutionRelationship> items = relationships ?? Enumerable.Empty<ExecutionRelationship>();
            if (!items.Any()) return;
            Console.WriteLine(); Console.WriteLine("================================================="); Console.WriteLine("EXECUTION RELATIONSHIPS"); Console.WriteLine("=================================================");
            foreach (ExecutionRelationship relation in items.OrderBy(r => r.SourceId, StringComparer.OrdinalIgnoreCase))
            {
                Console.WriteLine("[" + relation.Classification + "] " + relation.SourceKind + " " + relation.SourceId + " -> " + relation.TargetPath);
                Console.WriteLine("  Host PID: " + (relation.HostProcessId > 0 ? relation.HostProcessId.ToString() : "not observed") + " | " + relation.Detail);
                Console.WriteLine("  Evidence: " + (relation.EvidenceSource ?? "UNKNOWN") + " | Confidence: " + relation.Confidence.ToString().ToUpperInvariant() + " | Object: " + (relation.ObjectIdentity ?? "UNKNOWN") + (relation.RuleIds != null && relation.RuleIds.Count > 0 ? " | Rules: " + String.Join(",", relation.RuleIds.ToArray()) : String.Empty));
            }
        }

        private static int Rank(EvaluationStatus status) { return status == EvaluationStatus.Confirmed ? 0 : status == EvaluationStatus.Potential ? 1 : status == EvaluationStatus.Unknown ? 2 : status == EvaluationStatus.Informational ? 3 : 4; }
    }

    public static class JsonReporter
    {
        public static void Write(AnalysisResult result, string path)
        {
            string json = new JavaScriptSerializer { MaxJsonLength = Int32.MaxValue }.Serialize(result);
            File.WriteAllText(path, Pretty(json), new UTF8Encoding(false));
        }
        private static string Pretty(string json)
        {
            StringBuilder output = new StringBuilder(); bool quoted = false; int indent = 0;
            for (int i = 0; i < json.Length; i++)
            {
                char c = json[i]; if (c == '"' && !IsEscaped(json, i)) quoted = !quoted;
                if (!quoted && (c == '{' || c == '[')) { output.Append(c).AppendLine(); indent++; output.Append(new string(' ', indent * 2)); }
                else if (!quoted && (c == '}' || c == ']')) { output.AppendLine(); indent--; output.Append(new string(' ', indent * 2)).Append(c); }
                else if (!quoted && c == ',') { output.Append(c).AppendLine().Append(new string(' ', indent * 2)); }
                else if (!quoted && c == ':') output.Append(": "); else output.Append(c);
            }
            return output.ToString();
        }

        private static bool IsEscaped(string value, int index)
        {
            int slashes = 0;
            for (int i = index - 1; i >= 0 && value[i] == '\\'; i--) slashes++;
            return (slashes % 2) != 0;
        }
    }
}
