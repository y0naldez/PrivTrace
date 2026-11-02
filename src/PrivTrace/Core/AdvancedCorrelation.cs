using System;
using System.Collections.Generic;
using System.Linq;
using PrivTrace.Models;

namespace PrivTrace.Core
{
    public static class AdvancedCorrelation
    {
        private const string ServerOperatorsSid = "S-1-5-32-549";
        private const string BackupOperatorsSid = "S-1-5-32-551";

        public static List<CorrelationTrace> Correlate(AnalysisContext context, IList<Finding> findings)
        {
            AssignFindingIds(findings);
            List<CorrelationTrace> traces = new List<CorrelationTrace>();
            BuildServiceTraces(context, findings, traces);
            BuildBackupTrace(context, findings, traces);
            BuildDnsTrace(context, findings, traces);
            context.CorrelationTraces = traces;
            return traces;
        }

        public static void CorrelateSoftware(AnalysisContext context, IList<Finding> findings)
        {
            new SoftwareDiscoveryEngine().CorrelateFindings(context, findings);
        }

        private static void AssignFindingIds(IList<Finding> findings)
        {
            Dictionary<string, int> counts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            foreach (Finding finding in findings)
            {
                int count; counts.TryGetValue(finding.RuleId ?? "UNKNOWN", out count); count++; counts[finding.RuleId ?? "UNKNOWN"] = count;
                if (String.IsNullOrEmpty(finding.FindingId)) finding.FindingId = "F-" + (finding.RuleId ?? "UNKNOWN") + "-" + count.ToString("000");
            }
        }

        private static void BuildServiceTraces(AnalysisContext context, IList<Finding> findings, List<CorrelationTrace> traces)
        {
            WindowsGroup group = context.Token.Groups.FirstOrDefault(g => String.Equals(g.Sid, ServerOperatorsSid, StringComparison.OrdinalIgnoreCase));
            if (group == null || !group.Enabled || group.DenyOnly) return;
            foreach (WindowsService service in context.Services.Where(s => s.CanChangeConfig == TriState.Yes && IsPrivilegedAccount(s.Account)))
            {
                Finding groupFinding = Find(findings, "PT-009", null);
                Finding serviceFinding = Find(findings, "PT-014", service.Name);
                if (groupFinding == null || serviceFinding == null || serviceFinding.Status == EvaluationStatus.RuledOut) continue;
                CorrelationTrace trace = NewTrace(context, "SERVICE-" + service.Name, "Privileged Service Configuration", "FULL_DETECTION", EvaluationStatus.Confirmed, Severity.High, Confidence.High);
                AddRules(trace, groupFinding, serviceFinding);
                AddNode(trace, "user", "CurrentUser", context.Token.UserName + " (" + context.Token.UserSid + ")", RelationshipState.Observed, "TokenCollector", "EV-USER", "Integrity=" + context.Token.IntegrityLevel + "; restricted=" + context.Token.RestrictedState);
                AddNode(trace, "group", "TokenGroup", group.Name + " (" + group.Sid + ")", RelationshipState.Observed, "TokenCollector", "EV-GROUP-" + group.Sid, "Enabled=" + group.Enabled + "; denyOnly=" + group.DenyOnly);
                EffectiveServiceRight right = service.EffectiveRights == null ? null : service.EffectiveRights.FirstOrDefault(r => String.Equals(r.Right, "SERVICE_CHANGE_CONFIG", StringComparison.OrdinalIgnoreCase));
                string provenance = right == null || String.IsNullOrEmpty(right.Provenance) ? "UNKNOWN" : right.Provenance;
                AddNode(trace, "right", "EffectiveServiceRight", "SERVICE_CHANGE_CONFIG=Yes", RelationshipState.Observed, right == null ? "Fixture/ServiceCollector" : right.EvaluationMethod, "EV-SVC-RIGHT-" + service.Name, "Right provenance=" + provenance + "; SERVICE_START=" + service.CanStart + "; SERVICE_STOP=" + service.CanStop);
                AddNode(trace, "service", "WindowsService", service.Name, RelationshipState.Observed, "ServiceCollector", "EV-SVC-" + service.Name, "State=" + service.State + "; startType=" + service.StartType + "; binary=" + service.BinaryPath);
                AddNode(trace, "identity", "ExecutionContext", service.Account, RelationshipState.Configured, "QueryServiceConfig", "EV-SVC-ACCOUNT-" + service.Name, "Configured service identity");
                AddNode(trace, "outcome", "PotentialEscalationPath", "Privileged service execution path", RelationshipState.Inferred, "AdvancedCorrelation", "EV-CORR-SERVICE-" + service.Name, "Detection confirmed; execution or exploitation was not performed.");
                AddEdge(trace, "user", "group", "MEMBER_OF", RelationshipState.Observed, "EV-GROUP-" + group.Sid, groupFinding, "Token group attributes", "Membership is context, not permission provenance.");
                AddEdge(trace, "group", "right", "CORRELATED_WITH_EFFECTIVE_RIGHT", RelationshipState.Inferred, "EV-SVC-RIGHT-" + service.Name, serviceFinding, provenance, "Co-occurrence only; no causal ACE attribution.");
                AddEdge(trace, "right", "service", "APPLIES_TO", RelationshipState.Observed, "EV-SVC-RIGHT-" + service.Name, serviceFinding, provenance, "OpenService desired-access result applies to this exact service name.");
                AddEdge(trace, "service", "identity", "RUNS_AS", RelationshipState.Configured, "EV-SVC-ACCOUNT-" + service.Name, serviceFinding, "QueryServiceConfig", "Configured identity, not proof of current execution.");
                AddEdge(trace, "identity", "outcome", "ENABLES_CONDITIONAL_PATH", RelationshipState.Inferred, "EV-CORR-SERVICE-" + service.Name, serviceFinding, "Correlation", "Privileged execution requires a safe activation condition outside read-only analysis.");
                trace.VerifiedConditions.Add("Server Operators membership is enabled and not deny-only.");
                trace.VerifiedConditions.Add("SERVICE_CHANGE_CONFIG effective access is granted for the exact service.");
                trace.VerifiedConditions.Add("The configured service account is privileged.");
                trace.ConfirmedFacts.Add("CONFIRMED_RIGHT: SERVICE_CHANGE_CONFIG is granted for the exact service.");
                trace.ConfirmedFacts.Add("CONFIRMED_CONFIGURATION: service identity is " + service.Account + ".");
                trace.ConditionalOutcomes.Add("CONDITIONAL_EXECUTION: future privileged execution was not demonstrated.");
                if (String.Equals(service.StartType, "Disabled", StringComparison.OrdinalIgnoreCase)) { trace.Status = EvaluationStatus.Potential; trace.Classification = "PARTIAL_DETECTION"; trace.Confidence = Confidence.Medium; trace.PendingConditions.Add("Service is Disabled; an activation path was not verified."); }
                else if (!String.Equals(service.State, "Running", StringComparison.OrdinalIgnoreCase) && service.CanStart != TriState.Yes) trace.PendingConditions.Add("Service activation is not verified (state=" + service.State + ", SERVICE_START=" + service.CanStart + ").");
                trace.PendingConditions.Add("The granting ACE or other causal source of SERVICE_CHANGE_CONFIG remains " + provenance + ".");
                trace.PendingConditions.Add("No service modification, restart, payload, or privileged execution was performed.");
                trace.Trace.Add("Current User " + context.Token.UserName + " [OBSERVED]"); trace.Trace.Add("Server Operators " + group.Sid + " [OBSERVED]"); trace.Trace.Add("SERVICE_CHANGE_CONFIG [OBSERVED; provenance=" + provenance + "]"); trace.Trace.Add(service.Name + " [OBSERVED; " + service.State + "/" + service.StartType + "]"); trace.Trace.Add(service.Account + " [CONFIGURED]"); trace.Trace.Add("Privileged Execution Path [CONDITIONAL]");
                if (!traces.Any(t => String.Equals(t.TraceId, trace.TraceId, StringComparison.OrdinalIgnoreCase))) traces.Add(trace);
            }
        }

        private static void BuildBackupTrace(AnalysisContext context, IList<Finding> findings, List<CorrelationTrace> traces)
        {
            WindowsGroup group = context.Token.Groups.FirstOrDefault(g => String.Equals(g.Sid, BackupOperatorsSid, StringComparison.OrdinalIgnoreCase));
            if (group == null || !group.Enabled || group.DenyOnly) return;
            Finding groupFinding = Find(findings, "PT-010", null), backupFinding = Find(findings, "PT-003", null), restoreFinding = Find(findings, "PT-004", null);
            if (groupFinding == null) return;
            TokenPrivilege backup = FindPrivilege(context, "SeBackupPrivilege"), restore = FindPrivilege(context, "SeRestorePrivilege");
            CorrelationTrace trace = NewTrace(context, "BACKUP-CAPABILITY", "Backup Operator Token Capability", "PARTIAL_DETECTION", EvaluationStatus.Potential, Severity.Medium, Confidence.Medium);
            AddRules(trace, groupFinding, backupFinding, restoreFinding);
            AddNode(trace, "user", "CurrentUser", context.Token.UserName + " (" + context.Token.UserSid + ")", RelationshipState.Observed, "TokenCollector", "EV-USER", "Integrity=" + context.Token.IntegrityLevel + "; restricted=" + context.Token.RestrictedState);
            AddNode(trace, "group", "TokenGroup", group.Name + " (" + group.Sid + ")", RelationshipState.Observed, "TokenCollector", "EV-GROUP-" + group.Sid, "Enabled=" + group.Enabled + "; denyOnly=" + group.DenyOnly);
            string backupState = PrivilegeState(context, backup), restoreState = PrivilegeState(context, restore);
            AddNode(trace, "backup", "TokenPrivilege", "SeBackupPrivilege=" + backupState, backup == null && backupState == "Unknown" ? RelationshipState.Unknown : RelationshipState.Observed, "TokenCollector", "EV-PRIV-SeBackupPrivilege", "State is preserved; PrivTrace does not enable it.");
            AddNode(trace, "restore", "TokenPrivilege", "SeRestorePrivilege=" + restoreState, restore == null && restoreState == "Unknown" ? RelationshipState.Unknown : RelationshipState.Observed, "TokenCollector", "EV-PRIV-SeRestorePrivilege", "No privilege is inferred from group membership.");
            AddNode(trace, "capability", "BackupCapability", "Potential backup/restore capability", RelationshipState.Inferred, "AdvancedCorrelation", "EV-CORR-BACKUP", "Capability only; no protected file operation was attempted.");
            AddEdge(trace, "user", "group", "MEMBER_OF", RelationshipState.Observed, "EV-GROUP-" + group.Sid, groupFinding, "Token group attributes", "Effective membership verified.");
            AddEdge(trace, "group", "backup", "CORRELATED_WITH_TOKEN_PRIVILEGE", RelationshipState.Inferred, "EV-PRIV-SeBackupPrivilege", backupFinding, "Token enumeration", "Group membership does not create or enable this privilege.");
            AddEdge(trace, "group", "restore", restoreState == "Absent" || restoreState == "Removed" ? "PRIVILEGE_RULED_OUT" : "PRIVILEGE_STATE_EVALUATED", restoreState == "Unknown" ? RelationshipState.Unknown : RelationshipState.Observed, "EV-PRIV-SeRestorePrivilege", restoreFinding, "Token enumeration", "Absent, removed, or unknown state is negative/contextual evidence and never positive support.");
            AddEdge(trace, "backup", "capability", "MAY_ENABLE", RelationshipState.Inferred, "EV-CORR-BACKUP", backupFinding, "Windows privilege semantics", "Additional object and operation conditions remain unverified.");
            trace.VerifiedConditions.Add("Backup Operators membership is enabled and not deny-only.");
            trace.VerifiedConditions.Add("SeBackupPrivilege state=" + backupState + "."); trace.VerifiedConditions.Add("SeRestorePrivilege state=" + restoreState + ".");
            trace.ConfirmedFacts.Add("CONFIRMED_CONFIGURATION: token group and privilege states were enumerated.");
            trace.ConditionalOutcomes.Add("CONDITIONAL_EXECUTION: no privileged file operation was verified.");
            if (context.Token.Restricted) trace.PendingConditions.Add("The current token is restricted; effective use of capabilities is not established.");
            if (backupState != "Enabled") trace.PendingConditions.Add("SeBackupPrivilege is not observed Enabled (state=" + backupState + ").");
            if (restoreState != "Enabled") trace.PendingConditions.Add("SeRestorePrivilege is not observed Enabled (state=" + restoreState + ").");
            trace.PendingConditions.Add("No access to protected files or privileged file operation was verified.");
            trace.Trace.Add("Current User " + context.Token.UserName + " [OBSERVED]"); trace.Trace.Add("Backup Operators " + group.Sid + " [OBSERVED]"); trace.Trace.Add("SeBackupPrivilege [" + backupState + "]"); trace.Trace.Add("SeRestorePrivilege [" + restoreState + "]"); trace.Trace.Add("Backup Capability [CONDITIONAL]"); trace.Trace.Add("Privileged File Operation [NOT VERIFIED]");
            traces.Add(trace);
        }

        private static void BuildDnsTrace(AnalysisContext context, IList<Finding> findings, List<CorrelationTrace> traces)
        {
            WindowsGroup group = context.Token.Groups.FirstOrDefault(g => !String.IsNullOrEmpty(g.Name) && (g.Name.EndsWith("\\DnsAdmins", StringComparison.OrdinalIgnoreCase) || String.Equals(g.Name, "DnsAdmins", StringComparison.OrdinalIgnoreCase)));
            if (group == null || !group.Enabled || group.DenyOnly) return;
            Finding finding = Find(findings, "PT-011", null); if (finding == null) return;
            DnsServerSnapshot dns = context.DnsServer ?? new DnsServerSnapshot { Present = TriState.Unknown, ConfigurationReadState = "UNKNOWN", CanConfigurePlugin = TriState.Unknown };
            CorrelationTrace trace = NewTrace(context, "DNS-SERVER-PLUGIN", "DNS Server Plugin Configuration", "PARTIAL_DETECTION", EvaluationStatus.Potential, Severity.Medium, Confidence.Low);
            AddRules(trace, finding);
            AddNode(trace, "user", "CurrentUser", context.Token.UserName + " (" + context.Token.UserSid + ")", RelationshipState.Observed, "TokenCollector", "EV-USER", "Restricted=" + context.Token.RestrictedState);
            AddNode(trace, "group", "TokenGroup", group.Name + " (" + group.Sid + ")", RelationshipState.Observed, "TokenCollector", "EV-GROUP-" + group.Sid, "Enabled=" + group.Enabled + "; denyOnly=" + group.DenyOnly);
            RelationshipState dnsState = dns.Present == TriState.Yes ? RelationshipState.Observed : dns.Present == TriState.No ? RelationshipState.Observed : RelationshipState.Unknown;
            AddNode(trace, "dns", "DnsServer", dns.Present == TriState.Yes ? dns.ServiceName : "Local DNS Server=" + dns.Present, dnsState, "DnsServerCollector", "EV-DNS-SERVICE", "State=" + dns.State + "; startType=" + dns.StartType + "; account=" + dns.Account + "; SERVICE_CHANGE_CONFIG=" + dns.CanChangeConfig + "; SERVICE_START=" + dns.CanStart + "; SERVICE_STOP=" + dns.CanStop);
            if (dns.Present != TriState.Yes)
            {
                AddEdge(trace, "user", "group", "MEMBER_OF", RelationshipState.Observed, "EV-GROUP-" + group.Sid, finding, "Token group attributes", "Membership verified.");
                AddEdge(trace, "group", "dns", "LOCAL_SERVER_NOT_OBSERVED", dns.Present == TriState.No ? RelationshipState.Observed : RelationshipState.Unknown, "EV-DNS-SERVICE", finding, "Local exact-name service lookup", "No remote server was queried or inferred.");
                trace.VerifiedConditions.Add("DnsAdmins membership is enabled and not deny-only."); trace.VerifiedConditions.Add("Local DNS Server presence=" + dns.Present + ".");
                trace.PendingConditions.Add("Local DNS Server was not observed; remote servers are out of scope and were not inferred.");
                trace.Trace.Add("Current User " + context.Token.UserName + " [OBSERVED]"); trace.Trace.Add("DnsAdmins " + group.Sid + " [OBSERVED]"); trace.Trace.Add("DNS Server local [" + dns.Present + "]"); trace.Trace.Add("Remote DNS Server [OUT OF SCOPE / NOT INFERRED]");
                traces.Add(trace); return;
            }
            RelationshipState configState = String.Equals(dns.ConfigurationReadState, "OBSERVED", StringComparison.OrdinalIgnoreCase) ? RelationshipState.Configured : RelationshipState.Unknown;
            string plugin = String.IsNullOrEmpty(dns.ServerLevelPluginDll) ? "<not configured or not observable>" : dns.ServerLevelPluginDll;
            AddNode(trace, "plugin", "ServerLevelPluginDll", plugin, configState, "DnsServerCollector", "EV-DNS-PLUGIN", "ReadState=" + dns.ConfigurationReadState + "; KEY_SET_VALUE=" + dns.CanConfigurePlugin + "; rightProvenance=" + dns.RightProvenance);
            AddNode(trace, "identity", "ExecutionContext", dns.Account ?? "UNKNOWN", dns.Present == TriState.Yes ? RelationshipState.Configured : RelationshipState.Unknown, "ServiceCollector", "EV-DNS-ACCOUNT", "Configured DNS Server service identity.");
            AddNode(trace, "outcome", "PotentialEscalationPath", "Potential DNS plugin configuration path", RelationshipState.Inferred, "AdvancedCorrelation", "EV-CORR-DNS", "Configuration observation is separate from effective modification capability.");
            AddEdge(trace, "user", "group", "MEMBER_OF", RelationshipState.Observed, "EV-GROUP-" + group.Sid, finding, "Token group attributes", "Membership verified.");
            AddEdge(trace, "group", "dns", "CONTEXT_FOR_LOCAL_SERVER", dns.Present == TriState.Yes ? RelationshipState.Inferred : RelationshipState.Unknown, "EV-DNS-SERVICE", finding, "Local exact-name service lookup", "No remote server was queried or inferred.");
            AddEdge(trace, "dns", "plugin", "HAS_PLUGIN_CONFIGURATION", configState, "EV-DNS-PLUGIN", finding, "Directed registry read", "Observed configuration does not prove modification access or loading.");
            AddEdge(trace, "dns", "identity", "RUNS_AS", dns.Present == TriState.Yes ? RelationshipState.Configured : RelationshipState.Unknown, "EV-DNS-ACCOUNT", finding, "QueryServiceConfig", "Configured identity.");
            AddEdge(trace, "plugin", "outcome", "MAY_ENABLE_CONDITIONAL_PATH", RelationshipState.Inferred, "EV-CORR-DNS", finding, dns.RightProvenance, "Requires effective configuration rights and an activation mechanism.");
            trace.VerifiedConditions.Add("DnsAdmins membership is enabled and not deny-only."); trace.VerifiedConditions.Add("Local DNS Server presence=" + dns.Present + "."); trace.VerifiedConditions.Add("ServerLevelPluginDll read state=" + dns.ConfigurationReadState + "."); trace.VerifiedConditions.Add("Effective KEY_SET_VALUE=" + dns.CanConfigurePlugin + ".");
            trace.ConfirmedFacts.Add("CONFIRMED_CONFIGURATION: local DNS Server and observable configuration were collected.");
            trace.ConditionalOutcomes.Add("CONDITIONAL_EXECUTION: plugin modification and loading were not demonstrated.");
            if (dns.Present != TriState.Yes) trace.PendingConditions.Add("Local DNS Server was not observed; remote servers are out of scope and were not inferred.");
            if (!String.Equals(dns.ConfigurationReadState, "OBSERVED", StringComparison.OrdinalIgnoreCase)) trace.PendingConditions.Add("ServerLevelPluginDll configuration is not observable (" + dns.ConfigurationReadState + ").");
            if (dns.CanConfigurePlugin != TriState.Yes) trace.PendingConditions.Add("Effective ability to modify ServerLevelPluginDll is not proven (" + dns.CanConfigurePlugin + ").");
            if (String.Equals(dns.StartType, "Disabled", StringComparison.OrdinalIgnoreCase)) trace.PendingConditions.Add("DNS Server is Disabled; plugin loading is not active or verified.");
            trace.PendingConditions.Add("No plugin was written or loaded and DNS Server was not restarted.");
            trace.Trace.Add("Current User " + context.Token.UserName + " [OBSERVED]"); trace.Trace.Add("DnsAdmins " + group.Sid + " [OBSERVED]"); trace.Trace.Add("DNS Server local [" + dns.Present + "]"); trace.Trace.Add("ServerLevelPluginDll " + plugin + " [" + configState.ToString().ToUpperInvariant() + "; readState=" + dns.ConfigurationReadState + "]"); trace.Trace.Add((dns.Account ?? "UNKNOWN") + " [CONFIGURED]"); trace.Trace.Add("Potential DNS Plugin Configuration Path [CONDITIONAL]");
            traces.Add(trace);
        }

        private static CorrelationTrace NewTrace(AnalysisContext context, string suffix, string name, string classification, EvaluationStatus status, Severity severity, Confidence confidence)
        {
            return new CorrelationTrace { TraceId = "CT-" + suffix.ToUpperInvariant().Replace(' ', '-'), ScenarioId = context.ScenarioId, Name = name, Classification = classification, Status = status, Severity = severity, Confidence = confidence };
        }
        private static void AddNode(CorrelationTrace t, string id, string type, string label, RelationshipState state, string source, string evidence, string detail) { t.Nodes.Add(new CorrelationNode { NodeId = id, Type = type, Label = label, State = state, Source = source, EvidenceId = evidence, Detail = detail }); }
        private static void AddEdge(CorrelationTrace t, string from, string to, string relation, RelationshipState state, string evidence, Finding finding, string provenance, string detail) { t.Edges.Add(new CorrelationEdge { SourceNodeId = from, DestinationNodeId = to, Relation = relation, State = state, EvidenceId = evidence, RuleId = finding == null ? null : finding.RuleId, FindingId = finding == null ? null : finding.FindingId, Provenance = provenance, Detail = detail }); }
        private static void AddRules(CorrelationTrace trace, params Finding[] findings)
        {
            foreach (Finding f in findings.Where(x => x != null))
            {
                if (!trace.EvaluatedRuleIds.Contains(f.RuleId)) trace.EvaluatedRuleIds.Add(f.RuleId);
                if (f.Status == EvaluationStatus.RuledOut)
                {
                    if (!trace.RuledOutRuleIds.Contains(f.RuleId)) trace.RuledOutRuleIds.Add(f.RuleId);
                }
                else if (f.Status != EvaluationStatus.Unknown)
                {
                    if (!trace.SupportingRuleIds.Contains(f.RuleId)) trace.SupportingRuleIds.Add(f.RuleId);
                    if (!trace.RuleIds.Contains(f.RuleId)) trace.RuleIds.Add(f.RuleId); // Backward-compatible alias: supporting rules only.
                }
                if (!trace.FindingIds.Contains(f.FindingId)) trace.FindingIds.Add(f.FindingId);
            }
        }
        private static Finding Find(IList<Finding> findings, string rule, string target) { return findings.FirstOrDefault(f => String.Equals(f.RuleId, rule, StringComparison.OrdinalIgnoreCase) && (target == null || String.Equals(f.Target, target, StringComparison.OrdinalIgnoreCase))); }
        private static TokenPrivilege FindPrivilege(AnalysisContext c, string name) { return c.Token.Privileges.FirstOrDefault(p => String.Equals(p.Name, name, StringComparison.OrdinalIgnoreCase)); }
        private static string PrivilegeState(AnalysisContext c, TokenPrivilege privilege) { if (privilege != null) return privilege.State == TokenPrivilegeState.Unknown ? (privilege.Present ? (privilege.Enabled ? "Enabled" : "Disabled") : "Unknown") : privilege.State.ToString(); return c.Token.Errors.Any(e => e.IndexOf("privilege", StringComparison.OrdinalIgnoreCase) >= 0 && e.IndexOf("unavailable", StringComparison.OrdinalIgnoreCase) >= 0) ? "Unknown" : "Absent"; }
        private static bool IsPrivilegedAccount(string account) { return !String.IsNullOrEmpty(account) && (account.Equals("LocalSystem", StringComparison.OrdinalIgnoreCase) || account.Equals(@"NT AUTHORITY\SYSTEM", StringComparison.OrdinalIgnoreCase) || account.EndsWith("\\SYSTEM", StringComparison.OrdinalIgnoreCase)); }
    }
}
