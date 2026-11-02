using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Web.Script.Serialization;
using System.Diagnostics;
using PrivTrace.Collectors;
using PrivTrace.Models;
using PrivTrace.Rules;

namespace PrivTrace.Core
{
    public sealed class AnalyzerEngine
    {
        private readonly RuleEngine engine = new RuleEngine();

        public AnalysisContext Collect()
        {
            AnalysisContext context = new AnalysisContext { EvidenceOrigin = "LIVE_OBSERVED" };
            Measure(context, "System", delegate { context.System = new SystemCollector().Collect(); return 1; });
            Measure(context, "Token", delegate { context.Token = new TokenCollector().Collect(); return context.Token.Privileges.Count + context.Token.Groups.Count; });
            Measure(context, "Services", delegate { try { ServiceCollector services = new ServiceCollector(); context.Services = services.Collect(); context.ServiceEnumerationState = services.CollectionState; context.Diagnostics.AddRange(services.Diagnostics); foreach (string error in services.Errors) context.Errors.Add("Services: " + error); } catch (Exception ex) { context.ServiceEnumerationState = "UNKNOWN"; context.Errors.Add("Services: " + ex.Message); } return context.Services.Count; });
            Measure(context, "ServiceRegistry", delegate { try { RegistryCollector registry = new RegistryCollector(); registry.Collect(context.Services); foreach (string error in registry.Errors) context.Errors.Add("Service registry: " + error); } catch (Exception ex) { context.Errors.Add("Service registry: " + ex.Message); } return context.Services.Sum(s => s.RegistryEvidence == null ? 0 : s.RegistryEvidence.Count); });
            Measure(context, "DnsServer", delegate { try { context.DnsServer = new DnsServerCollector().Collect(context.Services, context.ServiceEnumerationState); foreach (string error in context.DnsServer.Errors) context.Errors.Add("DNS Server: " + error); } catch (Exception ex) { context.Errors.Add("DNS Server: " + ex.Message); } return context.DnsServer.Present == TriState.Yes ? 1 : 0; });
            Measure(context, "Tasks", delegate { try { ScheduledTaskCollector tasks = new ScheduledTaskCollector(); context.Tasks = tasks.Collect(); context.TaskEnumerationState = tasks.CollectionState; context.Diagnostics.AddRange(tasks.Diagnostics); foreach (string error in tasks.Errors) context.Errors.Add("Tasks: " + error); } catch (Exception ex) { context.TaskEnumerationState = "UNKNOWN"; context.Errors.Add("Tasks: " + ex.Message); } return context.Tasks.Count; });
            Measure(context, "Processes", delegate { try { ProcessCollector processes = new ProcessCollector(); context.Processes = processes.Collect(); foreach (string error in processes.Errors) context.Errors.Add("Processes: " + error); } catch (Exception ex) { context.Errors.Add("Processes: " + ex.Message); } return context.Processes.Count; });
            Measure(context, "Correlation", delegate { try { ExecutionCorrelation.Correlate(context); } catch (Exception ex) { context.Errors.Add("Execution correlation: " + ex.Message); } return context.Binaries.Count; });
            Measure(context, "Software", delegate { try { FileIdentityCollector.Enrich(context, true); return new SoftwareDiscoveryEngine().Discover(context, new SoftwareProfileCatalog().LoadEmbedded(), true).Count; } catch (Exception ex) { context.Errors.Add("Software discovery: " + ex.Message); return 0; } });
            return context;
        }

        private static void Measure(AnalysisContext context, string name, Func<int> action)
        {
            Stopwatch timer = Stopwatch.StartNew(); int items = 0;
            try { items = action(); }
            finally { timer.Stop(); context.Timings.Add(new CollectorTiming { Name = name, ElapsedMilliseconds = timer.ElapsedMilliseconds, Items = items }); }
        }

        public AnalysisContext LoadFixture(string path)
        {
            string json = File.ReadAllText(path);
            AnalysisContext context = new JavaScriptSerializer { MaxJsonLength = Int32.MaxValue }.Deserialize<AnalysisContext>(json);
            if (context == null) throw new InvalidDataException("Fixture did not contain an analysis context.");
            context.EvidenceOrigin = "IMPORTED_UNVERIFIED";
            Normalize(context); ExecutionCorrelation.Correlate(context, false); FileIdentityCollector.Enrich(context, false); new SoftwareDiscoveryEngine().Discover(context, new SoftwareProfileCatalog().LoadEmbedded(), false); return context;
        }

        public AnalysisResult Analyze(AnalysisContext context, IList<RuleDefinition> rules)
        {
            if (context.Software == null || context.Software.Count == 0) { FileIdentityCollector.Enrich(context, false); new SoftwareDiscoveryEngine().Discover(context, new SoftwareProfileCatalog().LoadEmbedded(), false); }
            AnalysisResult result = new AnalysisResult { Version = "1.0.0", SchemaVersion = "1.6", GeneratedUtc = DateTime.UtcNow, RulesEvaluated = rules.Count, Context = context };
            result.Findings.AddRange(engine.Evaluate(rules, context));
            result.CorrelationTraces.AddRange(AdvancedCorrelation.Correlate(context, result.Findings));
            AdvancedCorrelation.CorrelateSoftware(context, result.Findings);
            result.Errors.AddRange(context.Errors); return result;
        }

        private static void Normalize(AnalysisContext c)
        {
            if (c.Token == null) c.Token = new TokenSnapshot();
            if (String.IsNullOrEmpty(c.ServiceEnumerationState)) c.ServiceEnumerationState = c.Services != null ? "OBSERVED" : "UNKNOWN";
            if (String.IsNullOrEmpty(c.TaskEnumerationState)) c.TaskEnumerationState = c.Tasks != null ? "OBSERVED" : "UNKNOWN";
            if (c.System == null) c.System = new SystemSnapshot();
            if (c.Services == null) c.Services = new List<WindowsService>();
            if (c.Tasks == null) c.Tasks = new List<ScheduledTaskInfo>();
            if (c.Processes == null) c.Processes = new List<WindowsProcess>();
            if (c.Binaries == null) c.Binaries = new List<BinaryArtifact>();
            if (c.ExecutionRelationships == null) c.ExecutionRelationships = new List<ExecutionRelationship>();
            if (c.Software == null) c.Software = new List<SoftwareObservation>();
            if (c.SoftwareVersionEvidence == null) c.SoftwareVersionEvidence = new List<SoftwareVersionEvidence>();
            if (c.CorrelationTraces == null) c.CorrelationTraces = new List<CorrelationTrace>();
            if (c.DnsServer == null) c.DnsServer = new DnsServerSnapshot { Present = TriState.Unknown, CanConfigurePlugin = TriState.Unknown, ConfigurationReadState = "UNKNOWN" };
            if (c.Timings == null) c.Timings = new List<CollectorTiming>();
            if (c.Errors == null) c.Errors = new List<string>();
            if (c.Diagnostics == null) c.Diagnostics = new List<CollectorDiagnostic>();
            if (c.Token.Privileges == null) c.Token.Privileges = new List<TokenPrivilege>();
            if (c.Token.Groups == null) c.Token.Groups = new List<WindowsGroup>();
            if (c.Token.Errors == null) c.Token.Errors = new List<string>();
            foreach (TokenPrivilege privilege in c.Token.Privileges) if (privilege.State == TokenPrivilegeState.Unknown && privilege.Present) privilege.State = privilege.Enabled ? TokenPrivilegeState.Enabled : TokenPrivilegeState.Disabled;
            foreach (ScheduledTaskInfo task in c.Tasks) { if (task.Actions == null) task.Actions = new List<ScheduledTaskAction>(); if (task.Triggers == null) task.Triggers = new List<string>(); if (task.Errors == null) task.Errors = new List<string>(); foreach (ScheduledTaskAction action in task.Actions) { if (action.HijackCandidates == null) action.HijackCandidates = new List<string>(); if (action.HijackCandidatePermissions == null) action.HijackCandidatePermissions = new List<SecurityPermission>(); } }
            foreach (WindowsProcess process in c.Processes) { if (process.ServiceNames == null) process.ServiceNames = new List<string>(); if (process.Errors == null) process.Errors = new List<string>(); }
            foreach (SoftwareObservation software in c.Software) { if (software.VersionEvidence == null) software.VersionEvidence = new List<SoftwareVersionEvidence>(); if (software.ScheduledTaskPaths == null) software.ScheduledTaskPaths = new List<string>(); if (software.ConfiguredExecutablePaths == null) software.ConfiguredExecutablePaths = new List<string>(); if (software.ObservationStates == null) software.ObservationStates = new List<string>(); if (String.IsNullOrWhiteSpace(software.SoftwareContext)) software.SoftwareContext = "INTERESTING"; }
            foreach (WindowsService service in c.Services) { if (service.RegistryEvidence == null) service.RegistryEvidence = new List<ServiceRegistryEvidence>(); if (service.EffectiveRights == null) service.EffectiveRights = new List<EffectiveServiceRight>(); if (service.Errors == null) service.Errors = new List<string>(); }
            foreach (BinaryArtifact binary in c.Binaries) { if (binary.Sources == null) binary.Sources = new List<string>(); if (binary.ProcessIds == null) binary.ProcessIds = new List<int>(); if (binary.ServiceNames == null) binary.ServiceNames = new List<string>(); if (binary.TaskPaths == null) binary.TaskPaths = new List<string>(); if (binary.ExecutionIdentities == null) binary.ExecutionIdentities = new List<string>(); if (binary.Errors == null) binary.Errors = new List<string>(); }
            foreach (ExecutionRelationship relation in c.ExecutionRelationships) if (relation.RuleIds == null) relation.RuleIds = new List<string>();
        }
    }
}
