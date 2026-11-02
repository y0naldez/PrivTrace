using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using Microsoft.Win32;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Web.Script.Serialization;
using PrivTrace.Collectors;
using PrivTrace.Core;
using PrivTrace.Models;
using PrivTrace.Reporting;
using PrivTrace.Rules;
using PrivTrace.Security;

namespace PrivTrace.Tests
{
    internal static class TestRunner
    {
        private static int passed, failed, skipped, blocked;
        private static List<RuleDefinition> rules;
        private static readonly RuleEngine engine = new RuleEngine();
        private static readonly List<Dictionary<string, object>> syntheticScenarioResults = new List<Dictionary<string, object>>();

        private static int Main()
        {
            try { rules = new RuleCatalog().LoadEmbedded(); }
            catch (Exception ex) { Console.Error.WriteLine("Catalog bootstrap failed: " + ex); return 1; }

            Run("Catalog loads 27 functional rules", delegate { Equal(27, rules.Count); });
            Run("Catalog IDs are consecutive and scalable", delegate { for (int i = 1; i <= rules.Count; i++) True(rules.Any(r => r.Id == "PT-" + i.ToString("000"))); });
            Run("Duplicate IDs rejected", TestDuplicate);
            Run("Missing metadata rejected", TestMissingMetadata);
            Run("Malformed reference rejected", TestMalformedReference);
            Run("Malformed rule ID rejected", TestMalformedId);
            Run("Gap in rule IDs rejected", TestRuleIdGap);
            Run("Rule metadata uses synthetic scenario IDs", TestKnowledgeIntegrity);
            Run("Rule metadata uses Microsoft primary references", TestPrimaryReferences);

            foreach (RuleDefinition rule in rules)
            {
                RuleDefinition captured = rule;
                Run(captured.Id + " positive", delegate { Expect(captured, Build(captured.Id, "positive"), captured.Id == "PT-016" || captured.Evaluator == "PrivilegeEvaluator" || captured.Evaluator == "GroupEvaluator" ? EvaluationStatus.Potential : EvaluationStatus.Confirmed); });
                Run(captured.Id + " negative", delegate { Expect(captured, Build(captured.Id, "negative"), EvaluationStatus.RuledOut); });
                Run(captured.Id + " unknown", delegate { Expect(captured, Build(captured.Id, "unknown"), EvaluationStatus.Unknown); });
            }

            Run("Disabled privilege remains present", delegate { AnalysisContext c = Build("PT-001", "positive"); c.Token.Privileges[0].Enabled = false; Finding f = One("PT-001", c); Equal(EvaluationStatus.Potential, f.Status); Equal(Confidence.Low, f.Confidence); });
            Run("Removed privilege cannot be re-enabled", delegate { AnalysisContext c = Build("PT-001", "positive"); c.Token.Privileges[0].State = TokenPrivilegeState.Removed; c.Token.Privileges[0].Present = false; c.Token.Privileges[0].Enabled = false; Finding f = One("PT-001", c); Equal(EvaluationStatus.RuledOut, f.Status); True(f.MissingConditions.Any(x => x.IndexOf("cannot add", StringComparison.OrdinalIgnoreCase) >= 0)); });
            Run("PT-025 conditioned disabled privilege", delegate { AnalysisContext c = Build("PT-025", "positive"); c.Token.Privileges[0].Enabled = false; Finding f = One("PT-025", c); Equal(EvaluationStatus.Potential, f.Status); Equal(Confidence.Low, f.Confidence); True(f.MissingConditions.Count > 0); });
            Run("Known group SID detection is localization independent", delegate { AnalysisContext c = Build("PT-010", "positive"); c.Token.Groups[0].Name = "OPERADORES_DE_COPIA"; Equal(EvaluationStatus.Potential, One("PT-010", c).Status); });
            Run("Deny-only group is ruled out", delegate { AnalysisContext c = Build("PT-009", "positive"); c.Token.Groups[0].DenyOnly = true; Equal(EvaluationStatus.RuledOut, One("PT-009", c).Status); });
            Run("Common Users group does not trigger privileged groups", delegate { AnalysisContext c = Fresh(); c.Token.Groups.Add(new WindowsGroup { Sid = "S-1-5-32-545", Name = "Users", Enabled = true }); Equal(EvaluationStatus.RuledOut, One("PT-010", c).Status); });
            Run("Quoted path separates arguments", delegate { string exe, args; PathResolver.SplitCommandLine("\"C:\\Program Files\\Tool\\tool.exe\" -x 1", out exe, out args); Equal("C:\\Program Files\\Tool\\tool.exe", exe); Equal("-x 1", args); });
            Run("Unquoted path separates executable extension", delegate { string exe, args; PathResolver.SplitCommandLine("C:\\Program Files\\Tool\\tool.exe -x", out exe, out args); Equal("C:\\Program Files\\Tool\\tool.exe", exe); Equal("-x", args); });
            Run("Environment variables expand", delegate { string exe, args; PathResolver.SplitCommandLine("%WINDIR%\\System32\\cmd.exe /c ver", out exe, out args); True(Path.IsPathRooted(exe)); Equal("/c ver", args); });
            Run("Unquoted candidate generation", delegate { True(PathResolver.GetUnquotedCandidates("C:\\Program Files\\Tool\\tool.exe -x").Count >= 1); });
            Run("Quoted path has no unquoted candidates", delegate { Equal(0, PathResolver.GetUnquotedCandidates("\"C:\\Program Files\\Tool\\tool.exe\" -x").Count); });
            Run("Script extensions recognized", delegate { True(PathResolver.IsScript("C:\\jobs\\backup.ps1")); True(!PathResolver.IsScript("C:\\jobs\\backup.exe")); });
            Run("SYSTEM principal recognized", delegate { True(PathResolver.IsPrivilegedPrincipal("NT AUTHORITY\\SYSTEM")); });
            Run("Built-in service principals recognized", delegate { True(PathResolver.IsPrivilegedPrincipal("NT AUTHORITY\\NetworkService")); True(PathResolver.IsPrivilegedPrincipal("NT AUTHORITY\\Network Service")); True(PathResolver.IsPrivilegedPrincipal("NT AUTHORITY\\LocalService")); True(PathResolver.IsPrivilegedPrincipal("NT AUTHORITY\\Local Service")); });
            Run("Ordinary principal not privileged", delegate { True(!PathResolver.IsPrivilegedPrincipal("LAB\\operator")); });
            Run("CLI valid combination", delegate { CommandLineOptions o; string e; True(CommandLineParser.TryParse(new[] { "--verbose", "--rule", "PT-017" }, out o, out e)); Equal("PT-017", o.RuleId); });
            Run("CLI rejects unknown argument", delegate { CommandLineOptions o; string e; True(!CommandLineParser.TryParse(new[] { "--wat" }, out o, out e)); });
            Run("CLI rejects missing value", delegate { CommandLineOptions o; string e; True(!CommandLineParser.TryParse(new[] { "--json" }, out o, out e)); });
            Run("CLI rejects conflicting rule modes", delegate { CommandLineOptions o; string e; True(!CommandLineParser.TryParse(new[] { "--rule", "PT-001", "--rule-info", "PT-001" }, out o, out e)); });
            Run("CLI accepts process and binary views", delegate { CommandLineOptions o; string e; True(CommandLineParser.TryParse(new[] { "--processes", "--binaries" }, out o, out e)); True(o.Processes); True(o.Binaries); });
            Run("CLI accepts Spanish output flags", delegate { CommandLineOptions shortFlag, longFlag; string a, b; True(CommandLineParser.TryParse(new[] { "-es" }, out shortFlag, out a)); True(CommandLineParser.TryParse(new[] { "--es" }, out longFlag, out b)); True(shortFlag.Spanish && longFlag.Spanish); });
            Run("Spanish output explains service capabilities naturally", delegate
            {
                AnalysisContext c = Fresh(); WindowsService service = Service(TriState.Yes, TriState.Yes, TriState.No);
                service.Name = "KiteService"; service.ExecutablePath = @"C:\Program Files\Kite\KiteService.exe"; service.BinaryPath = service.ExecutablePath;
                service.State = "Stopped"; service.StartType = "Manual"; service.CanStart = TriState.Yes; service.CanStop = TriState.Unknown;
                service.ExecutablePermission.CanDelete = TriState.Yes; service.DirectoryPermission.CanDeleteChildren = TriState.Yes; c.Services.Add(service);
                string text = RenderSpanish(AnalyzeCorrelation(c), false);
                True(text.Contains("Puede iniciar el servicio? : SI (confirmado)"));
                True(text.Contains("Puede detener el servicio? : REVISAR MANUALMENTE"));
                True(text.Contains("Puede escribir el binario? : SI (confirmado)"));
                True(text.Contains("Puede reemplazarlo?        : SI (confirmado)"));
            });
            Run("Binary resolver handles quoted path", delegate { BinaryPathResolution r = BinaryPathResolver.Resolve("\"C:\\Program Files\\Tool\\tool.exe\" -x", null, false); Equal("C:\\Program Files\\Tool\\tool.exe", r.Path); Equal("-x", r.Arguments); True(!r.IsAmbiguous); });
            Run("Binary resolver expands environment variables", delegate { BinaryPathResolution r = BinaryPathResolver.Resolve("%WINDIR%\\System32\\cmd.exe /c ver", null, false); True(Path.IsPathRooted(r.Path)); });
            Run("Binary resolver marks unresolved relative path ambiguous", delegate { BinaryPathResolution r = BinaryPathResolver.Resolve("tool.exe -x", null, false); True(r.IsAmbiguous); Equal(TriState.Unknown, r.Exists); });
            Run("Binary resolver anchors relative path to configured directory", delegate { BinaryPathResolution r = BinaryPathResolver.Resolve("tool.exe", "C:\\Jobs", false); True(r.IsAmbiguous); Equal("C:\\Jobs\\tool.exe", r.Path); });
            Run("Binary resolver recognizes nonexistent absolute path", delegate { BinaryPathResolution r = BinaryPathResolver.Resolve("C:\\PrivTrace-Does-Not-Exist\\missing.exe", null, false); Equal(TriState.No, r.Exists); });
            Run("ACL effective allow and deny", TestEffectiveAcl);
            Run("Registry ACL effective allow and deny", TestRegistryAcl);
            Run("Live process enumeration includes current process", TestProcessEnumeration);
            Run("Exact PID correlates shared service host", TestSharedServiceProcess);
            Run("Binary inventory deduplicates process and service path", TestBinaryDeduplication);
            Run("SYN-SERVICE-BINARY-A maps to PT-013", delegate { AnalysisContext c = Veyon(TriState.Yes, "LocalSystem", true, "ACCESSIBLE"); Equal(EvaluationStatus.Confirmed, One("PT-013", c).Status); True(One("PT-013", c).Trace.Any(t => t.Contains("Configured executable"))); });
            Run("SYN-SERVICE-BINARY-B same identity is not escalation", delegate { Equal(EvaluationStatus.RuledOut, One("PT-013", Veyon(TriState.Yes, "LAB\\operator", true, "ACCESSIBLE")).Status); });
            Run("SYN-SERVICE-BINARY-C inaccessible process attributes remain UNKNOWN", delegate { AnalysisContext c = Veyon(TriState.No, "LocalSystem", true, "ACCESS_DENIED"); WindowsProcess p = c.Processes.Single(); Equal("ACCESS_DENIED", p.AccessStatus); True(p.OwnerAccount == null); True(p.IntegrityLevel == null || p.IntegrityLevel == "Unknown"); });
            Run("PT-014 NetworkService change-config is actionable", delegate { AnalysisContext c = Fresh(); WindowsService s = Service(TriState.No, TriState.No, TriState.Yes); s.Name = "tapisrv"; s.Account = @"NT AUTHORITY\NetworkService"; s.CanStart = TriState.Yes; s.CanStop = TriState.Yes; c.Services.Add(s); Finding f = One("PT-014", c); Equal(EvaluationStatus.Confirmed, f.Status); True(ConsoleReporter.IsActionable(f)); AnalysisResult result = AnalyzeCorrelation(c); string spanish = RenderSpanish(result, false), english = RenderResult(result, false); True(spanish.Contains("[ALTA] Servicio: tapisrv") && spanish.Contains("Puede cambiar configuracion? : SI (confirmado)") && spanish.Contains("Evidencia PT-014")); True(english.Contains("[HIGH] Service: tapisrv") && english.Contains("PT-014    : SERVICE_CHANGE_CONFIG (CONFIRMED)")); });
            Run("Negative ACL does not trigger PT-013", delegate { Equal(EvaluationStatus.RuledOut, One("PT-013", Veyon(TriState.No, "LocalSystem", false, null)).Status); });
            Run("Process only has no escalation finding", TestProcessOnly);
            Run("Configured task remains primary evidence without process", TestTaskWithoutProcess);
            Run("Process and binary console reports", TestExecutionReports);
            Run("PT-026 create-subkey only remains POTENTIAL", TestRegistryCreateOnly);
            Run("PT-027 missing ServiceDll with creatable parent is POTENTIAL", TestMissingServiceDll);
            Run("PT-027 disabled service is conditioned POTENTIAL", delegate { AnalysisContext c = Build("PT-027", "positive"); c.Services[0].StartType = "Disabled"; Equal(EvaluationStatus.Potential, One("PT-027", c).Status); });
            Run("ServiceDll relationship is configured, not observed", TestServiceDllRelationship);
            Run("Inaccessible ServiceDll evidence remains UNKNOWN", TestUnknownServiceDll);
            Run("Large innocuous service set stays quiet", TestServiceNoise);
            Run("SERVICE-REGISTRY offline service registry fixture correlates", TestServiceRegistryFixture);
            Run("SYN-SERVICE-BINARY-A offline fixture loads and correlates", TestServiceBinaryFixture);
            Run("SYN-TASK-A privileged scheduled task", delegate { Equal(EvaluationStatus.Confirmed, One("PT-017", Tftp(TriState.Yes, TriState.Yes, true, true)).Status); });
            Run("SYN-TASK-B same-level task", delegate { Equal(EvaluationStatus.RuledOut, One("PT-017", Tftp(TriState.Yes, TriState.No, true, true)).Status); });
            Run("SYN-TASK-C no associated task", delegate { Equal(EvaluationStatus.RuledOut, One("PT-017", Fresh()).Status); });
            Run("SYN-TASK-D effective deny", delegate { Equal(EvaluationStatus.RuledOut, One("PT-017", Tftp(TriState.No, TriState.Yes, true, true)).Status); });
            Run("SYN-TASK-E principal unavailable", delegate { Equal(EvaluationStatus.Unknown, One("PT-017", Tftp(TriState.Yes, TriState.Unknown, true, true)).Status); });
            Run("SYN-TASK-F service maps to PT-013", delegate { AnalysisContext c = Fresh(); c.Services.Add(Service(TriState.Yes, TriState.No, TriState.No)); Equal(EvaluationStatus.Confirmed, One("PT-013", c).Status); Equal(EvaluationStatus.RuledOut, One("PT-017", c).Status); });
            Run("Disabled task remains conditioned evidence", delegate { Finding f = One("PT-017", Tftp(TriState.Yes, TriState.Yes, false, true)); Equal(EvaluationStatus.Potential, f.Status); True(f.MissingConditions.Count > 0); });
            Run("Non-script does not trigger PT-019", delegate { Equal(EvaluationStatus.RuledOut, One("PT-019", Tftp(TriState.Yes, TriState.Yes, true, true)).Status); });
            Run("Script triggers PT-019", delegate { AnalysisContext c = Tftp(TriState.Yes, TriState.Yes, true, true); c.Tasks[0].Actions[0].Executable = "C:\\Backup\\job.ps1"; Equal(EvaluationStatus.Confirmed, One("PT-019", c).Status); });
            Run("Relative task path requires a concrete controllable PT-020 candidate", delegate { AnalysisContext c = Tftp(TriState.Yes, TriState.Yes, true, true); ScheduledTaskAction a = c.Tasks[0].Actions[0]; a.Executable = "tool.exe"; a.PathAmbiguous = true; a.HijackCandidates.Add("C:\\Jobs\\tool.exe"); a.HijackCandidatePermissions.Add(new SecurityPermission { Target = "C:\\Jobs", CanWrite = TriState.No, CanCreate = TriState.Yes }); Equal(EvaluationStatus.Confirmed, One("PT-020", c).Status); });
            Run("Missing path permission is UNKNOWN", delegate { AnalysisContext c = Tftp(TriState.Unknown, TriState.Yes, true, true); Equal(EvaluationStatus.Unknown, One("PT-017", c).Status); });
            Run("Synthetic DNS-operator fixture maps to PT-011", delegate { Equal(EvaluationStatus.Potential, One("PT-011", Build("PT-011", "positive")).Status); });
            Run("Synthetic backup-operator fixture maps to PT-003 and PT-010", delegate { Equal(EvaluationStatus.Potential, One("PT-003", Build("PT-003", "positive")).Status); Equal(EvaluationStatus.Potential, One("PT-010", Build("PT-010", "positive")).Status); });
            Run("Synthetic service-operator fixture maps to PT-009 and PT-014", delegate { Equal(EvaluationStatus.Potential, One("PT-009", Build("PT-009", "positive")).Status); Equal(EvaluationStatus.Confirmed, One("PT-014", Build("PT-014", "positive")).Status); });
            Run("Synthetic installer-policy fixture maps to PT-021", delegate { Equal(EvaluationStatus.Confirmed, One("PT-021", Build("PT-021", "positive")).Status); });
            Run("Synthetic event-log-reader fixture maps to PT-022", delegate { Equal(EvaluationStatus.Potential, One("PT-022", Build("PT-022", "positive")).Status); });
            Run("Synthetic impersonation-token fixture maps to PT-001", delegate { Equal(EvaluationStatus.Potential, One("PT-001", Build("PT-001", "positive")).Status); });
            Run("Synthetic spooler-correlation fixture maps to PT-024", delegate { Equal(EvaluationStatus.Confirmed, One("PT-024", Build("PT-024", "positive")).Status); });
            Run("Synthetic volume-management fixture maps to PT-008", delegate { Equal(EvaluationStatus.Potential, One("PT-008", Build("PT-008", "positive")).Status); });
            Run("Synthetic restore-privilege fixture maps to PT-004", delegate { Equal(EvaluationStatus.Potential, One("PT-004", Build("PT-004", "positive")).Status); });
            Run("Synthetic spooler-token fixture maps to PT-001 and PT-024", delegate { Equal(EvaluationStatus.Potential, One("PT-001", Build("PT-001", "positive")).Status); Equal(EvaluationStatus.Confirmed, One("PT-024", Build("PT-024", "positive")).Status); });
            Run("Synthetic alternate impersonation fixture maps to PT-001", delegate { Equal(EvaluationStatus.Potential, One("PT-001", Build("PT-001", "positive")).Status); });
            Run("Synthetic alternate installer fixture maps to PT-021", delegate { Equal(EvaluationStatus.Confirmed, One("PT-021", Build("PT-021", "positive")).Status); });
            Run("Synthetic token-source fixture maps to PT-001", delegate { Equal(EvaluationStatus.Potential, One("PT-001", Build("PT-001", "positive")).Status); });
            Run("Synthetic policy-conjunction fixture maps to PT-021", delegate { Equal(EvaluationStatus.Confirmed, One("PT-021", Build("PT-021", "positive")).Status); });
            Run("JSON export creates structured report", TestJsonExport);
            RunAdversarialScenarios();
            RunSyntheticScenarioMatrix();
            RunCorrelationScenarios();
            RunEvidenceIntegrityScenarios();
            RunCollectorStateScenarios();
            RunSingleFileScenarios();
            RunCleanOutputScenarios();
            RunSoftwareProfileScenarios();
            RunServiceDiscoveryScenarios();

            Console.WriteLine("TOTAL: " + (passed + failed + skipped + blocked) + "  PASSED: " + passed + "  FAILED: " + failed + "  SKIPPED: " + skipped + "  BLOCKED: " + blocked);
            return failed == 0 ? 0 : 1;
        }

        private sealed class SkippedTestException : Exception { internal SkippedTestException(string message) : base(message) { } }
        private sealed class BlockedTestException : Exception { internal BlockedTestException(string message) : base(message) { } }
        private static void Run(string name, Action action) { try { action(); passed++; Console.WriteLine("PASS " + name); } catch (SkippedTestException ex) { skipped++; Console.WriteLine("SKIPPED " + name + " :: " + ex.Message); } catch (BlockedTestException ex) { blocked++; Console.WriteLine("BLOCKED " + name + " :: " + ex.Message); } catch (Exception ex) { failed++; Console.WriteLine("FAIL " + name + " :: " + ex.Message); } }
        private static void True(bool value) { if (!value) throw new Exception("Expected true."); }
        private static void Equal<T>(T expected, T actual) { if (!Object.Equals(expected, actual)) throw new Exception("Expected " + expected + ", got " + actual + "."); }
        private static RuleDefinition Rule(string id) { return rules.Single(r => r.Id == id); }
        private static Finding One(string id, AnalysisContext context) { return engine.Evaluate(new[] { Rule(id) }, context).First(); }
        private static void Expect(RuleDefinition rule, AnalysisContext context, EvaluationStatus status) { Equal(status, engine.Evaluate(new[] { rule }, context).First().Status); }

        private static void RunAdversarialScenarios()
        {
            string[] easy = { "E01", "E02", "E03", "E04", "E05", "E06", "E07", "E08" };
            string[] medium = { "M01", "M02", "M03", "M04", "M05", "M06", "M07", "M08" };
            string[] hard = { "H01", "H02", "H03", "H04", "H05", "H06", "H07", "H08", "H09", "H10" };
            string[] privilege = { "P01", "P02", "P03", "P04", "P05" };
            foreach (string id in easy) { string captured = id; Run("ADVERSARIAL EASY " + captured, delegate { ValidateAdversarial(captured, AdversarialFixtures.Create(captured)); }); }
            foreach (string id in medium) { string captured = id; Run("ADVERSARIAL MEDIUM " + captured, delegate { ValidateAdversarial(captured, AdversarialFixtures.Create(captured)); }); }
            foreach (string id in hard) { string captured = id; Run("ADVERSARIAL HARD " + captured, delegate { ValidateAdversarial(captured, AdversarialFixtures.Create(captured)); }); }
            foreach (string id in privilege) { string captured = id; Run("ADVERSARIAL PRIVILEGE " + captured, delegate { ValidateAdversarial(captured, AdversarialFixtures.Create(captured)); }); }
            Run("ADVERSARIAL ZERO NOISE", delegate { ValidateAdversarial("ZN", AdversarialFixtures.Create("ZN")); });
        }

        private static void ValidateAdversarial(string id, AnalysisContext c)
        {
            if (id == "E01") { Finding f = One("PT-001", c); Equal(EvaluationStatus.Potential, f.Status); Equal(Severity.Medium, f.Severity); }
            else if (id == "E02") { Finding f = One("PT-001", c); Equal(EvaluationStatus.Potential, f.Status); Equal(Severity.Low, f.Severity); True(f.MissingConditions.Any(x => x.IndexOf("AdjustTokenPrivileges", StringComparison.OrdinalIgnoreCase) >= 0)); }
            else if (id == "E03") { Finding f = One("PT-003", c); Equal(EvaluationStatus.Potential, f.Status); Equal(Severity.Low, f.Severity); }
            else if (id == "E04") { Finding f = One("PT-003", c); Equal(EvaluationStatus.RuledOut, f.Status); True(!f.Evidence.Any(e => e.Value.IndexOf("enable", StringComparison.OrdinalIgnoreCase) >= 0)); }
            else if (id == "E05") Equal(EvaluationStatus.Confirmed, One("PT-013", c).Status);
            else if (id == "E06") Equal(EvaluationStatus.RuledOut, One("PT-013", c).Status);
            else if (id == "E07") Equal(EvaluationStatus.Confirmed, One("PT-021", c).Status);
            else if (id == "E08") Equal(EvaluationStatus.RuledOut, One("PT-021", c).Status);
            else if (id == "M01") Equal(EvaluationStatus.Confirmed, One("PT-017", c).Status);
            else if (id == "M02") { Finding f = One("PT-017", c); Equal(EvaluationStatus.Potential, f.Status); True(f.MissingConditions.Count > 0); }
            else if (id == "M03") { Finding f = One("PT-013", c); Equal(EvaluationStatus.Potential, f.Status); True(f.MissingConditions.Any(x => x.IndexOf("disabled", StringComparison.OrdinalIgnoreCase) >= 0)); }
            else if (id == "M04") { Finding f = One("PT-013", c); Equal(EvaluationStatus.Potential, f.Status); True(f.MissingConditions.Count > 0); }
            else if (id == "M05") Equal(EvaluationStatus.RuledOut, One("PT-015", c).Status);
            else if (id == "M06") { Equal(EvaluationStatus.Confirmed, One("PT-014", c).Status); Equal(EvaluationStatus.RuledOut, One("PT-013", c).Status); }
            else if (id == "M07") Equal(EvaluationStatus.Confirmed, One("PT-027", c).Status);
            else if (id == "M08") Equal(EvaluationStatus.Potential, One("PT-026", c).Status);
            else if (id == "H01")
            {
                ExecutionCorrelation.Correlate(c, false); Equal(1, c.Binaries.Count); BinaryArtifact b = c.Binaries.Single();
                True(b.Sources.Contains("ProcessImage") && b.Sources.Contains("ServiceConfiguration") && b.Sources.Contains("ScheduledTaskConfiguration"));
                Equal(EvaluationStatus.Confirmed, One("PT-013", c).Status); Equal(EvaluationStatus.Confirmed, One("PT-017", c).Status);
            }
            else if (id == "H02") { Equal(EvaluationStatus.RuledOut, One("PT-013", c).Status); Equal(TriState.Yes, c.Services[0].ExecutablePermission.CanDelete); }
            else if (id == "H03") { Finding f = One("PT-027", c); Equal(EvaluationStatus.Potential, f.Status); True(f.Evidence.Any(e => e.Value.IndexOf("exists=No", StringComparison.OrdinalIgnoreCase) >= 0)); }
            else if (id == "H04") { Equal(EvaluationStatus.Potential, One("PT-013", c).Status); Equal(EvaluationStatus.Confirmed, One("PT-014", c).Status); }
            else if (id == "H05") { Equal(EvaluationStatus.Potential, One("PT-017", c).Status); Equal(EvaluationStatus.Potential, One("PT-018", c).Status); }
            else if (id == "H06") { Equal("ACCESS_DENIED", c.Processes[0].AccessStatus); True(c.Processes[0].OwnerAccount == null); Equal(EvaluationStatus.RuledOut, One("PT-013", c).Status); }
            else if (id == "H07") { ExecutionCorrelation.Correlate(c, false); List<Finding> f = engine.Evaluate(new[] { Rule("PT-027") }, c); Equal(2, f.Count); Finding positive = f.Single(x => x.Status == EvaluationStatus.Confirmed); Equal("C:\\Windows\\System32\\vendor.dll", positive.Target); Finding protectedTarget = f.Single(x => x.Target == "C:\\Windows\\System32\\protected.dll"); Equal(EvaluationStatus.RuledOut, protectedTarget.Status); }
            else if (id == "H08") Equal(EvaluationStatus.RuledOut, One("PT-013", c).Status);
            else if (id == "H09") { List<Finding> f = engine.Evaluate(new[] { Rule("PT-026") }, c); Equal(1, f.Count); Equal(EvaluationStatus.Confirmed, f[0].Status); True(f[0].Evidence.Any(e => e.Subject.IndexOf("Registry32", StringComparison.OrdinalIgnoreCase) >= 0)); }
            else if (id == "H10") Equal(EvaluationStatus.Unknown, One("PT-013", c).Status);
            else if (id == "P01") ValidateDisabledPrivilege("PT-005", c);
            else if (id == "P02") ValidateDisabledPrivilege("PT-004", c);
            else if (id == "P03") ValidateDisabledPrivilege("PT-023", c);
            else if (id == "P04") Equal(EvaluationStatus.RuledOut, One("PT-001", c).Status);
            else if (id == "P05") Equal(EvaluationStatus.Unknown, One("PT-001", c).Status);
            else if (id == "ZN") ValidateZeroNoise(c);
            else throw new Exception("No expected result for " + id);
        }

        private static void ValidateDisabledPrivilege(string ruleId, AnalysisContext c)
        {
            Finding f = One(ruleId, c); Equal(EvaluationStatus.Potential, f.Status); Equal(Severity.Low, f.Severity); Equal(Confidence.Low, f.Confidence); True(f.MissingConditions.Count > 0);
        }

        private static void ValidateZeroNoise(AnalysisContext c)
        {
            ExecutionCorrelation.Correlate(c, false); List<Finding> findings = engine.Evaluate(rules, c);
            Equal(1, findings.Count(f => f.Status == EvaluationStatus.Confirmed));
            Equal("PT-013", findings.Single(f => f.Status == EvaluationStatus.Confirmed).RuleId);
            List<Finding> potential = findings.Where(f => f.Status == EvaluationStatus.Potential).ToList(); Equal(1, potential.Count); Equal("PT-003", potential[0].RuleId);
            Equal(0, findings.Count(f => f.Status == EvaluationStatus.Unknown));
            AnalysisResult result = new AnalysisResult { Context = c, Findings = findings, RulesEvaluated = rules.Count, GeneratedUtc = DateTime.UtcNow };
            StringWriter output = new StringWriter(); TextWriter prior = Console.Out;
            try { Console.SetOut(output); ConsoleReporter.Print(result, false); } finally { Console.SetOut(prior); }
            string text = output.ToString(); True(text.Contains("[LOW] PT-003")); True(!text.Contains("[HIGH] PT-003")); True(!text.Contains("PROCESSES")); True(!text.Contains("BINARIES"));
        }

        private static void RunSyntheticScenarioMatrix()
        {
            string[] machines = { "SYN-INSTALLER-POLICY-001", "SYN-SVC-CONFIG-001", "SYN-BACKUP-001", "SYN-DNS-001", "SYN-SVC-WRITE-001", "SYN-SVC-WRITE-002", "SYN-TASK-WRITE-001", "SYN-DLL-SEARCH-001" };
            string[] variants = { "A", "B", "C", "D", "E" };
            foreach (string machine in machines)
                foreach (string variant in variants)
                {
                    string capturedMachine = machine, capturedVariant = variant;
                    Run("SYNTHETIC-MATRIX " + capturedMachine + " " + capturedVariant, delegate { ValidateSyntheticScenario(capturedMachine, capturedVariant, SyntheticScenarioFixtures.Create(capturedMachine, capturedVariant)); });
                }
            Run("SYNTHETIC-MATRIX JSON result export", ExportSyntheticScenarioResults);
        }

        private static void RunCorrelationScenarios()
        {
            string[] ids = { "R01", "R02", "R03", "R04", "R05", "B01", "B02", "B03", "B04", "B05", "B06", "D01", "D02", "D03", "D04", "D05", "D06", "D07" };
            foreach (string id in ids) { string captured = id; Run("CORRELATION correlation " + captured, delegate { ValidateCorrelation(captured, CorrelationFixtures.Create(captured)); }); }

            Run("CORRELATION FP01 deny-only group", delegate { AnalysisContext c = CorrelationFixtures.Create("R01"); c.Token.Groups[0].DenyOnly = true; Equal(0, AnalyzeCorrelation(c).CorrelationTraces.Count); });
            Run("CORRELATION FP02 restricted token preserved", delegate { AnalysisContext c = CorrelationFixtures.Create("B01"); c.Token.Restricted = true; True(AnalyzeCorrelation(c).CorrelationTraces.Single().PendingConditions.Any(x => x.IndexOf("restricted", StringComparison.OrdinalIgnoreCase) >= 0)); });
            Run("CORRELATION FP03 disabled privilege not enabled", delegate { CorrelationTrace t = AnalyzeCorrelation(CorrelationFixtures.Create("B02")).CorrelationTraces.Single(); True(t.Nodes.Any(n => n.Label == "SeBackupPrivilege=Disabled")); });
            Run("CORRELATION FP04 absent privilege not invented", delegate { CorrelationTrace t = AnalyzeCorrelation(CorrelationFixtures.Create("B03")).CorrelationTraces.Single(); True(t.Nodes.Any(n => n.Label == "SeBackupPrivilege=Absent")); });
            Run("CORRELATION FP05 protected service no effective right", delegate { AnalysisContext c = CorrelationFixtures.Create("R01"); c.Services[0].CanChangeConfig = TriState.No; Equal(0, AnalyzeCorrelation(c).CorrelationTraces.Count); });
            Run("CORRELATION FP06 non-privileged service", delegate { AnalysisContext c = CorrelationFixtures.Create("R01"); c.Services[0].Account = @"LAB\svc"; Equal(0, AnalyzeCorrelation(c).CorrelationTraces.Count); });
            Run("CORRELATION FP07 allow ACE without effective access", delegate { AnalysisContext c = CorrelationFixtures.Create("R02"); c.Services[0].SecurityDescriptorSddl = "D:(A;;CC;;;BU)"; Equal(0, AnalyzeCorrelation(c).CorrelationTraces.Count); });
            Run("CORRELATION FP08 applicable deny", delegate { AnalysisContext c = CorrelationFixtures.Create("R02"); c.Services[0].SecurityDescriptorSddl = "D:(D;;CC;;;WD)"; Equal(0, AnalyzeCorrelation(c).CorrelationTraces.Count); });
            Run("CORRELATION FP09 MIC restriction remains unknown", delegate { AnalysisContext c = CorrelationFixtures.Create("R02"); c.Token.IntegrityLevel = "Low"; Equal(0, AnalyzeCorrelation(c).CorrelationTraces.Count); });
            Run("CORRELATION FP10 shared process services stay distinct", delegate { AnalysisContext c = CorrelationFixtures.Create("R01"); WindowsService second = CorrelationFixtures.Create("R02").Services[0]; second.Name = "SecondService"; second.ProcessId = c.Services[0].ProcessId = 444; c.Services.Add(second); Equal(1, AnalyzeCorrelation(c).CorrelationTraces.Count); });
            Run("CORRELATION FP11 overlapping groups do not duplicate", delegate { AnalysisContext c = CorrelationFixtures.Create("R01"); c.Token.Groups.Add(new WindowsGroup { Sid = "S-1-5-32-544", Name = @"BUILTIN\Administrators", Enabled = true }); Equal(1, AnalyzeCorrelation(c).CorrelationTraces.Count); });
            Run("CORRELATION FP12 inaccessible DNS registry", delegate { CorrelationTrace t = AnalyzeCorrelation(CorrelationFixtures.Create("D05")).CorrelationTraces.Single(); True(t.Nodes.Single(n => n.NodeId == "plugin").State == RelationshipState.Unknown); });
            Run("CORRELATION FP13 absent DNS server", delegate { CorrelationTrace t = AnalyzeCorrelation(CorrelationFixtures.Create("D02")).CorrelationTraces.Single(); True(t.Nodes.Single(n => n.NodeId == "dns").Label.Contains("No")); });
            Run("CORRELATION FP14 unknown plugin configuration", delegate { CorrelationTrace t = AnalyzeCorrelation(CorrelationFixtures.Create("D05")).CorrelationTraces.Single(); True(t.PendingConditions.Any(x => x.IndexOf("not observable", StringComparison.OrdinalIgnoreCase) >= 0)); });
            Run("CORRELATION FP15 duplicate correlation deduplicated", delegate { AnalysisContext c = CorrelationFixtures.Create("R01"); c.Services.Add(c.Services[0]); Equal(1, AnalyzeCorrelation(c).CorrelationTraces.Count); });
            Run("CORRELATION normal output deduplicates correlated findings", delegate { AnalysisResult result = AnalyzeCorrelation(CorrelationFixtures.Create("R01")); StringWriter output = new StringWriter(); TextWriter prior = Console.Out; try { Console.SetOut(output); ConsoleReporter.Print(result, false); } finally { Console.SetOut(prior); } string text = output.ToString(); True(text.Contains("Privileged Service Configuration")); True(!text.Contains("[HIGH] PT-014")); });
            Run("CORRELATION real engine trace artifact", ExportCorrelationTraces);
        }

        private static AnalysisResult AnalyzeCorrelation(AnalysisContext context)
        {
            return new AnalyzerEngine().Analyze(context, rules);
        }

        private static void ValidateCorrelation(string id, AnalysisContext c)
        {
            AnalysisResult result = AnalyzeCorrelation(c);
            if (id == "R01") { CorrelationTrace t = result.CorrelationTraces.Single(); Equal(EvaluationStatus.Confirmed, t.Status); True(t.RuleIds.Contains("PT-009") && t.RuleIds.Contains("PT-014")); }
            else if (id == "R02") Equal(0, result.CorrelationTraces.Count);
            else if (id == "R03") { Equal(0, result.CorrelationTraces.Count); Equal(EvaluationStatus.Confirmed, result.Findings.Single(f => f.RuleId == "PT-014").Status); }
            else if (id == "R04") { CorrelationTrace t = result.CorrelationTraces.Single(); Equal(EvaluationStatus.Potential, t.Status); Equal("PARTIAL_DETECTION", t.Classification); }
            else if (id == "R05") True(result.CorrelationTraces.Single().Edges.Any(e => e.Relation == "CORRELATED_WITH_EFFECTIVE_RIGHT" && e.Provenance == "UNKNOWN"));
            else if (id == "B01") { CorrelationTrace t = result.CorrelationTraces.Single(); True(t.RuleIds.Contains("PT-003") && t.RuleIds.Contains("PT-010")); True(t.Nodes.Any(n => n.Label == "SeRestorePrivilege=Absent")); }
            else if (id == "B02") True(result.CorrelationTraces.Single().Nodes.Any(n => n.Label == "SeBackupPrivilege=Disabled"));
            else if (id == "B03") True(result.CorrelationTraces.Single().Nodes.Any(n => n.Label == "SeBackupPrivilege=Absent"));
            else if (id == "B04") { Equal(0, result.CorrelationTraces.Count); Equal(EvaluationStatus.Potential, result.Findings.Single(f => f.RuleId == "PT-003").Status); }
            else if (id == "B05") True(result.CorrelationTraces.Single().Nodes.Any(n => n.Label == "SeBackupPrivilege=Unknown"));
            else if (id == "B06") True(result.CorrelationTraces.Single().Nodes.Any(n => n.Label == "SeRestorePrivilege=Disabled"));
            else if (id == "D01") { CorrelationTrace t = result.CorrelationTraces.Single(); True(t.RuleIds.SequenceEqual(new[] { "PT-011" })); True(t.Nodes.Any(n => n.Type == "DnsServer" && n.State == RelationshipState.Observed)); }
            else if (id == "D02") True(result.CorrelationTraces.Single().PendingConditions.Any(x => x.IndexOf("remote", StringComparison.OrdinalIgnoreCase) >= 0));
            else if (id == "D03") Equal(0, result.CorrelationTraces.Count);
            else if (id == "D04") { CorrelationTrace t = result.CorrelationTraces.Single(); Equal(RelationshipState.Configured, t.Nodes.Single(n => n.NodeId == "plugin").State); True(t.Nodes.Single(n => n.NodeId == "plugin").Label.EndsWith("plugin.dll", StringComparison.OrdinalIgnoreCase)); }
            else if (id == "D05") Equal(RelationshipState.Unknown, result.CorrelationTraces.Single().Nodes.Single(n => n.NodeId == "plugin").State);
            else if (id == "D06") { CorrelationTrace t = result.CorrelationTraces.Single(); True(t.Nodes.Single(n => n.NodeId == "dns").Label.Contains("No")); True(!t.Nodes.Any(n => n.Label.IndexOf("DNS Client", StringComparison.OrdinalIgnoreCase) >= 0)); }
            else if (id == "D07") True(result.CorrelationTraces.Single().PendingConditions.Any(x => x.IndexOf("Disabled", StringComparison.OrdinalIgnoreCase) >= 0));
        }

        private static void ExportCorrelationTraces()
        {
            List<CorrelationTrace> traces = new List<CorrelationTrace>();
            foreach (string id in new[] { "R01", "B01", "D04" }) traces.AddRange(AnalyzeCorrelation(CorrelationFixtures.Create(id)).CorrelationTraces);
            Equal(3, traces.Count); Equal(3, traces.Select(t => t.ScenarioId).Distinct().Count());
            Dictionary<string, object> report = new Dictionary<string, object>(); report["version"] = "1.1.0"; report["generatedUtc"] = DateTime.UtcNow.ToString("o"); report["validationLevel"] = "SYNTHETIC_PASS"; report["liveExternalMachinesValidated"] = false; report["engine"] = "AnalyzerEngine + RuleEngine + AdvancedCorrelation"; report["traces"] = traces;
            string path = Path.Combine(ProjectRoot(), "artifacts", "correlation-traces.json"); File.WriteAllText(path, new JavaScriptSerializer { MaxJsonLength = Int32.MaxValue }.Serialize(report), new UTF8Encoding(false));
            string json = File.ReadAllText(path); True(json.Contains("PT-009") && json.Contains("PT-003") && json.Contains("PT-011") && json.Contains("EvidenceId") && json.Contains("FindingId") && json.Contains("StatusName") && json.Contains("CONFIRMED") && json.Contains("PARTIAL_DETECTION"));
        }

        private static void RunEvidenceIntegrityScenarios()
        {
            Run("EVIDENCE-INTEGRITY 01 PT-004 absent is ruled out, not supporting", delegate { CorrelationTrace t = AnalyzeCorrelation(CorrelationFixtures.Create("B01")).CorrelationTraces.Single(); True(t.SupportingRuleIds.Contains("PT-010") && t.SupportingRuleIds.Contains("PT-003")); True(!t.SupportingRuleIds.Contains("PT-004") && !t.RuleIds.Contains("PT-004")); True(t.EvaluatedRuleIds.Contains("PT-004") && t.RuledOutRuleIds.Contains("PT-004")); });
            Run("EVIDENCE-INTEGRITY 02 confirmed right keeps execution conditional", delegate { CorrelationTrace t = AnalyzeCorrelation(CorrelationFixtures.Create("R01")).CorrelationTraces.Single(); Equal(EvaluationStatus.Confirmed, t.Status); True(t.ConfirmedFacts.Any(x => x.StartsWith("CONFIRMED_RIGHT", StringComparison.Ordinal))); True(t.ConditionalOutcomes.Any(x => x.StartsWith("CONDITIONAL_EXECUTION", StringComparison.Ordinal))); True(!t.ExploitationVerified); });
            Run("EVIDENCE-INTEGRITY 03 inaccessible service remains unknown", delegate { AnalysisContext c = CorrelationFixtures.Create("R01"); c.Services[0].CanChangeConfig = TriState.Unknown; c.Services[0].Errors.Add("ACCESS_DENIED"); AnalysisResult r = AnalyzeCorrelation(c); Equal(0, r.CorrelationTraces.Count); Equal(EvaluationStatus.Unknown, r.Findings.Single(f => f.RuleId == "PT-014").Status); });
            Run("EVIDENCE-INTEGRITY 04 inaccessible file remains unknown", delegate { Equal(EvaluationStatus.Unknown, AnalyzeCorrelation(Build("PT-013", "unknown")).Findings.Single(f => f.RuleId == "PT-013").Status); });
            Run("EVIDENCE-INTEGRITY 05 inaccessible token remains unknown", delegate { Equal(EvaluationStatus.Unknown, AnalyzeCorrelation(Build("PT-003", "unknown")).Findings.Single(f => f.RuleId == "PT-003").Status); });
            Run("EVIDENCE-INTEGRITY 06 inaccessible registry remains unknown", delegate { Equal(EvaluationStatus.Unknown, AnalyzeCorrelation(Build("PT-026", "unknown")).Findings.Single(f => f.RuleId == "PT-026").Status); });
            Run("EVIDENCE-INTEGRITY 07 protected process does not infer SYSTEM", delegate { AnalysisContext c = AdversarialFixtures.Create("H06"); AnalysisResult r = AnalyzeCorrelation(c); Equal("ACCESS_DENIED", r.Context.Processes[0].AccessStatus); True(r.Context.Processes[0].OwnerAccount == null); });
            Run("EVIDENCE-INTEGRITY 08 inaccessible task enumeration invents nothing", delegate { AnalysisContext c = Fresh(); c.Errors.Add("Tasks: ACCESS_DENIED"); AnalysisResult r = AnalyzeCorrelation(c); Equal(0, r.Context.Tasks.Count); True(r.Errors.Any(x => x.Contains("ACCESS_DENIED"))); });
            Run("EVIDENCE-INTEGRITY 09 disabled service remains conditioned", delegate { CorrelationTrace t = AnalyzeCorrelation(CorrelationFixtures.Create("R04")).CorrelationTraces.Single(); Equal(EvaluationStatus.Potential, t.Status); True(t.PendingConditions.Any(x => x.IndexOf("Disabled", StringComparison.OrdinalIgnoreCase) >= 0)); });
            Run("EVIDENCE-INTEGRITY 10 disabled task remains conditioned", delegate { Finding f = AnalyzeCorrelation(AdversarialFixtures.Create("M02")).Findings.Single(x => x.RuleId == "PT-017"); Equal(EvaluationStatus.Potential, f.Status); True(f.MissingConditions.Count > 0); });
            Run("EVIDENCE-INTEGRITY 11 disabled privilege distinct", delegate { True(AnalyzeCorrelation(CorrelationFixtures.Create("B02")).CorrelationTraces.Single().Nodes.Any(n => n.Label == "SeBackupPrivilege=Disabled")); });
            Run("EVIDENCE-INTEGRITY 12 absent privilege distinct", delegate { True(AnalyzeCorrelation(CorrelationFixtures.Create("B03")).CorrelationTraces.Single().Nodes.Any(n => n.Label == "SeBackupPrivilege=Absent")); });
            Run("EVIDENCE-INTEGRITY 13 removed privilege distinct", delegate { AnalysisContext c = CorrelationFixtures.Create("B01"); c.Token.Privileges.Clear(); c.Token.Privileges.Add(new TokenPrivilege { Name = "SeBackupPrivilege", State = TokenPrivilegeState.Removed, Present = false, Enabled = false }); CorrelationTrace t = AnalyzeCorrelation(c).CorrelationTraces.Single(); True(t.Nodes.Any(n => n.Label == "SeBackupPrivilege=Removed")); True(t.PendingConditions.Any(x => x.Contains("Removed"))); });
            Run("EVIDENCE-INTEGRITY 14 MIC restriction blocks positive file path", delegate { Equal(EvaluationStatus.RuledOut, AnalyzeCorrelation(AdversarialFixtures.Create("H08")).Findings.Single(f => f.RuleId == "PT-013").Status); });
            Run("EVIDENCE-INTEGRITY 15 deny-only group creates no route", delegate { AnalysisContext c = CorrelationFixtures.Create("R01"); c.Token.Groups[0].DenyOnly = true; Equal(0, AnalyzeCorrelation(c).CorrelationTraces.Count); });
            Run("EVIDENCE-INTEGRITY 16 shared PID does not merge service configuration", delegate { AnalysisContext c = CorrelationFixtures.Create("R01"); WindowsService second = CorrelationFixtures.Create("R02").Services[0]; second.Name = "ProtectedSibling"; c.Services[0].ProcessId = second.ProcessId = 700; c.Services.Add(second); AnalysisResult r = AnalyzeCorrelation(c); Equal(1, r.CorrelationTraces.Count); Equal("VMTools", r.CorrelationTraces[0].Nodes.Single(n => n.Type == "WindowsService").Label); });
            Run("EVIDENCE-INTEGRITY 17 JSON preserves unknown conditions", delegate { string path = TempPath("unknown"); try { JsonReporter.Write(AnalyzeCorrelation(CorrelationFixtures.Create("D05")), path); string json = File.ReadAllText(path); True(json.Contains("PendingConditions") && json.Contains("not observable") && json.Contains("UNKNOWN")); } finally { if (File.Exists(path)) File.Delete(path); } });
            Run("EVIDENCE-INTEGRITY 18 JSON separates supporting and ruled-out rules", delegate { string path = TempPath("rules"); try { JsonReporter.Write(AnalyzeCorrelation(CorrelationFixtures.Create("B01")), path); string json = File.ReadAllText(path); True(json.Contains("SupportingRuleIds") && json.Contains("RuledOutRuleIds")); ReportInspection i = ReportImporter.Inspect(path); True(i.SchemaValid); } finally { if (File.Exists(path)) File.Delete(path); } });
            Run("EVIDENCE-INTEGRITY 19 sanitization is consistent", TestReportSanitization);
            Run("EVIDENCE-INTEGRITY 20 import does not alter findings", TestReportImportIntegrity);
            Run("EVIDENCE-INTEGRITY 21 route deduplication", delegate { AnalysisContext c = CorrelationFixtures.Create("R01"); c.Services.Add(c.Services[0]); Equal(1, AnalyzeCorrelation(c).CorrelationTraces.Count); });
            Run("EVIDENCE-INTEGRITY 22 standard output remains high signal", delegate { AnalysisResult result = AnalyzeCorrelation(CorrelationFixtures.Create("R01")); StringWriter output = new StringWriter(); TextWriter prior = Console.Out; try { Console.SetOut(output); ConsoleReporter.Print(result, false); } finally { Console.SetOut(prior); } string text = output.ToString(); True(text.Contains("CONFIRMED_RIGHT") && text.Contains("CONDITIONAL_EXECUTION") && text.Contains("Exploitation verified: NO")); True(!text.Contains("PROCESSES") && !text.Contains("BINARIES") && !text.Contains("[HIGH] PT-014")); });
            Run("EVIDENCE-INTEGRITY 23 DNS absence is not inferred after inaccessible inventory", delegate { DnsServerSnapshot dns = new DnsServerCollector().Collect(new List<WindowsService>(), "ACCESS_DENIED", false); Equal(TriState.Unknown, dns.Present); Equal("UNKNOWN", dns.ConfigurationReadState); True(dns.Errors.Any(x => x.Contains("ACCESS_DENIED"))); });
            Run("EVIDENCE-INTEGRITY 24 regression trace artifact", ExportEvidenceIntegrityTraces);
        }

        private static void RunCollectorStateScenarios()
        {
            Run("COLLECTOR-STATE S01 SCM minimum access observed", delegate { Equal((uint)0x0004, CollectorOutcomeClassifier.ScManagerEnumerateService); Equal("OBSERVED", CollectorOutcomeClassifier.ServiceState(true, 0, true, 0, 12, 0)); });
            Run("COLLECTOR-STATE S02 SCM access denied is unknown inventory", delegate { Equal("ACCESS_DENIED", CollectorOutcomeClassifier.ServiceState(false, 5, false, 0, 0, 0)); Equal("DENIED", CollectorOutcomeClassifier.AccessProbeClassification(5)); });
            Run("COLLECTOR-STATE S03 SCM object failure preserves partial enumeration", delegate { Equal("PARTIAL", CollectorOutcomeClassifier.ServiceState(true, 0, true, 0, 11, 1)); });
            Run("COLLECTOR-STATE S04 missing service differs from access denied", delegate { Equal("OBJECT_NOT_FOUND", CollectorOutcomeClassifier.AccessProbeClassification(1060)); True(CollectorOutcomeClassifier.AccessProbeClassification(1060) != CollectorOutcomeClassifier.AccessProbeClassification(5)); });
            Run("COLLECTOR-STATE S05 service configuration requests minimum right", delegate { Equal((uint)0x0001, CollectorOutcomeClassifier.ServiceQueryConfig); True((CollectorOutcomeClassifier.ServiceQueryConfig & CollectorOutcomeClassifier.ServiceChangeConfig) == 0); True((CollectorOutcomeClassifier.ServiceQueryConfig & CollectorOutcomeClassifier.ServiceQueryStatus) == 0); });
            Run("COLLECTOR-STATE S06 registry fallback filters Win32 service types", delegate { True(ServiceCollector.IsWin32ServiceType(0x10)); True(ServiceCollector.IsWin32ServiceType(0x20)); True(ServiceCollector.IsWin32ServiceType(0x110)); True(!ServiceCollector.IsWin32ServiceType(0x01)); True(!ServiceCollector.IsWin32ServiceType(0x02)); });
            Run("COLLECTOR-STATE T01 Task Scheduler complete enumeration", delegate { Equal("OBSERVED", CollectorOutcomeClassifier.TaskState(true, 0, 8, 0, 0)); });
            Run("COLLECTOR-STATE T02 Task Scheduler global access denied", delegate { Equal("ACCESS_DENIED", CollectorOutcomeClassifier.TaskState(false, unchecked((int)0x80070005), 0, 0, 0)); });
            Run("COLLECTOR-STATE T03 inaccessible folder is partial", delegate { Equal("PARTIAL", CollectorOutcomeClassifier.TaskState(true, 0, 7, 1, 0)); });
            Run("COLLECTOR-STATE T04 inaccessible task is partial", delegate { Equal("PARTIAL", CollectorOutcomeClassifier.TaskState(true, 0, 7, 0, 1)); });
            Run("COLLECTOR-STATE T05 disabled task evidence is retained", delegate { AnalysisContext c = Tftp(TriState.Yes, TriState.Yes, false, true); Equal(1, c.Tasks.Count); True(!c.Tasks[0].Enabled); Equal(1, c.Tasks[0].Actions.Count); Equal(EvaluationStatus.Potential, One("PT-017", c).Status); });
            Run("COLLECTOR-STATE I01 Low integrity does not assign SCM causality", delegate { string low = CollectorOutcomeClassifier.ServiceState(true, 0, true, 0, 4, 1); string medium = CollectorOutcomeClassifier.ServiceState(true, 0, true, 0, 4, 1); Equal(low, medium); Equal("PARTIAL", low); });
            Run("COLLECTOR-STATE I02 Medium integrity can preserve observed state", delegate { TokenSnapshot t = new TokenSnapshot { IntegrityLevel = "Medium", Elevated = TriState.No }; Equal("OBSERVED", CollectorOutcomeClassifier.ServiceState(true, 0, true, 0, 4, 0)); Equal(TriState.No, t.Elevated); });
            Run("COLLECTOR-STATE I03 AppContainer differs from Low integrity", delegate { TokenSnapshot t = new TokenSnapshot { IntegrityLevel = "Low", IsAppContainer = TriState.Yes, RestrictedState = TriState.No }; Equal("Low", t.IntegrityLevel); Equal(TriState.Yes, t.IsAppContainer); Equal(TriState.No, t.RestrictedState); });
            Run("COLLECTOR-STATE I04 restricted token differs from integrity", delegate { TokenSnapshot t = new TokenSnapshot { IntegrityLevel = "Medium", IsAppContainer = TriState.No, RestrictedState = TriState.Yes }; Equal("Medium", t.IntegrityLevel); Equal(TriState.Yes, t.RestrictedState); Equal(TriState.No, t.IsAppContainer); });
            Run("COLLECTOR-STATE I05 disabled privilege remains present", delegate { TokenPrivilege p = new TokenPrivilege { Name = "SeBackupPrivilege", Present = true, Enabled = false, State = TokenPrivilegeState.Disabled }; True(p.Present); True(!p.Enabled); Equal(TokenPrivilegeState.Disabled, p.State); });
            Run("COLLECTOR-STATE JSON carries structured collector diagnostics", delegate { AnalysisContext c = Fresh(); c.Diagnostics.Add(new CollectorDiagnostic { Collector = "Services", Stage = "CONNECT", Api = "OpenSCManager", RequestedAccess = "SC_MANAGER_ENUMERATE_SERVICE", Win32Error = 5, Classification = "GLOBAL_ACCESS_DENIED" }); string path = TempPath("diagnostics"); try { JsonReporter.Write(AnalyzeCorrelation(c), path); string json = File.ReadAllText(path); True(json.Contains("GLOBAL_ACCESS_DENIED") && json.Contains("SC_MANAGER_ENUMERATE_SERVICE")); } finally { if (File.Exists(path)) File.Delete(path); } });
        }

        private static void RunSingleFileScenarios()
        {
            Run("SINGLE-FILE SINGLE-001 distribution executables exist", delegate { ForArchitectures(delegate(string arch, string exe) { True(File.Exists(exe)); }); });
            Run("SINGLE-FILE SINGLE-002 distributions contain no sidecars", delegate { ForArchitectures(delegate(string arch, string exe) { True(File.Exists(exe)); True(!File.Exists(exe + ".config")); True(!File.Exists(Path.ChangeExtension(exe, ".dll"))); True(!File.Exists(Path.ChangeExtension(exe, ".pdb"))); }); });
            Run("SINGLE-FILE SINGLE-003 list-rules returns exactly 27 rules", delegate { ForArchitectures(delegate(string arch, string exe) { ExternalResult r = RunExternal(exe, "--list-rules", Path.GetTempPath()); Equal(0, r.ExitCode); Equal(27, RuleLines(r.Output).Count); }); });
            Run("SINGLE-FILE SINGLE-004 PT-001 through PT-027 are embedded", delegate { ForArchitectures(delegate(string arch, string exe) { List<string> lines = RuleLines(RunExternal(exe, "--list-rules", Path.GetTempPath()).Output); for (int i = 1; i <= 27; i++) True(lines[i - 1].StartsWith("PT-" + i.ToString("000") + " ", StringComparison.Ordinal)); }); });
            Run("SINGLE-FILE SINGLE-005 rule-info PT-013", delegate { ForArchitectures(delegate(string arch, string exe) { ExternalResult r = RunExternal(exe, "--rule-info PT-013", Path.GetTempPath()); Equal(0, r.ExitCode); True(r.Output.Contains("PT-013 - Writable Service Binary")); }); });
            Run("SINGLE-FILE SINGLE-006 rule-info PT-027", delegate { ForArchitectures(delegate(string arch, string exe) { ExternalResult r = RunExternal(exe, "--rule-info PT-027", Path.GetTempPath()); Equal(0, r.ExitCode); True(r.Output.Contains("PT-027 - Writable Privileged ServiceDll")); }); });
            Run("SINGLE-FILE SINGLE-007 normal execution without external catalog", delegate { ForArchitectures(delegate(string arch, string exe) { ExternalResult r = RunExternal(exe, String.Empty, Path.GetTempPath()); Equal(0, r.ExitCode); True(r.Output.Contains("PrivTrace v1.1.0") && r.Output.Contains("Rules evaluated : 27")); }); });
            Run("SINGLE-FILE SINGLE-008 normal execution without config", delegate { ForArchitectures(delegate(string arch, string exe) { True(!File.Exists(exe + ".config")); Equal(0, RunExternal(exe, String.Empty, Path.GetTempPath()).ExitCode); }); });
            Run("SINGLE-FILE SINGLE-009 isolated directory contains only executable", delegate { ForArchitectures(delegate(string arch, string exe) { WithIsolatedExe(arch, exe, false, delegate(string copy, string cwd, string root) { Equal(1, Directory.GetFiles(Path.GetDirectoryName(copy)).Length); Equal(0, RunExternal(copy, "--list-rules", cwd).ExitCode); }); }); });
            Run("SINGLE-FILE SINGLE-010 current directory differs from executable", delegate { ForArchitectures(delegate(string arch, string exe) { WithIsolatedExe(arch, exe, false, delegate(string copy, string cwd, string root) { True(!String.Equals(Path.GetDirectoryName(copy), cwd, StringComparison.OrdinalIgnoreCase)); Equal(27, RuleLines(RunExternal(copy, "--list-rules", cwd).Output).Count); }); }); });
            Run("SINGLE-FILE SINGLE-011 executable works from path with spaces", delegate { ForArchitectures(delegate(string arch, string exe) { WithIsolatedExe(arch, exe, true, delegate(string copy, string cwd, string root) { True(copy.Contains(" ")); Equal(0, RunExternal(copy, "--rule-info PT-013", cwd).ExitCode); }); }); });
            Run("SINGLE-FILE SINGLE-012 embedded catalog byte integrity", delegate { byte[] embedded = new RuleCatalog().ReadEmbeddedBytes(); byte[] source = File.ReadAllBytes(KnowledgePath("rules", "rules.xml")); Equal(Sha256(source), Sha256(embedded)); Equal(27, new RuleCatalog().Load(new MemoryStream(embedded), "integrity test").Count); });
            Run("SINGLE-FILE SINGLE-013 external catalog cannot override embedded catalog", delegate { ForArchitectures(delegate(string arch, string exe) { WithIsolatedExe(arch, exe, false, delegate(string copy, string cwd, string root) { string fakeDir = Path.Combine(Path.GetDirectoryName(copy), "knowledge", "rules"); Directory.CreateDirectory(fakeDir); File.WriteAllText(Path.Combine(fakeDir, "rules.xml"), "<rules />"); List<string> lines = RuleLines(RunExternal(copy, "--list-rules", cwd).Output); Equal(27, lines.Count); True(lines[12].StartsWith("PT-013 ", StringComparison.Ordinal)); }); }); });
            Run("SINGLE-FILE SINGLE-014 verbose reporters work", delegate { ForArchitectures(delegate(string arch, string exe) { ExternalResult r = RunExternal(exe, "--verbose", Path.GetTempPath()); Equal(0, r.ExitCode); True(r.Output.Contains("Collection Coverage:") && r.Output.Contains("SUMMARY")); }); });
            Run("SINGLE-FILE SINGLE-015 JSON export works", delegate { ForArchitectures(delegate(string arch, string exe) { string root = NewTempDirectory("json-" + arch); try { string report = Path.Combine(root, "report.json"); ExternalResult r = RunExternal(exe, "--json " + Quote(report), root); Equal(0, r.ExitCode); True(File.Exists(report)); AnalysisResult parsed = new JavaScriptSerializer { MaxJsonLength = Int32.MaxValue }.Deserialize<AnalysisResult>(File.ReadAllText(report)); Equal("1.1.0", parsed.Version); Equal(27, parsed.RulesEvaluated); } finally { DeleteDirectory(root); } }); });
            Run("SINGLE-FILE SINGLE-016 report sanitization works", delegate { ForArchitectures(delegate(string arch, string exe) { string root = NewTempDirectory("sanitize-" + arch); try { string report = Path.Combine(root, "report.json"), sanitized = Path.Combine(root, "sanitized.json"); Equal(0, RunExternal(exe, "--json " + Quote(report), root).ExitCode); Equal(0, RunExternal(exe, "--sanitize-report " + Quote(report) + " --json " + Quote(sanitized), root).ExitCode); True(File.Exists(sanitized)); } finally { DeleteDirectory(root); } }); });
            Run("SINGLE-FILE SINGLE-017 report inspection works", delegate { ForArchitectures(delegate(string arch, string exe) { string root = NewTempDirectory("inspect-" + arch); try { string report = Path.Combine(root, "report.json"); Equal(0, RunExternal(exe, "--json " + Quote(report), root).ExitCode); ExternalResult r = RunExternal(exe, "--inspect-report " + Quote(report), root); Equal(0, r.ExitCode); True(r.Output.Contains("schema: 1.6") && r.Output.Contains("valid: True")); } finally { DeleteDirectory(root); } }); });
            Run("SINGLE-FILE SINGLE-018 embedded rules equal source baseline", delegate { List<RuleDefinition> source = new RuleCatalog().Load(KnowledgePath("rules", "rules.xml")); Equal(RuleSignature(source), RuleSignature(rules)); AnalysisContext fixture = CorrelationFixtures.Create("R01"); List<Finding> a = engine.Evaluate(source, fixture), b = engine.Evaluate(rules, fixture); Equal(FindingSignature(a), FindingSignature(b)); });
            Run("SINGLE-FILE SINGLE-019 executable has no network assembly dependency", delegate { ForArchitectures(delegate(string arch, string exe) { string metadataStrings = Encoding.UTF8.GetString(File.ReadAllBytes(exe)); True(metadataStrings.IndexOf("System.Net", StringComparison.OrdinalIgnoreCase) < 0 && metadataStrings.IndexOf("System.Net.Http", StringComparison.OrdinalIgnoreCase) < 0); }); });
            Run("SINGLE-FILE SINGLE-020 embedded resources are not extracted", delegate { ForArchitectures(delegate(string arch, string exe) { WithIsolatedExe(arch, exe, false, delegate(string copy, string cwd, string root) { string before = DirectorySignature(Path.GetDirectoryName(copy)); Equal(0, RunExternal(copy, "--list-rules", cwd).ExitCode); Equal(0, RunExternal(copy, String.Empty, cwd).ExitCode); Equal(before, DirectorySignature(Path.GetDirectoryName(copy))); }); }); });
        }

        private static void RunCleanOutputScenarios()
        {
            Run("CLEAN-OUTPUT CLEAN-001 clean is accepted and default", delegate { CommandLineOptions a, b; string ea, eb; True(CommandLineParser.TryParse(new string[0], out a, out ea)); True(CommandLineParser.TryParse(new[] { "--clean" }, out b, out eb)); True(a.Clean && b.Clean && !a.Verbose && !b.Verbose); });
            Run("CLEAN-OUTPUT CLEAN-002 verbose overrides clean projection", delegate { CommandLineOptions o; string e; True(CommandLineParser.TryParse(new[] { "--clean", "--verbose" }, out o, out e)); True(o.Verbose && !o.Clean); });
            Run("CLEAN-OUTPUT CLEAN-003 UNKNOWN severity is evidence-backed", delegate { Finding f = One("PT-017", Tftp(TriState.Unknown, TriState.Yes, true, true)); Equal(EvaluationStatus.Unknown, f.Status); Equal(Severity.High, f.RuleSeverity); Equal(Severity.Informational, f.FindingSeverity); });
            Run("CLEAN-OUTPUT CLEAN-004 synthetic fixture has exact 171 unresolved checks", delegate { AnalysisResult r = AnalyzeCorrelation(Synthetic171Unknown()); Equal(171, r.Findings.Count(f => f.Status == EvaluationStatus.Unknown)); Equal(148, r.Findings.Count(f => f.RuleId == "PT-018" && f.Status == EvaluationStatus.Unknown)); Equal(20, r.Findings.Count(f => f.RuleId == "PT-017" && f.Status == EvaluationStatus.Unknown)); Equal(2, r.Findings.Count(f => f.RuleId == "PT-020" && f.Status == EvaluationStatus.Unknown)); Equal(1, r.Findings.Count(f => f.RuleId == "PT-019" && f.Status == EvaluationStatus.Unknown)); Equal(0, r.Findings.Count(f => f.Status == EvaluationStatus.Confirmed || f.Status == EvaluationStatus.Potential)); });
            Run("CLEAN-OUTPUT CLEAN-005 synthetic clean output aggregates noise", delegate { string text = Render(Synthetic171Unknown(), false); True(text.Contains("No actionable escalation paths verified.")); True(text.Contains("Diagnostics: 171 checks unresolved.")); True(text.Contains("PT-018 checks: 148 unresolved.")); True(!text.Contains("Status: UNKNOWN")); True(!text.Contains("[HIGH] PT-017") && !text.Contains("[HIGH] PT-018") && !text.Contains("[HIGH] PT-019") && !text.Contains("[HIGH] PT-020")); });
            Run("CLEAN-OUTPUT CLEAN-006 synthetic verbose preserves individual diagnostics", delegate { string text = Render(Synthetic171Unknown(), true); Equal(171, CountText(text, "Status: UNKNOWN")); True(text.Contains("Rule severity: HIGH | Finding severity: INFORMATIONAL")); });
            Run("CLEAN-OUTPUT CLEAN-007 JSON preserves UNKNOWN without false HIGH", delegate { string path = TempPath("clean-output-json"); try { AnalysisResult r = AnalyzeCorrelation(Synthetic171Unknown()); JsonReporter.Write(r, path); AnalysisResult parsed = new JavaScriptSerializer { MaxJsonLength = Int32.MaxValue }.Deserialize<AnalysisResult>(File.ReadAllText(path)); Equal("1.1.0", parsed.Version); Equal("1.6", parsed.SchemaVersion); Equal(171, parsed.Findings.Count(f => f.Status == EvaluationStatus.Unknown)); True(parsed.Findings.Where(f => f.Status == EvaluationStatus.Unknown).All(f => f.FindingSeverity == Severity.Informational && f.RuleSeverity == Severity.High)); } finally { if (File.Exists(path)) File.Delete(path); } });
            Run("CLEAN-OUTPUT POS-A writable LocalSystem service remains visible", delegate { AnalysisContext c = Fresh(); c.Services.Add(Service(TriState.Yes, TriState.No, TriState.No)); AnalysisResult r = AnalyzeCorrelation(c); Finding f = r.Findings.Single(x => x.RuleId == "PT-013" && x.Status == EvaluationStatus.Confirmed); True(ConsoleReporter.IsActionable(f)); string clean = RenderResult(r, false); True(clean.Contains("Service: SyntheticService") && clean.Contains("PT-013    : FILE_WRITE_DATA (CONFIRMED)")); });
            Run("CLEAN-OUTPUT POS-B disabled SYSTEM task stays conditioned", delegate { Finding f = One("PT-017", Tftp(TriState.Yes, TriState.Yes, false, true)); Equal(EvaluationStatus.Potential, f.Status); True(ConsoleReporter.IsActionable(f)); True(f.MissingConditions.Any(x => x.IndexOf("disabled", StringComparison.OrdinalIgnoreCase) >= 0)); });
            Run("CLEAN-OUTPUT POS-C modifiable SYSTEM task definition", delegate { AnalysisContext c = Tftp(TriState.No, TriState.Yes, true, true); c.Tasks[0].CanModify = TriState.Yes; Finding f = One("PT-018", c); Equal(EvaluationStatus.Confirmed, f.Status); True(ConsoleReporter.IsActionable(f)); });
            Run("CLEAN-OUTPUT POS-D referenced script permission", delegate { AnalysisContext c = Tftp(TriState.Yes, TriState.Yes, true, true); c.Tasks[0].Actions[0].Executable = "C:\\Backup\\job.ps1"; Finding f = One("PT-019", c); Equal(EvaluationStatus.Confirmed, f.Status); True(ConsoleReporter.IsActionable(f)); });
            Run("CLEAN-OUTPUT POS-D2 interpreter script is evaluated", delegate { AnalysisContext c = Tftp(TriState.No, TriState.Yes, true, true); ScheduledTaskAction a = c.Tasks[0].Actions[0]; a.Executable = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"; a.Arguments = "-NoProfile -File \"C:\\Backup\\job.ps1\""; a.ReferencedScript = "C:\\Backup\\job.ps1"; a.ScriptPermission = new SecurityPermission { Target = a.ReferencedScript, CanWrite = TriState.Yes }; Finding f = One("PT-019", c); Equal(EvaluationStatus.Confirmed, f.Status); Equal(a.ReferencedScript, f.Target); });
            Run("CLEAN-OUTPUT POS-E relative action needs controllable candidate", delegate { AnalysisContext c = RelativeTask(TriState.Yes); Finding f = One("PT-020", c); Equal(EvaluationStatus.Confirmed, f.Status); True(f.Evidence.Any(e => e.Kind == "SearchCandidate" && e.Positive)); });
            Run("CLEAN-OUTPUT POS-F disabled privilege is conditioned, not HIGH", delegate { AnalysisContext c = Build("PT-001", "positive"); c.Token.Privileges[0].Enabled = false; c.Token.Privileges[0].State = TokenPrivilegeState.Disabled; Finding f = One("PT-001", c); Equal(EvaluationStatus.Potential, f.Status); Equal(Severity.Low, f.FindingSeverity); True(ConsoleReporter.IsActionable(f)); });
            Run("CLEAN-OUTPUT NEG-G same user is not escalation", delegate { Finding f = One("PT-017", Tftp(TriState.Yes, TriState.No, true, true)); Equal(EvaluationStatus.RuledOut, f.Status); True(!ConsoleReporter.IsActionable(f)); });
            Run("CLEAN-OUTPUT NOISE-H 200 unknown and one valid task", delegate { AnalysisContext c = TaskAclNoise(200); ScheduledTaskInfo valid = Task("\\Valid", TriState.Yes, TriState.Yes); valid.Actions.Clear(); c.Tasks.Add(valid); AnalysisResult r = AnalyzeCorrelation(c); Equal(200, r.Findings.Count(f => f.RuleId == "PT-018" && f.Status == EvaluationStatus.Unknown)); Equal(1, r.Findings.Count(f => f.RuleId == "PT-018" && f.Status == EvaluationStatus.Confirmed)); string text = RenderResult(r, false); Equal(1, CountText(text, "PT-018 - Weak Scheduled Task Permissions")); True(text.Contains("PT-018 checks: 200 unresolved.")); });
            Run("CLEAN-OUTPUT NEG relative name alone does not confirm PT-020", delegate { Finding f = One("PT-020", RelativeTask(TriState.Unknown)); Equal(EvaluationStatus.Unknown, f.Status); Equal(Severity.Informational, f.FindingSeverity); True(!ConsoleReporter.IsActionable(f)); });
            Run("CLEAN-OUTPUT EVIDENCE exports synthetic before/after comparison", ExportCleanOutputEvidence);
            Run("CLEAN-OUTPUT SINGLE x64/x86 are isolated embedded executables", delegate { foreach (string arch in new[] { "x64", "x86" }) { string exe = CleanOutputDistributionExe(arch); RequireOfficialDistribution(exe); True(File.Exists(exe)); ExternalResult list = RunExternal(exe, "--list-rules", Path.GetTempPath()); Equal(0, list.ExitCode); Equal(27, RuleLines(list.Output).Count); WithIsolatedExe("clean-output-" + arch, exe, true, delegate(string copy, string cwd, string root) { ExternalResult run = RunExternal(copy, "--clean", cwd); Equal(0, run.ExitCode); True(run.Output.Contains("PrivTrace v1.1.0")); }); } });
        }

        private static void RunSoftwareProfileScenarios()
        {
            List<SoftwareProfile> profiles = new SoftwareProfileCatalog().LoadEmbedded();
            Run("SOFTWARE-PROFILE PROFILE-001 embedded curated catalog", delegate { Equal(25, profiles.Count); Equal(25, profiles.Select(p => p.ProfileId).Distinct(StringComparer.OrdinalIgnoreCase).Count()); True(profiles.All(p => p.ReferenceIds.Count > 0 && p.RelevantExistingRules.All(id => rules.Any(r => r.Id == id)))); });
            Run("SOFTWARE-PROFILE PROFILE-002 embedded bytes equal source", delegate { string source = File.ReadAllText(Path.Combine(ProjectRoot(), "data", "knowledge", "software", "profiles.json")); using (Stream stream = typeof(SoftwareProfileCatalog).Assembly.GetManifestResourceStream(SoftwareProfileCatalog.ResourceName)) using (StreamReader reader = new StreamReader(stream)) Equal(source, reader.ReadToEnd()); });

            Run("SOFTWARE-PROFILE SW01 XAMPP Monsters", delegate { AnalysisResult r = AnalyzeSoftware(SoftwareFixture(@"C:\xampp\apache\bin\httpd.exe", 1101, "Apache HTTP Server", "Apache Software Foundation", SignatureStatus.Absent, null)); SoftwareObservation s = r.Context.Software.Single(); Equal("SW-XAMPP", s.ProfileId); Equal("NOT_VERIFIED", s.EscalationStatus); Equal(0, r.Findings.Count(f => f.RuleId == "PT-013" && f.Status == EvaluationStatus.Confirmed)); });
            Run("SOFTWARE-PROFILE SW02 XAMPP process grouping", delegate { AnalysisContext c = SoftwareFixture(@"C:\xampp\apache\bin\httpd.exe", 1101, "Apache HTTP Server", "Apache Software Foundation", SignatureStatus.Absent, null); c.Processes.Add(SoftwareProcess(@"C:\xampp\apache\bin\httpd.exe", 1102, "Apache HTTP Server", "Apache Software Foundation", SignatureStatus.Absent, null)); AnalysisResult r = AnalyzeSoftware(c); Equal(1, r.Context.Software.Count); Equal(2, r.Context.Software[0].ProcessIds.Count); });
            Run("SOFTWARE-PROFILE SW03 XAMPP properties.ini version source", TestXamppPropertiesVersion);
            Run("SOFTWARE-PROFILE SW04 XAMPP absent properties.ini", TestXamppAbsentProperties);
            Run("SOFTWARE-PROFILE SW05 TeamViewer", delegate { SoftwareObservation s = AnalyzeSoftware(SoftwareFixture(@"C:\Program Files\TeamViewer\TeamViewer.exe", 1201, "TeamViewer", "TeamViewer Germany GmbH", SignatureStatus.Valid, "CN=TeamViewer Germany GmbH")).Context.Software.Single(); Equal("SW-TEAMVIEWER", s.ProfileId); Equal("NOT_VERIFIED", s.EscalationStatus); });
            Run("SOFTWARE-PROFILE SW06 AnyDesk", delegate { SoftwareObservation s = AnalyzeSoftware(SoftwareFixture(@"C:\Program Files (x86)\AnyDesk\AnyDesk.exe", 1202, "AnyDesk", "AnyDesk Software GmbH", SignatureStatus.Valid, "CN=AnyDesk Software GmbH")).Context.Software.Single(); Equal("SW-ANYDESK", s.ProfileId); Equal("NOT_VERIFIED", s.EscalationStatus); });
            Run("SOFTWARE-PROFILE SW07 protected privileged Veyon", delegate { AnalysisContext c = SoftwareFixture(@"C:\Program Files\Veyon\veyon-service.exe", 1301, "Veyon", "Veyon Solutions", SignatureStatus.Valid, "CN=Veyon Solutions"); AddSoftwareService(c, c.Processes[0], "VeyonService", "LocalSystem", TriState.No); AnalysisResult r = AnalyzeSoftware(c); SoftwareObservation s = r.Context.Software.Single(); Equal("SW-VEYON", s.ProfileId); True(s.PrivilegedContextObserved); Equal("NOT_VERIFIED", s.EscalationStatus); Equal(0, s.ActiveRuleIds.Count); });
            Run("SOFTWARE-PROFILE SW08 writable privileged Veyon", delegate { AnalysisContext c = SoftwareFixture(@"C:\Program Files\Veyon\veyon-service.exe", 1302, "Veyon", "Veyon Solutions", SignatureStatus.Valid, "CN=Veyon Solutions"); AddSoftwareService(c, c.Processes[0], "VeyonService", "LocalSystem", TriState.Yes); AnalysisResult r = AnalyzeSoftware(c); Equal(EvaluationStatus.Confirmed, r.Findings.Single(f => f.RuleId == "PT-013").Status); SoftwareObservation software = r.Context.Software.Single(); True(software.ActiveRuleIds.Contains("PT-013")); Equal("EXISTING_RULE_VERIFIED", software.EscalationStatus); Equal(100, software.InvestigationPriority); string clean = RenderResult(r, false); True(clean.Contains("Service: VeyonService") && clean.Contains("PT-013    : FILE_WRITE_DATA (CONFIRMED)") && clean.Contains("Escalation : PT-013") && !clean.Contains("Rules      :")); });
            Run("SOFTWARE-PROFILE SW09 protected BarracudaDrive", delegate { AnalysisContext c = SoftwareFixture(@"C:\Program Files\BarracudaDrive\BarracudaDrive.exe", 1401, "BarracudaDrive", "Real Time Logic", SignatureStatus.Absent, null); AddSoftwareService(c, c.Processes[0], "BarracudaDrive", "LocalSystem", TriState.No); AnalysisResult r = AnalyzeSoftware(c); Equal("SW-BARRACUDADRIVE", r.Context.Software.Single().ProfileId); Equal("NOT_VERIFIED", r.Context.Software.Single().EscalationStatus); });
            Run("SOFTWARE-PROFILE SW10 writable BarracudaDrive", delegate { AnalysisContext c = SoftwareFixture(@"C:\Program Files\BarracudaDrive\BarracudaDrive.exe", 1402, "BarracudaDrive", "Real Time Logic", SignatureStatus.Absent, null); AddSoftwareService(c, c.Processes[0], "BarracudaDrive", "LocalSystem", TriState.Yes); AnalysisResult r = AnalyzeSoftware(c); Equal(EvaluationStatus.Confirmed, r.Findings.Single(f => f.RuleId == "PT-013").Status); True(r.Context.Software.Single().ActiveRuleIds.Contains("PT-013")); });
            Run("SOFTWARE-PROFILE SW11 MySQL", delegate { Equal("SW-MYSQL", AnalyzeSoftware(SoftwareFixture(@"C:\Program Files\MySQL\MySQL Server 8.0\bin\mysqld.exe", 1501, "MySQL Server", "Oracle Corporation", SignatureStatus.Valid, "CN=Oracle Corporation")).Context.Software.Single().ProfileId); });
            Run("SOFTWARE-PROFILE SW12 PostgreSQL", delegate { AnalysisContext c = SoftwareFixture(@"C:\Program Files\PostgreSQL\16\bin\postgres.exe", 1502, "PostgreSQL", "PostgreSQL Global Development Group", SignatureStatus.Absent, null); c.Processes.Add(SoftwareProcess(@"C:\Program Files\PostgreSQL\16\bin\postgres.exe", 1503, "PostgreSQL", "PostgreSQL Global Development Group", SignatureStatus.Absent, null)); SoftwareObservation s = AnalyzeSoftware(c).Context.Software.Single(); Equal("SW-POSTGRESQL", s.ProfileId); Equal(2, s.ProcessIds.Count); });
            Run("SOFTWARE-PROFILE SW13 legitimate Windows process classification", delegate { AnalysisContext c = SoftwareFixture(@"C:\Windows\System32\svchost.exe", 1601, "Microsoft Windows Operating System", "Microsoft Corporation", SignatureStatus.Valid, "CN=Microsoft Windows"); AnalysisResult r = AnalyzeSoftware(c); Equal(SoftwareClassification.WindowsComponent, c.Processes[0].FileIdentity.SoftwareClassification); Equal(0, r.Context.Software.Count); });
            Run("SOFTWARE-PROFILE SW14 spoofed svchost name", delegate { AnalysisContext c = SoftwareFixture(@"C:\Users\Mike\Downloads\svchost.exe", 1602, null, null, SignatureStatus.Absent, null); AnalysisResult r = AnalyzeSoftware(c); Equal(SoftwareClassification.Unclassified, c.Processes[0].FileIdentity.SoftwareClassification); Equal(0, r.Context.Software.Count); Equal(0, r.Findings.Count(f => f.Status == EvaluationStatus.Confirmed)); });
            Run("SOFTWARE-PROFILE SW15 unknown process stays out of CLEAN", delegate { AnalysisContext c = SoftwareFixture(@"C:\Tools\unknown.exe", 1603, null, null, SignatureStatus.Unknown, null); Equal(0, AnalyzeSoftware(c).Context.Software.Count); });
            Run("SOFTWARE-PROFILE SW16 unprofiled privileged third party", delegate { AnalysisContext c = SoftwareFixture(@"D:\Vendor\agent-host.exe", 1604, "Vendor Agent", "Example Vendor Ltd", SignatureStatus.Valid, "CN=Example Vendor Ltd"); AddSoftwareService(c, c.Processes[0], "VendorAgent", "LocalSystem", TriState.No); SoftwareObservation s = AnalyzeSoftware(c).Context.Software.Single(); Equal("HEURISTIC_IDENTIFICATION", s.IdentificationStatus); Equal(SoftwareClassification.ThirdPartySoftware, s.Classification); Equal("NOT_VERIFIED", s.EscalationStatus); });
            Run("SOFTWARE-PROFILE SW17 invalid signature retained", delegate { AnalysisContext c = SoftwareFixture(@"C:\Program Files\TeamViewer\TeamViewer.exe", 1605, "TeamViewer", "TeamViewer Germany GmbH", SignatureStatus.Invalid, "CN=TeamViewer Germany GmbH"); AnalysisResult r = AnalyzeSoftware(c); Equal(SignatureStatus.Invalid, r.Context.Software.Single().SignatureStatus); Equal(0, r.Findings.Count(f => f.Status == EvaluationStatus.Confirmed)); });
            Run("SOFTWARE-PROFILE SW18 unknown signature retained", delegate { AnalysisContext c = SoftwareFixture(@"C:\Program Files (x86)\AnyDesk\AnyDesk.exe", 1606, "AnyDesk", "AnyDesk Software GmbH", SignatureStatus.Unknown, null); Equal(SignatureStatus.Unknown, AnalyzeSoftware(c).Context.Software.Single().SignatureStatus); });
            Run("SOFTWARE-PROFILE SW19 absent metadata remains conservative", delegate { AnalysisContext c = SoftwareFixture(@"C:\Tools\nameless.exe", 1607, null, null, SignatureStatus.Absent, null); AnalyzeSoftware(c); Equal(SoftwareClassification.Unclassified, c.Processes[0].FileIdentity.SoftwareClassification); Equal(0, c.Software.Count); });
            Run("SOFTWARE-PROFILE SW20 product with multiple services", delegate { AnalysisContext c = SoftwareFixture(@"C:\Program Files\Veyon\veyon-service.exe", 1701, "Veyon", "Veyon Solutions", SignatureStatus.Valid, "CN=Veyon Solutions"); WindowsProcess second = SoftwareProcess(@"C:\Program Files\Veyon\veyon-server.exe", 1702, "Veyon", "Veyon Solutions", SignatureStatus.Valid, "CN=Veyon Solutions"); c.Processes.Add(second); AddSoftwareService(c, c.Processes[0], "VeyonService", "LocalSystem", TriState.No); AddSoftwareService(c, second, "VeyonSession", @"LAB\operator", TriState.No); SoftwareObservation s = AnalyzeSoftware(c).Context.Software.Single(); Equal(2, s.ProcessIds.Count); Equal(2, s.ServiceNames.Count); });
            Run("SOFTWARE-PROFILE SW21 Windows classification does not suppress PT rules", delegate { AnalysisContext c = SoftwareFixture(@"C:\Windows\System32\inetsrv\w3wp.exe", 1801, "Microsoft Internet Information Services", "Microsoft Corporation", SignatureStatus.Valid, "CN=Microsoft Windows"); AddSoftwareService(c, c.Processes[0], "W3SVC", "LocalSystem", TriState.Yes); AnalysisResult r = AnalyzeSoftware(c); Equal(SoftwareClassification.WindowsComponent, c.Processes[0].FileIdentity.SoftwareClassification); Equal(EvaluationStatus.Confirmed, r.Findings.Single(f => f.RuleId == "PT-013").Status); True(r.Context.Software.Single().ActiveRuleIds.Contains("PT-013")); });
            Run("SOFTWARE-PROFILE SW22 high-volume signal stays compact", TestSoftwareHighVolume);

            Run("SOFTWARE-PROFILE FP01 CompanyName Microsoft is not a valid signature", delegate { AnalysisContext c = SoftwareFixture(@"C:\Tools\vendor.exe", 1901, "Microsoft Example", "Microsoft Corporation", SignatureStatus.Absent, null); AnalyzeSoftware(c); Equal(SoftwareClassification.Unclassified, c.Processes[0].FileIdentity.SoftwareClassification); });
            Run("SOFTWARE-PROFILE FP02 System32 is not an identity proof", delegate { AnalysisContext c = SoftwareFixture(@"C:\Windows\System32\customservice.exe", 1902, null, null, SignatureStatus.Absent, null); AnalyzeSoftware(c); Equal(SoftwareClassification.Unclassified, c.Processes[0].FileIdentity.SoftwareClassification); });
            Run("SOFTWARE-PROFILE FP03 Program Files does not mean third party", delegate { AnalysisContext c = SoftwareFixture(@"C:\Program Files\Microsoft\Example.exe", 1903, "Microsoft Windows Component", "Microsoft Corporation", SignatureStatus.Valid, "CN=Microsoft Windows"); AnalyzeSoftware(c); Equal(SoftwareClassification.WindowsComponent, c.Processes[0].FileIdentity.SoftwareClassification); });
            Run("SOFTWARE-PROFILE FP04 executable name alone does not identify product", delegate { Equal(0, AnalyzeSoftware(SoftwareFixture(@"C:\Users\Mike\Downloads\AnyDesk.exe", 1904, null, null, SignatureStatus.Absent, null)).Context.Software.Count); });
            Run("SOFTWARE-PROFILE FP05 old ProductVersion is not a CVE", delegate { AnalysisContext c = SoftwareFixture(@"C:\Program Files\TeamViewer\TeamViewer.exe", 1905, "TeamViewer", "TeamViewer Germany GmbH", SignatureStatus.Valid, "CN=TeamViewer Germany GmbH"); c.Processes[0].FileIdentity.ProductVersion = "1.0.0"; AnalysisResult r = AnalyzeSoftware(c); Equal(0, r.Findings.Count(f => f.Status == EvaluationStatus.Confirmed)); Equal("NOT_VERIFIED", r.Context.Software.Single().EscalationStatus); });
            Run("SOFTWARE-PROFILE FP06 third party does not imply escalation", delegate { AnalysisResult r = AnalyzeSoftware(SoftwareFixture(@"C:\Program Files (x86)\AnyDesk\AnyDesk.exe", 1906, "AnyDesk", "AnyDesk Software GmbH", SignatureStatus.Valid, "CN=AnyDesk Software GmbH")); Equal(0, r.Context.Software.Single().ActiveRuleIds.Count); });
            Run("SOFTWARE-PROFILE FP07 same-user service is not escalation", delegate { AnalysisContext c = SoftwareFixture(@"C:\Program Files\Veyon\veyon-service.exe", 1907, "Veyon", "Veyon Solutions", SignatureStatus.Valid, "CN=Veyon Solutions"); AddSoftwareService(c, c.Processes[0], "VeyonService", @"LAB\operator", TriState.Yes); AnalysisResult r = AnalyzeSoftware(c); Equal(0, r.Findings.Count(f => f.RuleId == "PT-013" && f.Status == EvaluationStatus.Confirmed)); });
            Run("SOFTWARE-PROFILE FP08 running process does not invent service", delegate { SoftwareObservation s = AnalyzeSoftware(SoftwareFixture(@"C:\xampp\apache\bin\httpd.exe", 1908, "Apache HTTP Server", "Apache Software Foundation", SignatureStatus.Absent, null)).Context.Software.Single(); Equal(0, s.ServiceNames.Count); });
            Run("SOFTWARE-PROFILE FP09 installed service without process is not active software", delegate { AnalysisContext c = Fresh(); c.Services.Add(Service(TriState.No, TriState.No, TriState.No)); Equal(0, AnalyzeSoftware(c).Context.Software.Count); });
            Run("SOFTWARE-PROFILE FP10 same executable name does not merge installations", delegate { AnalysisContext c = SoftwareFixture(@"C:\Program Files\TeamViewer\TeamViewer.exe", 1910, "TeamViewer", "TeamViewer Germany GmbH", SignatureStatus.Valid, "CN=TeamViewer Germany GmbH"); c.Processes.Add(SoftwareProcess(@"D:\Portable\TeamViewer\TeamViewer.exe", 1911, "TeamViewer", "TeamViewer Germany GmbH", SignatureStatus.Valid, "CN=TeamViewer Germany GmbH")); Equal(2, AnalyzeSoftware(c).Context.Software.Count); });
            Run("SOFTWARE-PROFILE FP11 unsigned is not malware or escalation", delegate { AnalysisResult r = AnalyzeSoftware(SoftwareFixture(@"C:\xampp\apache\bin\httpd.exe", 1912, "Apache HTTP Server", "Apache Software Foundation", SignatureStatus.Absent, null)); Equal(SignatureStatus.Absent, r.Context.Software.Single().SignatureStatus); Equal(0, r.Findings.Count(f => f.Status == EvaluationStatus.Confirmed)); });
            Run("SOFTWARE-PROFILE FP12 unknown ACL is not writable", delegate { AnalysisContext c = SoftwareFixture(@"C:\Program Files\Veyon\veyon-service.exe", 1913, "Veyon", "Veyon Solutions", SignatureStatus.Valid, "CN=Veyon Solutions"); AddSoftwareService(c, c.Processes[0], "VeyonService", "LocalSystem", TriState.Unknown); AnalysisResult r = AnalyzeSoftware(c); Equal(EvaluationStatus.Unknown, r.Findings.Single(f => f.RuleId == "PT-013").Status); Equal("NOT_VERIFIED", r.Context.Software.Single().EscalationStatus); });
            Run("SOFTWARE-PROFILE FP13 untrusted metadata alone stays out of CLEAN", delegate { AnalysisContext c = SoftwareFixture(@"C:\Downloads\AnyDesk.exe", 1914, "AnyDesk", "AnyDesk Software GmbH", SignatureStatus.Absent, null); Equal(0, AnalyzeSoftware(c).Context.Software.Count); });

            Run("SOFTWARE-PROFILE SIGNATURE live verifier is offline and conservative", delegate { FileIdentityMetadata identity = new FileIdentityMetadata(); AuthenticodeVerifier.Verify(typeof(TestRunner).Assembly.Location, identity); True(identity.SignatureStatus == SignatureStatus.Absent || identity.SignatureStatus == SignatureStatus.Invalid || identity.SignatureStatus == SignatureStatus.Unknown); True(identity.SignatureStatus != SignatureStatus.Valid); });
            Run("SOFTWARE-PROFILE CLEAN interesting software is concise", delegate { AnalysisResult r = AnalyzeSoftware(SoftwareFixture(@"C:\xampp\apache\bin\httpd.exe", 2001, "Apache HTTP Server", "Apache Software Foundation", SignatureStatus.Absent, null)); string text = RenderResult(r, false); True(text.Contains("INTERESTING SOFTWARE") && text.Contains("Apache HTTP Server / XAMPP") && text.Contains(@"Process    : C:\xampp\apache\bin\httpd.exe") && text.Contains("Source     : UNKNOWN") && text.Contains("Escalation : NOT VERIFIED")); True(!text.Contains("Classification:") && !text.Contains("TRACE:")); });
            Run("SOFTWARE-PROFILE VERBOSE preserves software evidence", delegate { AnalysisResult r = AnalyzeSoftware(SoftwareFixture(@"C:\xampp\apache\bin\httpd.exe", 2002, "Apache HTTP Server", "Apache Software Foundation", SignatureStatus.Absent, null)); string text = RenderResult(r, true); True(text.Contains("Classification: THIRD_PARTY_SOFTWARE") && text.Contains("IdentificationSignal") && text.Contains("TRACE:")); });
            Run("SOFTWARE-PROFILE JSON preserves PE signature product and PIDs", TestSoftwareJson);
            Run("SOFTWARE-PROFILE sanitization covers software paths and identities", TestSoftwareSanitization);
            Run("SOFTWARE-PROFILE scheduled-task relationship remains configured", delegate { AnalysisContext c = SoftwareFixture(@"C:\Program Files\TeamViewer\TeamViewer.exe", 2203, "TeamViewer", "TeamViewer Germany GmbH", SignatureStatus.Valid, "CN=TeamViewer Germany GmbH"); ScheduledTaskInfo task = Task("\\TeamViewer Update", TriState.No, TriState.Yes); task.Actions.Add(Action(c.Processes[0].ImagePath, false, TriState.No)); c.Tasks.Add(task); SoftwareObservation s = AnalyzeSoftware(c).Context.Software.Single(); True(s.PrivilegedContextObserved); True(s.Evidence.Any(e => e.Kind == "AssociatedScheduledTask" && e.State == RelationshipState.Configured)); });
            Run("SOFTWARE-PROFILE TRACE engine observations", ExportSoftwareProfileSoftwareTraces);
            Run("SOFTWARE-PROFILE SINGLE x64/x86 embedded profiles", delegate { foreach (string arch in new[] { "x64", "x86" }) { string exe = SoftwareProfileDistributionExe(arch); RequireOfficialDistribution(exe); True(File.Exists(exe)); ExternalResult list = RunExternal(exe, "--list-rules", Path.GetTempPath()); Equal(0, list.ExitCode); Equal(27, RuleLines(list.Output).Count); WithIsolatedExe("software-profile-" + arch, exe, true, delegate(string copy, string cwd, string root) { ExternalResult run = RunExternal(copy, "--clean", cwd); Equal(0, run.ExitCode); True(run.Output.Contains("PrivTrace v1.1.0")); }); } });

            Run("VERSION-PROVENANCE VP01 XAMPP controlled standard-layout root valid properties", delegate { TestXamppFixture("xampp", "8.2.12-0", "8.2.12-0", null); });
            Run("VERSION-PROVENANCE VP02 simulated D drive resolver plus real nested-root reader", TestVp02OtherDrive);
            Run("VERSION-PROVENANCE VP03 XAMPP path with spaces", delegate { TestXamppFixture(Path.Combine("Program Files", "xampp"), "8.0.30-1", "8.0.30-1", null); });
            Run("VERSION-PROVENANCE VP04 properties absent", TestVp04Absent);
            Run("VERSION-PROVENANCE VP05 properties unreadable", TestVp05Unreadable);
            Run("VERSION-PROVENANCE VP06 malformed properties version", delegate { TestXamppFixture("xampp", "not-a-version", null, "INVALID_DATA"); });
            Run("VERSION-PROVENANCE VP07 httpd without XAMPP evidence", delegate { Equal(0, AnalyzeSoftware(SoftwareFixture(@"C:\Tools\httpd.exe", 5607, "Apache HTTP Server", "Apache Software Foundation", SignatureStatus.Absent, null)).Context.Software.Count); });
            Run("VERSION-PROVENANCE VP08 independent Apache is not XAMPP", delegate { SoftwareObservation s = AnalyzeSoftware(SoftwareFixture(@"C:\Apache24\bin\httpd.exe", 5608, "Apache HTTP Server", "Apache Software Foundation", SignatureStatus.Absent, null)).Context.Software.Single(); Equal("SW-APACHE", s.ProfileId); });
            Run("VERSION-PROVENANCE VP09 fixture-independent XAMPP version", delegate { TestXamppFixture("xampp", "9.7.4-6", "9.7.4-6", null); });
            Run("VERSION-PROVENANCE VP10 two XAMPP installations", TestVp10TwoInstallations);
            Run("VERSION-PROVENANCE VP11 PE and package versions remain distinct", TestVp11VersionConflict);
            Run("VERSION-PROVENANCE VP12 real reader rejects another installation config", TestVp12ExternalConfigReader);
            Run("VERSION-PROVENANCE VP13 static catalog version rejected", TestVp13StaticCatalogVersion);
            Run("VERSION-PROVENANCE VP14 UNKNOWN after all authorized strategies fail", TestVp14AllStrategiesUnknown);
            Run("VERSION-PROVENANCE VP15 JSON preserves exact provenance", TestVp15JsonProvenance);
            Run("VERSION-PROVENANCE VP16 CLEAN prints concise observed version", TestVp16CleanVersion);
            Run("VERSION-PROVENANCE VP17 real junction rejected", TestVp17RealJunction);
            Run("VERSION-PROVENANCE verbose version provenance includes confidence and origin", TestVerboseVersionProvenance);
            Run("VERSION-PROVENANCE controlled RegistryKey uninstall reader", TestControlledUninstallRegistryReader);
            Run("VERSION-PROVENANCE imported fixture evidence is unverified", TestImportedEvidenceOrigin);
            Run("VERSION-PROVENANCE CLEAN integration separates XAMPP and VMware Tools", TestCleanXamppAndVmware);
            Run("VERSION-PROVENANCE CO01 CLEAN XAMPP process version source", TestCo01CleanXampp);
            Run("VERSION-PROVENANCE CO02 CLEAN PE version source", TestCo02CleanPeSource);
            Run("VERSION-PROVENANCE CO03 CLEAN registry version source", TestCo03CleanRegistrySource);
            Run("VERSION-PROVENANCE CO04 CLEAN unknown version has no source", TestCo04CleanUnknownVersion);
            Run("VERSION-PROVENANCE CO05 CLEAN groups processes and JSON retains paths", TestCo05MultipleProcesses);
            Run("VERSION-PROVENANCE CO06 CLEAN imported evidence is not live", TestCo06ImportedEvidence);
            Run("VERSION-PROVENANCE CO07 CLEAN regression high signal", TestCo07CleanRegression);
            Run("VERSION-PROVENANCE SINGLE x64/x86 embedded profiles", TestVersionProvenanceDistributions);
        }

        private static void RunServiceDiscoveryScenarios()
        {
            Run("SERVICE-DISCOVERY FISH01 GlassFish service discovery", TestFish01);
            Run("SERVICE-DISCOVERY FISH02 SynaMan service discovery", TestFish02);
            Run("SERVICE-DISCOVERY FISH03 TotalAV infrastructure classification", TestFish03);
            Run("SERVICE-DISCOVERY FISH04 VMware regression", TestFish04);
            Run("SERVICE-DISCOVERY FISH05 PT-013 domain1 semantics", delegate { TestFishPt013(FishService("domain1", @"C:\glassfish4\glassfish\domains\domain1\bin\domain1Service.exe", "GlassFish Server", "Oracle", "Running", TriState.No, TriState.Yes, TriState.Yes, TriState.No, TriState.No, "LocalSystem"), false); });
            Run("SERVICE-DISCOVERY FISH06 PT-013 SynaMan conditional execution", delegate { TestFishPt013(FishService("SynaMan", @"C:\SynaMan\SynaMan.exe", "SynaMan", "Synametrics Technologies", "Running", TriState.No, TriState.Yes, TriState.Yes, TriState.No, TriState.No, "LocalSystem"), false); });
            Run("SERVICE-DISCOVERY FISH07 PT-013 SecurityService start right", delegate { TestFishPt013(FishService("SecurityService", @"C:\Program Files (x86)\TotalAV\SecurityService.exe", "TotalAV", "Total Security Limited", "Running", TriState.Yes, TriState.Yes, TriState.Yes, TriState.No, TriState.No, "LocalSystem"), true); });
            Run("SERVICE-DISCOVERY FISH08 PT-016 directory create is conditional", TestFish08);
            Run("SERVICE-DISCOVERY FISH09 PT-016 replacement ACL", TestFish09);
            Run("SERVICE-DISCOVERY FISH10 service grouping retains findings", TestFish10);
            Run("SERVICE-DISCOVERY FISH11 shared executable keeps services distinct", TestFish11);
            Run("SERVICE-DISCOVERY FISH12 same product different installations", TestFish12);
            Run("SERVICE-DISCOVERY FISH13 version unknown", TestFish13);
            Run("SERVICE-DISCOVERY FISH14 PE version provenance", TestFish14);
            Run("SERVICE-DISCOVERY FISH15 service without process", TestFish15);
            Run("SERVICE-DISCOVERY FISH16 exact service PID correlation", TestFish16);
            Run("SERVICE-DISCOVERY FISH17 ACL unknown", TestFish17);
            Run("SERVICE-DISCOVERY FISH18 runtime protection unknown", TestFish18);
            Run("SERVICE-DISCOVERY FISH19 Monsters XAMPP regression", TestXamppPropertiesVersion);
            Run("SERVICE-DISCOVERY FISH20 mixed Fish environment", TestFish20);
            Run("SERVICE-DISCOVERY EDGE-A privileged protected executable", delegate { WindowsService s = FishService("SynaMan", @"C:\SynaMan\SynaMan.exe", "SynaMan", "Synametrics", "Running", TriState.No, TriState.No, TriState.No, TriState.No, TriState.No, "LocalSystem"); Equal(EvaluationStatus.RuledOut, FishFinding(AnalyzeSoftware(FishContext(s)), "PT-013", s.Name).Status); });
            Run("SERVICE-DISCOVERY EDGE-B non-privileged service", delegate { WindowsService s = FishService("SynaMan", @"C:\SynaMan\SynaMan.exe", "SynaMan", "Synametrics", "Running", TriState.Yes, TriState.Yes, TriState.Yes, TriState.Yes, TriState.Yes, @"LAB\operator"); Equal(EvaluationStatus.RuledOut, AnalyzeSoftware(FishContext(s)).Findings.First(f => f.RuleId == "PT-013").Status); });
            Run("SERVICE-DISCOVERY EDGE-C directory writable executable protected", delegate { WindowsService s = FishService("SynaMan", @"C:\SynaMan\SynaMan.exe", "SynaMan", "Synametrics", "Running", TriState.No, TriState.No, TriState.Yes, TriState.No, TriState.No, "LocalSystem"); AnalysisResult r = AnalyzeSoftware(FishContext(s)); Equal(EvaluationStatus.RuledOut, FishFinding(r, "PT-013", s.Name).Status); Equal(EvaluationStatus.Potential, FishFinding(r, "PT-016", s.Name).Status); });
            Run("SERVICE-DISCOVERY EDGE-D executable writable directory protected", delegate { WindowsService s = FishService("SynaMan", @"C:\SynaMan\SynaMan.exe", "SynaMan", "Synametrics", "Running", TriState.No, TriState.Yes, TriState.No, TriState.No, TriState.No, "LocalSystem"); AnalysisResult r = AnalyzeSoftware(FishContext(s)); Equal(EvaluationStatus.Confirmed, FishFinding(r, "PT-013", s.Name).Status); Equal(EvaluationStatus.RuledOut, FishFinding(r, "PT-016", s.Name).Status); });
            Run("SERVICE-DISCOVERY EDGE-E FILE_ADD_FILE without delete-child", TestFish08);
            Run("SERVICE-DISCOVERY EDGE-F WRITE_DAC distinct", TestEdgeWriteDac);
            Run("SERVICE-DISCOVERY EDGE-G disabled service conditioned", TestEdgeDisabled);
            Run("SERVICE-DISCOVERY EDGE-H running without restart right", delegate { WindowsService s = FishService("SynaMan", @"C:\SynaMan\SynaMan.exe", "SynaMan", "Synametrics", "Running", TriState.No, TriState.Yes, TriState.No, TriState.No, TriState.No, "LocalSystem"); Finding f = FishFinding(AnalyzeSoftware(FishContext(s)), "PT-013", s.Name); Equal("CONDITIONAL_EXECUTION", f.ExecutionState); Equal(TriState.No, s.CanStart); });
            Run("SERVICE-DISCOVERY EDGE-I service ImagePath arguments", TestEdgeArguments);
            Run("SERVICE-DISCOVERY EDGE-J service environment path", TestEdgeEnvironment);
            Run("SERVICE-DISCOVERY EDGE-K missing configured executable", TestEdgeMissing);
            Run("SERVICE-DISCOVERY EDGE-L unquoted service path", delegate { AnalysisContext c = Fresh(); WindowsService s = Service(TriState.No, TriState.No, TriState.No); s.UnquotedCandidates.Add(@"C:\Program.exe"); s.UnquotedCandidatePermissions.Add(new SecurityPermission { CanWrite = TriState.Yes }); c.Services.Add(s); Equal(EvaluationStatus.Confirmed, One("PT-015", c).Status); });
            Run("SERVICE-DISCOVERY EDGE-M UNC service path", TestEdgeUnc);
            Run("SERVICE-DISCOVERY EDGE-N wrapper does not infer child process", TestEdgeWrapper);
            Run("SERVICE-DISCOVERY EDGE-O runtime protection unknown", TestFish18);
            Run("SERVICE-DISCOVERY INST01 verified registered SynaMan", TestInstalled01);
            Run("SERVICE-DISCOVERY INST02 name-only wrong publisher rejected", TestInstalled02);
            Run("SERVICE-DISCOVERY INST03 unknown publisher with corroborated path", TestInstalled03);
            Run("SERVICE-DISCOVERY INST04 wrong product rejected", TestInstalled04);
            Run("SERVICE-DISCOVERY INST05 unverified installation root rejected", TestInstalled05);
            Run("SERVICE-DISCOVERY INST06 service and installed evidence merge", TestInstalled06);
            Run("SERVICE-DISCOVERY INST07 controlled RegistryKey candidate reader", TestInstalled07);
            Run("SERVICE-DISCOVERY SINGLE x64/x86 isolated", TestServiceDiscoveryDistributions);
        }

        private static AnalysisContext SoftwareFixture(string path, int pid, string product, string company, SignatureStatus signature, string signer)
        {
            AnalysisContext c = Fresh(); c.ServiceEnumerationState = "OBSERVED"; c.TaskEnumerationState = "OBSERVED"; c.System.AlwaysInstallElevatedMachine = TriState.No; c.System.AlwaysInstallElevatedUser = TriState.No;
            c.Processes.Add(SoftwareProcess(path, pid, product, company, signature, signer)); return c;
        }

        private static WindowsProcess SoftwareProcess(string path, int pid, string product, string company, SignatureStatus signature, string signer)
        {
            return new WindowsProcess { ProcessId = pid, Name = Path.GetFileName(path), ImagePath = path, ImagePathSource = "SyntheticFixture", State = "RUNNING", AccessStatus = "ACCESSIBLE", OwnerAccount = @"LAB\operator", OwnerSid = "S-1-5-21-1-2-3-1105", IntegrityLevel = "Medium", Architecture = "x64", FileIdentity = new FileIdentityMetadata { CanonicalPath = path, MetadataState = "OBSERVED", ProductName = product, CompanyName = company, FileDescription = product, OriginalFilename = Path.GetFileName(path), SignatureStatus = signature, SignerSubject = signer, VersionConfidence = VersionConfidence.Unknown } };
        }

        private static void AddSoftwareService(AnalysisContext c, WindowsProcess process, string name, string account, TriState write)
        {
            c.Services.Add(new WindowsService { Name = name, DisplayName = name, State = "Running", StartType = "Automatic", ProcessId = process.ProcessId, Account = account, BinaryPath = process.ImagePath, ExecutablePath = process.ImagePath, CanStart = TriState.No, CanStop = TriState.No, CanChangeConfig = TriState.No, ExecutablePermission = new SecurityPermission { Target = process.ImagePath, ObjectType = "File", CanWrite = write, CanCreate = TriState.No, CanDelete = TriState.No, CanChangePermissions = TriState.No }, DirectoryPermission = new SecurityPermission { Target = Path.GetDirectoryName(process.ImagePath), ObjectType = "Directory", CanWrite = TriState.No, CanCreate = TriState.No, CanDelete = TriState.No, CanChangePermissions = TriState.No } });
        }

        private static AnalysisResult AnalyzeSoftware(AnalysisContext c)
        {
            ExecutionCorrelation.Correlate(c, false); c.Software.Clear(); FileIdentityCollector.Enrich(c, false); new SoftwareDiscoveryEngine().Discover(c, new SoftwareProfileCatalog().LoadEmbedded(), false); return AnalyzeCorrelation(c);
        }

        private static AnalysisResult AnalyzeSoftwareLive(AnalysisContext c)
        {
            ExecutionCorrelation.Correlate(c, false); c.Software.Clear(); FileIdentityCollector.Enrich(c, false); new SoftwareDiscoveryEngine().Discover(c, new SoftwareProfileCatalog().LoadEmbedded(), true, new RegisteredSoftwareEntry[0]); return AnalyzeCorrelation(c);
        }

        private static AnalysisResult AnalyzeSoftwareLiveWithPeReads(AnalysisContext c)
        {
            ExecutionCorrelation.Correlate(c, false); c.Software.Clear(); FileIdentityCollector.Enrich(c, true); new SoftwareDiscoveryEngine().Discover(c, new SoftwareProfileCatalog().LoadEmbedded(), true, new RegisteredSoftwareEntry[0]); return AnalyzeCorrelation(c);
        }

        private static void TestXamppPropertiesVersion()
        {
            string root = NewTempDirectory("xampp-version"), xampp = Path.Combine(root, "xampp"), bin = Path.Combine(xampp, "apache", "bin"); Directory.CreateDirectory(bin);
            try { File.WriteAllText(Path.Combine(xampp, "properties.ini"), "[General]\r\nbase_stack_name=XAMPP\r\nbase_stack_version=8.2.12-0\r\n"); AnalysisContext c = SoftwareFixture(Path.Combine(bin, "httpd.exe"), 2101, "Apache HTTP Server", "Apache Software Foundation", SignatureStatus.Absent, null); SoftwareObservation s = AnalyzeSoftwareLive(c).Context.Software.Single(); Equal("8.2.12-0", s.Version); Equal("XAMPP_PROPERTIES_INI", s.VersionSource); Equal(VersionConfidence.High, s.VersionConfidence); }
            finally { DeleteDirectory(root); }
        }

        private static void TestXamppAbsentProperties()
        {
            string root = NewTempDirectory("xampp-absent"), xampp = Path.Combine(root, "xampp"), bin = Path.Combine(xampp, "apache", "bin"); Directory.CreateDirectory(bin);
            try { AnalysisContext c = SoftwareFixture(Path.Combine(bin, "httpd.exe"), 2102, "Apache HTTP Server", "Apache Software Foundation", SignatureStatus.Absent, null); SoftwareObservation s = AnalyzeSoftwareLive(c).Context.Software.Single(); True(s.Version == null); Equal("UNKNOWN", s.VersionSource); True(s.VersionEvidence.Any(v => v.SourceType == "XAMPP_PROPERTIES_INI" && v.ReadStatus == "NOT_FOUND" && v.ObservationStatus == "UNKNOWN")); True(s.PendingConditions.Any(x => x.Contains("absent"))); }
            finally { DeleteDirectory(root); }
        }

        private static void TestXamppFixture(string relativeRoot, string configuredVersion, string expectedVersion, string expectedReadStatus)
        {
            string temporary = NewTempDirectory("vp-xampp"), xampp = Path.Combine(temporary, relativeRoot), bin = Path.Combine(xampp, "apache", "bin"); Directory.CreateDirectory(bin);
            try
            {
                File.WriteAllText(Path.Combine(xampp, "properties.ini"), "[General]\r\nbase_stack_name=XAMPP\r\nbase_stack_version=" + configuredVersion + "\r\n");
                SoftwareObservation s = AnalyzeSoftwareLive(SoftwareFixture(Path.Combine(bin, "httpd.exe"), 5601, "Apache HTTP Server", "Apache Software Foundation", SignatureStatus.Absent, null)).Context.Software.Single();
                Equal(expectedVersion, s.Version); SoftwareVersionEvidence evidence = s.VersionEvidence.Single(v => v.SourceType == "XAMPP_PROPERTIES_INI"); Equal("base_stack_version", evidence.SourceField); Equal(Path.Combine(xampp, "properties.ini"), evidence.SourcePath); Equal(expectedVersion == null ? "UNKNOWN" : "OBSERVED", evidence.ObservationStatus); if (expectedReadStatus != null) Equal(expectedReadStatus, evidence.ReadStatus);
            }
            finally { DeleteDirectory(temporary); }
        }

        private static void TestVp02OtherDrive()
        {
            Equal(@"D:\Tools\xampp", SoftwareDiscoveryEngine.ResolveXamppInstallationRoot(@"D:\Tools\xampp\apache\bin\httpd.exe"));
            TestXamppFixture(Path.Combine("Tools", "xampp"), "8.1.25-2", "8.1.25-2", null);
        }

        private static void TestVp04Absent()
        {
            string temporary = NewTempDirectory("vp04"), xampp = Path.Combine(temporary, "xampp"), bin = Path.Combine(xampp, "apache", "bin"); Directory.CreateDirectory(bin);
            try { SoftwareObservation s = AnalyzeSoftwareLive(SoftwareFixture(Path.Combine(bin, "httpd.exe"), 5604, "Apache HTTP Server", "Apache Software Foundation", SignatureStatus.Absent, null)).Context.Software.Single(); True(s.Version == null); SoftwareVersionEvidence e = s.VersionEvidence.Single(v => v.SourceType == "XAMPP_PROPERTIES_INI"); Equal("UNKNOWN", e.ObservationStatus); Equal("NOT_FOUND", e.ReadStatus); True(!String.IsNullOrWhiteSpace(e.CollectionError)); }
            finally { DeleteDirectory(temporary); }
        }

        private static void TestVp05Unreadable()
        {
            string temporary = NewTempDirectory("vp05"), xampp = Path.Combine(temporary, "xampp"), bin = Path.Combine(xampp, "apache", "bin"), config = Path.Combine(xampp, "properties.ini"); Directory.CreateDirectory(bin); File.WriteAllText(config, "base_stack_version=8.2.1-0");
            try { using (FileStream locked = new FileStream(config, FileMode.Open, FileAccess.ReadWrite, FileShare.None)) { SoftwareObservation s = AnalyzeSoftwareLive(SoftwareFixture(Path.Combine(bin, "httpd.exe"), 5605, "Apache HTTP Server", "Apache Software Foundation", SignatureStatus.Absent, null)).Context.Software.Single(); SoftwareVersionEvidence e = s.VersionEvidence.Single(v => v.SourceType == "XAMPP_PROPERTIES_INI"); Equal("UNKNOWN", e.ObservationStatus); True(e.ReadStatus == "ERROR" || e.ReadStatus == "ACCESS_DENIED"); } }
            finally { DeleteDirectory(temporary); }
        }

        private static void TestVp10TwoInstallations()
        {
            string temporary = NewTempDirectory("vp10"), first = Path.Combine(temporary, "one", "xampp"), second = Path.Combine(temporary, "two", "xampp"); Directory.CreateDirectory(Path.Combine(first, "apache", "bin")); Directory.CreateDirectory(Path.Combine(second, "apache", "bin"));
            try { File.WriteAllText(Path.Combine(first, "properties.ini"), "base_stack_version=8.1.1-0"); File.WriteAllText(Path.Combine(second, "properties.ini"), "xampp_version=8.2.2-0"); AnalysisContext c = SoftwareFixture(Path.Combine(first, "apache", "bin", "httpd.exe"), 5610, "Apache HTTP Server", "Apache Software Foundation", SignatureStatus.Absent, null); c.Processes.Add(SoftwareProcess(Path.Combine(second, "apache", "bin", "httpd.exe"), 5611, "Apache HTTP Server", "Apache Software Foundation", SignatureStatus.Absent, null)); List<SoftwareObservation> items = AnalyzeSoftwareLive(c).Context.Software.OrderBy(s => s.Version).ToList(); Equal(2, items.Count); Equal("8.1.1-0", items[0].Version); Equal("8.2.2-0", items[1].Version); }
            finally { DeleteDirectory(temporary); }
        }

        private static void TestVp11VersionConflict()
        {
            string temporary = NewTempDirectory("vp11"), xampp = Path.Combine(temporary, "xampp"), executable = Path.Combine(xampp, "apache", "bin", "httpd.exe"); Directory.CreateDirectory(Path.GetDirectoryName(executable));
            try
            {
                File.Copy(typeof(AnalyzerEngine).Assembly.Location, executable, true); File.WriteAllText(Path.Combine(xampp, "properties.ini"), "base_stack_version=8.2.12-0");
                AnalysisContext c = SoftwareFixture(executable, 5612, null, null, SignatureStatus.Unknown, null); c.Processes[0].FileIdentity = null;
                SoftwareObservation s = AnalyzeSoftwareLiveWithPeReads(c).Context.Software.Single(); FileVersionInfo actual = FileVersionInfo.GetVersionInfo(executable);
                Equal("8.2.12-0", s.Version); Equal("8.2.12-0", s.VersionEvidence.Single(v => v.Product == "XAMPP" && v.SourceType == "XAMPP_PROPERTIES_INI").Value);
                Equal(actual.ProductVersion, s.VersionEvidence.Single(v => v.Product == "Apache HTTP Server" && v.SourceType == "PE_PRODUCT_VERSION").Value);
                Equal(actual.FileVersion, s.VersionEvidence.Single(v => v.SourceType == "PE_FILE_VERSION").Value); True(!String.Equals("8.2.12-0", actual.ProductVersion, StringComparison.Ordinal));
            }
            finally { DeleteDirectory(temporary); }
        }

        private static void TestVp12ExternalConfigReader()
        {
            string temporary = NewTempDirectory("vp12"), first = Path.Combine(temporary, "first"), second = Path.Combine(temporary, "second"), executable = Path.Combine(first, "apache", "bin", "httpd.exe"), outside = Path.Combine(second, "properties.ini"); Directory.CreateDirectory(Path.GetDirectoryName(executable)); Directory.CreateDirectory(second); File.WriteAllText(outside, "base_stack_version=99.1.1-0");
            try { SoftwareVersionEvidence e = SoftwareDiscoveryEngine.ReadXamppVersionFromSource(first, executable, outside, "TEST_FIXTURE"); Equal("REJECTED", e.ReadStatus); Equal("UNKNOWN", e.ObservationStatus); True(e.Value == null); Equal("TEST_FIXTURE", e.EvidenceOrigin); }
            finally { DeleteDirectory(temporary); }
        }

        private static void TestVp14AllStrategiesUnknown()
        {
            string temporary = NewTempDirectory("vp14"), xampp = Path.Combine(temporary, "xampp"), executable = Path.Combine(xampp, "apache", "bin", "httpd.exe"); Directory.CreateDirectory(Path.GetDirectoryName(executable));
            try { AnalysisContext c = SoftwareFixture(executable, 5614, "Apache HTTP Server", "Apache Software Foundation", SignatureStatus.Absent, null); SoftwareObservation s = AnalyzeSoftwareLive(c).Context.Software.Single(); True(s.Version == null); Equal("UNKNOWN", s.VersionSource); True(s.VersionEvidence.Any(v => v.SourceType == "XAMPP_PROPERTIES_INI" && v.ReadStatus == "NOT_FOUND")); True(s.VersionEvidence.Where(v => v.SourceType == "PE_PRODUCT_VERSION" || v.SourceType == "PE_FILE_VERSION").All(v => v.ObservationStatus == "UNKNOWN")); True(!s.VersionEvidence.Any(v => v.ObservationStatus == "OBSERVED")); }
            finally { DeleteDirectory(temporary); }
        }

        private static void TestVp13StaticCatalogVersion()
        {
            List<SoftwareProfile> profiles = new SoftwareProfileCatalog().LoadEmbedded(); profiles[0].Version = "7.3.10-1"; bool rejected = false; try { new SoftwareProfileCatalog().Validate(profiles); } catch (InvalidDataException) { rejected = true; } True(rejected);
        }

        private static void TestVp15JsonProvenance()
        {
            string temporary = NewTempDirectory("vp15"), xampp = Path.Combine(temporary, "observed", "xampp"), missing = Path.Combine(temporary, "missing", "xampp"), executable = Path.Combine(xampp, "apache", "bin", "httpd.exe"), missingExecutable = Path.Combine(missing, "apache", "bin", "httpd.exe"), json = Path.Combine(temporary, "report.json"); Directory.CreateDirectory(Path.GetDirectoryName(executable)); Directory.CreateDirectory(Path.GetDirectoryName(missingExecutable));
            try { File.WriteAllText(Path.Combine(xampp, "properties.ini"), "xampp_version=8.3.4-0"); AnalysisContext c = SoftwareFixture(executable, 5615, "Apache HTTP Server", "Apache Software Foundation", SignatureStatus.Absent, null); c.Processes.Add(SoftwareProcess(missingExecutable, 5617, "Apache HTTP Server", "Apache Software Foundation", SignatureStatus.Absent, null)); JsonReporter.Write(AnalyzeSoftwareLive(c), json); AnalysisResult parsed = new JavaScriptSerializer { MaxJsonLength = Int32.MaxValue }.Deserialize<AnalysisResult>(File.ReadAllText(json)); SoftwareObservation observation = parsed.Context.Software.Single(s => s.InstallationRoot == xampp), failedObservation = parsed.Context.Software.Single(s => s.InstallationRoot == missing); SoftwareVersionEvidence e = observation.VersionEvidence.Single(v => v.SourceType == "XAMPP_PROPERTIES_INI"), failedEvidence = failedObservation.VersionEvidence.Single(v => v.SourceType == "XAMPP_PROPERTIES_INI"); Equal("8.3.4-0", e.Value); Equal("XAMPP", e.Product); Equal(Path.Combine(xampp, "properties.ini"), e.SourcePath); Equal("xampp_version", e.SourceField); Equal("OBSERVED", e.ObservationStatus); Equal("SUCCESS", e.ReadStatus); Equal(VersionConfidence.High, e.Confidence); Equal("TEST_FIXTURE", e.EvidenceOrigin); True(e.CollectionError == null); Equal("NOT_FOUND", failedEvidence.ReadStatus); Equal(VersionConfidence.Unknown, failedEvidence.Confidence); True(!String.IsNullOrWhiteSpace(failedEvidence.CollectionError)); Equal("TEST_FIXTURE", failedEvidence.EvidenceOrigin); Dictionary<string, object> artifact = new Dictionary<string, object>(); artifact["ValidationLevel"] = "TEST_FIXTURE"; artifact["RunningProcess"] = observation.Evidence.First(v => v.Kind == "RunningProcess"); artifact["ExecutablePath"] = observation.CanonicalExecutable; artifact["InstallationRoot"] = observation.InstallationRoot; artifact["ConfigFile"] = e.SourcePath; artifact["ParsedVersion"] = e; artifact["EvidenceProvenance"] = e.EvidenceOrigin; artifact["ProductIdentity"] = new Dictionary<string, object> { { "ProfileId", observation.ProfileId }, { "Product", e.Product }, { "IdentificationStatus", observation.IdentificationStatus } }; File.WriteAllText(Path.Combine(ProjectRoot(), "artifacts", "version-provenance-xampp-evidence.json"), new JavaScriptSerializer { MaxJsonLength = Int32.MaxValue }.Serialize(artifact), new UTF8Encoding(false)); }
            finally { DeleteDirectory(temporary); }
        }

        private static void TestVp17RealJunction()
        {
            string temporary = NewTempDirectory("vp17"), actual = Path.Combine(temporary, "actual"), junction = Path.Combine(temporary, "junction"); Directory.CreateDirectory(Path.Combine(actual, "apache", "bin")); File.WriteAllText(Path.Combine(actual, "properties.ini"), "base_stack_version=77.1.1-0");
            try
            {
                ExternalResult create = RunExternal(Environment.GetEnvironmentVariable("ComSpec") ?? "cmd.exe", "/d /c mklink /J " + Quote(junction) + " " + Quote(actual), temporary);
                if (create.ExitCode != 0 || !Directory.Exists(junction)) throw new SkippedTestException("The host did not permit creation of a temporary junction: " + (create.Error + " " + create.Output).Trim());
                SoftwareVersionEvidence e = SoftwareDiscoveryEngine.ReadXamppVersionFromSource(junction, Path.Combine(junction, "apache", "bin", "httpd.exe"), Path.Combine(junction, "properties.ini"), "TEST_FIXTURE"); Equal("REJECTED", e.ReadStatus); True(e.Value == null); True(e.CollectionError.IndexOf("reparse", StringComparison.OrdinalIgnoreCase) >= 0);
            }
            finally
            {
                if (Directory.Exists(junction)) RunExternal(Environment.GetEnvironmentVariable("ComSpec") ?? "cmd.exe", "/d /c rmdir " + Quote(junction), temporary);
                DeleteDirectory(temporary);
            }
        }

        private static void TestVerboseVersionProvenance()
        {
            string temporary = NewTempDirectory("verbose-origin"), xampp = Path.Combine(temporary, "xampp"), executable = Path.Combine(xampp, "apache", "bin", "httpd.exe"); Directory.CreateDirectory(Path.GetDirectoryName(executable));
            try { File.WriteAllText(Path.Combine(xampp, "properties.ini"), "base_stack_version=8.2.10-0"); string text = RenderResult(AnalyzeSoftwareLive(SoftwareFixture(executable, 5618, "Apache HTTP Server", "Apache Software Foundation", SignatureStatus.Absent, null)), true); True(text.Contains("type=XAMPP_PROPERTIES_INI") && text.Contains("confidence=HIGH") && text.Contains("origin=TEST_FIXTURE")); }
            finally { DeleteDirectory(temporary); }
        }

        private static void TestControlledUninstallRegistryReader()
        {
            string unique = "Software\\PrivTrace\\Tests\\" + Guid.NewGuid().ToString("N"), root = NewTempDirectory("registry-root");
            try
            {
                using (RegistryKey test = Registry.CurrentUser.CreateSubKey(unique)) using (RegistryKey product = test.CreateSubKey("Product")) { product.SetValue("InstallLocation", root); product.SetValue("DisplayName", "Controlled XAMPP"); product.SetValue("DisplayVersion", "8.4.1-0"); }
                using (RegistryKey test = Registry.CurrentUser.OpenSubKey(unique, false)) { SoftwareObservation item = new SoftwareObservation { ProfileId = "SW-XAMPP", ProductName = "Apache HTTP Server / XAMPP", InstallationRoot = root }; List<SoftwareVersionEvidence> evidence = SoftwareDiscoveryEngine.ReadUninstallRegistryKey(item, test, "HKCU\\" + unique, "CONTROLLED", "TEST_FIXTURE"); SoftwareVersionEvidence e = evidence.Single(); Equal("8.4.1-0", e.Value); Equal("DisplayVersion", e.SourceField); Equal("UNINSTALL_REGISTRY", e.SourceType); Equal("TEST_FIXTURE", e.EvidenceOrigin); Equal(VersionConfidence.Medium, e.Confidence); }
            }
            catch (UnauthorizedAccessException ex) { throw new SkippedTestException("The host denied creation of an isolated HKCU test key: " + ex.Message); }
            finally { try { Registry.CurrentUser.DeleteSubKeyTree(unique); } catch { } DeleteDirectory(root); }
        }

        private static void TestImportedEvidenceOrigin()
        {
            AnalysisContext c = SoftwareFixture(@"C:\xampp\apache\bin\httpd.exe", 5619, "Apache HTTP Server", "Apache Software Foundation", SignatureStatus.Absent, null); c.EvidenceOrigin = "IMPORTED_UNVERIFIED"; c.SoftwareVersionEvidence.Add(new SoftwareVersionEvidence { ProductId = "SW-XAMPP", InstallationRoot = @"C:\xampp", Product = "XAMPP", SourceType = "XAMPP_PROPERTIES_INI", SourcePath = @"C:\xampp\properties.ini", SourceField = "base_stack_version", Value = "7.3.10-1", ObservationStatus = "OBSERVED", ReadStatus = "SUCCESS", Confidence = VersionConfidence.High, EvidenceOrigin = "LIVE_OBSERVED" }); AnalysisResult result = AnalyzeSoftware(c); SoftwareObservation s = result.Context.Software.Single(); True(s.Version == null); SoftwareVersionEvidence e = s.VersionEvidence.Single(v => v.SourceType == "XAMPP_PROPERTIES_INI"); Equal("IMPORTED_UNVERIFIED", e.EvidenceOrigin); Equal("UNKNOWN", e.ObservationStatus); Equal("IMPORTED_UNVERIFIED", e.ReadStatus); True(!String.IsNullOrWhiteSpace(e.CollectionError)); True(!RenderResult(result, false).Contains("7.3.10-1")); True(RenderResult(result, true).Contains("origin=IMPORTED_UNVERIFIED"));
        }

        private static void TestVp16CleanVersion()
        {
            string temporary = NewTempDirectory("vp16"), xampp = Path.Combine(temporary, "xampp"), executable = Path.Combine(xampp, "apache", "bin", "httpd.exe"); Directory.CreateDirectory(Path.GetDirectoryName(executable));
            try { File.WriteAllText(Path.Combine(xampp, "properties.ini"), "base_stack_version=8.2.9-0"); string clean = RenderResult(AnalyzeSoftwareLive(SoftwareFixture(executable, 5616, "Apache HTTP Server", "Apache Software Foundation", SignatureStatus.Absent, null)), false); True(clean.Contains("Version    : 8.2.9-0")); True(!clean.Contains("source: XAMPP_PROPERTIES_INI") && !clean.Contains("SourceField") && !clean.Contains("CollectionError")); }
            finally { DeleteDirectory(temporary); }
        }

        private static void TestCleanXamppAndVmware()
        {
            string temporary = NewTempDirectory("clean-context"), xampp = Path.Combine(temporary, "xampp"), httpd = Path.Combine(xampp, "apache", "bin", "httpd.exe"); Directory.CreateDirectory(Path.GetDirectoryName(httpd));
            try
            {
                File.WriteAllText(Path.Combine(xampp, "properties.ini"), "base_stack_version=7.3.10-1");
                AnalysisContext c = SoftwareFixture(httpd, 5620, "Apache HTTP Server", "Apache Software Foundation", SignatureStatus.Absent, null);
                WindowsProcess vmware = SoftwareProcess(@"C:\Program Files\VMware\VMware Tools\vmtoolsd.exe", 5621, "VMware Tools", "VMware, Inc.", SignatureStatus.Valid, "CN=VMware, Inc."); vmware.FileIdentity.ProductVersion = "11.1.1 build-16303738"; c.Processes.Add(vmware); AddSoftwareService(c, vmware, "VMTools", "LocalSystem", TriState.No);
                AnalysisResult result = AnalyzeSoftwareLive(c); string clean = RenderResult(result, false); File.WriteAllText(Path.Combine(ProjectRoot(), "artifacts", "version-provenance-clean-xampp-vmware.txt"), clean, new UTF8Encoding(false));
                SoftwareObservation xamppObservation = result.Context.Software.Single(s => s.ProfileId == "SW-XAMPP"), vmwareObservation = result.Context.Software.Single(s => s.ProfileId == "SW-VMWARE-TOOLS");
                Equal("INTERESTING", xamppObservation.SoftwareContext); Equal("INFRASTRUCTURE", vmwareObservation.SoftwareContext); True(xamppObservation.InvestigationPriority > vmwareObservation.InvestigationPriority); True(vmwareObservation.ServiceNames.Contains("VMTools"));
                int paths = clean.IndexOf("ESCALATION PATHS", StringComparison.Ordinal), interesting = clean.IndexOf("INTERESTING SOFTWARE", StringComparison.Ordinal), xamppLine = clean.IndexOf("Apache HTTP Server / XAMPP", StringComparison.Ordinal), infrastructure = clean.IndexOf("INFRASTRUCTURE SOFTWARE", StringComparison.Ordinal), vmwareLine = clean.IndexOf("VMware Tools", StringComparison.Ordinal);
                True(paths >= 0 && clean.Contains("No actionable escalation paths verified.")); True(paths < interesting && interesting < xamppLine && xamppLine < infrastructure && infrastructure < vmwareLine);
                True(clean.Contains("Process    : " + httpd) && clean.Contains("Version    : 7.3.10-1") && clean.Contains("Source     : " + Path.Combine(xampp, "properties.ini")));
                True(clean.Contains(@"Process    : C:\Program Files\VMware\VMware Tools\vmtoolsd.exe") && clean.Contains("Version    : 11.1.1 build-16303738") && clean.Contains(@"Source     : PE metadata (C:\Program Files\VMware\VMware Tools\vmtoolsd.exe)")); Equal(2, CountText(clean, "Escalation : NOT VERIFIED"));
                True(clean.Contains("Service    : VMTools") && !clean.Contains("Services   :") && !clean.Contains("Rules      :"));
                True(clean.Substring(interesting, infrastructure - interesting).Contains("Apache HTTP Server / XAMPP") && !clean.Substring(interesting, infrastructure - interesting).Contains("VMware Tools")); True(!clean.Substring(infrastructure).Contains("Apache HTTP Server / XAMPP") && clean.Substring(infrastructure).Contains("VMware Tools"));
            }
            finally { DeleteDirectory(temporary); }
        }

        private static void TestCo01CleanXampp()
        {
            AnalysisContext c = SoftwareFixture(@"C:\xampp\apache\bin\httpd.exe", 5701, "Apache HTTP Server", "Apache Software Foundation", SignatureStatus.Absent, null);
            c.SoftwareVersionEvidence.Add(new SoftwareVersionEvidence { ProductId = "SW-XAMPP", InstallationRoot = @"C:\xampp", Product = "XAMPP", SourceType = "XAMPP_PROPERTIES_INI", SourcePath = @"C:\xampp\properties.ini", SourceField = "base_stack_version", Value = "7.3.10-1", ObservationStatus = "OBSERVED", ReadStatus = "SUCCESS", Confidence = VersionConfidence.High, EvidenceOrigin = "TEST_FIXTURE" });
            string clean = RenderResult(AnalyzeSoftware(c), false), expected = "[1] Apache HTTP Server / XAMPP\r\n    Process    : C:\\xampp\\apache\\bin\\httpd.exe\r\n    Version    : 7.3.10-1\r\n    Source     : C:\\xampp\\properties.ini\r\n    Escalation : NOT VERIFIED";
            True(clean.Contains(expected));
        }

        private static void TestCo02CleanPeSource()
        {
            string temporary = NewTempDirectory("co02"), executable = Path.Combine(temporary, "TeamViewer", "TeamViewer.exe"); Directory.CreateDirectory(Path.GetDirectoryName(executable));
            try
            {
                File.Copy(typeof(AnalyzerEngine).Assembly.Location, executable, true); AnalysisContext c = SoftwareFixture(executable, 5702, null, null, SignatureStatus.Unknown, null); c.Processes[0].FileIdentity = null;
                FileVersionInfo actual = FileVersionInfo.GetVersionInfo(executable); string clean = RenderResult(AnalyzeSoftwareLiveWithPeReads(c), false);
                True(clean.Contains("Process    : " + executable)); True(clean.Contains("Version    : " + actual.ProductVersion)); True(clean.Contains("Source     : PE metadata (" + executable + ")"));
            }
            finally { DeleteDirectory(temporary); }
        }

        private static void TestCo03CleanRegistrySource()
        {
            string unique = "Software\\PrivTrace\\Tests\\CO03-" + Guid.NewGuid().ToString("N"), root = NewTempDirectory("co03"), installation = Path.Combine(root, "xampp"), executable = Path.Combine(installation, "apache", "bin", "httpd.exe"); Directory.CreateDirectory(Path.GetDirectoryName(executable));
            try
            {
                using (RegistryKey test = Registry.CurrentUser.CreateSubKey(unique)) using (RegistryKey product = test.CreateSubKey("Product")) { product.SetValue("InstallLocation", installation); product.SetValue("DisplayName", "Controlled XAMPP"); product.SetValue("DisplayVersion", "8.4.2-0"); }
                SoftwareVersionEvidence evidence; using (RegistryKey test = Registry.CurrentUser.OpenSubKey(unique, false)) { SoftwareObservation item = new SoftwareObservation { ProfileId = "SW-XAMPP", ProductName = "Apache HTTP Server / XAMPP", InstallationRoot = installation }; evidence = SoftwareDiscoveryEngine.ReadUninstallRegistryKey(item, test, "HKCU\\" + unique, "CONTROLLED", "TEST_FIXTURE").Single(); }
                AnalysisContext c = SoftwareFixture(executable, 5703, "Apache HTTP Server", "Apache Software Foundation", SignatureStatus.Absent, null); c.SoftwareVersionEvidence.Add(evidence); string clean = RenderResult(AnalyzeSoftware(c), false);
                if (!clean.Contains("Version    : 8.4.2-0") || !clean.Contains("Source     : Registry (" + evidence.RegistryKey + ")")) throw new Exception("Unexpected CO03 CLEAN output:" + Environment.NewLine + clean);
            }
            catch (UnauthorizedAccessException ex) { throw new SkippedTestException("The host denied creation of the isolated CO03 HKCU test key: " + ex.Message); }
            finally { try { Registry.CurrentUser.DeleteSubKeyTree(unique); } catch { } DeleteDirectory(root); }
        }

        private static void TestCo04CleanUnknownVersion()
        {
            string clean = RenderResult(AnalyzeSoftware(SoftwareFixture(@"C:\xampp\apache\bin\httpd.exe", 5704, "Apache HTTP Server", "Apache Software Foundation", SignatureStatus.Absent, null)), false);
            True(clean.Contains(@"Process    : C:\xampp\apache\bin\httpd.exe")); True(clean.Contains("Version    : UNKNOWN")); True(clean.Contains("Source     : UNKNOWN"));
        }

        private static void TestCo05MultipleProcesses()
        {
            AnalysisContext c = SoftwareFixture(@"C:\Tomcat9\bin\tomcat9.exe", 5705, "Apache Tomcat", "Apache Software Foundation", SignatureStatus.Absent, null); c.Processes.Add(SoftwareProcess(@"C:\Tomcat9\bin\prunsrv.exe", 5706, "Apache Tomcat", "Apache Software Foundation", SignatureStatus.Absent, null)); AnalysisResult result = AnalyzeSoftware(c); string clean = RenderResult(result, false), json = TempPath("co05");
            try { Equal(1, CountText(clean, "Apache Tomcat")); Equal(1, CountText(clean, @"Process    : C:\Tomcat9\bin\tomcat9.exe")); JsonReporter.Write(result, json); AnalysisResult parsed = new JavaScriptSerializer { MaxJsonLength = Int32.MaxValue }.Deserialize<AnalysisResult>(File.ReadAllText(json)); Equal(2, parsed.Context.Software.Single().ProcessIds.Count); Equal(2, parsed.Context.Software.Single().ProcessPaths.Count); True(parsed.Context.Software.Single().ProcessPaths.Contains(@"C:\Tomcat9\bin\tomcat9.exe") && parsed.Context.Software.Single().ProcessPaths.Contains(@"C:\Tomcat9\bin\prunsrv.exe")); }
            finally { if (File.Exists(json)) File.Delete(json); }
        }

        private static void TestCo06ImportedEvidence()
        {
            AnalysisContext c = SoftwareFixture(@"C:\xampp\apache\bin\httpd.exe", 5707, "Apache HTTP Server", "Apache Software Foundation", SignatureStatus.Absent, null); c.EvidenceOrigin = "IMPORTED_UNVERIFIED"; c.SoftwareVersionEvidence.Add(new SoftwareVersionEvidence { ProductId = "SW-XAMPP", InstallationRoot = @"C:\xampp", Product = "XAMPP", SourceType = "XAMPP_PROPERTIES_INI", SourcePath = @"C:\xampp\properties.ini", SourceField = "base_stack_version", Value = "99.9.9-9", ObservationStatus = "OBSERVED", ReadStatus = "SUCCESS", Confidence = VersionConfidence.High, EvidenceOrigin = "LIVE_OBSERVED" }); AnalysisResult result = AnalyzeSoftware(c); string clean = RenderResult(result, false), verbose = RenderResult(result, true);
            True(clean.Contains("Process    : UNKNOWN (IMPORTED_UNVERIFIED)")); True(clean.Contains("Version    : UNKNOWN")); True(clean.Contains("Source     : UNKNOWN")); True(!clean.Contains("99.9.9-9")); True(verbose.Contains("origin=IMPORTED_UNVERIFIED"));
        }

        private static void TestCo07CleanRegression()
        {
            TestCleanXamppAndVmware(); string noisy = RenderResult(AnalyzeCorrelation(Synthetic171Unknown()), false);
            True(noisy.Contains("No actionable escalation paths verified.")); Equal(0, CountText(noisy, "Status: UNKNOWN")); True(!noisy.Contains("CVE-") && !noisy.Contains("VULNERABLE"));
        }

        private static AnalysisContext FishContext(params WindowsService[] services)
        {
            AnalysisContext context = Fresh(); context.ServiceEnumerationState = "OBSERVED"; context.TaskEnumerationState = "OBSERVED";
            context.System.AlwaysInstallElevatedMachine = TriState.No; context.System.AlwaysInstallElevatedUser = TriState.No;
            foreach (WindowsService service in services) context.Services.Add(service);
            return context;
        }

        private static WindowsService FishService(string name, string path, string product, string company, string state, TriState canStart, TriState fileWrite, TriState directoryCreate, TriState fileDelete, TriState deleteChild, string account)
        {
            return new WindowsService
            {
                Name = name, DisplayName = name, BinaryPath = Quote(path) + " --service", ExecutablePath = path, Account = account,
                State = state, StartType = "Automatic", CanStart = canStart, CanStop = TriState.No, CanChangeConfig = TriState.No,
                RuntimeProtectionState = "UNKNOWN",
                FileIdentity = new FileIdentityMetadata { CanonicalPath = path, MetadataState = "OBSERVED", ProductName = product, CompanyName = company, FileDescription = product, OriginalFilename = Path.GetFileName(path), ProductVersion = null, FileVersion = null, VersionConfidence = VersionConfidence.Unknown },
                ExecutablePermission = new SecurityPermission { Target = path, ObjectType = "File", CanWrite = fileWrite, CanCreate = TriState.No, CanDelete = fileDelete, CanDeleteChildren = TriState.No, CanChangePermissions = TriState.No },
                DirectoryPermission = new SecurityPermission { Target = Path.GetDirectoryName(path), ObjectType = "Directory", CanWrite = TriState.No, CanCreate = directoryCreate, CanDelete = TriState.No, CanDeleteChildren = deleteChild, CanChangePermissions = TriState.No }
            };
        }

        private static Finding FishFinding(AnalysisResult result, string ruleId, string serviceName)
        {
            Finding exact = result.Findings.FirstOrDefault(f => f.RuleId == ruleId && String.Equals(f.ServiceName, serviceName, StringComparison.OrdinalIgnoreCase));
            return exact ?? result.Findings.First(f => f.RuleId == ruleId);
        }

        private static void TestFish01()
        {
            WindowsService service = FishService("domain1", @"C:\glassfish4\glassfish\domains\domain1\bin\domain1Service.exe", "GlassFish Server Open Source Edition", "Oracle Corporation", "Running", TriState.No, TriState.No, TriState.No, TriState.No, TriState.No, "LocalSystem");
            AnalysisResult result = AnalyzeSoftware(FishContext(service)); SoftwareObservation item = result.Context.Software.Single(s => s.ProfileId == "SW-GLASSFISH");
            Equal(0, item.ProcessPaths.Count); True(item.ServiceNames.Contains("domain1")); True(item.ConfiguredExecutablePaths.Contains(service.ExecutablePath)); True(item.ObservationStates.Contains("SERVICE_CONFIGURED") && item.ObservationStates.Contains("SERVICE_RUNNING"));
        }

        private static void TestFish02()
        {
            WindowsService service = FishService("SynaMan", @"C:\SynaMan\SynaMan.exe", "SynaMan", "Synametrics Technologies", "Running", TriState.No, TriState.No, TriState.No, TriState.No, TriState.No, "LocalSystem");
            AnalysisResult result = AnalyzeSoftware(FishContext(service)); SoftwareObservation item = result.Context.Software.Single(s => s.ProfileId == "SW-SYNAMAN");
            True(item.ServiceNames.Contains("SynaMan")); True(item.Version == null); True(!RenderResult(result, false).Contains("VULNERABLE"));
        }

        private static void TestFish03()
        {
            WindowsService service = FishService("SecurityService", @"C:\Program Files (x86)\TotalAV\SecurityService.exe", "TotalAV", "Total Security Limited", "Running", TriState.No, TriState.No, TriState.No, TriState.No, TriState.No, "LocalSystem");
            AnalysisResult result = AnalyzeSoftware(FishContext(service)); SoftwareObservation item = result.Context.Software.Single(s => s.ProfileId == "SW-TOTALAV");
            Equal("INFRASTRUCTURE", item.SoftwareContext); True(!result.Findings.Any(f => f.Severity == Severity.High && f.Status == EvaluationStatus.Confirmed));
        }

        private static void TestFish04()
        {
            WindowsService service = FishService("VMTools", @"C:\Program Files\VMware\VMware Tools\vmtoolsd.exe", "VMware Tools", "VMware, Inc.", "Running", TriState.No, TriState.No, TriState.No, TriState.No, TriState.No, "LocalSystem");
            SoftwareObservation item = AnalyzeSoftware(FishContext(service)).Context.Software.Single(s => s.ProfileId == "SW-VMWARE-TOOLS"); Equal("INFRASTRUCTURE", item.SoftwareContext); True(item.ServiceNames.Contains("VMTools"));
        }

        private static void TestFishPt013(WindowsService service, bool expectedCanStart)
        {
            Finding finding = FishFinding(AnalyzeSoftware(FishContext(service)), "PT-013", service.Name);
            Equal(EvaluationStatus.Confirmed, finding.Status); Equal("CONFIRMED_RIGHT", finding.PermissionState); Equal("FILE_WRITE_DATA", finding.VerifiedOperation); Equal("CONDITIONAL_EXECUTION", finding.ExecutionState); Equal("UNKNOWN", finding.RuntimeProtectionState); Equal(expectedCanStart ? TriState.Yes : TriState.No, service.CanStart); True(finding.Evidence.Any(e => e.Kind == "ExecutableAcl"));
        }

        private static void TestFish08()
        {
            WindowsService service = FishService("SynaMan", @"C:\SynaMan\SynaMan.exe", "SynaMan", "Synametrics", "Running", TriState.No, TriState.No, TriState.Yes, TriState.No, TriState.No, "LocalSystem");
            Finding finding = FishFinding(AnalyzeSoftware(FishContext(service)), "PT-016", service.Name); Equal(EvaluationStatus.Potential, finding.Status); Equal(Severity.Medium, finding.Severity); Equal("DIRECTORY_CREATE_CONFIRMED", finding.PermissionState); Equal("FILE_ADD_FILE", finding.VerifiedOperation);
        }

        private static void TestFish09()
        {
            WindowsService service = FishService("SynaMan", @"C:\SynaMan\SynaMan.exe", "SynaMan", "Synametrics", "Running", TriState.No, TriState.No, TriState.Yes, TriState.No, TriState.Yes, "LocalSystem");
            Finding finding = FishFinding(AnalyzeSoftware(FishContext(service)), "PT-016", service.Name); Equal(EvaluationStatus.Confirmed, finding.Status); Equal("FILE_REPLACE_CONFIRMED", finding.PermissionState); Equal("FILE_REPLACEMENT", finding.VerifiedOperation);
        }

        private static void TestFish10()
        {
            WindowsService glassfish = FishService("domain1", @"C:\glassfish4\glassfish\domains\domain1\bin\domain1Service.exe", "GlassFish Server", "Oracle", "Running", TriState.No, TriState.Yes, TriState.Yes, TriState.No, TriState.Yes, "LocalSystem");
            WindowsService synaman = FishService("SynaMan", @"C:\SynaMan\SynaMan.exe", "SynaMan", "Synametrics", "Running", TriState.No, TriState.Yes, TriState.Yes, TriState.No, TriState.Yes, "LocalSystem");
            WindowsService totalav = FishService("SecurityService", @"C:\Program Files (x86)\TotalAV\SecurityService.exe", "TotalAV", "Total Security Limited", "Running", TriState.Yes, TriState.Yes, TriState.Yes, TriState.No, TriState.Yes, "LocalSystem");
            AnalysisResult result = AnalyzeSoftware(FishContext(glassfish, synaman, totalav)); string clean = RenderResult(result, false), json = TempPath("fish10");
            try { Equal(3, CountText(clean, "Service    :")); True(clean.Contains("Service    : domain1") && clean.Contains("Service    : SynaMan") && clean.Contains("Service    : SecurityService")); JsonReporter.Write(result, json); AnalysisResult parsed = new JavaScriptSerializer { MaxJsonLength = Int32.MaxValue }.Deserialize<AnalysisResult>(File.ReadAllText(json)); Equal(6, parsed.Findings.Count(f => (f.RuleId == "PT-013" || f.RuleId == "PT-016") && f.Status != EvaluationStatus.RuledOut)); }
            finally { if (File.Exists(json)) File.Delete(json); }
        }

        private static void TestFish11()
        {
            string path = @"C:\Shared\service-host.exe"; WindowsService first = FishService("AlphaService", path, "SynaMan", "Synametrics", "Running", TriState.No, TriState.Yes, TriState.Yes, TriState.No, TriState.Yes, "LocalSystem"), second = FishService("BetaService", path, "SynaMan", "Synametrics", "Running", TriState.No, TriState.Yes, TriState.Yes, TriState.No, TriState.Yes, "LocalSystem");
            AnalysisResult result = AnalyzeSoftware(FishContext(first, second)); string clean = RenderResult(result, false); Equal(1, result.Context.Software.Count); True(clean.Contains("Service: AlphaService") && clean.Contains("Service: BetaService") && clean.Contains("Service    : AlphaService, BetaService")); Equal(2, result.Findings.Count(f => f.RuleId == "PT-013" && f.Status == EvaluationStatus.Confirmed));
        }

        private static void TestFish12()
        {
            WindowsService first = FishService("SynaManA", @"C:\Apps\SynaMan-A\SynaMan.exe", "SynaMan", "Synametrics", "Running", TriState.No, TriState.No, TriState.No, TriState.No, TriState.No, "LocalSystem"), second = FishService("SynaManB", @"D:\Apps\SynaMan-B\SynaMan.exe", "SynaMan", "Synametrics", "Stopped", TriState.No, TriState.No, TriState.No, TriState.No, TriState.No, "LocalSystem");
            List<SoftwareObservation> items = AnalyzeSoftware(FishContext(first, second)).Context.Software.Where(s => s.ProfileId == "SW-SYNAMAN").ToList(); Equal(2, items.Count); Equal(2, items.Select(s => s.InstallationRoot).Distinct(StringComparer.OrdinalIgnoreCase).Count());
        }

        private static void TestFish13()
        {
            WindowsService service = FishService("domain1", @"C:\glassfish4\glassfish\domains\domain1\bin\domain1Service.exe", "GlassFish Server", "Oracle", "Running", TriState.No, TriState.No, TriState.No, TriState.No, TriState.No, "LocalSystem");
            SoftwareObservation item = AnalyzeSoftware(FishContext(service)).Context.Software.Single(); True(item.Version == null); Equal("UNKNOWN", item.VersionSource); True(!item.VersionEvidence.Any(v => v.ObservationStatus == "OBSERVED"));
        }

        private static void TestFish14()
        {
            WindowsService service = FishService("SynaMan", @"C:\SynaMan\SynaMan.exe", "SynaMan", "Synametrics", "Running", TriState.No, TriState.No, TriState.No, TriState.No, TriState.No, "LocalSystem"); service.FileIdentity.ProductVersion = "5.7.1"; service.FileIdentity.FileVersion = "5.7.1.0"; service.FileIdentity.VersionConfidence = VersionConfidence.High;
            SoftwareObservation item = AnalyzeSoftware(FishContext(service)).Context.Software.Single(s => s.ProfileId == "SW-SYNAMAN"); Equal("5.7.1", item.Version); SoftwareVersionEvidence evidence = item.VersionEvidence.Single(v => v.SourceType == "PE_PRODUCT_VERSION" && v.Value == "5.7.1"); Equal(service.ExecutablePath, evidence.SourcePath); Equal("ProductVersion", evidence.SourceField); Equal("TEST_FIXTURE", evidence.EvidenceOrigin); Equal(VersionConfidence.Medium, evidence.Confidence);
        }

        private static void TestFish15()
        {
            WindowsService service = FishService("SynaMan", @"C:\SynaMan\SynaMan.exe", "SynaMan", "Synametrics", "Stopped", TriState.No, TriState.No, TriState.No, TriState.No, TriState.No, "LocalSystem"); AnalysisResult result = AnalyzeSoftware(FishContext(service));
            Equal(0, result.Context.Processes.Count); SoftwareObservation item = result.Context.Software.Single(); True(item.ObservationStates.Contains("SERVICE_CONFIGURED") && !item.ObservationStates.Contains("PROCESS_RUNNING")); ExecutionRelationship relation = result.Context.ExecutionRelationships.Single(r => r.SourceKind == "ServiceExecutable"); Equal("CONFIGURED", relation.Classification); Equal(0, relation.HostProcessId);
        }

        private static void TestFish16()
        {
            WindowsService service = FishService("SynaMan", @"C:\SynaMan\SynaMan.exe", "SynaMan", "Synametrics", "Running", TriState.No, TriState.No, TriState.No, TriState.No, TriState.No, "LocalSystem"); service.ProcessId = 5757; AnalysisContext context = FishContext(service); context.Processes.Add(SoftwareProcess(service.ExecutablePath, 5757, "SynaMan", "Synametrics", SignatureStatus.Unknown, null));
            AnalysisResult result = AnalyzeSoftware(context); ExecutionRelationship relation = result.Context.ExecutionRelationships.Single(r => r.SourceKind == "ServiceExecutable"); Equal("OBSERVED", relation.Classification); Equal(5757, relation.HostProcessId); True(result.Context.Software.Single().ObservationStates.Contains("PROCESS_RUNNING"));
        }

        private static void TestFish17()
        {
            WindowsService service = FishService("SynaMan", @"C:\SynaMan\SynaMan.exe", "SynaMan", "Synametrics", "Running", TriState.Unknown, TriState.Unknown, TriState.Unknown, TriState.Unknown, TriState.Unknown, "LocalSystem"); AnalysisResult result = AnalyzeSoftware(FishContext(service));
            Finding direct = FishFinding(result, "PT-013", service.Name), directory = FishFinding(result, "PT-016", service.Name); True(direct.Status != EvaluationStatus.Confirmed && directory.Status != EvaluationStatus.Confirmed); True(!result.Findings.Any(f => f.ServiceName == service.Name && f.Severity == Severity.High && f.Status == EvaluationStatus.Confirmed));
        }

        private static void TestFish18()
        {
            WindowsService service = FishService("SynaMan", @"C:\SynaMan\SynaMan.exe", "SynaMan", "Synametrics", "Running", TriState.No, TriState.Yes, TriState.No, TriState.No, TriState.No, "LocalSystem"); Finding finding = FishFinding(AnalyzeSoftware(FishContext(service)), "PT-013", service.Name); Equal("UNKNOWN", finding.RuntimeProtectionState); True(finding.MissingConditions.Any(e => e.IndexOf("self-protection", StringComparison.OrdinalIgnoreCase) >= 0));
        }

        private static AnalysisResult MixedFishResult()
        {
            WindowsService glassfish = FishService("domain1", @"C:\glassfish4\glassfish\domains\domain1\bin\domain1Service.exe", "GlassFish Server", "Oracle", "Running", TriState.No, TriState.Yes, TriState.Yes, TriState.No, TriState.Yes, "LocalSystem"); glassfish.FileIdentity.ProductVersion = "4.1.2";
            WindowsService synaman = FishService("SynaMan", @"C:\SynaMan\SynaMan.exe", "SynaMan", "Synametrics Technologies", "Running", TriState.No, TriState.Yes, TriState.Yes, TriState.No, TriState.Yes, "LocalSystem"); synaman.FileIdentity.ProductVersion = "5.1";
            WindowsService totalav = FishService("SecurityService", @"C:\Program Files (x86)\TotalAV\SecurityService.exe", "TotalAV", "Total Security Limited", "Running", TriState.Yes, TriState.Yes, TriState.Yes, TriState.No, TriState.Yes, "LocalSystem"); totalav.FileIdentity.ProductVersion = "6.0";
            WindowsService vmware = FishService("VMTools", @"C:\Program Files\VMware\VMware Tools\vmtoolsd.exe", "VMware Tools", "VMware, Inc.", "Running", TriState.No, TriState.No, TriState.No, TriState.No, TriState.No, "LocalSystem"); vmware.FileIdentity.ProductVersion = "11.1.1 build-16303738";
            AnalysisContext context = FishContext(glassfish, synaman, totalav, vmware); context.TaskEnumerationState = "PARTIAL";
            for (int i = 0; i < 5; i++) { ScheduledTaskInfo task = Task("\\FishUnknown" + i, TriState.Unknown, TriState.Unknown); task.Actions.Add(Action(@"C:\Fish\unknown" + i + ".exe", false, TriState.Unknown)); context.Tasks.Add(task); }
            return AnalyzeSoftware(context);
        }

        private static void TestFish20()
        {
            AnalysisResult result = MixedFishResult(); string clean = RenderResult(result, false), artifact = Path.Combine(ProjectRoot(), "artifacts"); Directory.CreateDirectory(artifact); File.WriteAllText(Path.Combine(artifact, "service-discovery-fish-clean.txt"), clean, new UTF8Encoding(false)); JsonReporter.Write(result, Path.Combine(artifact, "service-discovery-fish-report.json"));
            Equal(4, CountText(clean, "Service    :")); Equal(6, result.Findings.Count(f => (f.RuleId == "PT-013" || f.RuleId == "PT-016") && f.Status != EvaluationStatus.RuledOut)); Equal(4, result.Context.Software.Count); True(clean.Contains("GlassFish") && clean.Contains("SynaMan") && clean.Contains("TotalAV") && clean.Contains("VMware Tools")); True(clean.Contains("Tasks: PARTIAL") && CountText(clean, "Status: UNKNOWN") == 0);
        }

        private static void TestEdgeWriteDac()
        {
            WindowsService service = FishService("SynaMan", @"C:\SynaMan\SynaMan.exe", "SynaMan", "Synametrics", "Running", TriState.No, TriState.No, TriState.No, TriState.No, TriState.No, "LocalSystem"); service.ExecutablePermission.CanChangePermissions = TriState.Yes; Finding finding = FishFinding(AnalyzeSoftware(FishContext(service)), "PT-013", service.Name); Equal(EvaluationStatus.Potential, finding.Status); Equal("WRITE_DAC", finding.VerifiedOperation);
        }

        private static void TestEdgeDisabled()
        {
            WindowsService service = FishService("SynaMan", @"C:\SynaMan\SynaMan.exe", "SynaMan", "Synametrics", "Stopped", TriState.No, TriState.Yes, TriState.No, TriState.No, TriState.No, "LocalSystem"); service.StartType = "Disabled"; Finding finding = FishFinding(AnalyzeSoftware(FishContext(service)), "PT-013", service.Name); Equal("CONDITIONAL_EXECUTION", finding.ExecutionState); True(finding.MissingConditions.Any(p => p.IndexOf("disabled", StringComparison.OrdinalIgnoreCase) >= 0 || p.IndexOf("start", StringComparison.OrdinalIgnoreCase) >= 0));
        }

        private static void TestEdgeArguments()
        {
            WindowsService service = FishService("SynaMan", @"C:\Program Files\SynaMan\SynaMan.exe", "SynaMan", "Synametrics", "Running", TriState.No, TriState.No, TriState.No, TriState.No, TriState.No, "LocalSystem"); service.BinaryPath = Quote(service.ExecutablePath) + " --service --port 6060"; SoftwareObservation item = AnalyzeSoftware(FishContext(service)).Context.Software.Single(); True(item.ConfiguredExecutablePaths.Contains(service.ExecutablePath));
        }

        private static void TestEdgeEnvironment()
        {
            WindowsService service = FishService("SecurityService", @"C:\Program Files (x86)\TotalAV\SecurityService.exe", "TotalAV", "Total Security Limited", "Running", TriState.No, TriState.No, TriState.No, TriState.No, TriState.No, "LocalSystem"); service.BinaryPath = @"%ProgramFiles(x86)%\TotalAV\SecurityService.exe --service"; SoftwareObservation item = AnalyzeSoftware(FishContext(service)).Context.Software.Single(); Equal("SW-TOTALAV", item.ProfileId); True(item.ConfiguredExecutablePaths.Contains(service.ExecutablePath));
        }

        private static void TestEdgeMissing()
        {
            WindowsService service = FishService("SynaMan", @"C:\Missing\SynaMan.exe", "SynaMan", "Synametrics", "Stopped", TriState.No, TriState.Unknown, TriState.Unknown, TriState.Unknown, TriState.Unknown, "LocalSystem"); service.FileIdentity.MetadataState = "NOT_FOUND"; AnalysisResult result = AnalyzeSoftware(FishContext(service)); SoftwareObservation item = result.Context.Software.Single(); True(item.Version == null); True(item.ObservationStates.Contains("SERVICE_CONFIGURED")); True(!result.Findings.Any(f => f.ServiceName == service.Name && f.Status == EvaluationStatus.Confirmed));
        }

        private static void TestEdgeUnc()
        {
            WindowsService service = FishService("SynaMan", @"\\server\share\SynaMan\SynaMan.exe", "SynaMan", "Synametrics", "Stopped", TriState.No, TriState.Unknown, TriState.Unknown, TriState.Unknown, TriState.Unknown, "LocalSystem"); SoftwareObservation item = AnalyzeSoftware(FishContext(service)).Context.Software.Single(); Equal(service.ExecutablePath, item.ConfiguredExecutablePaths.Single()); True(item.ObservationStates.Contains("SERVICE_CONFIGURED"));
        }

        private static void TestEdgeWrapper()
        {
            WindowsService service = FishService("domain1", @"C:\glassfish4\glassfish\domains\domain1\bin\domain1Service.exe", "GlassFish Server", "Oracle", "Running", TriState.No, TriState.No, TriState.No, TriState.No, TriState.No, "LocalSystem"); service.BinaryPath = Quote(service.ExecutablePath) + " domain1"; AnalysisResult result = AnalyzeSoftware(FishContext(service)); Equal(0, result.Context.Processes.Count); ExecutionRelationship relation = result.Context.ExecutionRelationships.Single(r => r.SourceKind == "ServiceExecutable"); Equal("CONFIGURED", relation.Classification); Equal(0, relation.HostProcessId);
        }

        private static RegisteredSoftwareEntry InstalledEntry(string name, string publisher, string root, string version, bool verified)
        {
            return new RegisteredSoftwareEntry { DisplayName = name, Publisher = publisher, InstallLocation = root, DisplayVersion = version, RegistryKey = @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Controlled", ViewName = "CONTROLLED", InstallationRootVerified = verified };
        }

        private static AnalysisResult AnalyzeInstalled(AnalysisContext context, params RegisteredSoftwareEntry[] entries)
        {
            ExecutionCorrelation.Correlate(context, false); context.Software.Clear(); FileIdentityCollector.Enrich(context, false); new SoftwareDiscoveryEngine().Discover(context, new SoftwareProfileCatalog().LoadEmbedded(), false, entries); return AnalyzeCorrelation(context);
        }

        private static void TestInstalled01()
        {
            AnalysisResult result = AnalyzeInstalled(Fresh(), InstalledEntry("SynaMan", "Synametrics Technologies", @"C:\SynaMan", "5.7.1", true)); SoftwareObservation item = result.Context.Software.Single();
            Equal("SW-SYNAMAN", item.ProfileId); Equal("INSTALLED", item.State); True(item.ObservationStates.Contains("INSTALLED")); Equal(0, item.ProcessPaths.Count); Equal("5.7.1", item.Version); Equal("UNINSTALL_REGISTRY", item.VersionSource); SoftwareVersionEvidence evidence = item.VersionEvidence.Single(v => v.SourceType == "UNINSTALL_REGISTRY"); Equal("TEST_FIXTURE", evidence.EvidenceOrigin); Equal("DisplayVersion", evidence.SourceField); Equal("SUCCESS", evidence.ReadStatus);
        }

        private static void TestInstalled02()
        {
            AnalysisResult result = AnalyzeInstalled(Fresh(), InstalledEntry("SynaMan", "Unknown Transfer Corp", @"C:\Tools\Transfer", "5.7.1", true)); Equal(0, result.Context.Software.Count);
        }

        private static void TestInstalled03()
        {
            AnalysisResult result = AnalyzeInstalled(Fresh(), InstalledEntry("TotalAV", null, @"C:\Program Files (x86)\TotalAV", "6.2.0", true)); SoftwareObservation item = result.Context.Software.Single(); Equal("SW-TOTALAV", item.ProfileId); Equal("INFRASTRUCTURE", item.SoftwareContext); Equal("INSTALLED", item.State); Equal("6.2.0", item.Version);
        }

        private static void TestInstalled04()
        {
            AnalysisResult result = AnalyzeInstalled(Fresh(), InstalledEntry("Apache HTTP Server", "Apache Software Foundation", @"C:\Apache24", "2.4.62", true)); Equal(1, result.Context.Software.Count); Equal("SW-APACHE", result.Context.Software.Single().ProfileId); True(!result.Context.Software.Any(s => s.ProfileId == "SW-XAMPP"));
        }

        private static void TestInstalled05()
        {
            AnalysisResult result = AnalyzeInstalled(Fresh(), InstalledEntry("SynaMan", "Synametrics Technologies", @"C:\Missing\SynaMan", "5.7.1", false)); Equal(0, result.Context.Software.Count);
        }

        private static void TestInstalled06()
        {
            WindowsService service = FishService("SynaMan", @"C:\SynaMan\SynaMan.exe", "SynaMan", "Synametrics Technologies", "Running", TriState.No, TriState.No, TriState.No, TriState.No, TriState.No, "LocalSystem"); AnalysisResult result = AnalyzeInstalled(FishContext(service), InstalledEntry("SynaMan", "Synametrics Technologies", @"C:\SynaMan", "5.7.1", true)); SoftwareObservation item = result.Context.Software.Single(); string clean = RenderResult(result, false);
            True(item.ObservationStates.Contains("SERVICE_CONFIGURED") && item.ObservationStates.Contains("SERVICE_RUNNING") && item.ObservationStates.Contains("INSTALLED")); True(!item.ObservationStates.Contains("PROCESS_RUNNING")); Equal(0, item.ProcessPaths.Count); True(clean.Contains("Service    : SynaMan") && clean.Contains("Version    : 5.7.1") && clean.Contains("Source     : Registry ("));
        }

        private static void TestInstalled07()
        {
            string unique = "Software\\PrivTrace\\Tests\\INST07-" + Guid.NewGuid().ToString("N"), root = NewTempDirectory("installed-reader");
            try
            {
                using (RegistryKey test = Registry.CurrentUser.CreateSubKey(unique)) using (RegistryKey product = test.CreateSubKey("SynaMan")) { product.SetValue("DisplayName", "SynaMan"); product.SetValue("Publisher", "Synametrics Technologies"); product.SetValue("InstallLocation", root); product.SetValue("DisplayVersion", "5.7.2"); }
                List<SoftwareObservation> observations = new List<SoftwareObservation>(); using (RegistryKey test = Registry.CurrentUser.OpenSubKey(unique, false)) SoftwareDiscoveryEngine.AddInstalledCandidatesFromKey(observations, new SoftwareProfileCatalog().LoadEmbedded(), test, "HKCU\\" + unique, "CONTROLLED", "TEST_FIXTURE");
                SoftwareObservation item = observations.Single(); Equal("SW-SYNAMAN", item.ProfileId); True(item.ObservationStates.Contains("INSTALLED")); SoftwareVersionEvidence evidence = item.VersionEvidence.Single(); Equal("5.7.2", evidence.Value); Equal("UNINSTALL_REGISTRY", evidence.SourceType); Equal("TEST_FIXTURE", evidence.EvidenceOrigin); Equal("SUCCESS", evidence.ReadStatus);
            }
            catch (UnauthorizedAccessException ex) { throw new SkippedTestException("The host denied creation of the isolated INST07 HKCU test key: " + ex.Message); }
            finally { try { Registry.CurrentUser.DeleteSubKeyTree(unique); } catch { } DeleteDirectory(root); }
        }

        private static void TestServiceDiscoveryDistributions()
        {
            foreach (string arch in new[] { "x64", "x86" })
            {
                string exe = ServiceDiscoveryDistributionExe(arch); if (!File.Exists(exe)) throw new SkippedTestException("SERVICE-DISCOVERY distribution has not been generated yet: " + exe);
                True(File.Exists(exe)); ExternalResult list = RunExternal(exe, "--list-rules", Path.GetTempPath()); Equal(0, list.ExitCode); Equal(27, RuleLines(list.Output).Count);
                WithIsolatedExe("service-discovery-" + arch, exe, true, delegate(string copy, string cwd, string root)
                {
                    AnalysisContext fixture = FishContext(FishService("domain1", @"C:\glassfish4\glassfish\domains\domain1\bin\domain1Service.exe", "GlassFish Server", "Oracle", "Running", TriState.No, TriState.Yes, TriState.Yes, TriState.No, TriState.Yes, "LocalSystem"));
                    string fixturePath = Path.Combine(root, "fish-fixture.json"), jsonPath = Path.Combine(root, "result.json"); File.WriteAllText(fixturePath, new JavaScriptSerializer { MaxJsonLength = Int32.MaxValue }.Serialize(fixture), new UTF8Encoding(false));
                    ExternalResult clean = RunExternal(copy, "--offline-fixture " + Quote(fixturePath) + " --clean --json " + Quote(jsonPath), cwd); Equal(0, clean.ExitCode); True(clean.Output.Contains("PrivTrace v1.1.0") && clean.Output.Contains("Service    : domain1") && clean.Output.Contains("PT-013") && clean.Output.Contains("PT-016"));
                    ExternalResult verbose = RunExternal(copy, "--offline-fixture " + Quote(fixturePath) + " --verbose", cwd); Equal(0, verbose.ExitCode); True(verbose.Output.Contains("FINDINGS (FULL DIAGNOSTICS)") && verbose.Output.Contains("Configured :") && verbose.Output.Contains("SERVICE_CONFIGURED") && verbose.Output.Contains("origin=IMPORTED_UNVERIFIED"));
                    True(File.Exists(jsonPath)); AnalysisResult parsed = new JavaScriptSerializer { MaxJsonLength = Int32.MaxValue }.Deserialize<AnalysisResult>(File.ReadAllText(jsonPath)); Equal("1.1.0", parsed.Version); Equal(27, parsed.RulesEvaluated); Equal(1, Directory.GetFiles(Path.GetDirectoryName(copy), "*", SearchOption.AllDirectories).Length);
                });
            }
        }

        private static void TestVersionProvenanceDistributions()
        {
            foreach (string arch in new[] { "x64", "x86" })
            {
                string exe = VersionProvenanceDistributionExe(arch); RequireOfficialDistribution(exe); True(File.Exists(exe)); ExternalResult list = RunExternal(exe, "--list-rules", Path.GetTempPath()); Equal(0, list.ExitCode); Equal(27, RuleLines(list.Output).Count);
                WithIsolatedExe("version-provenance-" + arch, exe, true, delegate(string copy, string cwd, string root)
                {
                    AnalysisContext c = SoftwareFixture(@"C:\xampp\apache\bin\httpd.exe", 5630, "Apache HTTP Server", "Apache Software Foundation", SignatureStatus.Absent, null); c.SoftwareVersionEvidence.Add(new SoftwareVersionEvidence { ProductId = "SW-XAMPP", InstallationRoot = @"C:\xampp", Product = "XAMPP", SourceType = "XAMPP_PROPERTIES_INI", SourcePath = @"C:\xampp\properties.ini", SourceField = "base_stack_version", Value = "7.3.10-1", ObservationStatus = "OBSERVED", ReadStatus = "SUCCESS", Confidence = VersionConfidence.High }); WindowsProcess vmware = SoftwareProcess(@"C:\Program Files\VMware\VMware Tools\vmtoolsd.exe", 5631, "VMware Tools", "VMware, Inc.", SignatureStatus.Valid, "CN=VMware, Inc."); vmware.FileIdentity.ProductVersion = "11.1.1 build-16303738"; c.Processes.Add(vmware); AddSoftwareService(c, vmware, "VMTools", "LocalSystem", TriState.No);
                    string fixture = Path.Combine(root, "context-fixture.json"); File.WriteAllText(fixture, new JavaScriptSerializer { MaxJsonLength = Int32.MaxValue }.Serialize(c), new UTF8Encoding(false)); ExternalResult run = RunExternal(copy, "--offline-fixture \"" + fixture + "\" --clean", cwd); Equal(0, run.ExitCode); True(run.Output.Contains("PrivTrace v1.1.0") && run.Output.Contains("INTERESTING SOFTWARE") && run.Output.Contains("INFRASTRUCTURE SOFTWARE") && run.Output.Contains("Apache HTTP Server / XAMPP") && run.Output.Contains("VMware Tools") && run.Output.Contains("Process    : UNKNOWN (IMPORTED_UNVERIFIED)") && run.Output.Contains("Source     : UNKNOWN") && run.Output.Contains("Service    : VMTools")); True(run.Output.IndexOf("INTERESTING SOFTWARE", StringComparison.Ordinal) < run.Output.IndexOf("INFRASTRUCTURE SOFTWARE", StringComparison.Ordinal)); Equal(1, Directory.GetFiles(Path.GetDirectoryName(copy), "*", SearchOption.AllDirectories).Length);
                });
            }
        }

        private static void TestSoftwareHighVolume()
        {
            AnalysisContext c = Fresh(); c.ServiceEnumerationState = "OBSERVED"; c.TaskEnumerationState = "PARTIAL"; c.System.AlwaysInstallElevatedMachine = TriState.No; c.System.AlwaysInstallElevatedUser = TriState.No;
            int pid = 3000; for (int i = 0; i < 150; i++) c.Processes.Add(SoftwareProcess(@"C:\Windows\System32\normal" + i + ".exe", pid++, null, null, SignatureStatus.Unknown, null));
            for (int i = 0; i < 7; i++) c.Processes.Add(SoftwareProcess(@"C:\xampp\apache\bin\httpd.exe", pid++, "Apache HTTP Server", "Apache Software Foundation", SignatureStatus.Absent, null));
            for (int i = 0; i < 7; i++) c.Processes.Add(SoftwareProcess(@"C:\Program Files\TeamViewer\TeamViewer.exe", pid++, "TeamViewer", "TeamViewer Germany GmbH", SignatureStatus.Valid, "CN=TeamViewer Germany GmbH"));
            for (int i = 0; i < 6; i++) c.Processes.Add(SoftwareProcess(@"C:\Program Files\MySQL\MySQL Server 8.0\bin\mysqld.exe", pid++, "MySQL Server", "Oracle Corporation", SignatureStatus.Valid, "CN=Oracle Corporation"));
            AddSoftwareService(c, c.Processes[157], "TeamViewer", "LocalSystem", TriState.Yes);
            for (int i = 0; i < 39; i++) c.Services.Add(new WindowsService { Name = "Ordinary" + i, Account = @"LAB\operator", ExecutablePath = @"C:\Tools\ordinary" + i + ".exe", ExecutablePermission = new SecurityPermission { CanWrite = TriState.No }, DirectoryPermission = new SecurityPermission { CanCreate = TriState.No } });
            for (int i = 0; i < 15; i++) c.Tasks.Add(Task("\\Unknown" + i, TriState.Unknown, TriState.Yes));
            AnalysisResult r = AnalyzeSoftware(c); Equal(3, r.Context.Software.Count); Equal(1, r.Findings.Count(f => f.RuleId == "PT-013" && f.Status == EvaluationStatus.Confirmed)); string text = RenderResult(r, false); Equal(3, CountText(text, "    Version    :")); Equal(3, CountText(text, "    Process    :")); Equal(3, CountText(text, "    Source     :")); True(CountText(text, "Status: UNKNOWN") == 0); True(text.Split(new[] { '\n' }).Length < 130); True(text.IndexOf("TeamViewer", StringComparison.Ordinal) < text.IndexOf("Apache HTTP Server / XAMPP", StringComparison.Ordinal) && text.IndexOf("Apache HTTP Server / XAMPP", StringComparison.Ordinal) < text.IndexOf("MySQL", StringComparison.Ordinal));
        }

        private static void TestSoftwareJson()
        {
            string path = TempPath("software-profile-software"); try { AnalysisContext c = SoftwareFixture(@"C:\Program Files\TeamViewer\TeamViewer.exe", 2201, "TeamViewer", "TeamViewer Germany GmbH", SignatureStatus.Valid, "CN=TeamViewer Germany GmbH"); c.Processes[0].FileIdentity.ProductVersion = "15.0"; c.Processes[0].FileIdentity.FileVersion = "15.0.1.2"; AnalysisResult r = AnalyzeSoftware(c); JsonReporter.Write(r, path); string json = File.ReadAllText(path); True(json.Contains("SoftwareClassification") && json.Contains("ProductVersion") && json.Contains("FileVersion") && json.Contains("SignerSubject") && json.Contains("2201") && json.Contains("SW-TEAMVIEWER")); }
            finally { if (File.Exists(path)) File.Delete(path); }
        }

        private static void TestSoftwareSanitization()
        {
            string source = TempPath("software-profile-source"), sanitized = TempPath("software-profile-sanitized");
            try { AnalysisContext c = SoftwareFixture(@"C:\Users\PrivateUser\Apps\TeamViewer\TeamViewer.exe", 2202, "TeamViewer", "TeamViewer Germany GmbH", SignatureStatus.Valid, "CN=TeamViewer Germany GmbH"); c.Processes[0].OwnerAccount = @"PRIVATE\PrivateUser"; JsonReporter.Write(AnalyzeSoftware(c), source); ReportSanitizer.Sanitize(source, sanitized); string text = File.ReadAllText(sanitized); True(!text.Contains("PrivateUser") && text.Contains("<PATH-") && text.Contains("<ACCOUNT-")); }
            finally { if (File.Exists(source)) File.Delete(source); if (File.Exists(sanitized)) File.Delete(sanitized); }
        }

        private static void ExportSoftwareProfileSoftwareTraces()
        {
            List<SoftwareObservation> traces = new List<SoftwareObservation>();
            traces.AddRange(AnalyzeSoftware(SoftwareFixture(@"C:\xampp\apache\bin\httpd.exe", 2301, "Apache HTTP Server", "Apache Software Foundation", SignatureStatus.Absent, null)).Context.Software);
            AnalysisContext protectedVeyon = SoftwareFixture(@"C:\Program Files\Veyon\veyon-service.exe", 2302, "Veyon", "Veyon Solutions", SignatureStatus.Valid, "CN=Veyon Solutions"); AddSoftwareService(protectedVeyon, protectedVeyon.Processes[0], "VeyonService", "LocalSystem", TriState.No); traces.AddRange(AnalyzeSoftware(protectedVeyon).Context.Software);
            AnalysisContext writableVeyon = SoftwareFixture(@"C:\Program Files\Veyon\veyon-service.exe", 2303, "Veyon", "Veyon Solutions", SignatureStatus.Valid, "CN=Veyon Solutions"); AddSoftwareService(writableVeyon, writableVeyon.Processes[0], "VeyonService", "LocalSystem", TriState.Yes); traces.AddRange(AnalyzeSoftware(writableVeyon).Context.Software);
            AnalysisContext barracuda = SoftwareFixture(@"C:\Program Files\BarracudaDrive\BarracudaDrive.exe", 2304, "BarracudaDrive", "Real Time Logic", SignatureStatus.Absent, null); AddSoftwareService(barracuda, barracuda.Processes[0], "BarracudaDrive", "LocalSystem", TriState.Yes); traces.AddRange(AnalyzeSoftware(barracuda).Context.Software);
            AnalysisContext windows = SoftwareFixture(@"C:\Windows\System32\inetsrv\w3wp.exe", 2305, "Microsoft Internet Information Services", "Microsoft Corporation", SignatureStatus.Valid, "CN=Microsoft Windows"); AddSoftwareService(windows, windows.Processes[0], "W3SVC", "LocalSystem", TriState.Yes); traces.AddRange(AnalyzeSoftware(windows).Context.Software);
            Dictionary<string, object> artifact = new Dictionary<string, object>(); artifact["version"] = "1.1.0"; artifact["validationLevel"] = "SYNTHETIC_PASS"; artifact["liveMachineValidated"] = false; artifact["traces"] = traces;
            string path = Path.Combine(ProjectRoot(), "artifacts", "software-profile-software-traces.json"); File.WriteAllText(path, new JavaScriptSerializer { MaxJsonLength = Int32.MaxValue }.Serialize(artifact), new UTF8Encoding(false)); Equal(5, traces.Count); True(traces.All(t => t.Trace.Count >= 3 && t.Evidence.Count >= 2));
        }

        private static void ExportCleanOutputEvidence()
        {
            AnalysisContext fixture = Synthetic171Unknown(); AnalysisResult result = AnalyzeCorrelation(fixture); StringBuilder legacy = new StringBuilder();
            legacy.AppendLine("PrivTrace v1.1.0 REPRESENTATIVE BASELINE PROJECTION");
            foreach (Finding f in result.Findings.Where(x => x.Status == EvaluationStatus.Unknown)) legacy.AppendLine("[" + f.RuleSeverity.ToString().ToUpperInvariant() + "] " + f.RuleId + " - " + f.Name + "\r\nStatus: UNKNOWN | Confidence: UNKNOWN\r\nRecommendation: " + f.Recommendation);
            legacy.AppendLine("Confirmed: 0"); legacy.AppendLine("Potential: 0"); legacy.AppendLine("Unknown checks: " + result.Findings.Count(f => f.Status == EvaluationStatus.Unknown));
            string root = Path.Combine(ProjectRoot(), "artifacts");
            File.WriteAllText(Path.Combine(root, "clean-output-synthetic-171-fixture.json"), new JavaScriptSerializer { MaxJsonLength = Int32.MaxValue }.Serialize(fixture), new UTF8Encoding(false));
            File.WriteAllText(Path.Combine(root, "clean-output-synthetic-171-before.txt"), legacy.ToString(), new UTF8Encoding(false));
            File.WriteAllText(Path.Combine(root, "clean-output-synthetic-171-clean.txt"), RenderResult(result, false), new UTF8Encoding(false));
            File.WriteAllText(Path.Combine(root, "clean-output-synthetic-171-verbose.txt"), RenderResult(result, true), new UTF8Encoding(false));
            JsonReporter.Write(result, Path.Combine(root, "clean-output-synthetic-171-report.json"));
            True(File.ReadAllText(Path.Combine(root, "clean-output-synthetic-171-clean.txt")).Contains("Diagnostics: 171 checks unresolved."));
        }

        private static AnalysisContext Synthetic171Unknown()
        {
            AnalysisContext c = TaskAclNoise(148);
            for (int i = 0; i < 20; i++) { ScheduledTaskInfo t = Task("\\ExactUnknown" + i, TriState.No, TriState.Yes); t.Actions.Add(Action("C:\\Windows\\System32\\exact" + i + ".exe", false, TriState.Unknown)); c.Tasks.Add(t); }
            for (int i = 0; i < 2; i++) { ScheduledTaskInfo t = Task("\\RelativeUnknown" + i, TriState.No, TriState.Yes); t.Actions.Add(Action("relative" + i + ".exe", true, TriState.Unknown)); c.Tasks.Add(t); }
            ScheduledTaskInfo script = Task("\\ScriptUnknown", TriState.No, TriState.Yes); script.Actions.Add(Action("C:\\Jobs\\unknown.ps1", false, TriState.Unknown)); c.Tasks.Add(script);
            return c;
        }

        private static AnalysisContext TaskAclNoise(int count)
        {
            AnalysisContext c = Fresh(); c.ServiceEnumerationState = "OBSERVED"; c.TaskEnumerationState = "OBSERVED"; c.System.AlwaysInstallElevatedMachine = TriState.No; c.System.AlwaysInstallElevatedUser = TriState.No;
            for (int i = 0; i < count; i++) c.Tasks.Add(Task("\\AclUnknown" + i, TriState.Unknown, TriState.Yes));
            return c;
        }

        private static ScheduledTaskInfo Task(string path, TriState canModify, TriState higher)
        {
            return new ScheduledTaskInfo { Name = path.TrimStart('\\'), Path = path, Enabled = true, State = "Ready", Principal = higher == TriState.Yes ? "SYSTEM" : higher == TriState.No ? "LAB\\operator" : null, PrincipalIsHigher = higher, CanModify = canModify };
        }

        private static ScheduledTaskAction Action(string executable, bool ambiguous, TriState write)
        {
            return new ScheduledTaskAction { Type = "0", OriginalExecutable = executable, Executable = executable, PathAmbiguous = ambiguous, TargetPermission = new SecurityPermission { Target = executable, CanWrite = write } };
        }

        private static AnalysisContext RelativeTask(TriState candidateControl)
        {
            AnalysisContext c = Fresh(); ScheduledTaskInfo task = Task("\\Relative", TriState.No, TriState.Yes); ScheduledTaskAction action = Action("tool.exe", true, TriState.Unknown);
            if (candidateControl != TriState.Unknown) { action.HijackCandidates.Add("C:\\Jobs\\tool.exe"); action.HijackCandidatePermissions.Add(new SecurityPermission { Target = "C:\\Jobs", CanWrite = TriState.No, CanCreate = candidateControl }); }
            task.Actions.Add(action); c.Tasks.Add(task); return c;
        }

        private static string Render(AnalysisContext context, bool verbose) { return RenderResult(AnalyzeCorrelation(context), verbose); }
        private static string RenderResult(AnalysisResult result, bool verbose) { StringWriter output = new StringWriter(); TextWriter prior = Console.Out; try { Console.SetOut(output); ConsoleReporter.Print(result, verbose); } finally { Console.SetOut(prior); } return output.ToString(); }
        private static string RenderSpanish(AnalysisResult result, bool verbose) { StringWriter output = new StringWriter(); TextWriter prior = Console.Out; try { Console.SetOut(output); SpanishConsoleReporter.Print(result, verbose); } finally { Console.SetOut(prior); } return output.ToString(); }
        private static int CountText(string value, string needle) { return (value ?? String.Empty).Split(new[] { needle }, StringSplitOptions.None).Length - 1; }

        private static string TempPath(string suffix) { return Path.Combine(Path.GetTempPath(), "privtrace-evidence-integrity-" + suffix + "-" + Guid.NewGuid().ToString("N") + ".json"); }

        private sealed class ExternalResult { internal int ExitCode; internal string Output; internal string Error; }

        private static void ForArchitectures(Action<string, string> action)
        {
            foreach (string arch in new[] { "x64", "x86" }) { string exe = DistributionExe(arch); RequireOfficialDistribution(exe); action(arch, exe); }
        }

        private static void RequireOfficialDistribution(string exe) { if (!File.Exists(exe)) throw new SkippedTestException("Official distribution artifact has not been generated: " + exe); }

        private static string DistributionExe(string arch)
        {
            return Path.Combine(ProjectRoot(), "dist", "PrivTrace-v1.1.0-win-" + arch + ".exe");
        }

        private static string CleanOutputDistributionExe(string arch) { return DistributionExe(arch); }

        private static string SoftwareProfileDistributionExe(string arch) { return DistributionExe(arch); }
        private static string VersionProvenanceDistributionExe(string arch) { return DistributionExe(arch); }
        private static string ServiceDiscoveryDistributionExe(string arch) { return DistributionExe(arch); }

        private static ExternalResult RunExternal(string exe, string arguments, string workingDirectory)
        {
            ProcessStartInfo start = new ProcessStartInfo(exe, arguments ?? String.Empty) { WorkingDirectory = workingDirectory, UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true };
            using (Process process = Process.Start(start))
            {
                string output = process.StandardOutput.ReadToEnd(), error = process.StandardError.ReadToEnd(); process.WaitForExit();
                return new ExternalResult { ExitCode = process.ExitCode, Output = output, Error = error };
            }
        }

        private static List<string> RuleLines(string output)
        {
            return (output ?? String.Empty).Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries).Where(x => Regex.IsMatch(x, @"^PT-\d{3}\s")).ToList();
        }

        private static void WithIsolatedExe(string arch, string sourceExe, bool pathWithSpaces, Action<string, string, string> action)
        {
            string root = NewTempDirectory(pathWithSpaces ? "single exe path with spaces " + arch : "single-exe-" + arch);
            try
            {
                string package = Path.Combine(root, pathWithSpaces ? "package with spaces" : "package"), working = Path.Combine(root, "different-current-directory");
                Directory.CreateDirectory(package); Directory.CreateDirectory(working);
                string copy = Path.Combine(package, "PrivTrace.exe"); File.Copy(sourceExe, copy, true);
                action(copy, working, root);
            }
            finally { DeleteDirectory(root); }
        }

        private static string NewTempDirectory(string label)
        {
            string path = Path.Combine(Path.GetTempPath(), "PrivTrace-" + label + "-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(path); return path;
        }

        private static void DeleteDirectory(string path)
        {
            if (!String.IsNullOrEmpty(path) && path.StartsWith(Path.GetTempPath(), StringComparison.OrdinalIgnoreCase) && Directory.Exists(path)) Directory.Delete(path, true);
        }

        private static string Quote(string path) { return "\"" + path.Replace("\"", "\\\"") + "\""; }

        private static string Sha256(byte[] bytes)
        {
            using (SHA256 sha = SHA256.Create()) return BitConverter.ToString(sha.ComputeHash(bytes)).Replace("-", String.Empty);
        }

        private static string RuleSignature(IList<RuleDefinition> items) { return new JavaScriptSerializer { MaxJsonLength = Int32.MaxValue }.Serialize(items); }
        private static string FindingSignature(IList<Finding> items) { return String.Join("|", items.Select(x => x.RuleId + ":" + x.Status + ":" + x.Severity + ":" + x.Confidence + ":" + x.Target).ToArray()); }

        private static string DirectorySignature(string root)
        {
            return String.Join("|", Directory.GetFiles(root, "*", SearchOption.AllDirectories).OrderBy(x => x, StringComparer.OrdinalIgnoreCase).Select(x => x.Substring(root.Length).ToLowerInvariant() + ":" + new FileInfo(x).Length + ":" + Sha256(File.ReadAllBytes(x))).ToArray());
        }

        private static void TestReportSanitization()
        {
            string source = TempPath("source"), sanitized = TempPath("sanitized");
            try
            {
                AnalysisContext c = CorrelationFixtures.Create("R01"); c.System.MachineName = "PRIVATEHOST"; JsonReporter.Write(AnalyzeCorrelation(c), source); ReportSanitizer.Sanitize(source, sanitized);
                string output = File.ReadAllText(sanitized); True(!output.Contains(@"LAB\operator") && !output.Contains("S-1-5-21-500-500-500-1105") && !output.Contains("PRIVATEHOST")); True(output.Contains("<ACCOUNT-001>") && output.Contains("<SID-") && output.Contains("<HOST-001>"));
                True(output.Split(new[] { "<ACCOUNT-001>" }, StringSplitOptions.None).Length > 2);
            }
            finally { if (File.Exists(source)) File.Delete(source); if (File.Exists(sanitized)) File.Delete(sanitized); }
        }

        private static void TestReportImportIntegrity()
        {
            string source = TempPath("import");
            try
            {
                AnalysisResult original = AnalyzeCorrelation(CorrelationFixtures.Create("B01")); JsonReporter.Write(original, source); string before = File.ReadAllText(source); ReportInspection inspection = ReportImporter.Inspect(source); string after = File.ReadAllText(source);
                True(inspection.SchemaValid); Equal(before, after); Equal(original.Findings.Count, inspection.Findings); True(inspection.ActiveRules.Contains("PT-003") && !inspection.ActiveRules.Contains("PT-004"));
            }
            finally { if (File.Exists(source)) File.Delete(source); }
        }

        private static void ExportEvidenceIntegrityTraces()
        {
            List<CorrelationTrace> traces = new List<CorrelationTrace>(); foreach (string id in new[] { "R01", "B01", "D04" }) traces.AddRange(AnalyzeCorrelation(CorrelationFixtures.Create(id)).CorrelationTraces);
            CorrelationTrace backup = traces.Single(t => t.ScenarioId == "B01"); True(backup.SupportingRuleIds.Contains("PT-003") && !backup.SupportingRuleIds.Contains("PT-004") && backup.RuledOutRuleIds.Contains("PT-004"));
            Dictionary<string, object> report = new Dictionary<string, object>(); report["version"] = "1.1.0"; report["schemaVersion"] = "1.1"; report["generatedUtc"] = DateTime.UtcNow.ToString("o"); report["validationLevel"] = "SYNTHETIC_PASS"; report["liveMachineValidated"] = false; report["engine"] = "AnalyzerEngine + RuleEngine + AdvancedCorrelation"; report["traces"] = traces;
            string path = Path.Combine(ProjectRoot(), "artifacts", "evidence-integrity-regression-traces.json"); File.WriteAllText(path, new JavaScriptSerializer { MaxJsonLength = Int32.MaxValue }.Serialize(report), new UTF8Encoding(false)); True(File.ReadAllText(path).Contains("RuledOutRuleIds"));
        }

        private static void ValidateSyntheticScenario(string machine, string variant, AnalysisContext c)
        {
            Dictionary<string, EvaluationStatus> observed = new Dictionary<string, EvaluationStatus>(StringComparer.OrdinalIgnoreCase);
            if (machine == "SYN-INSTALLER-POLICY-001")
            {
                EvaluationStatus expected = variant == "A" || variant == "B" ? EvaluationStatus.Confirmed : variant == "E" ? EvaluationStatus.Unknown : EvaluationStatus.RuledOut;
                Finding f = One("PT-021", c); Equal(expected, f.Status); observed["PT-021"] = f.Status;
            }
            else if (machine == "SYN-SVC-CONFIG-001")
            {
                Finding group = One("PT-009", c), service = One("PT-014", c); Equal(EvaluationStatus.Potential, group.Status);
                EvaluationStatus expected = variant == "C" ? EvaluationStatus.RuledOut : variant == "E" ? EvaluationStatus.Unknown : EvaluationStatus.Confirmed;
                Equal(expected, service.Status); observed["PT-009"] = group.Status; observed["PT-014"] = service.Status;
            }
            else if (machine == "SYN-BACKUP-001")
            {
                Finding backup = One("PT-003", c), restore = One("PT-004", c), group = One("PT-010", c);
                EvaluationStatus privilegeExpected = variant == "C" ? EvaluationStatus.RuledOut : variant == "E" ? EvaluationStatus.Unknown : EvaluationStatus.Potential;
                EvaluationStatus groupExpected = variant == "E" ? EvaluationStatus.Unknown : EvaluationStatus.Potential;
                Equal(privilegeExpected, backup.Status); Equal(variant == "A" ? EvaluationStatus.Unknown : privilegeExpected, restore.Status); Equal(groupExpected, group.Status);
                if (variant == "D") { Equal(Severity.Low, backup.Severity); Equal(Severity.Low, restore.Severity); }
                observed["PT-003"] = backup.Status; observed["PT-004"] = restore.Status; observed["PT-010"] = group.Status;
            }
            else if (machine == "SYN-DNS-001")
            {
                EvaluationStatus expected = variant == "C" || variant == "D" ? EvaluationStatus.RuledOut : variant == "E" ? EvaluationStatus.Unknown : EvaluationStatus.Potential;
                Finding f = One("PT-011", c); Equal(expected, f.Status); observed["PT-011"] = f.Status;
            }
            else if (machine == "SYN-SVC-WRITE-001" || machine == "SYN-SVC-WRITE-002")
            {
                EvaluationStatus expected = variant == "C" ? EvaluationStatus.RuledOut : variant == "D" ? EvaluationStatus.Potential : variant == "E" ? EvaluationStatus.Unknown : EvaluationStatus.Confirmed;
                Finding f = One("PT-013", c); Equal(expected, f.Status); observed["PT-013"] = f.Status;
            }
            else if (machine == "SYN-TASK-WRITE-001")
            {
                EvaluationStatus expected = variant == "B" ? EvaluationStatus.Confirmed : variant == "D" ? EvaluationStatus.Potential : variant == "E" ? EvaluationStatus.Unknown : EvaluationStatus.RuledOut;
                Finding f = One("PT-017", c); Equal(expected, f.Status); observed["PT-017"] = f.Status;
            }
            else if (machine == "SYN-DLL-SEARCH-001")
            {
                Finding binary = One("PT-013", c), serviceDll = One("PT-027", c);
                Equal(EvaluationStatus.RuledOut, binary.Status); Equal(EvaluationStatus.RuledOut, serviceDll.Status);
                True(c.ExecutionRelationships.Any(r => r.Classification == "SYNTHETIC_UNMODELED"));
                observed["PT-013"] = binary.Status; observed["PT-027"] = serviceDll.Status;
            }
            else throw new Exception("No SYNTHETIC-MATRIX expectations for " + machine);
            RecordSyntheticScenario(machine, variant, observed);
        }

        private static void RecordSyntheticScenario(string machine, string variant, IDictionary<string, EvaluationStatus> observed)
        {
            Dictionary<string, object> row = new Dictionary<string, object>(); row["machine"] = machine; row["variant"] = variant;
            row["baselineCase"] = variant == "A"; row["validationLevel"] = "SYNTHETIC_PASS"; row["classification"] = SyntheticScenarioClassification(machine);
            row["observed"] = observed.ToDictionary(x => x.Key, x => x.Value.ToString()); row["diagnostics"] = new string[0]; syntheticScenarioResults.Add(row);
        }

        private static string SyntheticScenarioClassification(string machine)
        {
            if (machine == "SYN-INSTALLER-POLICY-001" || machine == "SYN-SVC-WRITE-001" || machine == "SYN-SVC-WRITE-002") return "FULL_DETECTION";
            if (machine == "SYN-SVC-CONFIG-001" || machine == "SYN-BACKUP-001" || machine == "SYN-DNS-001") return "PARTIAL_DETECTION";
            return machine == "SYN-TASK-WRITE-001" ? "COLLECTION_LIMITATION" : "OUT_OF_SCOPE";
        }

        private static void ExportSyntheticScenarioResults()
        {
            Equal(40, syntheticScenarioResults.Count); string root = ProjectRoot();
            string directory = Path.Combine(root, "artifacts"); Directory.CreateDirectory(directory); string path = Path.Combine(directory, "synthetic-scenario-synthetic-results.json");
            Dictionary<string, object> report = new Dictionary<string, object>(); report["version"] = "1.1.0"; report["generatedUtc"] = DateTime.UtcNow.ToString("o"); report["validationLevel"] = "SYNTHETIC_PASS"; report["liveMachineValidated"] = false; report["results"] = syntheticScenarioResults;
            File.WriteAllText(path, new JavaScriptSerializer { MaxJsonLength = Int32.MaxValue }.Serialize(report), new UTF8Encoding(false)); Dictionary<string, object> parsed = JsonObject(path); Equal("1.1.0", parsed["version"] as string); True(File.ReadAllText(path).Contains("SYN-DLL-SEARCH-001"));
        }

        private static string ProjectRoot()
        {
            string current = AppDomain.CurrentDomain.BaseDirectory;
            for (int i = 0; i < 8; i++)
            {
                if (File.Exists(Path.Combine(current, "src", "PrivTrace", "PrivTrace.csproj"))) return current;
                DirectoryInfo parent = Directory.GetParent(current); if (parent == null) break; current = parent.FullName;
            }
            throw new DirectoryNotFoundException("Could not locate the PrivTrace project root for result export.");
        }

        private static AnalysisContext Fresh() { return new AnalysisContext { EvidenceOrigin = "TEST_FIXTURE", Token = new TokenSnapshot { UserName = "LAB\\operator", IntegrityLevel = "Medium", Elevated = TriState.No }, System = new SystemSnapshot { IsWindows = true, Architecture = "x64", OsVersion = "Synthetic" } }; }

        private static AnalysisContext Build(string id, string mode)
        {
            AnalysisContext c = Fresh(); bool positive = mode == "positive", unknown = mode == "unknown";
            int n = Int32.Parse(id.Substring(3));
            if (n == 21)
            {
                c.System.AlwaysInstallElevatedMachine = positive ? TriState.Yes : unknown ? TriState.Unknown : TriState.Yes;
                c.System.AlwaysInstallElevatedUser = positive ? TriState.Yes : unknown ? TriState.Unknown : TriState.No;
            }
            else if (n == 22)
            {
                if (positive) c.Token.Groups.Add(Group(id));
                if (unknown) c.Token.Errors.Add("Synthetic token groups unavailable");
            }
            else if (n == 23)
            {
                if (positive) c.Token.Privileges.Add(new TokenPrivilege { Name = "SeTcbPrivilege", Present = true, Enabled = true });
                if (unknown) c.Token.Errors.Add("Synthetic token privileges unavailable");
            }
            else if (n == 24)
            {
                if (positive)
                {
                    c.Services.Add(new WindowsService { Name = "Spooler", State = "Running", Account = "LocalSystem" });
                    c.Token.Privileges.Add(new TokenPrivilege { Name = "SeImpersonatePrivilege", Present = true, Enabled = true });
                }
                else if (unknown) c.Errors.Add("Services: Synthetic access denied");
                else c.Services.Add(new WindowsService { Name = "Spooler", State = "Stopped", Account = "LocalSystem" });
            }
            else if (n == 26)
            {
                WindowsService service = Service(TriState.No, TriState.No, TriState.No);
                service.RegistryEvidence.Add(new ServiceRegistryEvidence { View = "Registry64", ServiceKeyPath = @"HKLM\SYSTEM\CurrentControlSet\Services\SyntheticService", ServiceKeyPermission = RegistryPermission(positive ? TriState.Yes : unknown ? TriState.Unknown : TriState.No, TriState.No), ParametersKeyPermission = RegistryPermission(TriState.No, TriState.No) });
                c.Services.Add(service);
            }
            else if (n == 27)
            {
                WindowsService service = Service(TriState.No, TriState.No, TriState.No); service.ServiceType = "0x20"; service.ProcessId = 432; service.BinaryPath = @"C:\Windows\System32\svchost.exe -k Vendor"; service.ExecutablePath = @"C:\Windows\System32\svchost.exe"; service.StartType = "Manual"; service.CanStart = TriState.Yes;
                TriState write = positive ? TriState.Yes : unknown ? TriState.Unknown : TriState.No;
                service.RegistryEvidence.Add(new ServiceRegistryEvidence { View = "Registry64", ServiceDll = @"%SystemRoot%\System32\vendor.dll", ServiceDllPath = @"C:\Windows\System32\vendor.dll", ServiceDllExists = unknown ? TriState.Unknown : TriState.Yes, ServiceDllPermission = new SecurityPermission { Target = @"C:\Windows\System32\vendor.dll", ObjectType = "File", CanWrite = write, CanCreate = TriState.No, CanDelete = TriState.No, CanChangePermissions = TriState.No }, ServiceDllDirectoryPermission = new SecurityPermission { Target = @"C:\Windows\System32", ObjectType = "Directory", CanCreate = TriState.No } });
                c.Services.Add(service);
            }
            else if (n <= 8 || n == 25)
            {
                if (positive) c.Token.Privileges.Add(new TokenPrivilege { Name = n == 25 ? "SeCreateTokenPrivilege" : PrivilegeName(n), Present = true, Enabled = true });
                if (unknown) c.Token.Errors.Add("Synthetic access denied");
            }
            else if (n <= 12)
            {
                if (positive) c.Token.Groups.Add(Group(id));
                if (unknown) c.Token.Errors.Add("Synthetic token groups unavailable");
            }
            else if (n <= 16)
            {
                WindowsService s = Service(positive ? TriState.Yes : unknown ? TriState.Unknown : TriState.No, positive ? TriState.Yes : unknown ? TriState.Unknown : TriState.No, positive ? TriState.Yes : unknown ? TriState.Unknown : TriState.No);
                if (n == 14) s.CanChangeConfig = positive ? TriState.Yes : unknown ? TriState.Unknown : TriState.No;
                if (n == 15 && (positive || unknown)) { s.UnquotedCandidates.Add("C:\\Program.exe"); s.UnquotedCandidatePermissions.Add(new SecurityPermission { CanWrite = positive ? TriState.No : TriState.Unknown, CanCreate = positive ? TriState.Yes : TriState.Unknown }); }
                c.Services.Add(s);
            }
            else
            {
                TriState permission = positive ? TriState.Yes : unknown ? TriState.Unknown : TriState.No;
                TriState higher = positive ? TriState.Yes : unknown ? TriState.Unknown : TriState.No;
                c = Tftp(permission, higher, true, true);
                if (n == 18) c.Tasks[0].CanModify = permission;
                if (n == 19) c.Tasks[0].Actions[0].Executable = "C:\\Backup\\job.ps1";
                if (n == 20)
                {
                    ScheduledTaskAction action = c.Tasks[0].Actions[0]; action.Executable = "tool.exe"; action.PathAmbiguous = true;
                    if (positive) { action.HijackCandidates.Add("C:\\Jobs\\tool.exe"); action.HijackCandidatePermissions.Add(new SecurityPermission { Target = "C:\\Jobs", CanWrite = TriState.No, CanCreate = TriState.Yes }); }
                }
            }
            return c;
        }

        private static string PrivilegeName(int n) { return new[] { "", "SeImpersonatePrivilege", "SeAssignPrimaryTokenPrivilege", "SeBackupPrivilege", "SeRestorePrivilege", "SeDebugPrivilege", "SeTakeOwnershipPrivilege", "SeLoadDriverPrivilege", "SeManageVolumePrivilege" }[n]; }
        private static WindowsGroup Group(string id) { if (id == "PT-011") return new WindowsGroup { Sid = "S-1-5-21-1-2-3-1101", Name = "LAB\\DnsAdmins", Enabled = true }; return new WindowsGroup { Sid = id == "PT-009" ? "S-1-5-32-549" : id == "PT-010" ? "S-1-5-32-551" : id == "PT-022" ? "S-1-5-32-573" : "S-1-5-32-550", Name = "Localized name", Enabled = true }; }
        private static WindowsService Service(TriState binaryWrite, TriState directoryCreate, TriState config)
        {
            return new WindowsService { Name = "SyntheticService", BinaryPath = "C:\\Program Files\\Vendor App\\svc.exe", ExecutablePath = "C:\\Program Files\\Vendor App\\svc.exe", Account = "LocalSystem", State = "Stopped", StartType = "Automatic", CanStart = TriState.No, CanChangeConfig = config, ExecutablePermission = new SecurityPermission { CanWrite = binaryWrite }, DirectoryPermission = new SecurityPermission { CanCreate = directoryCreate }, UnquotedCandidates = new List<string>() };
        }
        private static SecurityPermission RegistryPermission(TriState setValue, TriState createSubKey) { return new SecurityPermission { ObjectType = "RegistryKey", CanWrite = setValue, CanCreate = createSubKey, CanDelete = TriState.No, CanChangePermissions = TriState.No }; }
        private static AnalysisContext Tftp(TriState write, TriState higher, bool enabled, bool associated)
        {
            AnalysisContext c = Fresh(); if (!associated) return c;
            ScheduledTaskInfo task = new ScheduledTaskInfo { Name = "Backup", Path = "\\Backup", Enabled = enabled, Principal = higher == TriState.Yes ? "SYSTEM" : higher == TriState.No ? "LAB\\operator" : null, PrincipalIsHigher = higher, CanModify = TriState.No };
            task.Actions.Add(new ScheduledTaskAction { Type = "0", Executable = "C:\\Backup\\TFTP.EXE", Arguments = "-i 192.168.234.57 get backup.txt", WorkingDirectory = "C:\\Backup", TargetPermission = new SecurityPermission { Target = "C:\\Backup\\TFTP.EXE", CanWrite = write }, HijackCandidates = new List<string>() });
            c.Tasks.Add(task); return c;
        }

        private static void TestDuplicate() { List<RuleDefinition> copy = new List<RuleDefinition>(rules); copy.Add(rules[0]); Throws(delegate { new RuleCatalog().Validate(copy); }); }
        private static void TestMissingMetadata() { RuleDefinition old = rules[0]; string name = old.Name; old.Name = null; try { Throws(delegate { new RuleCatalog().Validate(rules); }); } finally { old.Name = name; } }
        private static void TestMalformedReference() { RuleDefinition old = rules[0]; string url = old.References[0].Url; old.References[0].Url = "not a URL"; try { Throws(delegate { new RuleCatalog().Validate(rules); }); } finally { old.References[0].Url = url; } }
        private static void TestMalformedId() { RuleDefinition old = rules[0]; string id = old.Id; old.Id = "PT-1"; try { Throws(delegate { new RuleCatalog().Validate(rules); }); } finally { old.Id = id; } }
        private static void TestRuleIdGap() { List<RuleDefinition> copy = rules.Where(r => r.Id != "PT-012").ToList(); Throws(delegate { new RuleCatalog().Validate(copy); }); }
        private static string KnowledgePath(params string[] parts) { string path = Path.Combine(ProjectRoot(), "data", "knowledge"); foreach (string part in parts) path = Path.Combine(path, part); return path; }
        private static Dictionary<string, object> JsonObject(string path) { return (Dictionary<string, object>)new JavaScriptSerializer { MaxJsonLength = Int32.MaxValue }.DeserializeObject(File.ReadAllText(path)); }
        private static void TestKnowledgeIntegrity()
        {
            Regex syntheticId = new Regex(@"^SYN-[A-Z0-9]+(?:-[A-Z0-9]+)*$", RegexOptions.CultureInvariant);
            foreach (RuleDefinition rule in rules) foreach (string scenario in rule.RelatedLabs) True(syntheticId.IsMatch(scenario));
        }
        private static void TestPrimaryReferences()
        {
            foreach (RuleDefinition rule in rules)
            {
                foreach (ReferenceMetadata reference in rule.References)
                {
                    Uri uri; True(Uri.TryCreate(reference.Url, UriKind.Absolute, out uri));
                    Equal("learn.microsoft.com", uri.Host.ToLowerInvariant());
                    Equal("Microsoft", reference.Author);
                }
            }
        }
        private static void TestEffectiveAcl()
        {
            string path = Path.Combine(Path.GetTempPath(), "PrivTrace-acl-" + Guid.NewGuid().ToString("N") + ".tmp");
            try
            {
                File.WriteAllText(path, "synthetic"); AccessEvaluator evaluator = new AccessEvaluator(); SecurityPermission allowed = evaluator.EvaluatePath(path, false); if (allowed.CanWrite != TriState.Yes) throw new Exception("Allow evaluation=" + allowed.CanWrite + ", detail=" + allowed.Detail + ", Win32=" + evaluator.LastAccessCheckError);
                SecurityIdentifier sid = WindowsIdentity.GetCurrent().User; FileSecurity security = File.GetAccessControl(path, AccessControlSections.Access);
                security.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.WriteData | FileSystemRights.AppendData | FileSystemRights.WriteAttributes, AccessControlType.Deny)); File.SetAccessControl(path, security);
                Equal(TriState.No, evaluator.EvaluatePath(path, false).CanWrite);
            }
            finally { if (File.Exists(path)) File.Delete(path); }
        }
        private static void TestRegistryAcl()
        {
            string path = Path.Combine(Path.GetTempPath(), "PrivTrace-regacl-" + Guid.NewGuid().ToString("N") + ".tmp");
            try
            {
                File.WriteAllText(path, "synthetic"); AccessEvaluator evaluator = new AccessEvaluator(); FileSecurity security = File.GetAccessControl(path, AccessControlSections.Access | AccessControlSections.Owner | AccessControlSections.Group);
                Equal(TriState.Yes, evaluator.EvaluateRegistrySddl(security.GetSecurityDescriptorSddlForm(AccessControlSections.All), 0x2));
                security.AddAccessRule(new FileSystemAccessRule(WindowsIdentity.GetCurrent().User, FileSystemRights.WriteData, AccessControlType.Deny)); File.SetAccessControl(path, security);
                string deny = File.GetAccessControl(path, AccessControlSections.Access | AccessControlSections.Owner | AccessControlSections.Group).GetSecurityDescriptorSddlForm(AccessControlSections.All);
                Equal(TriState.No, evaluator.EvaluateRegistrySddl(deny, 0x2));
            }
            finally { if (File.Exists(path)) File.Delete(path); }
        }
        private static void TestProcessEnumeration()
        {
            ProcessCollector collector = new ProcessCollector(); List<WindowsProcess> processes = collector.Collect();
            WindowsProcess current = processes.FirstOrDefault(p => p.ProcessId == System.Diagnostics.Process.GetCurrentProcess().Id);
            True(current != null); Equal("ACCESSIBLE", current.AccessStatus); True(!String.IsNullOrWhiteSpace(current.ImagePath)); True(current.ParentProcessId >= 0);
        }
        private static void TestSharedServiceProcess()
        {
            AnalysisContext c = Fresh(); c.Processes.Add(new WindowsProcess { ProcessId = 700, ParentProcessId = 1, Name = "svchost.exe", ImagePath = "C:\\Windows\\System32\\svchost.exe", AccessStatus = "ACCESSIBLE" });
            c.Services.Add(new WindowsService { Name = "SvcA", ProcessId = 700, ExecutablePath = "C:\\Windows\\System32\\svchost.exe", Account = "LocalSystem" });
            c.Services.Add(new WindowsService { Name = "SvcB", ProcessId = 700, ExecutablePath = "C:\\Windows\\System32\\svchost.exe", Account = "LocalSystem" });
            ExecutionCorrelation.Correlate(c); Equal(2, c.Processes[0].ServiceNames.Count); True(c.Processes[0].ServiceNames.Contains("SvcA")); True(c.Processes[0].ServiceNames.Contains("SvcB"));
        }
        private static void TestBinaryDeduplication()
        {
            AnalysisContext c = Veyon(TriState.Yes, "LocalSystem", true, "ACCESSIBLE");
            Equal(1, c.Binaries.Count); True(c.Binaries[0].Sources.Contains("ProcessImage")); True(c.Binaries[0].Sources.Contains("ServiceConfiguration")); True(c.Binaries[0].ObservedProcessImage);
        }
        private static void TestProcessOnly()
        {
            AnalysisContext c = Fresh(); c.Processes.Add(new WindowsProcess { ProcessId = 800, Name = "elevated.exe", ImagePath = "C:\\Tools\\elevated.exe", OwnerAccount = "NT AUTHORITY\\SYSTEM", IntegrityLevel = "System", AccessStatus = "ACCESSIBLE" });
            ExecutionCorrelation.Correlate(c); Equal(EvaluationStatus.RuledOut, One("PT-013", c).Status); Equal(EvaluationStatus.RuledOut, One("PT-017", c).Status);
        }
        private static void TestTaskWithoutProcess()
        {
            AnalysisContext c = Tftp(TriState.Yes, TriState.Yes, true, true); ExecutionCorrelation.Correlate(c);
            Finding finding = One("PT-017", c); Equal(EvaluationStatus.Confirmed, finding.Status); True(finding.Evidence.Any(e => e.Kind == "TaskActionReference")); True(finding.Evidence.Any(e => e.Kind == "ObservedProcess" && !e.Positive));
        }
        private static void TestExecutionReports()
        {
            AnalysisContext c = Veyon(TriState.Yes, "LocalSystem", true, "ACCESSIBLE"); StringWriter output = new StringWriter(); TextWriter original = Console.Out;
            try { Console.SetOut(output); ConsoleReporter.PrintProcesses(c.Processes, true); ConsoleReporter.PrintBinaries(c.Binaries, true); }
            finally { Console.SetOut(original); }
            string text = output.ToString(); True(text.Contains("PROCESSES")); True(text.Contains("BINARIES")); True(text.Contains("VeyonSvc"));
        }
        private static void TestRegistryCreateOnly()
        {
            AnalysisContext c = Fresh(); WindowsService service = Service(TriState.No, TriState.No, TriState.No);
            service.RegistryEvidence.Add(new ServiceRegistryEvidence { ServiceKeyPath = @"HKLM\SYSTEM\CurrentControlSet\Services\SyntheticService", ServiceKeyPermission = RegistryPermission(TriState.No, TriState.Yes) }); c.Services.Add(service);
            Equal(EvaluationStatus.Potential, One("PT-026", c).Status);
        }
        private static void TestMissingServiceDll()
        {
            AnalysisContext c = Build("PT-027", "negative"); WindowsService service = c.Services[0]; ServiceRegistryEvidence evidence = service.RegistryEvidence[0];
            evidence.ServiceDllExists = TriState.No; evidence.ServiceDllPermission.CanWrite = TriState.Unknown; evidence.ServiceDllDirectoryPermission.CanCreate = TriState.Yes;
            Equal(EvaluationStatus.Potential, One("PT-027", c).Status);
        }
        private static void TestServiceDllRelationship()
        {
            AnalysisContext c = Build("PT-027", "positive"); c.Processes.Add(new WindowsProcess { ProcessId = 432, ImagePath = @"C:\Windows\System32\svchost.exe", OwnerAccount = "LocalSystem", AccessStatus = "ACCESSIBLE" });
            ExecutionCorrelation.Correlate(c); Equal(1, c.ExecutionRelationships.Count(r => r.SourceKind == "ServiceDll")); Equal(1, c.ExecutionRelationships.Count(r => r.SourceKind == "ServiceExecutable")); ExecutionRelationship relation = c.ExecutionRelationships.Single(r => r.SourceKind == "ServiceDll"); Equal("CONFIGURED", relation.Classification); True(relation.Detail.Contains("not observed"));
            BinaryArtifact dll = c.Binaries.Single(b => b.Sources.Contains("ServiceDllConfiguration")); True(!dll.ObservedProcessImage); Equal(1, dll.Sources.Count(s => s == "ServiceDllConfiguration"));
        }
        private static void TestUnknownServiceDll() { Equal(EvaluationStatus.Unknown, One("PT-027", Build("PT-027", "unknown")).Status); }
        private static void TestServiceNoise()
        {
            AnalysisContext c = Fresh();
            for (int i = 0; i < 300; i++) { WindowsService service = Service(TriState.No, TriState.No, TriState.No); service.Name = "Safe" + i; service.Account = "NT AUTHORITY\\LocalService"; service.ServiceType = "0x10"; service.RegistryEvidence.Add(new ServiceRegistryEvidence { ServiceKeyPermission = RegistryPermission(TriState.No, TriState.No) }); c.Services.Add(service); }
            Equal(EvaluationStatus.RuledOut, One("PT-026", c).Status); Equal(EvaluationStatus.RuledOut, One("PT-027", c).Status);
        }
        private static void TestServiceRegistryFixture()
        {
            string path = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "fixtures", "service-registry-correlation.json"); AnalysisContext c = new AnalyzerEngine().LoadFixture(path);
            Equal(EvaluationStatus.Confirmed, One("PT-026", c).Status); Equal(EvaluationStatus.Confirmed, One("PT-027", c).Status); Equal(1, c.ExecutionRelationships.Count(r => r.SourceKind == "ServiceDll")); Equal(2, c.ExecutionRelationships.Count(r => r.SourceKind == "ServiceExecutable")); True(c.ExecutionRelationships.Where(r => r.SourceKind == "ServiceDll").All(r => r.Classification == "CONFIGURED"));
        }
        private static AnalysisContext Veyon(TriState write, string account, bool withProcess, string accessStatus)
        {
            AnalysisContext c = Fresh(); string path = "C:\\Users\\Ela Arwel\\Veyon\\veyon-service.exe";
            c.Services.Add(new WindowsService { Name = "VeyonSvc", ProcessId = withProcess ? 600 : 0, BinaryPath = "\"" + path + "\" --service", ExecutablePath = path, Account = account, State = "Running", ExecutablePermission = new SecurityPermission { Target = path, ObjectType = "File", CanWrite = write, CanCreate = TriState.No, CanDelete = write, CanChangePermissions = TriState.No }, DirectoryPermission = new SecurityPermission { Target = Path.GetDirectoryName(path), ObjectType = "Directory", CanCreate = TriState.No } });
            if (withProcess) c.Processes.Add(new WindowsProcess { ProcessId = 600, ParentProcessId = 4, Name = "veyon-service.exe", ImagePath = path, ImagePathSource = "Synthetic", AccessStatus = accessStatus, OwnerAccount = accessStatus == "ACCESS_DENIED" ? null : account, IntegrityLevel = accessStatus == "ACCESS_DENIED" ? "Unknown" : PathResolver.IsPrivilegedPrincipal(account) ? "System" : "Medium" });
            ExecutionCorrelation.Correlate(c); return c;
        }
        private static void TestServiceBinaryFixture()
        {
            string path = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "fixtures", "service-binary-correlation.json"); AnalysisContext c = new AnalyzerEngine().LoadFixture(path);
            Equal(EvaluationStatus.Confirmed, One("PT-013", c).Status); Equal(1, c.Processes.Count); Equal(1, c.Binaries.Count);
        }
        private static void Throws(Action action) { bool threw = false; try { action(); } catch { threw = true; } True(threw); }
        private static void TestJsonExport() { string path = Path.Combine(Path.GetTempPath(), "PrivTrace-test-report-" + Guid.NewGuid().ToString("N") + ".json"); try { AnalysisContext c = Veyon(TriState.Yes, "LocalSystem", true, "ACCESSIBLE"); AnalysisResult r = new AnalysisResult { GeneratedUtc = DateTime.UtcNow, RulesEvaluated = 1, Context = c }; r.Findings.Add(One("PT-013", c)); JsonReporter.Write(r, path); True(File.Exists(path)); string json = File.ReadAllText(path); True(json.Contains("RulesEvaluated")); True(json.Contains("Processes")); True(json.Contains("Binaries")); } finally { if (File.Exists(path)) File.Delete(path); } }
    }
}
