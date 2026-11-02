using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Web.Script.Serialization;
using PrivTrace.Models;

namespace PrivTrace.Core
{
    public sealed class ReportInspection
    {
        public ReportInspection() { Errors = new List<string>(); CollectorDiagnostics = new List<string>(); ActiveRules = new List<string>(); UnknownRules = new List<string>(); RelatedObjects = new List<string>(); TraceClassifications = new List<string>(); }
        public string SourcePath { get; set; }
        public string SourceSha256 { get; set; }
        public string Version { get; set; }
        public string SchemaVersion { get; set; }
        public bool SchemaValid { get; set; }
        public int Findings { get; set; }
        public int CorrelationTraces { get; set; }
        public int UnknownConditions { get; set; }
        public List<string> ActiveRules { get; set; }
        public List<string> UnknownRules { get; set; }
        public List<string> RelatedObjects { get; set; }
        public List<string> TraceClassifications { get; set; }
        public List<string> Errors { get; set; }
        public List<string> CollectorDiagnostics { get; set; }
    }

    public static class ReportImporter
    {
        public static ReportInspection Inspect(string path)
        {
            ReportInspection inspection = new ReportInspection { SourcePath = Path.GetFullPath(path) };
            byte[] bytes = File.ReadAllBytes(path); inspection.SourceSha256 = Hash(bytes);
            AnalysisResult report;
            try { report = new JavaScriptSerializer { MaxJsonLength = Int32.MaxValue }.Deserialize<AnalysisResult>(Encoding.UTF8.GetString(bytes)); }
            catch (Exception ex) { inspection.Errors.Add("Invalid JSON: " + ex.Message); return inspection; }
            if (report == null) { inspection.Errors.Add("Report root is null."); return inspection; }
            inspection.Version = report.Version; inspection.SchemaVersion = report.SchemaVersion;
            if (String.IsNullOrEmpty(report.Version)) inspection.Errors.Add("Version is missing.");
            if (String.IsNullOrEmpty(report.SchemaVersion)) inspection.Errors.Add("SchemaVersion is missing.");
            if (report.Context == null) inspection.Errors.Add("Context is missing.");
            if (report.Findings == null) inspection.Errors.Add("Findings are missing.");
            if (report.CorrelationTraces == null) inspection.Errors.Add("CorrelationTraces are missing.");
            if (report.Findings != null)
            {
                inspection.Findings = report.Findings.Count;
                inspection.ActiveRules.AddRange(report.Findings.Where(f => f.Status != EvaluationStatus.RuledOut && f.Status != EvaluationStatus.Unknown).Select(f => f.RuleId).Where(x => !String.IsNullOrEmpty(x)).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(x => x));
                inspection.UnknownRules.AddRange(report.Findings.Where(f => f.Status == EvaluationStatus.Unknown).Select(f => f.RuleId).Where(x => !String.IsNullOrEmpty(x)).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(x => x));
                inspection.UnknownConditions += report.Findings.Where(f => f.Status == EvaluationStatus.Unknown || f.Status == EvaluationStatus.Potential).Sum(f => f.MissingConditions == null ? 0 : f.MissingConditions.Count);
                inspection.RelatedObjects.AddRange(report.Findings.Select(f => f.Target).Where(x => !String.IsNullOrEmpty(x)));
            }
            if (report.Errors != null) inspection.CollectorDiagnostics.AddRange(report.Errors);
            if (report.CorrelationTraces != null)
            {
                inspection.CorrelationTraces = report.CorrelationTraces.Count;
                foreach (CorrelationTrace trace in report.CorrelationTraces)
                {
                    if (trace.PendingConditions != null) inspection.UnknownConditions += trace.PendingConditions.Count;
                    if (!String.IsNullOrEmpty(trace.Classification)) inspection.TraceClassifications.Add(trace.TraceId + ":" + trace.Classification);
                    IEnumerable<string> supporting = trace.SupportingRuleIds ?? new List<string>(), ruled = trace.RuledOutRuleIds ?? new List<string>(), evaluated = trace.EvaluatedRuleIds ?? new List<string>();
                    foreach (string rule in supporting.Intersect(ruled, StringComparer.OrdinalIgnoreCase)) inspection.Errors.Add("Rule " + rule + " is both supporting and ruled out in " + trace.TraceId + ".");
                    foreach (string rule in supporting.Concat(ruled).Distinct(StringComparer.OrdinalIgnoreCase)) if (!evaluated.Contains(rule, StringComparer.OrdinalIgnoreCase)) inspection.Errors.Add("Rule " + rule + " is not listed as evaluated in " + trace.TraceId + ".");
                    if (trace.ExploitationVerified) inspection.Errors.Add("Unsupported ExploitationVerified=true in read-only report " + trace.TraceId + ".");
                    if (trace.Nodes != null) inspection.RelatedObjects.AddRange(trace.Nodes.Select(n => n.Label).Where(x => !String.IsNullOrEmpty(x)));
                }
            }
            inspection.RelatedObjects = inspection.RelatedObjects.Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(x => x).ToList();
            inspection.SchemaValid = inspection.Errors.Count == 0;
            return inspection;
        }

        private static string Hash(byte[] bytes) { using (SHA256 sha = SHA256.Create()) return BitConverter.ToString(sha.ComputeHash(bytes)).Replace("-", String.Empty); }
    }

    public static class ReportSanitizer
    {
        public static void Sanitize(string inputPath, string outputPath)
        {
            string json = File.ReadAllText(inputPath); AnalysisResult report = new JavaScriptSerializer { MaxJsonLength = Int32.MaxValue }.Deserialize<AnalysisResult>(json);
            if (report == null || report.Context == null) throw new InvalidDataException("Input is not a PrivTrace analysis report.");
            SortedSet<string> accounts = new SortedSet<string>(StringComparer.OrdinalIgnoreCase), sids = new SortedSet<string>(StringComparer.OrdinalIgnoreCase), paths = new SortedSet<string>(StringComparer.OrdinalIgnoreCase), hosts = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
            AddAccount(accounts, report.Context.Token == null ? null : report.Context.Token.UserName); AddSid(sids, report.Context.Token == null ? null : report.Context.Token.UserSid); AddHost(hosts, report.Context.System == null ? null : report.Context.System.MachineName);
            if (report.Context.Token != null) foreach (WindowsGroup g in report.Context.Token.Groups ?? new List<WindowsGroup>()) { AddSid(sids, g.Sid); AddAccount(accounts, g.Name); }
            foreach (WindowsService s in report.Context.Services ?? new List<WindowsService>()) { AddAccount(accounts, s.Account); AddPath(paths, s.BinaryPath); AddPath(paths, s.ExecutablePath); }
            foreach (WindowsProcess p in report.Context.Processes ?? new List<WindowsProcess>()) { AddAccount(accounts, p.OwnerAccount); AddSid(sids, p.OwnerSid); AddPath(paths, p.ImagePath); AddPath(paths, p.ParentImagePath); }
            foreach (SoftwareObservation software in report.Context.Software ?? new List<SoftwareObservation>())
            {
                AddPath(paths, software.CanonicalExecutable); AddPath(paths, software.InstallationRoot);
                foreach (string p in software.ProcessPaths ?? new List<string>()) AddPath(paths, p);
                foreach (string identity in software.ExecutionIdentities ?? new List<string>()) AddAccount(accounts, identity);
                foreach (SoftwareEvidence evidence in software.Evidence ?? new List<SoftwareEvidence>()) AddEmbeddedPaths(paths, evidence.Value);
                foreach (string trace in software.Trace ?? new List<string>()) AddEmbeddedPaths(paths, trace);
            }
            foreach (BinaryArtifact b in report.Context.Binaries ?? new List<BinaryArtifact>()) { AddPath(paths, b.Path); foreach (string identity in b.ExecutionIdentities ?? new List<string>()) AddAccount(accounts, identity); }
            foreach (ScheduledTaskInfo task in report.Context.Tasks ?? new List<ScheduledTaskInfo>()) { AddAccount(accounts, task.Principal); foreach (ScheduledTaskAction a in task.Actions ?? new List<ScheduledTaskAction>()) { AddPath(paths, a.Executable); AddPath(paths, a.OriginalExecutable); AddPath(paths, a.WorkingDirectory); } }
            if (report.Context.DnsServer != null) { AddAccount(accounts, report.Context.DnsServer.Account); AddPath(paths, report.Context.DnsServer.ServerLevelPluginDll); }
            Dictionary<string, string> replacements = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase); AddAliases(replacements, paths, "PATH"); AddAliases(replacements, accounts, "ACCOUNT"); AddAliases(replacements, sids, "SID"); AddAliases(replacements, hosts, "HOST");
            JavaScriptSerializer serializer = new JavaScriptSerializer { MaxJsonLength = Int32.MaxValue };
            foreach (KeyValuePair<string, string> pair in replacements.OrderByDescending(p => p.Key.Length))
            {
                string encoded = serializer.Serialize(pair.Key);
                if (encoded.Length >= 2) encoded = encoded.Substring(1, encoded.Length - 2);
                json = ReplaceOrdinalIgnoreCase(json, encoded, pair.Value);
                json = ReplaceOrdinalIgnoreCase(json, pair.Key, pair.Value);
            }
            File.WriteAllText(outputPath, json, new UTF8Encoding(false));
        }

        private static void AddAliases(Dictionary<string, string> map, IEnumerable<string> values, string kind) { int i = 0; foreach (string value in values) { i++; if (!map.ContainsKey(value)) map[value] = "<" + kind + "-" + i.ToString("000") + ">"; } }
        private static void AddAccount(ISet<string> set, string value) { if (!String.IsNullOrWhiteSpace(value) && value.IndexOf('\\') >= 0 && !value.StartsWith(@"BUILTIN\", StringComparison.OrdinalIgnoreCase) && !value.StartsWith(@"NT AUTHORITY\", StringComparison.OrdinalIgnoreCase) && !value.StartsWith(@"NT SERVICE\", StringComparison.OrdinalIgnoreCase)) set.Add(value); }
        private static void AddSid(ISet<string> set, string value) { if (!String.IsNullOrWhiteSpace(value) && value.StartsWith("S-1-", StringComparison.OrdinalIgnoreCase)) set.Add(value); }
        private static void AddPath(ISet<string> set, string value) { if (!String.IsNullOrWhiteSpace(value) && (value.IndexOf(@":\", StringComparison.Ordinal) >= 0 || value.StartsWith(@"\\", StringComparison.Ordinal))) set.Add(value); }
        private static void AddEmbeddedPaths(ISet<string> set, string value)
        {
            if (String.IsNullOrWhiteSpace(value)) return;
            foreach (Match match in Regex.Matches(value, @"(?i)(?:[A-Z]:\\|\\\\)[^\[\r\n]+"))
            {
                string candidate = match.Value.Trim();
                if (candidate.EndsWith(";", StringComparison.Ordinal)) candidate = candidate.Substring(0, candidate.Length - 1).TrimEnd();
                AddPath(set, candidate);
            }
        }
        private static void AddHost(ISet<string> set, string value) { if (!String.IsNullOrWhiteSpace(value)) set.Add(value); }
        private static string ReplaceOrdinalIgnoreCase(string input, string oldValue, string newValue) { int index = 0; StringBuilder output = new StringBuilder(); while (true) { int found = input.IndexOf(oldValue, index, StringComparison.OrdinalIgnoreCase); if (found < 0) { output.Append(input, index, input.Length - index); return output.ToString(); } output.Append(input, index, found - index); output.Append(newValue); index = found + oldValue.Length; } }
    }
}
