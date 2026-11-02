using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using PrivTrace.Models;
using PrivTrace.Security;

namespace PrivTrace.Rules
{
    public sealed class RuleCatalog
    {
        public const string EmbeddedResourceName = "PrivTrace.Knowledge.Rules.rules.xml";

        public List<RuleDefinition> LoadEmbedded()
        {
            Assembly assembly = typeof(RuleCatalog).Assembly;
            using (Stream stream = assembly.GetManifestResourceStream(EmbeddedResourceName))
            {
                if (stream == null) throw new InvalidDataException("Embedded rule catalog resource is missing: " + EmbeddedResourceName);
                return Load(stream, "embedded resource " + EmbeddedResourceName);
            }
        }

        public byte[] ReadEmbeddedBytes()
        {
            Assembly assembly = typeof(RuleCatalog).Assembly;
            using (Stream stream = assembly.GetManifestResourceStream(EmbeddedResourceName))
            {
                if (stream == null) throw new InvalidDataException("Embedded rule catalog resource is missing: " + EmbeddedResourceName);
                using (MemoryStream copy = new MemoryStream()) { stream.CopyTo(copy); return copy.ToArray(); }
            }
        }

        public List<RuleDefinition> Load(string path)
        {
            if (!File.Exists(path)) throw new FileNotFoundException("Rule catalog not found.", path);
            using (Stream stream = File.OpenRead(path)) return Load(stream, path);
        }

        public List<RuleDefinition> Load(Stream stream, string source)
        {
            if (stream == null) throw new ArgumentNullException("stream");
            XDocument document;
            try { document = XDocument.Load(stream, LoadOptions.SetLineInfo); }
            catch (Exception ex) { throw new InvalidDataException("Rule catalog is invalid or corrupt: " + source, ex); }
            if (document.Root == null || document.Root.Name != "rules") throw new InvalidDataException("Rule catalog root element is invalid: " + source);
            List<RuleDefinition> rules = new List<RuleDefinition>();
            foreach (XElement node in document.Root.Elements("rule"))
            {
                RuleDefinition rule = new RuleDefinition
                {
                    Id = Attr(node, "id"), Name = Attr(node, "name"), Category = Attr(node, "category"),
                    Severity = ParseSeverity(Attr(node, "severity")), Evaluator = Attr(node, "evaluator"),
                    Version = Attr(node, "version"), Verification = Attr(node, "verification"),
                    Description = Value(node, "description"), Limitations = Value(node, "limitations"), Recommendation = Value(node, "recommendation")
                };
                ReadStrings(node.Element("required"), "condition", rule.RequiredConditions);
                ReadStrings(node.Element("optional"), "condition", rule.OptionalConditions);
                ReadStrings(node.Element("invalidating"), "condition", rule.InvalidatingConditions);
                ReadStrings(node.Element("evidence"), "item", rule.EvidenceRequirements);
                ReadStrings(node.Element("labs"), "lab", rule.RelatedLabs);
                XElement references = node.Element("references");
                if (references != null)
                    foreach (XElement reference in references.Elements("reference"))
                        rule.References.Add(new ReferenceMetadata { SourceId = Attr(reference, "sourceId"), Url = Attr(reference, "url"), Title = Attr(reference, "title"), Author = Attr(reference, "author"), Type = Attr(reference, "type"), Accessed = Attr(reference, "accessed"), Verification = Attr(reference, "verification") });
                rules.Add(rule);
            }
            Validate(rules); return rules;
        }

        public void Validate(IList<RuleDefinition> rules)
        {
            HashSet<string> ids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            Dictionary<string, string> categoryEvaluators = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                { "Privileges", "PrivilegeEvaluator" }, { "Groups", "GroupEvaluator" },
                { "Services", "ServiceEvaluator" }, { "ScheduledTasks", "TaskEvaluator" },
                { "System", "SystemEvaluator" }
            };
            foreach (RuleDefinition rule in rules)
            {
                if (String.IsNullOrWhiteSpace(rule.Id) || String.IsNullOrWhiteSpace(rule.Name) || String.IsNullOrWhiteSpace(rule.Category) || String.IsNullOrWhiteSpace(rule.Evaluator) || String.IsNullOrWhiteSpace(rule.Version) || String.IsNullOrWhiteSpace(rule.Description) || String.IsNullOrWhiteSpace(rule.Limitations) || String.IsNullOrWhiteSpace(rule.Recommendation) || String.IsNullOrWhiteSpace(rule.Verification) || rule.RequiredConditions.Count == 0 || rule.EvidenceRequirements.Count == 0) throw new InvalidDataException("Incomplete rule metadata: " + (rule.Id ?? "<no id>"));
                if (!ids.Add(rule.Id)) throw new InvalidDataException("Duplicate rule ID: " + rule.Id);
                string expectedEvaluator;
                if (!categoryEvaluators.TryGetValue(rule.Category, out expectedEvaluator)) throw new InvalidDataException("Unknown category: " + rule.Category);
                if (!String.Equals(rule.Evaluator, expectedEvaluator, StringComparison.Ordinal)) throw new InvalidDataException("Incompatible category/evaluator in " + rule.Id);
                foreach (ReferenceMetadata reference in rule.References)
                {
                    Uri uri; if (!Uri.TryCreate(reference.Url, UriKind.Absolute, out uri) || (uri.Scheme != "https" && uri.Scheme != "http")) throw new InvalidDataException("Malformed reference in " + rule.Id);
                }
            }
            if (rules.Count == 0) throw new InvalidDataException("The rule catalog is empty.");
            foreach (string id in ids) if (!Regex.IsMatch(id, @"^PT-\d{3}$", RegexOptions.CultureInvariant)) throw new InvalidDataException("Malformed rule ID: " + id);
            for (int i = 1; i <= rules.Count; i++) if (!ids.Contains("PT-" + i.ToString("000"))) throw new InvalidDataException("Missing rule PT-" + i.ToString("000"));
        }

        private static string Attr(XElement node, string name) { XAttribute value = node.Attribute(name); return value == null ? null : value.Value.Trim(); }
        private static string Value(XElement node, string name) { XElement value = node.Element(name); return value == null ? null : value.Value.Trim(); }
        private static void ReadStrings(XElement parent, string name, IList<string> values) { if (parent != null) foreach (XElement item in parent.Elements(name)) values.Add(item.Value.Trim()); }
        private static Severity ParseSeverity(string value) { Severity result; return Enum.TryParse(value, true, out result) ? result : Severity.Informational; }
    }

    public sealed class RuleEngine
    {
        private static readonly Dictionary<string, string> Privileges = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { "PT-001", "SeImpersonatePrivilege" }, { "PT-002", "SeAssignPrimaryTokenPrivilege" }, { "PT-003", "SeBackupPrivilege" }, { "PT-004", "SeRestorePrivilege" },
            { "PT-005", "SeDebugPrivilege" }, { "PT-006", "SeTakeOwnershipPrivilege" }, { "PT-007", "SeLoadDriverPrivilege" }, { "PT-008", "SeManageVolumePrivilege" }, { "PT-023", "SeTcbPrivilege" },
            { "PT-025", "SeCreateTokenPrivilege" }
        };
        private static readonly Dictionary<string, string> GroupSids = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { "PT-009", "S-1-5-32-549" }, { "PT-010", "S-1-5-32-551" }, { "PT-012", "S-1-5-32-550" }, { "PT-022", "S-1-5-32-573" }
        };

        public List<Finding> Evaluate(IEnumerable<RuleDefinition> rules, AnalysisContext context)
        {
            List<Finding> findings = new List<Finding>();
            foreach (RuleDefinition rule in rules)
            {
                if (rule.Evaluator == "PrivilegeEvaluator") findings.Add(EvaluatePrivilege(rule, context));
                else if (rule.Evaluator == "GroupEvaluator") findings.Add(EvaluateGroup(rule, context));
                else if (rule.Evaluator == "SystemEvaluator") findings.Add(EvaluateSystem(rule, context));
                else if (rule.Evaluator == "ServiceEvaluator") findings.AddRange(EvaluateServices(rule, context));
                else if (rule.Evaluator == "TaskEvaluator") findings.AddRange(EvaluateTasks(rule, context));
            }
            foreach (Finding finding in findings) NormalizeFindingSeverity(finding);
            return findings;
        }

        private static Finding Base(RuleDefinition rule) { return new Finding { RuleId = rule.Id, Name = rule.Name, Category = rule.Category, RuleSeverity = rule.Severity, Severity = rule.Severity, Recommendation = rule.Recommendation, Confidence = Confidence.Unknown }; }

        private static void NormalizeFindingSeverity(Finding finding)
        {
            if (finding.Status == EvaluationStatus.Unknown || finding.Status == EvaluationStatus.RuledOut || finding.Status == EvaluationStatus.Informational)
                finding.Severity = Severity.Informational;
        }

        private static Finding EvaluatePrivilege(RuleDefinition rule, AnalysisContext context)
        {
            Finding finding = Base(rule); string name = Privileges[rule.Id];
            TokenPrivilege privilege = context.Token.Privileges.FirstOrDefault(p => String.Equals(p.Name, name, StringComparison.OrdinalIgnoreCase));
            if (privilege == null)
            {
                finding.Status = context.Token.Errors.Count > 0 ? EvaluationStatus.Unknown : EvaluationStatus.RuledOut;
                finding.MissingConditions.Add(context.Token.Errors.Count > 0 ? "Token enumeration was incomplete." : "Privilege is absent from the current token.");
                return finding;
            }
            TokenPrivilegeState state = PrivilegeState(privilege); finding.Target = name;
            if (state == TokenPrivilegeState.Removed)
            {
                finding.Status = EvaluationStatus.RuledOut; finding.Confidence = Confidence.High; finding.Severity = Severity.Informational;
                finding.Evidence.Add(new Evidence { Kind = "TokenPrivilege", Subject = name, Value = "Removed from the current token; it cannot be re-enabled in this token.", Positive = false });
                finding.MissingConditions.Add("AdjustTokenPrivileges cannot add or restore a removed privilege."); return finding;
            }
            if (state == TokenPrivilegeState.Unknown)
            {
                finding.Status = EvaluationStatus.Unknown; finding.Confidence = Confidence.Unknown; finding.Severity = Severity.Informational;
                finding.Evidence.Add(new Evidence { Kind = "TokenPrivilege", Subject = name, Value = "Privilege state is UNKNOWN.", Positive = false }); return finding;
            }
            bool enabled = state == TokenPrivilegeState.Enabled;
            finding.Status = EvaluationStatus.Potential; finding.Confidence = enabled ? Confidence.Medium : Confidence.Low; finding.Severity = enabled ? Severity.Medium : Severity.Low;
            finding.Evidence.Add(new Evidence { Kind = "TokenPrivilege", Subject = name, Value = enabled ? "Present and enabled" : "Present but disabled", Positive = true });
            finding.Trace.Add("Current token"); finding.Trace.Add(name + (enabled ? " (enabled)" : " (disabled)")); finding.Trace.Add("Technique-specific preconditions remain");
            if (!enabled) finding.MissingConditions.Add("The privilege is present but disabled. AdjustTokenPrivileges may enable an existing privilege, but PrivTrace did not modify the token and enabling can still be restricted or fail.");
            finding.MissingConditions.Add("No exploitation precondition or privileged target was tested by the privilege-presence rule.");
            return finding;
        }

        private static Finding EvaluateSystem(RuleDefinition rule, AnalysisContext context)
        {
            Finding finding = Base(rule);
            if (rule.Id != "PT-021") { finding.Status = EvaluationStatus.Unknown; finding.MissingConditions.Add("No system evaluator is registered for this rule."); return finding; }
            TriState machine = context.System.AlwaysInstallElevatedMachine, user = context.System.AlwaysInstallElevatedUser;
            finding.Target = @"HKLM/HKCU\Software\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated";
            finding.Evidence.Add(new Evidence { Kind = "RegistryPolicy", Subject = "Machine", Value = "Machine policy: " + machine, Positive = machine == TriState.Yes });
            finding.Evidence.Add(new Evidence { Kind = "RegistryPolicy", Subject = "User", Value = "User policy: " + user, Positive = user == TriState.Yes });
            if (machine == TriState.Yes && user == TriState.Yes) { finding.Status = EvaluationStatus.Confirmed; finding.Confidence = Confidence.High; finding.Trace.Add("Current user"); finding.Trace.Add("Machine policy enabled"); finding.Trace.Add("User policy enabled"); finding.Trace.Add("Windows Installer elevated policy"); }
            else if (machine == TriState.Unknown || user == TriState.Unknown) { finding.Status = EvaluationStatus.Unknown; finding.Confidence = Confidence.Unknown; finding.MissingConditions.Add("One or both policy values could not be read."); }
            else { finding.Status = EvaluationStatus.RuledOut; finding.Confidence = Confidence.High; finding.MissingConditions.Add("Microsoft requires both user and machine policy values to be enabled."); }
            return finding;
        }

        private static Finding EvaluateGroup(RuleDefinition rule, AnalysisContext context)
        {
            Finding finding = Base(rule); WindowsGroup group = null;
            if (rule.Id == "PT-011") group = context.Token.Groups.FirstOrDefault(g => !String.IsNullOrEmpty(g.Name) && (g.Name.EndsWith("\\DnsAdmins", StringComparison.OrdinalIgnoreCase) || String.Equals(g.Name, "DnsAdmins", StringComparison.OrdinalIgnoreCase)));
            else group = context.Token.Groups.FirstOrDefault(g => String.Equals(g.Sid, GroupSids[rule.Id], StringComparison.OrdinalIgnoreCase));
            if (group == null) { finding.Status = context.Token.Errors.Count > 0 ? EvaluationStatus.Unknown : EvaluationStatus.RuledOut; finding.MissingConditions.Add("Effective group membership was not observed."); return finding; }
            finding.Target = group.Name ?? group.Sid;
            if (!group.Enabled || group.DenyOnly) { finding.Status = EvaluationStatus.RuledOut; finding.Confidence = Confidence.High; finding.Evidence.Add(new Evidence { Kind = "TokenGroup", Subject = group.Sid, Value = group.DenyOnly ? "Deny-only" : "Disabled", Positive = false }); return finding; }
            finding.Status = EvaluationStatus.Potential; finding.Confidence = rule.Id == "PT-011" ? Confidence.Low : Confidence.Medium;
            finding.Evidence.Add(new Evidence { Kind = "TokenGroup", Subject = group.Sid, Value = "Enabled: " + group.Name, Positive = true });
            finding.Trace.Add("Current token"); finding.Trace.Add("Enabled group " + group.Sid); finding.Trace.Add("Group-specific capability requires target correlation");
            finding.MissingConditions.Add("Relevant privileged object and effective object rights must be verified."); return finding;
        }

        private static IEnumerable<Finding> EvaluateServices(RuleDefinition rule, AnalysisContext context)
        {
            List<Finding> list = new List<Finding>();
            if (rule.Id == "PT-024")
            {
                WindowsService spooler = context.Services.FirstOrDefault(s => String.Equals(s.Name, "Spooler", StringComparison.OrdinalIgnoreCase));
                TokenPrivilege impersonate = context.Token.Privileges.FirstOrDefault(p => String.Equals(p.Name, "SeImpersonatePrivilege", StringComparison.OrdinalIgnoreCase));
                if (spooler == null)
                {
                    Finding missing = Base(rule); missing.Status = context.Errors.Any(e => e.StartsWith("Services:", StringComparison.OrdinalIgnoreCase)) ? EvaluationStatus.Unknown : EvaluationStatus.RuledOut; missing.MissingConditions.Add("Print Spooler was not enumerated."); list.Add(missing); return list;
                }
                bool running = String.Equals(spooler.State, "Running", StringComparison.OrdinalIgnoreCase);
                bool complete = running && IsHigher(spooler.Account) && impersonate != null && impersonate.Enabled;
                Finding finding = Base(rule); finding.Target = spooler.Name; finding.Status = complete ? EvaluationStatus.Confirmed : EvaluationStatus.RuledOut; finding.Confidence = complete ? Confidence.High : Confidence.Medium;
                finding.Evidence.Add(new Evidence { Kind = "Service", Subject = "Spooler", Value = "State=" + spooler.State + ", Account=" + spooler.Account, Positive = running && IsHigher(spooler.Account) });
                finding.Evidence.Add(new Evidence { Kind = "TokenPrivilege", Subject = "SeImpersonatePrivilege", Value = impersonate == null ? "Absent" : impersonate.Enabled ? "Present and enabled" : "Present but disabled", Positive = impersonate != null && impersonate.Enabled });
                if (complete) { finding.Trace.Add("Current token with SeImpersonatePrivilege"); finding.Trace.Add("Running Print Spooler"); finding.Trace.Add("LocalSystem service authentication surface"); }
                else finding.MissingConditions.Add("The rule requires a running privileged Spooler and enabled SeImpersonatePrivilege; exploitability remains version and mitigation dependent.");
                list.Add(finding); return list;
            }
            foreach (WindowsService service in context.Services)
            {
                if (rule.Id == "PT-026")
                {
                    if (!IsHigher(service.Account)) continue;
                    List<ServiceRegistryEvidence> registry = service.RegistryEvidence ?? new List<ServiceRegistryEvidence>();
                    ServiceRegistryEvidence direct = registry.FirstOrDefault(r => HasRegistryMutation(r.ServiceKeyPermission) || (!String.IsNullOrWhiteSpace(r.ServiceDll) && HasRegistryMutation(r.ParametersKeyPermission)));
                    ServiceRegistryEvidence createOnly = registry.FirstOrDefault(r => r.ServiceKeyPermission != null && r.ServiceKeyPermission.CanCreate == TriState.Yes);
                    bool registryUnknown = registry.Count == 0 || registry.Any(r => IsPermissionUnknown(r.ServiceKeyPermission));
                    if (direct != null)
                    {
                        SecurityPermission permission = HasRegistryMutation(direct.ServiceKeyPermission) ? direct.ServiceKeyPermission : direct.ParametersKeyPermission;
                        Finding finding = ObjectFinding(rule, service.Name, true, false, "Effective registry mutation right on " + permission.Target, "Current user", "Registry AccessCheck: " + RegistryRights(permission), "Privileged service " + service.Name, service.Account);
                        AddPermissionEvidence(finding, permission, "RegistryAcl"); list.Add(finding);
                    }
                    else if (createOnly != null)
                    {
                        Finding finding = Base(rule); finding.Target = service.Name; finding.Status = EvaluationStatus.Potential; finding.Confidence = Confidence.Medium;
                        finding.Evidence.Add(new Evidence { Kind = "RegistryAcl", Subject = createOnly.ServiceKeyPath, Value = "KEY_CREATE_SUB_KEY is effectively granted on the service key.", Positive = true });
                        finding.Trace.Add("Current user"); finding.Trace.Add("KEY_CREATE_SUB_KEY on " + createOnly.ServiceKeyPath); finding.Trace.Add("Privileged service " + service.Name); finding.MissingConditions.Add("A concrete writable configuration value or controllable subkey was not verified."); list.Add(finding);
                    }
                    else if (registryUnknown)
                    {
                        Finding finding = ObjectFinding(rule, service.Name, false, true, "Service registry permissions are unavailable.", "Current user", "Registry evidence unavailable", "Privileged service " + service.Name); list.Add(finding);
                    }
                    continue;
                }
                if (rule.Id == "PT-027")
                {
                    if (!IsHigher(service.Account) || !IsSharedProcessService(service)) continue;
                    ServiceRegistryEvidence dll = (service.RegistryEvidence ?? new List<ServiceRegistryEvidence>()).FirstOrDefault(r => !String.IsNullOrWhiteSpace(r.ServiceDllPath));
                    if (dll == null) continue;
                    bool writableExisting = dll.ServiceDllExists == TriState.Yes && EffectiveWrite(dll.ServiceDllPermission) == TriState.Yes;
                    bool plantMissing = dll.ServiceDllExists == TriState.No && EffectiveCreate(dll.ServiceDllDirectoryPermission) == TriState.Yes;
                    bool controllableExisting = dll.ServiceDllExists == TriState.Yes && dll.ServiceDllPermission != null && (dll.ServiceDllPermission.CanDelete == TriState.Yes || dll.ServiceDllPermission.CanChangePermissions == TriState.Yes);
                    bool permissionUnknown = dll.ServiceDllExists == TriState.Unknown || EffectiveWrite(dll.ServiceDllPermission) == TriState.Unknown || (dll.ServiceDllExists == TriState.No && EffectiveCreate(dll.ServiceDllDirectoryPermission) == TriState.Unknown);
                    bool disabled = String.Equals(service.StartType, "Disabled", StringComparison.OrdinalIgnoreCase); bool startUnknown = String.IsNullOrWhiteSpace(service.StartType);
                    bool running = String.Equals(service.State, "Running", StringComparison.OrdinalIgnoreCase); bool automatic = !String.IsNullOrWhiteSpace(service.StartType) && service.StartType.StartsWith("Automatic", StringComparison.OrdinalIgnoreCase);
                    bool demandStart = String.Equals(service.StartType, "Manual", StringComparison.OrdinalIgnoreCase) && service.CanStart == TriState.Yes; bool activationReady = !disabled && (running || automatic || demandStart);
                    Finding finding = Base(rule); finding.Target = dll.ServiceDllPath;
                    finding.Status = writableExisting && activationReady ? EvaluationStatus.Confirmed : (writableExisting || plantMissing || controllableExisting) ? EvaluationStatus.Potential : permissionUnknown ? EvaluationStatus.Unknown : EvaluationStatus.RuledOut;
                    finding.Confidence = finding.Status == EvaluationStatus.Confirmed ? Confidence.High : finding.Status == EvaluationStatus.Potential ? Confidence.Medium : finding.Status == EvaluationStatus.Unknown ? Confidence.Unknown : Confidence.High;
                    finding.Evidence.Add(new Evidence { Kind = "ServiceDllConfiguration", Subject = service.Name, Value = "CONFIGURED relation: " + dll.ServiceDll + " -> " + dll.ServiceDllPath + "; exists=" + dll.ServiceDllExists + "; DLL load was not observed.", Positive = true });
                    finding.Evidence.Add(new Evidence { Kind = "Service", Subject = service.Name, Value = "Type=" + service.ServiceType + ", State=" + service.State + ", Account=" + service.Account + ", HostPID=" + service.ProcessId, Positive = true });
                    if (dll.ServiceDllPermission != null) AddPermissionEvidence(finding, dll.ServiceDllPermission, "FileAcl");
                    finding.Trace.Add("Current user"); finding.Trace.Add("Effective filesystem right on configured ServiceDll"); finding.Trace.Add("CONFIGURED ServiceDll relation for " + service.Name); finding.Trace.Add("Privileged shared-process service account " + service.Account);
                    if (disabled) finding.MissingConditions.Add("The service is disabled; a permitted activation mechanism was not verified.");
                    else if (!activationReady && (writableExisting || plantMissing || controllableExisting)) finding.MissingConditions.Add(startUnknown ? "The service start type is unavailable." : "No running, automatic, or effectively startable service activation was verified.");
                    if (!writableExisting) finding.MissingConditions.Add(plantMissing ? "The DLL is missing; creation in the parent is possible but runtime loading remains unobserved." : controllableExisting ? "Control rights may permit replacement, but direct write access was not verified." : "Effective write/create access could not be verified.");
                    finding.MissingConditions.Add("PrivTrace does not claim that the configured DLL is currently loaded or will load automatically.");
                    list.Add(finding); continue;
                }
                bool match = false; bool unknown = false; string evidence = null;
                if (rule.Id == "PT-013")
                {
                    if (!IsHigher(service.Account)) continue;
                    TriState contentWrite = EffectiveWrite(service.ExecutablePermission); bool replacement = FileReplacementConfirmed(service);
                    if (contentWrite == TriState.Yes || replacement)
                    {
                        string operation = contentWrite == TriState.Yes ? "FILE_WRITE_DATA" : "FILE_REPLACEMENT";
                        list.Add(ServiceExecutionFinding(rule, service, service.ExecutablePath ?? service.BinaryPath, (contentWrite == TriState.Yes ? "Executable content write confirmed" : "Executable replacement rights confirmed") + " for service account " + service.Account, operation, contentWrite == TriState.Yes ? "CONFIRMED_RIGHT" : "FILE_REPLACE_CONFIRMED")); continue;
                    }
                    if (service.ExecutablePermission != null && service.ExecutablePermission.CanChangePermissions == TriState.Yes)
                    {
                        Finding control = ServiceExecutionFinding(rule, service, service.ExecutablePath ?? service.BinaryPath, "WRITE_DAC is confirmed but is not treated as FILE_WRITE_DATA", "WRITE_DAC", "CONFIRMED_RIGHT"); control.Status = EvaluationStatus.Potential; control.Confidence = Confidence.Medium; control.MissingConditions.Add("WRITE_DAC was not converted into a content-write or replacement claim; no DACL was changed."); list.Add(control); continue;
                    }
                    match = false; unknown = contentWrite == TriState.Unknown || ReplacementUnknown(service); evidence = "Executable content-write right: " + contentWrite + "; replacement right: " + (replacement ? "Yes" : ReplacementUnknown(service) ? "Unknown" : "No");
                }
                else if (rule.Id == "PT-014") { match = service.CanChangeConfig == TriState.Yes && IsHigher(service.Account); unknown = service.CanChangeConfig == TriState.Unknown; evidence = "SERVICE_CHANGE_CONFIG granted for service account " + service.Account; }
                else if (rule.Id == "PT-015") { TriState candidate = CandidateControl(service.UnquotedCandidatePermissions); if (candidate == TriState.Yes && IsHigher(service.Account)) { list.Add(ServiceExecutionFinding(rule, service, service.Name, "Unquoted path has a concrete controllable candidate", "SEARCH_PATH_CANDIDATE_CONTROL", "CONFIRMED_RIGHT")); continue; } match = false; unknown = candidate == TriState.Unknown && service.UnquotedCandidates != null && service.UnquotedCandidates.Count > 0; evidence = "Unquoted candidate control: " + candidate; }
                else if (rule.Id == "PT-016")
                {
                    TriState create = EffectiveCreate(service.DirectoryPermission); if (!IsHigher(service.Account)) continue;
                    if (create == TriState.Yes && FileReplacementConfirmed(service)) { list.Add(ServiceExecutionFinding(rule, service, service.Name, "Executable directory permits creation and the existing executable can be replaced", "FILE_REPLACEMENT", "FILE_REPLACE_CONFIRMED")); continue; }
                    if (create == TriState.Yes)
                    {
                        Finding directory = ServiceExecutionFinding(rule, service, service.Name, "Executable directory permits file creation; replacement or a concrete load path was not established", "FILE_ADD_FILE", "DIRECTORY_CREATE_CONFIRMED");
                        directory.Status = EvaluationStatus.Potential; directory.Confidence = Confidence.Medium; directory.Severity = Severity.Medium; directory.ExecutionState = "PRIVILEGED_EXECUTION_CONDITIONAL";
                        directory.MissingConditions.Add("FILE_ADD_FILE does not prove control of the configured executable; FILE_DELETE_CHILD or executable DELETE was not confirmed.");
                        directory.MissingConditions.Add("No concrete privileged load path for a newly created file was verified."); list.Add(directory); continue;
                    }
                    match = false; unknown = create == TriState.Unknown; evidence = "Directory FILE_ADD_FILE right: " + create;
                }
                if (match || unknown)
                {
                    Finding finding = ObjectFinding(rule, service.Name, match, unknown, evidence, "Current user", "Effective file or service-object right", "Configured executable " + (service.ExecutablePath ?? service.BinaryPath), "Service " + service.Name, service.Account);
                    BinaryArtifact binary = FindBinary(context, service.ExecutablePath);
                    if (binary != null)
                    {
                        finding.Evidence.Add(new Evidence { Kind = "BinaryCorrelation", Subject = binary.Path, Value = "Path sources=" + String.Join(",", binary.Sources.ToArray()) + "; observed PIDs=" + String.Join(",", binary.ProcessIds.Select(p => p.ToString()).ToArray()), Positive = binary.ObservedProcessImage });
                        if (!binary.ObservedProcessImage) finding.MissingConditions.Add("No active process image matching the configured service executable was observed; the configured service path remains the primary evidence.");
                    }
                    list.Add(finding);
                }
            }
            if (list.Count == 0) { Finding none = Base(rule); none.Status = context.Services.Count == 0 && context.Errors.Any(e => e.StartsWith("Services:", StringComparison.OrdinalIgnoreCase)) ? EvaluationStatus.Unknown : EvaluationStatus.RuledOut; none.MissingConditions.Add(context.Services.Count == 0 ? "No service data was available." : "No service satisfied the correlated conditions."); list.Add(none); }
            return list;
        }

        private static IEnumerable<Finding> EvaluateTasks(RuleDefinition rule, AnalysisContext context)
        {
            List<Finding> list = new List<Finding>();
            foreach (ScheduledTaskInfo task in context.Tasks)
            {
                if (rule.Id == "PT-018")
                {
                    bool match = task.CanModify == TriState.Yes && task.PrincipalIsHigher == TriState.Yes;
                    bool unknown = !match && task.PrincipalIsHigher != TriState.No && (task.CanModify == TriState.Unknown || task.PrincipalIsHigher == TriState.Unknown);
                    if (match || unknown)
                    {
                        Finding taskFinding = ObjectFinding(rule, task.Path, match, unknown, "Task definition permission: " + task.CanModify + "; enabled=" + task.Enabled, "Current user", "Task " + task.Path, task.Principal);
                        ConditionDisabledTask(taskFinding, task); list.Add(taskFinding);
                    }
                    continue;
                }
                foreach (ScheduledTaskAction action in task.Actions)
                {
                    if (String.IsNullOrWhiteSpace(action.Executable)) continue;
                    string scriptPath = ReferencedScript(action); bool script = !String.IsNullOrWhiteSpace(scriptPath);
                    SecurityPermission relevantPermission = script ? (action.ScriptPermission ?? (PathResolver.IsScript(action.Executable) ? action.TargetPermission : null)) : action.TargetPermission;
                    TriState writeState = EffectiveWrite(relevantPermission); bool writable = writeState == TriState.Yes;
                    bool permissionUnknown = writeState == TriState.Unknown;
                    bool higher = task.PrincipalIsHigher == TriState.Yes; bool higherUnknown = task.PrincipalIsHigher == TriState.Unknown;
                    bool match = false, unknown = false; string evidence = null;
                    bool concreteExecutable = IsConcreteAbsolute(action.Executable) && !action.PathAmbiguous;
                    if (rule.Id == "PT-017") { match = !script && concreteExecutable && writable && higher; unknown = !script && concreteExecutable && task.PrincipalIsHigher != TriState.No && (permissionUnknown || higherUnknown); evidence = "Exact executable is writable and task principal is higher"; }
                    else if (rule.Id == "PT-019") { match = script && IsConcreteAbsolute(scriptPath) && writable && higher; unknown = script && task.PrincipalIsHigher != TriState.No && (!IsConcreteAbsolute(scriptPath) || permissionUnknown || higherUnknown); evidence = "Referenced script is writable and task principal is higher: " + scriptPath; }
                    else if (rule.Id == "PT-020")
                    {
                        bool ambiguous = action.PathAmbiguous || !Path.IsPathRooted(action.Executable) || (action.HijackCandidates != null && action.HijackCandidates.Count > 0);
                        TriState candidate = CandidateControl(action.HijackCandidatePermissions);
                        bool concreteCandidate = action.HijackCandidates != null && action.HijackCandidates.Count > 0;
                        string controllableCandidate = ControllableCandidate(action);
                        match = ambiguous && concreteCandidate && controllableCandidate != null && candidate == TriState.Yes && higher;
                        unknown = ambiguous && task.PrincipalIsHigher != TriState.No && !match && (candidate == TriState.Unknown || !concreteCandidate || higherUnknown);
                        evidence = match ? "Concrete execution-search candidate is controllable" : "Execution path resolution or candidate control is unresolved";
                    }
                    if (match || unknown)
                    {
                        string target = rule.Id == "PT-019" ? scriptPath : action.Executable;
                        Finding finding = ObjectFinding(rule, target, match, unknown, evidence, "Current user", "Verified effective permission", "Task " + task.Path, task.Principal);
                        if (rule.Id == "PT-020" && match)
                        {
                            string candidatePath = ControllableCandidate(action);
                            finding.Evidence.Add(new Evidence { Kind = "SearchCandidate", Subject = candidatePath, Value = "Concrete controllable candidate evaluated: " + candidatePath, Positive = true });
                        }
                        finding.Evidence.Add(new Evidence { Kind = "TaskState", Subject = task.Path, Value = task.Enabled ? "Task is enabled." : "Task is disabled; configuration is retained but no active trigger is claimed.", Positive = task.Enabled });
                        ConditionDisabledTask(finding, task);
                        BinaryArtifact binary = FindBinary(context, action.Executable);
                        if (binary != null)
                        {
                            finding.Evidence.Add(new Evidence { Kind = "TaskActionReference", Subject = task.Path, Value = "Configured task action references " + (action.OriginalExecutable ?? action.Executable) + "; normalized path=" + action.Executable, Positive = true });
                            finding.Evidence.Add(new Evidence { Kind = "ObservedProcess", Subject = binary.Path, Value = binary.ObservedProcessImage ? "A matching process image was observed separately; this does not prove the task launched it." : "No matching active process was required or observed.", Positive = binary.ObservedProcessImage });
                        }
                        list.Add(finding);
                    }
                }
            }
            if (list.Count == 0) { Finding none = Base(rule); none.Status = context.Tasks.Count == 0 && context.Errors.Any(e => e.StartsWith("Tasks:", StringComparison.OrdinalIgnoreCase)) ? EvaluationStatus.Unknown : EvaluationStatus.RuledOut; none.MissingConditions.Add(context.Tasks.Count == 0 ? "No scheduled task data was available." : "No task satisfied the correlated conditions."); list.Add(none); }
            return list;
        }

        private static Finding ObjectFinding(RuleDefinition rule, string target, bool match, bool unknown, string evidence, params string[] trace)
        {
            Finding finding = Base(rule); finding.Target = target;
            finding.Status = match ? EvaluationStatus.Confirmed : unknown ? EvaluationStatus.Unknown : EvaluationStatus.RuledOut;
            finding.Confidence = match ? Confidence.High : Confidence.Unknown;
            finding.Evidence.Add(new Evidence { Kind = rule.Category, Subject = target, Value = evidence, Positive = match });
            if (match) finding.Trace.AddRange(trace);
            else { finding.Trace.Add("Current user"); finding.Trace.Add("Required permission or execution identity UNKNOWN"); finding.Trace.Add("Configured object " + (target ?? "UNKNOWN")); }
            if (!match) finding.MissingConditions.Add("One or more effective-permission or execution-principal checks are unavailable.");
            return finding;
        }

        private static TokenPrivilegeState PrivilegeState(TokenPrivilege privilege)
        {
            if (privilege.State != TokenPrivilegeState.Unknown) return privilege.State;
            return privilege.Present ? (privilege.Enabled ? TokenPrivilegeState.Enabled : TokenPrivilegeState.Disabled) : TokenPrivilegeState.Unknown;
        }
        private static TriState EffectiveWrite(SecurityPermission permission)
        {
            if (permission == null || permission.CanWrite == TriState.Unknown) return TriState.Unknown;
            if (permission.CanWrite == TriState.No) return TriState.No;
            if (permission.MandatoryIntegrityAllowsWrite.HasValue)
            {
                if (permission.MandatoryIntegrityAllowsWrite.Value == TriState.No) return TriState.No;
                if (permission.MandatoryIntegrityAllowsWrite.Value == TriState.Unknown) return TriState.Unknown;
            }
            return TriState.Yes;
        }
        private static TriState EffectiveCreate(SecurityPermission permission)
        {
            if (permission == null || permission.CanCreate == TriState.Unknown) return TriState.Unknown;
            if (permission.CanCreate == TriState.No) return TriState.No;
            if (permission.MandatoryIntegrityAllowsWrite.HasValue)
            {
                if (permission.MandatoryIntegrityAllowsWrite.Value == TriState.No) return TriState.No;
                if (permission.MandatoryIntegrityAllowsWrite.Value == TriState.Unknown) return TriState.Unknown;
            }
            return TriState.Yes;
        }
        private static TriState CandidateControl(IEnumerable<SecurityPermission> permissions)
        {
            if (permissions == null) return TriState.Unknown; bool unknown = false, any = false;
            foreach (SecurityPermission permission in permissions)
            {
                any = true;
                TriState write = EffectiveWrite(permission), create = EffectiveCreate(permission);
                if (write == TriState.Yes || create == TriState.Yes) return TriState.Yes;
                if (write == TriState.Unknown || create == TriState.Unknown) unknown = true;
            }
            return !any || unknown ? TriState.Unknown : TriState.No;
        }
        private static bool IsConcreteAbsolute(string path)
        {
            if (String.IsNullOrWhiteSpace(path)) return false;
            try { return Path.IsPathRooted(path); } catch { return false; }
        }
        private static string ControllableCandidate(ScheduledTaskAction action)
        {
            if (action == null || action.HijackCandidates == null || action.HijackCandidatePermissions == null) return null;
            int count = Math.Min(action.HijackCandidates.Count, action.HijackCandidatePermissions.Count);
            for (int i = 0; i < count; i++)
            {
                SecurityPermission permission = action.HijackCandidatePermissions[i];
                if (EffectiveWrite(permission) == TriState.Yes || EffectiveCreate(permission) == TriState.Yes) return action.HijackCandidates[i];
            }
            return null;
        }
        private static string ReferencedScript(ScheduledTaskAction action)
        {
            if (!String.IsNullOrWhiteSpace(action.ReferencedScript)) return action.ReferencedScript;
            if (PathResolver.IsScript(action.Executable)) return action.Executable;
            string file = null; try { file = Path.GetFileName(action.Executable); } catch { }
            if (String.IsNullOrWhiteSpace(file) || String.IsNullOrWhiteSpace(action.Arguments)) return null;
            string lower = file.ToLowerInvariant();
            if (lower != "powershell.exe" && lower != "powershell" && lower != "pwsh.exe" && lower != "pwsh" && lower != "cscript.exe" && lower != "wscript.exe" && lower != "cmd.exe") return null;
            return PathResolver.FindScriptReference(action.Arguments, action.WorkingDirectory);
        }
        private static Finding ServiceExecutionFinding(RuleDefinition rule, WindowsService service, string target, string evidence, string operation, string permissionState)
        {
            Finding finding = Base(rule); finding.Target = target; bool disabled = String.Equals(service.StartType, "Disabled", StringComparison.OrdinalIgnoreCase);
            bool running = String.Equals(service.State, "Running", StringComparison.OrdinalIgnoreCase); bool automatic = !String.IsNullOrWhiteSpace(service.StartType) && service.StartType.StartsWith("Automatic", StringComparison.OrdinalIgnoreCase);
            bool demandStart = String.Equals(service.StartType, "Manual", StringComparison.OrdinalIgnoreCase) && service.CanStart == TriState.Yes;
            bool ready = !disabled && (running || automatic || demandStart);
            finding.Status = ready ? EvaluationStatus.Confirmed : EvaluationStatus.Potential; finding.Confidence = ready ? Confidence.High : Confidence.Medium;
            finding.Evidence.Add(new Evidence { Kind = "ServiceExecution", Subject = service.Name, Value = evidence + "; state=" + service.State + "; startType=" + service.StartType + "; canStart=" + service.CanStart + "; canChangeConfig=" + service.CanChangeConfig, Positive = true });
            if (service.ExecutablePermission != null) AddPermissionEvidence(finding, service.ExecutablePermission, "ExecutableAcl");
            if (service.DirectoryPermission != null) AddPermissionEvidence(finding, service.DirectoryPermission, "DirectoryAcl");
            finding.ServiceName = service.Name; finding.ObjectIdentity = service.Name + "|" + (service.ExecutablePath ?? service.BinaryPath ?? "UNKNOWN"); finding.PermissionState = permissionState; finding.ConfigurationState = "CONFIRMED_CONFIGURATION"; finding.ExecutionState = "CONDITIONAL_EXECUTION"; finding.RuntimeProtectionState = String.IsNullOrWhiteSpace(service.RuntimeProtectionState) ? "UNKNOWN" : service.RuntimeProtectionState; finding.VerifiedOperation = operation;
            finding.Trace.Add("Current user"); finding.Trace.Add("Effective filesystem control"); finding.Trace.Add("Configured executable " + (service.ExecutablePath ?? service.BinaryPath)); finding.Trace.Add("Service " + service.Name); finding.Trace.Add(service.Account);
            finding.Trace.Add(permissionState + ": " + operation); finding.Trace.Add("CONFIRMED_CONFIGURATION: service account=" + service.Account); finding.Trace.Add("CONDITIONAL_EXECUTION: no binary modification, restart, or payload execution was performed");
            if (!ready) finding.MissingConditions.Add(disabled ? "The service is disabled. Reconfiguration and a later activation are not assumed." : "No running, automatic, or effectively startable service activation was verified.");
            else finding.MissingConditions.Add("Service state/start rights are context only; execution of modified content was not tested.");
            if (String.Equals(finding.RuntimeProtectionState, "UNKNOWN", StringComparison.OrdinalIgnoreCase)) finding.MissingConditions.Add("Runtime or application self-protection was not evaluated and remains UNKNOWN.");
            return finding;
        }

        private static bool FileReplacementConfirmed(WindowsService service)
        {
            return service != null && EffectiveCreate(service.DirectoryPermission) == TriState.Yes && ((service.DirectoryPermission != null && service.DirectoryPermission.CanDeleteChildren == TriState.Yes) || (service.ExecutablePermission != null && service.ExecutablePermission.CanDelete == TriState.Yes));
        }

        private static bool ReplacementUnknown(WindowsService service)
        {
            if (service == null || EffectiveCreate(service.DirectoryPermission) == TriState.Unknown) return true;
            return EffectiveCreate(service.DirectoryPermission) == TriState.Yes && ((service.DirectoryPermission == null || service.DirectoryPermission.CanDeleteChildren == TriState.Unknown) && (service.ExecutablePermission == null || service.ExecutablePermission.CanDelete == TriState.Unknown));
        }
        private static void ConditionDisabledTask(Finding finding, ScheduledTaskInfo task)
        {
            if (task.Enabled) return;
            if (finding.Status == EvaluationStatus.Confirmed) { finding.Status = EvaluationStatus.Potential; finding.Confidence = Confidence.Medium; }
            finding.MissingConditions.Add(task.CanModify == TriState.Yes ? "The task is disabled. Definition modification is available, but re-enabling or execution was not attempted." : "The task is disabled and no verified reactivation capability is assumed.");
        }
        private static bool IsHigher(string account) { return PathResolver.IsPrivilegedPrincipal(account); }
        private static bool HasRegistryMutation(SecurityPermission permission) { return permission != null && (permission.CanWrite == TriState.Yes || permission.CanDelete == TriState.Yes || permission.CanChangePermissions == TriState.Yes); }
        private static bool IsPermissionUnknown(SecurityPermission permission) { return permission == null || permission.CanWrite == TriState.Unknown || permission.CanCreate == TriState.Unknown || permission.CanDelete == TriState.Unknown || permission.CanChangePermissions == TriState.Unknown; }
        private static string RegistryRights(SecurityPermission permission) { return "set-value=" + permission.CanWrite + ", create-subkey=" + permission.CanCreate + ", delete=" + permission.CanDelete + ", write-DACL=" + permission.CanChangePermissions; }
        private static bool IsSharedProcessService(WindowsService service)
        {
            if (service == null || String.IsNullOrWhiteSpace(service.ServiceType)) return false;
            uint value; string text = service.ServiceType.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? service.ServiceType.Substring(2) : service.ServiceType;
            bool shared = UInt32.TryParse(text, System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture, out value) && (value & 0x20) == 0x20;
            string executable = service.ExecutablePath ?? service.BinaryPath;
            string file = null; try { file = Path.GetFileName(executable); } catch { }
            return shared && String.Equals(file, "svchost.exe", StringComparison.OrdinalIgnoreCase);
        }
        private static void AddPermissionEvidence(Finding finding, SecurityPermission permission, string kind)
        {
            finding.Evidence.Add(new Evidence { Kind = kind, Subject = permission.Target, Value = (permission.ObjectType == "RegistryKey" ? RegistryRights(permission) : "write=" + permission.CanWrite + ", create=" + permission.CanCreate + ", delete=" + permission.CanDelete + ", delete-child=" + permission.CanDeleteChildren + ", write-DACL=" + permission.CanChangePermissions) + "; owner=" + (permission.OwnerAccount ?? permission.OwnerSid ?? "UNKNOWN"), Positive = permission.CanWrite == TriState.Yes || permission.CanCreate == TriState.Yes || permission.CanDelete == TriState.Yes || permission.CanDeleteChildren == TriState.Yes || permission.CanChangePermissions == TriState.Yes });
        }
        private static BinaryArtifact FindBinary(AnalysisContext context, string path) { return context.Binaries == null ? null : context.Binaries.FirstOrDefault(b => BinaryPathResolver.SamePath(b.Path, path)); }
    }
}
