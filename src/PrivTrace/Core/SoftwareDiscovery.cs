using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Web.Script.Serialization;
using Microsoft.Win32;
using PrivTrace.Models;
using PrivTrace.Security;
using PrivTrace.Interop;

namespace PrivTrace.Core
{
    public sealed class SoftwareProfileDocument
    {
        public string SchemaVersion { get; set; }
        public List<SoftwareProfile> Profiles { get; set; }
    }

    internal sealed class RegisteredSoftwareEntry
    {
        internal string DisplayName;
        internal string Publisher;
        internal string InstallLocation;
        internal string DisplayVersion;
        internal string RegistryKey;
        internal string ViewName;
        internal bool InstallationRootVerified;
    }

    public sealed class SoftwareProfileCatalog
    {
        public const string ResourceName = "PrivTrace.Knowledge.Software.profiles.json";

        public List<SoftwareProfile> LoadEmbedded()
        {
            Stream stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(ResourceName);
            if (stream == null) throw new InvalidDataException("Embedded software profile catalog is missing: " + ResourceName);
            using (stream) using (StreamReader reader = new StreamReader(stream, Encoding.UTF8, true))
            {
                SoftwareProfileDocument document = new JavaScriptSerializer { MaxJsonLength = Int32.MaxValue }.Deserialize<SoftwareProfileDocument>(reader.ReadToEnd());
                if (document == null || document.Profiles == null) throw new InvalidDataException("Software profile catalog is malformed.");
                Validate(document.Profiles); return document.Profiles;
            }
        }

        public void Validate(IList<SoftwareProfile> profiles)
        {
            if (profiles == null || profiles.Count < 15 || profiles.Count > 25) throw new InvalidDataException("Software profile catalog must contain 15 through 25 profiles.");
            HashSet<string> ids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (SoftwareProfile profile in profiles)
            {
                if (profile == null || String.IsNullOrWhiteSpace(profile.ProfileId) || String.IsNullOrWhiteSpace(profile.ProductName) || String.IsNullOrWhiteSpace(profile.Vendor) || String.IsNullOrWhiteSpace(profile.Category) || profile.ExecutableNames == null || profile.ExecutableNames.Count == 0 || profile.TrustedIdentificationHints == null || profile.ExpectedPathPatterns == null || profile.OptionalServiceNames == null || profile.OptionalVersionSources == null || profile.RelevantExistingRules == null || String.IsNullOrWhiteSpace(profile.ResearchReason) || String.IsNullOrWhiteSpace(profile.FalsePositiveNotes) || profile.ReferenceIds == null || profile.ReferenceIds.Count == 0)
                    throw new InvalidDataException("Incomplete software profile: " + (profile == null ? "<null>" : profile.ProfileId));
                if (!String.IsNullOrWhiteSpace(profile.Version)) throw new InvalidDataException("Software profiles may describe version strategies but may not contain observed version values: " + profile.ProfileId);
                if (!String.IsNullOrWhiteSpace(profile.SoftwareContext) && !new[] { "INTERESTING", "RESEARCH_SURFACE", "INFRASTRUCTURE" }.Contains(profile.SoftwareContext, StringComparer.OrdinalIgnoreCase)) throw new InvalidDataException("Unknown software context in " + profile.ProfileId + ": " + profile.SoftwareContext);
                foreach (string source in profile.OptionalVersionSources) if (!new[] { "PE_FILE_VERSION", "PE_PRODUCT_VERSION", "UNINSTALL_REGISTRY", "XAMPP_PROPERTIES_INI" }.Contains(source ?? String.Empty, StringComparer.OrdinalIgnoreCase)) throw new InvalidDataException("Unknown or unsupported version strategy in " + profile.ProfileId + ": " + source);
                if (!ids.Add(profile.ProfileId)) throw new InvalidDataException("Duplicate software profile: " + profile.ProfileId);
                foreach (string rule in profile.RelevantExistingRules) if (!System.Text.RegularExpressions.Regex.IsMatch(rule ?? String.Empty, "^PT-0(0[1-9]|1[0-9]|2[0-7])$")) throw new InvalidDataException("Invalid rule reference in " + profile.ProfileId + ": " + rule);
            }
        }
    }

    public static class FileIdentityCollector
    {
        public static void Enrich(AnalysisContext context, bool liveFileReads)
        {
            foreach (WindowsProcess process in context.Processes ?? new List<WindowsProcess>())
            {
                if (process.FileIdentity != null) Normalize(process.FileIdentity, process.ImagePath);
                else process.FileIdentity = Read(process.ImagePath, liveFileReads, process.Errors);
            }
            foreach (WindowsService service in context.Services ?? new List<WindowsService>())
            {
                string path = service.ExecutablePath ?? service.BinaryPath;
                if (service.FileIdentity != null) Normalize(service.FileIdentity, path);
                else service.FileIdentity = Read(path, liveFileReads, service.Errors);
                if (String.IsNullOrWhiteSpace(service.RuntimeProtectionState)) service.RuntimeProtectionState = "UNKNOWN";
            }
            foreach (ScheduledTaskInfo task in context.Tasks ?? new List<ScheduledTaskInfo>()) foreach (ScheduledTaskAction action in task.Actions ?? new List<ScheduledTaskAction>())
            {
                if (action.FileIdentity != null) Normalize(action.FileIdentity, action.Executable);
                else action.FileIdentity = Read(action.Executable, liveFileReads, task.Errors);
            }
        }

        private static FileIdentityMetadata Read(string path, bool liveFileReads, IList<string> errors)
        {
            FileIdentityMetadata identity = new FileIdentityMetadata { CanonicalPath = Canonical(path), MetadataState = "UNKNOWN", VersionConfidence = VersionConfidence.Unknown, SignatureStatus = SignatureStatus.Unknown };
            if (!liveFileReads || String.IsNullOrWhiteSpace(path)) return identity;
            try
            {
                FileVersionInfo info = FileVersionInfo.GetVersionInfo(path);
                identity.CompanyName = Clean(info.CompanyName); identity.FileDescription = Clean(info.FileDescription); identity.OriginalFilename = Clean(info.OriginalFilename);
                identity.ProductName = Clean(info.ProductName); identity.ProductVersion = Clean(info.ProductVersion); identity.FileVersion = Clean(info.FileVersion); identity.MetadataState = "OBSERVED";
                if (!String.IsNullOrWhiteSpace(identity.ProductVersion)) { identity.VersionSource = "PE_PRODUCT_VERSION"; identity.VersionConfidence = VersionConfidence.Medium; }
                else if (!String.IsNullOrWhiteSpace(identity.FileVersion)) { identity.VersionSource = "PE_FILE_VERSION"; identity.VersionConfidence = VersionConfidence.Low; }
            }
            catch (Exception ex) { identity.MetadataState = "ERROR"; if (errors != null) errors.Add("FileVersionInfo: " + ex.GetType().Name + ": " + ex.Message); }
            AuthenticodeVerifier.Verify(path, identity); return identity;
        }

        private static void Normalize(FileIdentityMetadata identity, string path) { if (String.IsNullOrWhiteSpace(identity.CanonicalPath)) identity.CanonicalPath = Canonical(path); if (String.IsNullOrWhiteSpace(identity.MetadataState)) identity.MetadataState = "UNKNOWN"; }
        private static string Clean(string value) { return String.IsNullOrWhiteSpace(value) ? null : value.Trim(); }
        private static string Canonical(string path) { if (String.IsNullOrWhiteSpace(path)) return null; try { return Path.GetFullPath(path); } catch { return path; } }
    }

    public sealed class SoftwareDiscoveryEngine
    {
        public List<SoftwareObservation> Discover(AnalysisContext context, IList<SoftwareProfile> profiles, bool liveTargetedReads)
        {
            return Discover(context, profiles, liveTargetedReads, null);
        }

        internal List<SoftwareObservation> Discover(AnalysisContext context, IList<SoftwareProfile> profiles, bool liveTargetedReads, IEnumerable<RegisteredSoftwareEntry> registeredEntries)
        {
            List<SoftwareObservation> observations = new List<SoftwareObservation>();
            foreach (WindowsProcess process in context.Processes ?? new List<WindowsProcess>())
            {
                AddProcessCandidate(observations, context, profiles, process, liveTargetedReads);
            }
            foreach (WindowsService service in context.Services ?? new List<WindowsService>()) AddServiceCandidate(observations, context, profiles, service, liveTargetedReads);
            foreach (ScheduledTaskInfo task in context.Tasks ?? new List<ScheduledTaskInfo>()) foreach (ScheduledTaskAction action in task.Actions ?? new List<ScheduledTaskAction>()) AddTaskCandidate(observations, profiles, task, action, liveTargetedReads);
            if (registeredEntries != null) AddInstalledCandidatesFromEntries(observations, profiles, registeredEntries, "TEST_FIXTURE");
            else if (liveTargetedReads) AddInstalledCandidates(observations, context, profiles);
            foreach (SoftwareObservation item in observations)
            {
                ApplyVersion(context, item, profiles.FirstOrDefault(p => String.Equals(p.ProfileId, item.ProfileId, StringComparison.OrdinalIgnoreCase)), liveTargetedReads); BuildTrace(item);
            }
            context.Software = observations.OrderBy(o => o.ProductName, StringComparer.OrdinalIgnoreCase).ThenBy(o => o.InstallationRoot, StringComparer.OrdinalIgnoreCase).ToList();
            return context.Software;
        }

        private static ProfileMatch BestMatch(IList<SoftwareProfile> profiles, WindowsProcess candidate, bool liveTargetedReads)
        {
            return profiles.Select(p => Match(p, candidate, liveTargetedReads)).Where(m => m.Identified).OrderByDescending(m => m.StrongIdentification).ThenByDescending(m => m.SignalFamilies).ThenByDescending(m => m.PathSpecificity).FirstOrDefault();
        }

        private static void AddProcessCandidate(List<SoftwareObservation> observations, AnalysisContext context, IList<SoftwareProfile> profiles, WindowsProcess process, bool liveTargetedReads)
        {
            if (process == null || String.IsNullOrWhiteSpace(process.ImagePath)) return;
            ProfileMatch match = BestMatch(profiles, process, liveTargetedReads); SoftwareClassification classification = Classify(process, match == null ? null : match.Profile);
            if (process.FileIdentity != null) process.FileIdentity.SoftwareClassification = classification;
            bool privilegedService = AssociatedServices(context, process).Any(s => IsPrivileged(s.Account));
            if (match == null && !(classification == SoftwareClassification.ThirdPartySoftware && privilegedService)) return;
            if (match != null && !match.StrongIdentification && (!privilegedService || String.Equals(match.Profile.ProfileId, "SW-XAMPP", StringComparison.OrdinalIgnoreCase))) return;
            if (classification == SoftwareClassification.WindowsComponent && !privilegedService) return;
            SoftwareObservation item = GetOrCreate(observations, process, match, classification, "PROCESS_RUNNING", "RunningProcess", "ProcessCollector");
            AddProcess(item, process, context); AddUnique(item.ObservationStates, "PROCESS_RUNNING"); item.State = "PROCESS_RUNNING";
        }

        private static void AddServiceCandidate(List<SoftwareObservation> observations, AnalysisContext context, IList<SoftwareProfile> profiles, WindowsService service, bool liveTargetedReads)
        {
            string path = service == null ? null : (service.ExecutablePath ?? service.BinaryPath); if (String.IsNullOrWhiteSpace(path)) return;
            WindowsProcess candidate = new WindowsProcess { ImagePath = path, FileIdentity = service.FileIdentity, ServiceNames = new List<string> { service.Name } };
            ProfileMatch match = BestMatch(profiles, candidate, liveTargetedReads); SoftwareClassification classification = Classify(candidate, match == null ? null : match.Profile);
            bool privileged = IsPrivileged(service.Account);
            if (match == null && !(classification == SoftwareClassification.ThirdPartySoftware && privileged)) return;
            if (match != null && !match.StrongIdentification) return;
            SoftwareObservation item = GetOrCreate(observations, candidate, match, classification, "SERVICE_CONFIGURED", "ConfiguredServiceExecutable", "ServiceCollector");
            AddUnique(item.ConfiguredExecutablePaths, path); AddUnique(item.ServiceNames, service.Name); AddUnique(item.ExecutionIdentities, service.Account); AddUnique(item.ObservationStates, "SERVICE_CONFIGURED");
            item.Evidence.Add(new SoftwareEvidence { Kind = "AssociatedService", Value = service.Name + " configures " + path + " as " + (service.Account ?? "UNKNOWN"), State = RelationshipState.Configured, Source = "ServiceCollector+ExecutionInventory" });
            item.Evidence.Add(new SoftwareEvidence { Kind = "ServiceState", Value = service.Name + " state=" + (service.State ?? "UNKNOWN") + "; startType=" + (service.StartType ?? "UNKNOWN") + "; PID=" + service.ProcessId, State = RelationshipState.Observed, Source = "ServiceCollector" });
            if (String.Equals(service.State, "Running", StringComparison.OrdinalIgnoreCase)) AddUnique(item.ObservationStates, "SERVICE_RUNNING");
            item.State = item.ProcessIds.Count > 0 ? "PROCESS_RUNNING" : String.Equals(service.State, "Running", StringComparison.OrdinalIgnoreCase) ? "SERVICE_RUNNING" : "SERVICE_CONFIGURED";
            if (privileged) item.PrivilegedContextObserved = true;
            if (service.ExecutablePermission != null) item.Evidence.Add(new SoftwareEvidence { Kind = "EffectiveFilePermission", Value = "write=" + service.ExecutablePermission.CanWrite + ", delete=" + service.ExecutablePermission.CanDelete + ", write-DACL=" + service.ExecutablePermission.CanChangePermissions, State = RelationshipState.Observed, Source = "ExecutionInventory/AccessCheck" });
        }

        private static void AddTaskCandidate(List<SoftwareObservation> observations, IList<SoftwareProfile> profiles, ScheduledTaskInfo task, ScheduledTaskAction action, bool liveTargetedReads)
        {
            if (action == null || String.IsNullOrWhiteSpace(action.Executable)) return;
            WindowsProcess candidate = new WindowsProcess { ImagePath = action.Executable, FileIdentity = action.FileIdentity };
            ProfileMatch match = BestMatch(profiles, candidate, liveTargetedReads); if (match == null || !match.StrongIdentification) return;
            SoftwareClassification classification = Classify(candidate, match.Profile); SoftwareObservation item = GetOrCreate(observations, candidate, match, classification, "TASK_CONFIGURED", "ConfiguredTaskExecutable", "ScheduledTaskCollector");
            AddUnique(item.ConfiguredExecutablePaths, action.Executable); AddUnique(item.ScheduledTaskPaths, task.Path); AddUnique(item.ExecutionIdentities, task.Principal); AddUnique(item.ObservationStates, "TASK_CONFIGURED");
            if (item.ProcessIds.Count == 0 && item.ServiceNames.Count == 0) item.State = "TASK_CONFIGURED";
            item.Evidence.Add(new SoftwareEvidence { Kind = "AssociatedScheduledTask", Value = task.Path + " configures " + action.Executable + " as " + (task.Principal ?? "UNKNOWN"), State = RelationshipState.Configured, Source = "ScheduledTaskCollector+ExecutionInventory" });
            if (task.PrincipalIsHigher == TriState.Yes || IsPrivileged(task.Principal)) item.PrivilegedContextObserved = true;
        }

        private static void AddInstalledCandidates(List<SoftwareObservation> observations, AnalysisContext context, IList<SoftwareProfile> profiles)
        {
            foreach (RegistryHive hive in new[] { RegistryHive.LocalMachine, RegistryHive.CurrentUser }) foreach (RegistryView view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
            {
                string rootName = (hive == RegistryHive.LocalMachine ? "HKLM" : "HKCU") + @"\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
                try
                {
                    using (RegistryKey root = RegistryKey.OpenBaseKey(hive, view)) using (RegistryKey uninstall = root.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", false))
                        AddInstalledCandidatesFromKey(observations, profiles, uninstall, rootName, view.ToString(), "LIVE_OBSERVED");
                }
                catch (Exception ex) { context.Errors.Add("Installed software registry " + rootName + " [" + view + "]: " + ex.GetType().Name + ": " + ex.Message); }
            }
        }

        internal static void AddInstalledCandidatesFromKey(List<SoftwareObservation> observations, IList<SoftwareProfile> profiles, RegistryKey uninstall, string registryPath, string viewName, string origin)
        {
            if (uninstall == null) return;
            foreach (string name in uninstall.GetSubKeyNames()) using (RegistryKey key = uninstall.OpenSubKey(name, false))
            {
                if (key == null) continue; string displayName = Convert.ToString(key.GetValue("DisplayName", null)), publisher = Convert.ToString(key.GetValue("Publisher", null)), location = Convert.ToString(key.GetValue("InstallLocation", null)), version = Convert.ToString(key.GetValue("DisplayVersion", null));
                string root = null; try { if (!String.IsNullOrWhiteSpace(location)) root = Path.GetFullPath(Environment.ExpandEnvironmentVariables(location)).TrimEnd('\\', '/'); } catch { }
                AddInstalledCandidatesFromEntries(observations, profiles, new[] { new RegisteredSoftwareEntry { DisplayName = displayName, Publisher = publisher, InstallLocation = root, DisplayVersion = version, RegistryKey = registryPath + "\\" + name, ViewName = viewName, InstallationRootVerified = !String.IsNullOrWhiteSpace(root) && Directory.Exists(root) } }, origin);
            }
        }

        internal static void AddInstalledCandidatesFromEntries(List<SoftwareObservation> observations, IList<SoftwareProfile> profiles, IEnumerable<RegisteredSoftwareEntry> entries, string origin)
        {
            foreach (RegisteredSoftwareEntry entry in entries ?? Enumerable.Empty<RegisteredSoftwareEntry>())
            {
                if (entry == null || !entry.InstallationRootVerified || String.IsNullOrWhiteSpace(entry.DisplayName) || String.IsNullOrWhiteSpace(entry.InstallLocation)) continue;
                SoftwareProfile profile = profiles.FirstOrDefault(p => RegistryIdentityMatches(p, entry.DisplayName, entry.Publisher, entry.InstallLocation)); if (profile == null) continue;
                string root; try { root = Path.GetFullPath(Environment.ExpandEnvironmentVariables(entry.InstallLocation)).TrimEnd('\\', '/'); } catch { continue; }
                string observationId = profile.ProfileId + "|" + root.ToUpperInvariant(); SoftwareObservation item = observations.FirstOrDefault(o => String.Equals(o.ObservationId, observationId, StringComparison.OrdinalIgnoreCase));
                if (item == null)
                {
                    item = new SoftwareObservation { ObservationId = observationId, ProfileId = profile.ProfileId, ProductName = profile.ProductName, Vendor = profile.Vendor, Category = profile.Category, SoftwareContext = String.IsNullOrWhiteSpace(profile.SoftwareContext) ? "INTERESTING" : profile.SoftwareContext.ToUpperInvariant(), InvestigationPriority = profile.InvestigationPriority, Classification = SoftwareClassification.ThirdPartySoftware, IdentificationStatus = "PRODUCT_IDENTIFIED", IdentificationConfidence = Confidence.Medium, InstallationRoot = root, State = "INSTALLED", VersionSource = "UNKNOWN", VersionConfidence = VersionConfidence.Unknown, SignatureStatus = SignatureStatus.Unknown, EscalationStatus = "NOT_VERIFIED" };
                    foreach (string rule in profile.RelevantExistingRules) item.RelevantRuleIds.Add(rule); item.ObservationStates.Add("INSTALLED"); observations.Add(item);
                }
                AddUnique(item.ObservationStates, "INSTALLED"); item.Evidence.Add(new SoftwareEvidence { Kind = "RegisteredInstallation", Value = entry.DisplayName + "; publisher=" + (entry.Publisher ?? "UNKNOWN") + "; root=" + root, State = RelationshipState.Observed, Source = entry.RegistryKey + " [" + entry.ViewName + "]" });
                if (ValidVersion(entry.DisplayVersion))
                {
                    SoftwareVersionEvidence evidence = NewVersionEvidence(profile.ProfileId, root, entry.DisplayName, "UNINSTALL_REGISTRY", VersionConfidence.Medium, origin); evidence.Value = evidence.Version = entry.DisplayVersion.Trim(); evidence.RegistryKey = entry.RegistryKey + " [" + entry.ViewName + "]"; evidence.SourceField = "DisplayVersion"; evidence.ObservationStatus = "OBSERVED"; evidence.ReadStatus = "SUCCESS"; AddVersionEvidence(item, evidence);
                }
            }
        }

        internal static bool RegistryIdentityMatches(SoftwareProfile profile, string displayName, string publisher, string location)
        {
            if (profile == null) return false; string product = profile.ProductName ?? String.Empty;
            bool productMatch = Contains(displayName, product) || ProfileIdTokens(profile.ProfileId).Any(t => Contains(displayName, t)); if (!productMatch) return false;
            bool vendorMatch = !String.IsNullOrWhiteSpace(publisher) && publisher.Trim().Length >= 5 && (Contains(publisher, profile.Vendor) || Contains(profile.Vendor, publisher));
            bool pathMatch = profile.ExpectedPathPatterns.Any(p => ContainsPattern((location ?? String.Empty).TrimEnd('\\', '/') + "\\", p));
            return vendorMatch || pathMatch;
        }

        private static IEnumerable<string> ProfileIdTokens(string value) { return (value ?? String.Empty).Split(new[] { '-' }, StringSplitOptions.RemoveEmptyEntries).Where(t => t.Length >= 4 && !String.Equals(t, "TOOLS", StringComparison.OrdinalIgnoreCase) && !String.Equals(t, "WINDOWS", StringComparison.OrdinalIgnoreCase) && !String.Equals(t, "SERVER", StringComparison.OrdinalIgnoreCase)); }

        private static SoftwareObservation GetOrCreate(List<SoftwareObservation> observations, WindowsProcess candidate, ProfileMatch match, SoftwareClassification classification, string state, string evidenceKind, string evidenceSource)
        {
            string profileId = match == null ? "HEURISTIC-THIRD-PARTY" : match.Profile.ProfileId, root = InstallationRoot(candidate.ImagePath, match == null ? null : match.Profile);
            string key = profileId + "|" + (root ?? candidate.ImagePath).ToUpperInvariant(); SoftwareObservation item = observations.FirstOrDefault(o => String.Equals(o.ObservationId, key, StringComparison.OrdinalIgnoreCase));
            if (item != null) return item;
            item = NewObservation(candidate, match, classification, root, key, state, evidenceKind, evidenceSource); observations.Add(item); return item;
        }

        public void CorrelateFindings(AnalysisContext context, IList<Finding> findings)
        {
            foreach (SoftwareObservation software in context.Software ?? new List<SoftwareObservation>())
            {
                foreach (Finding finding in findings.Where(f => (f.Status == EvaluationStatus.Confirmed || f.Status == EvaluationStatus.Potential) && MatchesSoftware(f, software)))
                {
                    if (!software.ActiveRuleIds.Contains(finding.RuleId, StringComparer.OrdinalIgnoreCase)) software.ActiveRuleIds.Add(finding.RuleId);
                    software.Evidence.Add(new SoftwareEvidence { Kind = "ExistingRule", Value = finding.RuleId + " " + finding.Status.ToString().ToUpperInvariant() + " target=" + finding.Target, State = RelationshipState.Observed, Source = "RuleEngine" });
                }
                software.EscalationStatus = software.ActiveRuleIds.Count > 0 ? "EXISTING_RULE_VERIFIED" : "NOT_VERIFIED";
                if (software.ActiveRuleIds.Count > 0) software.InvestigationPriority = Math.Max(software.InvestigationPriority, 100);
                if (software.ActiveRuleIds.Count == 0) software.PendingConditions.Add("No existing PrivTrace rule produced a confirmed or evidence-backed potential result for this installation.");
                else software.Trace.Add("Existing rules " + String.Join(",", software.ActiveRuleIds.ToArray()) + " [OBSERVED RESULT]");
                software.Trace.Add("Escalation " + software.EscalationStatus + " [ADVANCED CORRELATION]");
            }
        }

        private static SoftwareObservation NewObservation(WindowsProcess process, ProfileMatch match, SoftwareClassification classification, string root, string key, string state, string evidenceKind, string evidenceSource)
        {
            SoftwareProfile profile = match == null ? null : match.Profile; FileIdentityMetadata identity = process.FileIdentity ?? new FileIdentityMetadata();
            SoftwareObservation item = new SoftwareObservation
            {
                ObservationId = key, ProfileId = profile == null ? null : profile.ProfileId,
                ProductName = profile == null ? (identity.ProductName ?? identity.FileDescription ?? "Unclassified third-party software") : profile.ProductName,
                Vendor = profile == null ? identity.CompanyName : profile.Vendor, Category = profile == null ? "Privileged third-party service" : profile.Category,
                SoftwareContext = profile == null || String.IsNullOrWhiteSpace(profile.SoftwareContext) ? "INTERESTING" : profile.SoftwareContext.ToUpperInvariant(),
                InvestigationPriority = profile == null || profile.InvestigationPriority <= 0 ? 50 : profile.InvestigationPriority,
                Classification = classification, IdentificationStatus = profile == null ? "HEURISTIC_IDENTIFICATION" : match.StrongIdentification ? "PRODUCT_IDENTIFIED" : "PRODUCT_CANDIDATE",
                IdentificationConfidence = match == null || !match.StrongIdentification ? Confidence.Low : match.SignalFamilies >= 3 ? Confidence.High : Confidence.Medium,
                InstallationRoot = root, CanonicalExecutable = identity.CanonicalPath ?? process.ImagePath, State = state,
                SignatureStatus = identity.SignatureStatus, SignerSubject = identity.SignerSubject, EscalationStatus = "NOT_VERIFIED"
            };
            if (profile != null) foreach (string rule in profile.RelevantExistingRules) item.RelevantRuleIds.Add(rule);
            item.ObservationStates.Add(state);
            item.Evidence.Add(new SoftwareEvidence { Kind = evidenceKind, Value = process.ImagePath + (process.ProcessId > 0 ? " PID=" + process.ProcessId : String.Empty), State = state == "PROCESS_RUNNING" ? RelationshipState.Observed : RelationshipState.Configured, Source = evidenceSource });
            if (match != null) foreach (string signal in match.Signals) item.Evidence.Add(new SoftwareEvidence { Kind = "IdentificationSignal", Value = signal, State = RelationshipState.Observed, Source = "SoftwareProfileCatalog" });
            if (identity.SignatureStatus != SignatureStatus.Unknown) item.Evidence.Add(new SoftwareEvidence { Kind = "Authenticode", Value = identity.SignatureStatusName + (String.IsNullOrWhiteSpace(identity.SignerSubject) ? String.Empty : " signer=" + identity.SignerSubject), State = RelationshipState.Observed, Source = "WinVerifyTrust" });
            return item;
        }

        private static void AddProcess(SoftwareObservation item, WindowsProcess process, AnalysisContext context)
        {
            if (!item.ProcessIds.Contains(process.ProcessId)) item.ProcessIds.Add(process.ProcessId);
            AddUnique(item.ProcessPaths, process.ImagePath); AddUnique(item.ExecutionIdentities, process.OwnerAccount ?? process.OwnerSid);
            foreach (WindowsService service in AssociatedServices(context, process))
            {
                AddUnique(item.ServiceNames, service.Name); AddUnique(item.ExecutionIdentities, service.Account);
                item.Evidence.Add(new SoftwareEvidence { Kind = "AssociatedService", Value = service.Name + " runs as " + (service.Account ?? "UNKNOWN"), State = RelationshipState.Configured, Source = "ServiceCollector+exact PID/path correlation" });
                if (IsPrivileged(service.Account)) item.PrivilegedContextObserved = true;
            }
            foreach (ScheduledTaskInfo task in context.Tasks ?? new List<ScheduledTaskInfo>())
            {
                foreach (ScheduledTaskAction action in task.Actions ?? new List<ScheduledTaskAction>())
                {
                    if (!BinaryPathResolver.SamePath(action.Executable, process.ImagePath)) continue;
                    AddUnique(item.ScheduledTaskPaths, task.Path);
                    AddUnique(item.ExecutionIdentities, task.Principal);
                    item.Evidence.Add(new SoftwareEvidence { Kind = "AssociatedScheduledTask", Value = task.Path + " runs " + action.Executable + " as " + (task.Principal ?? "UNKNOWN"), State = RelationshipState.Configured, Source = "ScheduledTaskCollector+exact executable correlation" });
                    if (task.PrincipalIsHigher == TriState.Yes || IsPrivileged(task.Principal)) item.PrivilegedContextObserved = true;
                }
            }
            if (IsPrivileged(process.OwnerAccount)) item.PrivilegedContextObserved = true;
            BinaryArtifact binary = (context.Binaries ?? new List<BinaryArtifact>()).FirstOrDefault(b => BinaryPathResolver.SamePath(b.Path, process.ImagePath));
            if (binary != null && binary.FilePermission != null)
                item.Evidence.Add(new SoftwareEvidence { Kind = "EffectiveFilePermission", Value = "write=" + binary.FilePermission.CanWrite + ", delete=" + binary.FilePermission.CanDelete + ", write-DACL=" + binary.FilePermission.CanChangePermissions, State = RelationshipState.Observed, Source = "ExecutionInventory/AccessCheck" });
        }

        private static void ApplyVersion(AnalysisContext context, SoftwareObservation item, SoftwareProfile profile, bool liveTargetedReads)
        {
            string origin = EvidenceOrigin(context, liveTargetedReads);
            foreach (SoftwareVersionEvidence supplied in (context.SoftwareVersionEvidence ?? new List<SoftwareVersionEvidence>()).Where(v => String.Equals(v.ProductId, item.ProfileId, StringComparison.OrdinalIgnoreCase) && SameRoot(v.InstallationRoot, item.InstallationRoot)))
                AddVersionEvidence(item, NormalizeSuppliedEvidence(supplied, item, profile, origin));

            if (liveTargetedReads && Allows(profile, "XAMPP_PROPERTIES_INI") && String.Equals(item.ProfileId, "SW-XAMPP", StringComparison.OrdinalIgnoreCase))
                AddVersionEvidence(item, ReadXamppVersion(item.InstallationRoot, item.CanonicalExecutable, origin));
            if (liveTargetedReads && Allows(profile, "UNINSTALL_REGISTRY")) foreach (SoftwareVersionEvidence registry in ReadUninstallRegistry(item, origin)) AddVersionEvidence(item, registry);
            AddPeVersionEvidence(context, item, profile, origin);

            SoftwareVersionEvidence primary;
            if (String.Equals(item.ProfileId, "SW-XAMPP", StringComparison.OrdinalIgnoreCase))
                primary = item.VersionEvidence.FirstOrDefault(v => IsObserved(v) && String.Equals(v.Product, "XAMPP", StringComparison.OrdinalIgnoreCase) && (String.Equals(v.SourceType, "XAMPP_PROPERTIES_INI", StringComparison.OrdinalIgnoreCase) || String.Equals(v.SourceType, "UNINSTALL_REGISTRY", StringComparison.OrdinalIgnoreCase)));
            else
                primary = item.VersionEvidence.FirstOrDefault(v => IsObserved(v) && (String.Equals(v.SourceType, "UNINSTALL_REGISTRY", StringComparison.OrdinalIgnoreCase) || String.Equals(v.SourceType, "PE_PRODUCT_VERSION", StringComparison.OrdinalIgnoreCase)))
                    ?? item.VersionEvidence.FirstOrDefault(v => IsObserved(v) && String.Equals(v.SourceType, "PE_FILE_VERSION", StringComparison.OrdinalIgnoreCase));

            if (primary != null) { item.Version = primary.Value; item.VersionSource = primary.SourceType; item.VersionConfidence = primary.Confidence; }
            else { item.Version = null; item.VersionSource = "UNKNOWN"; item.VersionConfidence = VersionConfidence.Unknown; item.PendingConditions.Add("Product version was not available from an approved observed source."); }
        }

        private static SoftwareVersionEvidence ReadXamppVersion(string root, string executable, string origin)
        {
            string path = String.IsNullOrWhiteSpace(root) ? null : Path.Combine(root, "properties.ini");
            return ReadXamppVersionFromSource(root, executable, path, origin);
        }

        internal static SoftwareVersionEvidence ReadXamppVersionFromSource(string root, string executable, string source, string origin)
        {
            SoftwareVersionEvidence result = NewVersionEvidence("SW-XAMPP", root, "XAMPP", "XAMPP_PROPERTIES_INI", VersionConfidence.High, origin);
            if (String.IsNullOrWhiteSpace(root)) return Failed(result, "NOT_READ", "XAMPP installation root was not established; properties.ini was not read.");
            string path;
            try
            {
                path = Path.GetFullPath(source); result.SourcePath = path;
                string validationError;
                if (!ValidateXamppSource(root, executable, path, out validationError)) return Failed(result, "REJECTED", validationError);
                if (!File.Exists(path)) return Failed(result, "NOT_FOUND", "XAMPP properties.ini was absent at the identified installation root.");
                using (FileStream stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                {
                    if (!OpenedFileMatches(stream, path, out validationError)) return Failed(result, "REJECTED", validationError);
                    using (StreamReader reader = new StreamReader(stream, Encoding.UTF8, true))
                    {
                        string line;
                        while ((line = reader.ReadLine()) != null)
                        {
                            string value = line.Trim(); int equals = value.IndexOf('='); if (equals <= 0) continue;
                            string key = value.Substring(0, equals).Trim(), version = value.Substring(equals + 1).Trim();
                            if (!key.Equals("xampp_version", StringComparison.OrdinalIgnoreCase) && !key.Equals("base_stack_version", StringComparison.OrdinalIgnoreCase)) continue;
                            result.SourceField = key;
                            if (!ValidVersion(version)) return Failed(result, "INVALID_DATA", "XAMPP properties.ini contained a malformed value in field " + key + ".");
                            result.Value = result.Version = version; result.ObservationStatus = "OBSERVED"; result.ReadStatus = "SUCCESS"; return result;
                        }
                    }
                }
                return Failed(result, "FIELD_NOT_FOUND", "XAMPP properties.ini did not contain an approved XAMPP version key.");
            }
            catch (UnauthorizedAccessException ex) { return Failed(result, "ACCESS_DENIED", "XAMPP properties.ini could not be read: " + ex.GetType().Name + ": " + ex.Message); }
            catch (Exception ex) { return Failed(result, "ERROR", "XAMPP properties.ini could not be read: " + ex.GetType().Name + ": " + ex.Message); }
        }

        private static void AddPeVersionEvidence(AnalysisContext context, SoftwareObservation item, SoftwareProfile profile, string origin)
        {
            HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (WindowsProcess process in (context.Processes ?? new List<WindowsProcess>()).Where(p => item.ProcessIds.Contains(p.ProcessId)).GroupBy(p => p.ImagePath, StringComparer.OrdinalIgnoreCase).Select(g => g.First()))
            {
                AddPeVersionEvidence(item, profile, process.ImagePath, process.FileIdentity, origin, seen);
            }
            foreach (WindowsService service in (context.Services ?? new List<WindowsService>()).Where(s => item.ServiceNames.Contains(s.Name, StringComparer.OrdinalIgnoreCase))) AddPeVersionEvidence(item, profile, service.ExecutablePath ?? service.BinaryPath, service.FileIdentity, origin, seen);
            foreach (ScheduledTaskInfo task in context.Tasks ?? new List<ScheduledTaskInfo>()) if (item.ScheduledTaskPaths.Contains(task.Path, StringComparer.OrdinalIgnoreCase)) foreach (ScheduledTaskAction action in task.Actions ?? new List<ScheduledTaskAction>()) AddPeVersionEvidence(item, profile, action.Executable, action.FileIdentity, origin, seen);
        }

        private static void AddPeVersionEvidence(SoftwareObservation item, SoftwareProfile profile, string path, FileIdentityMetadata identity, string origin, HashSet<string> seen)
        {
            if (String.IsNullOrWhiteSpace(path) || !seen.Add(path)) return;
            string product = String.Equals(item.ProfileId, "SW-XAMPP", StringComparison.OrdinalIgnoreCase) ? "Apache HTTP Server" : item.ProductName;
            if (Allows(profile, "PE_PRODUCT_VERSION")) AddVersionEvidence(item, PeEvidence(item, path, product, "PE_PRODUCT_VERSION", "ProductVersion", identity == null ? null : identity.ProductVersion, identity == null ? "PE metadata was unavailable." : identity.MetadataState, origin));
            if (Allows(profile, "PE_FILE_VERSION")) AddVersionEvidence(item, PeEvidence(item, path, Path.GetFileName(path), "PE_FILE_VERSION", "FileVersion", identity == null ? null : identity.FileVersion, identity == null ? "PE metadata was unavailable." : identity.MetadataState, origin));
        }

        private static SoftwareVersionEvidence PeEvidence(SoftwareObservation item, string path, string product, string type, string field, string value, string state, string origin)
        {
            SoftwareVersionEvidence evidence = NewVersionEvidence(item.ProfileId, item.InstallationRoot, product, type, type == "PE_PRODUCT_VERSION" ? VersionConfidence.Medium : VersionConfidence.Low, origin);
            evidence.SourcePath = path; evidence.SourceField = field;
            if (!String.IsNullOrWhiteSpace(value)) { evidence.Value = evidence.Version = value.Trim(); evidence.ObservationStatus = "OBSERVED"; evidence.ReadStatus = "SUCCESS"; }
            else Failed(evidence, String.Equals(state, "ERROR", StringComparison.OrdinalIgnoreCase) ? "ERROR" : "FIELD_NOT_FOUND", "PE " + field + " was not available for the observed executable.");
            return evidence;
        }

        private static IEnumerable<SoftwareVersionEvidence> ReadUninstallRegistry(SoftwareObservation item, string origin)
        {
            List<SoftwareVersionEvidence> results = new List<SoftwareVersionEvidence>();
            if (String.IsNullOrWhiteSpace(item.InstallationRoot)) return results;
            foreach (RegistryView view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
            {
                try
                {
                    using (RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view))
                    using (RegistryKey uninstall = baseKey.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", false))
                    {
                        results.AddRange(ReadUninstallRegistryKey(item, uninstall, "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", view.ToString(), origin));
                    }
                }
                catch (Exception ex)
                {
                    SoftwareVersionEvidence evidence = NewVersionEvidence(item.ProfileId, item.InstallationRoot, item.ProductName, "UNINSTALL_REGISTRY", VersionConfidence.Unknown, origin);
                    results.Add(Failed(evidence, "ERROR", "Uninstall registry read failed for " + view + ": " + ex.GetType().Name + ": " + ex.Message));
                }
            }
            return results;
        }

        internal static List<SoftwareVersionEvidence> ReadUninstallRegistryKey(SoftwareObservation item, RegistryKey uninstall, string registryPath, string viewName, string origin)
        {
            List<SoftwareVersionEvidence> results = new List<SoftwareVersionEvidence>();
            if (item == null || uninstall == null || String.IsNullOrWhiteSpace(item.InstallationRoot)) return results;
            foreach (string name in uninstall.GetSubKeyNames()) using (RegistryKey key = uninstall.OpenSubKey(name, false))
            {
                if (key == null) continue;
                string location = Convert.ToString(key.GetValue("InstallLocation")), displayIcon = Convert.ToString(key.GetValue("DisplayIcon"));
                if (!SameRoot(location, item.InstallationRoot) && !PathWithin(ParseDisplayIcon(displayIcon), item.InstallationRoot)) continue;
                string displayName = Convert.ToString(key.GetValue("DisplayName")), value = Convert.ToString(key.GetValue("DisplayVersion"));
                SoftwareVersionEvidence evidence = NewVersionEvidence(item.ProfileId, item.InstallationRoot, String.Equals(item.ProfileId, "SW-XAMPP", StringComparison.OrdinalIgnoreCase) ? "XAMPP" : (displayName ?? item.ProductName), "UNINSTALL_REGISTRY", VersionConfidence.Medium, origin);
                evidence.RegistryKey = registryPath + "\\" + name + (String.IsNullOrWhiteSpace(viewName) ? String.Empty : " [" + viewName + "]"); evidence.SourceField = "DisplayVersion";
                if (String.IsNullOrWhiteSpace(value)) Failed(evidence, "FIELD_NOT_FOUND", "The matching uninstall entry did not contain DisplayVersion.");
                else { evidence.Value = evidence.Version = value.Trim(); evidence.ObservationStatus = "OBSERVED"; evidence.ReadStatus = "SUCCESS"; }
                results.Add(evidence);
            }
            return results;
        }

        private static SoftwareVersionEvidence NormalizeSuppliedEvidence(SoftwareVersionEvidence evidence, SoftwareObservation item, SoftwareProfile profile, string contextOrigin)
        {
            evidence.SourceType = evidence.SourceType ?? evidence.Source; evidence.Source = evidence.SourceType; evidence.Value = evidence.Value ?? evidence.Version; evidence.Version = evidence.Value;
            evidence.Product = evidence.Product ?? item.ProductName; evidence.CollectionError = evidence.CollectionError ?? evidence.Error; evidence.Error = evidence.CollectionError;
            if (!ApprovedVersionSource(evidence.SourceType)) return Failed(evidence, "REJECTED", "Version evidence from a knowledge/catalog value or unknown strategy was rejected.");
            if (!Allows(profile, evidence.SourceType)) return Failed(evidence, "REJECTED", "The product profile did not authorize this version strategy.");
            if (!String.IsNullOrWhiteSpace(evidence.SourcePath) && !PathWithin(evidence.SourcePath, item.InstallationRoot)) return Failed(evidence, "REJECTED", "Version source path was outside the identified installation root.");
            if (!String.Equals(contextOrigin, "TEST_FIXTURE", StringComparison.OrdinalIgnoreCase))
            {
                evidence.EvidenceOrigin = "IMPORTED_UNVERIFIED"; evidence.ObservationStatus = "UNKNOWN"; evidence.ReadStatus = "IMPORTED_UNVERIFIED"; evidence.Confidence = VersionConfidence.Unknown;
                evidence.CollectionError = evidence.Error = "The version was supplied by an external fixture and was not read directly by PrivTrace."; return evidence;
            }
            evidence.EvidenceOrigin = "TEST_FIXTURE";
            if (String.IsNullOrWhiteSpace(evidence.ObservationStatus)) evidence.ObservationStatus = String.IsNullOrWhiteSpace(evidence.Value) ? "UNKNOWN" : "OBSERVED";
            if (String.IsNullOrWhiteSpace(evidence.ReadStatus)) evidence.ReadStatus = String.IsNullOrWhiteSpace(evidence.Value) ? "UNKNOWN" : "SUCCESS";
            return evidence;
        }

        private static void AddVersionEvidence(SoftwareObservation item, SoftwareVersionEvidence evidence)
        {
            if (evidence == null) return; item.VersionEvidence.Add(evidence);
            item.Evidence.Add(new SoftwareEvidence { Kind = "VersionEvidence", Value = (evidence.Product ?? "UNKNOWN") + "=" + (evidence.Value ?? "UNKNOWN") + " source=" + (evidence.SourceType ?? "UNKNOWN") + " field=" + (evidence.SourceField ?? "UNKNOWN") + " read=" + (evidence.ReadStatus ?? "UNKNOWN"), State = IsObserved(evidence) ? RelationshipState.Observed : RelationshipState.Unknown, Source = evidence.SourceType ?? "UNKNOWN" });
            if (!String.IsNullOrWhiteSpace(evidence.CollectionError)) item.PendingConditions.Add(evidence.CollectionError);
        }

        private static SoftwareVersionEvidence NewVersionEvidence(string productId, string root, string product, string type, VersionConfidence confidence, string origin)
        {
            return new SoftwareVersionEvidence { ProductId = productId, InstallationRoot = root, Product = product, SourceType = type, Source = type, Value = null, Version = null, ObservationStatus = "UNKNOWN", ReadStatus = "NOT_READ", Confidence = confidence, EvidenceOrigin = origin };
        }
        private static SoftwareVersionEvidence Failed(SoftwareVersionEvidence evidence, string status, string error) { evidence.Value = evidence.Version = null; evidence.ObservationStatus = "UNKNOWN"; evidence.ReadStatus = status; evidence.CollectionError = evidence.Error = error; evidence.Confidence = VersionConfidence.Unknown; return evidence; }
        private static string EvidenceOrigin(AnalysisContext context, bool liveTargetedReads)
        {
            string origin = context == null ? null : context.EvidenceOrigin;
            if (String.Equals(origin, "LIVE_OBSERVED", StringComparison.OrdinalIgnoreCase) || String.Equals(origin, "TEST_FIXTURE", StringComparison.OrdinalIgnoreCase) || String.Equals(origin, "IMPORTED_UNVERIFIED", StringComparison.OrdinalIgnoreCase)) return origin.ToUpperInvariant();
            return liveTargetedReads ? "LIVE_OBSERVED" : "IMPORTED_UNVERIFIED";
        }
        private static bool IsObserved(SoftwareVersionEvidence evidence) { return evidence != null && !String.IsNullOrWhiteSpace(evidence.Value) && String.Equals(evidence.ObservationStatus, "OBSERVED", StringComparison.OrdinalIgnoreCase) && String.Equals(evidence.ReadStatus, "SUCCESS", StringComparison.OrdinalIgnoreCase) && (String.Equals(evidence.EvidenceOrigin, "LIVE_OBSERVED", StringComparison.OrdinalIgnoreCase) || String.Equals(evidence.EvidenceOrigin, "TEST_FIXTURE", StringComparison.OrdinalIgnoreCase)); }
        private static bool ApprovedVersionSource(string source) { return new[] { "PE_FILE_VERSION", "PE_PRODUCT_VERSION", "UNINSTALL_REGISTRY", "XAMPP_PROPERTIES_INI" }.Contains(source ?? String.Empty, StringComparer.OrdinalIgnoreCase); }
        private static bool Allows(SoftwareProfile profile, string source) { if (profile == null) return String.Equals(source, "PE_PRODUCT_VERSION", StringComparison.OrdinalIgnoreCase) || String.Equals(source, "PE_FILE_VERSION", StringComparison.OrdinalIgnoreCase); return profile.OptionalVersionSources != null && profile.OptionalVersionSources.Contains(source ?? String.Empty, StringComparer.OrdinalIgnoreCase); }
        private static bool ValidVersion(string value) { return !String.IsNullOrWhiteSpace(value) && value.Length <= 128 && System.Text.RegularExpressions.Regex.IsMatch(value, @"^[0-9]+(?:\.[0-9]+){1,4}(?:[-+._][A-Za-z0-9]+)*$"); }
        private static string ParseDisplayIcon(string value) { if (String.IsNullOrWhiteSpace(value)) return null; string result = value.Trim().Trim('"'); int comma = result.LastIndexOf(','); if (comma > 2) result = result.Substring(0, comma).Trim().Trim('"'); return result; }

        private static bool ValidateXamppSource(string root, string executable, string source, out string error)
        {
            error = null; string fullRoot, fullExecutable, fullSource;
            try { fullRoot = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar); fullExecutable = Path.GetFullPath(executable); fullSource = Path.GetFullPath(source); }
            catch (Exception ex) { error = "XAMPP paths could not be canonicalized: " + ex.Message; return false; }
            if (String.Equals(fullRoot, Path.GetPathRoot(fullRoot).TrimEnd((char)92), StringComparison.OrdinalIgnoreCase)) { error = "A volume root cannot be used as an XAMPP installation root."; return false; }
            string relative = fullExecutable.Substring(Math.Min(fullExecutable.Length, fullRoot.Length)).TrimStart((char)92, '/').Replace('/', (char)92);
            if (!PathWithin(fullExecutable, fullRoot) || !String.Equals(relative, @"apache\bin\httpd.exe", StringComparison.OrdinalIgnoreCase)) { error = "The executable/root relationship was not a validated XAMPP apache\\bin\\httpd.exe layout."; return false; }
            if (!PathWithin(fullSource, fullRoot) || !String.Equals(Path.GetDirectoryName(fullSource), fullRoot, StringComparison.OrdinalIgnoreCase)) { error = "The configuration source was outside the validated installation root."; return false; }
            foreach (string checkedPath in new[] { fullRoot, Path.Combine(fullRoot, "apache"), Path.Combine(fullRoot, "apache", "bin"), fullSource })
            {
                if (!Directory.Exists(checkedPath) && !File.Exists(checkedPath)) continue;
                if ((File.GetAttributes(checkedPath) & FileAttributes.ReparsePoint) != 0) { error = "A reparse point in the installation path prevented the targeted configuration read."; return false; }
            }
            return true;
        }

        private static bool OpenedFileMatches(FileStream stream, string expectedPath, out string error)
        {
            error = null; StringBuilder buffer = new StringBuilder(32768);
            uint length = NativeMethods.GetFinalPathNameByHandle(stream.SafeFileHandle.DangerousGetHandle(), buffer, (uint)buffer.Capacity, 0);
            if (length == 0) return true;
            if (length >= buffer.Capacity) { error = "The final path of the opened version source exceeded the verification buffer."; return false; }
            string finalPath = buffer.ToString();
            if (finalPath.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase)) finalPath = @"\\" + finalPath.Substring(8);
            else if (finalPath.StartsWith(@"\\?\", StringComparison.OrdinalIgnoreCase)) finalPath = finalPath.Substring(4);
            if (!String.Equals(Path.GetFullPath(expectedPath), Path.GetFullPath(finalPath), StringComparison.OrdinalIgnoreCase)) { error = "The opened version source resolved to a different final path; possible reparse-point substitution was rejected."; return false; }
            return true;
        }

        private static ProfileMatch Match(SoftwareProfile profile, WindowsProcess process, bool liveTargetedReads)
        {
            ProfileMatch result = new ProfileMatch { Profile = profile }; string name = Path.GetFileName(process.ImagePath ?? process.Name ?? String.Empty); FileIdentityMetadata identity = process.FileIdentity ?? new FileIdentityMetadata();
            if (!profile.ExecutableNames.Any(pattern => Wildcard(pattern, name))) return result;
            result.Signals.Add("ExecutableName=" + name); result.SignalFamilies++;
            string pathPattern = profile.ExpectedPathPatterns.Where(p => ContainsPattern(process.ImagePath, p)).OrderByDescending(p => p.Length).FirstOrDefault();
            if (pathPattern != null) { result.Signals.Add("ExpectedPath=" + pathPattern); result.SignalFamilies++; result.PathSpecificity = pathPattern.Replace("*", String.Empty).Length; }
            string hint = profile.TrustedIdentificationHints.FirstOrDefault(h => HintMatches(h, identity));
            if (hint != null) { result.Signals.Add("Metadata=" + hint); result.SignalFamilies++; }
            string service = (process.ServiceNames ?? new List<string>()).FirstOrDefault(s => profile.OptionalServiceNames.Any(p => Wildcard(p, s)));
            if (service != null) { result.Signals.Add("Service=" + service); result.SignalFamilies++; }
            bool xamppConfig = false;
            if (liveTargetedReads && String.Equals(profile.ProfileId, "SW-XAMPP", StringComparison.OrdinalIgnoreCase))
            {
                string candidateRoot = XamppLayoutRoot(process.ImagePath), candidateSource = String.IsNullOrWhiteSpace(candidateRoot) ? null : Path.Combine(candidateRoot, "properties.ini"), validationError;
                xamppConfig = !String.IsNullOrWhiteSpace(candidateSource) && ValidateXamppSource(candidateRoot, process.ImagePath, candidateSource, out validationError) && File.Exists(candidateSource);
                if (xamppConfig) { result.Signals.Add("KnownConfig=properties.ini@derived-root"); result.SignalFamilies++; result.PathSpecificity = Math.Max(result.PathSpecificity, 32); }
            }
            result.StrongIdentification = String.Equals(profile.ProfileId, "SW-XAMPP", StringComparison.OrdinalIgnoreCase) ? pathPattern != null || xamppConfig : pathPattern != null || service != null || (hint != null && identity.SignatureStatus == SignatureStatus.Valid);
            result.Identified = result.SignalFamilies >= 2; return result;
        }

        private static SoftwareClassification Classify(WindowsProcess process, SoftwareProfile profile)
        {
            FileIdentityMetadata identity = process.FileIdentity ?? new FileIdentityMetadata(); bool microsoftSigner = identity.SignatureStatus == SignatureStatus.Valid && Contains(identity.SignerSubject, "Microsoft");
            bool microsoftMetadata = Contains(identity.CompanyName, "Microsoft") || Contains(identity.ProductName, "Windows") || Contains(identity.ProductName, "Microsoft");
            if (microsoftSigner && microsoftMetadata) return SoftwareClassification.WindowsComponent;
            if (profile != null && profile.Category == "WindowsRole" && microsoftSigner) return SoftwareClassification.WindowsComponent;
            if (profile != null) return SoftwareClassification.ThirdPartySoftware;
            if (!String.IsNullOrWhiteSpace(identity.CompanyName) && !Contains(identity.CompanyName, "Microsoft")) return SoftwareClassification.ThirdPartySoftware;
            return SoftwareClassification.Unclassified;
        }

        internal static string ResolveXamppInstallationRoot(string path) { return InstallationRoot(path, new SoftwareProfile { ProfileId = "SW-XAMPP" }); }

        private static string InstallationRoot(string path, SoftwareProfile profile)
        {
            if (String.IsNullOrWhiteSpace(path)) return null;
            string normalized = path.Replace('/', '\\');
            if (profile != null && profile.ProfileId == "SW-XAMPP")
            {
                try
                {
                    string bin = Path.GetDirectoryName(normalized), apache = Path.GetDirectoryName(bin), root = Path.GetDirectoryName(apache);
                    if (String.Equals(Path.GetFileName(normalized), "httpd.exe", StringComparison.OrdinalIgnoreCase) && String.Equals(Path.GetFileName(bin), "bin", StringComparison.OrdinalIgnoreCase) && String.Equals(Path.GetFileName(apache), "apache", StringComparison.OrdinalIgnoreCase)) return root;
                }
                catch { }
            }
            try { return Path.GetDirectoryName(normalized); } catch { return normalized; }
        }
        private static string XamppLayoutRoot(string path)
        {
            if (String.IsNullOrWhiteSpace(path)) return null;
            try { string normalized = path.Replace('/', (char)92), bin = Path.GetDirectoryName(normalized), apache = Path.GetDirectoryName(bin); return String.Equals(Path.GetFileName(normalized), "httpd.exe", StringComparison.OrdinalIgnoreCase) && String.Equals(Path.GetFileName(bin), "bin", StringComparison.OrdinalIgnoreCase) && String.Equals(Path.GetFileName(apache), "apache", StringComparison.OrdinalIgnoreCase) ? Path.GetDirectoryName(apache) : null; }
            catch { return null; }
        }
        private static IEnumerable<WindowsService> AssociatedServices(AnalysisContext context, WindowsProcess process)
        {
            return (context.Services ?? new List<WindowsService>()).Where(s => (process.ServiceNames ?? new List<string>()).Contains(s.Name, StringComparer.OrdinalIgnoreCase) || (s.ProcessId > 0 && s.ProcessId == process.ProcessId) || BinaryPathResolver.SamePath(s.ExecutablePath, process.ImagePath));
        }
        private static bool MatchesSoftware(Finding finding, SoftwareObservation software)
        {
            if (finding == null || software == null) return false;
            if (software.ServiceNames.Contains(finding.Target, StringComparer.OrdinalIgnoreCase)) return true;
            if (software.ScheduledTaskPaths.Contains(finding.Target, StringComparer.OrdinalIgnoreCase)) return true;
            return software.ProcessPaths.Any(p => BinaryPathResolver.SamePath(p, finding.Target)) || BinaryPathResolver.SamePath(software.CanonicalExecutable, finding.Target);
        }
        private static void BuildTrace(SoftwareObservation item)
        {
            item.Trace.Add("Product " + item.ProductName + " [" + item.IdentificationStatus + "]");
            if (item.ProcessPaths.Count > 0) item.Trace.Add("Process " + item.CanonicalExecutable + " [PROCESS_RUNNING; OBSERVED; PIDs=" + String.Join(",", item.ProcessIds.Select(p => p.ToString()).ToArray()) + "]");
            else item.Trace.Add("Process [UNKNOWN; no process image was correlated]");
            foreach (string path in item.ConfiguredExecutablePaths) item.Trace.Add("Configured executable " + path + " [" + String.Join(",", item.ObservationStates.ToArray()) + "]");
            item.Trace.Add("Installation root " + (item.InstallationRoot ?? "UNKNOWN") + " [DERIVED FROM EXECUTABLE PATH]");
            foreach (SoftwareVersionEvidence version in item.VersionEvidence.Where(IsObserved)) item.Trace.Add("Version " + version.Product + "=" + version.Value + " [OBSERVED; " + version.SourceType + "; " + (version.SourcePath ?? version.RegistryKey ?? "UNKNOWN SOURCE") + "; field=" + (version.SourceField ?? "UNKNOWN") + "]");
            if (item.ServiceNames.Count > 0) item.Trace.Add("Services " + String.Join(",", item.ServiceNames.ToArray()) + " [CONFIGURED]");
            if (item.ExecutionIdentities.Count > 0) item.Trace.Add("Execution identities " + String.Join(",", item.ExecutionIdentities.ToArray()) + " [OBSERVED/CONFIGURED]");
        }
        private static bool HintMatches(string hint, FileIdentityMetadata identity)
        {
            int colon = (hint ?? String.Empty).IndexOf(':'); if (colon <= 0) return false; string field = hint.Substring(0, colon).ToLowerInvariant(), expected = hint.Substring(colon + 1);
            string actual = field == "company" ? identity.CompanyName : field == "product" ? identity.ProductName : field == "description" ? identity.FileDescription : field == "original" ? identity.OriginalFilename : field == "signer" ? identity.SignerSubject : null;
            return Contains(actual, expected);
        }
        private static bool ContainsPattern(string value, string pattern) { if (String.IsNullOrWhiteSpace(value) || String.IsNullOrWhiteSpace(pattern)) return false; string normalized = value.Replace('/', '\\'); string regex = System.Text.RegularExpressions.Regex.Escape(pattern.Replace('/', '\\')).Replace("\\*", ".*"); return System.Text.RegularExpressions.Regex.IsMatch(normalized, regex, System.Text.RegularExpressions.RegexOptions.IgnoreCase); }
        private static bool Contains(string value, string expected) { return !String.IsNullOrWhiteSpace(value) && !String.IsNullOrWhiteSpace(expected) && value.IndexOf(expected, StringComparison.OrdinalIgnoreCase) >= 0; }
        private static bool Wildcard(string pattern, string value) { if (String.IsNullOrWhiteSpace(pattern) || String.IsNullOrWhiteSpace(value)) return false; string regex = "^" + System.Text.RegularExpressions.Regex.Escape(pattern).Replace("\\*", ".*") + "$"; return System.Text.RegularExpressions.Regex.IsMatch(value, regex, System.Text.RegularExpressions.RegexOptions.IgnoreCase); }
        private static bool SameRoot(string left, string right) { if (String.IsNullOrWhiteSpace(left) || String.IsNullOrWhiteSpace(right)) return false; try { return String.Equals(Path.GetFullPath(left).TrimEnd('\\'), Path.GetFullPath(right).TrimEnd('\\'), StringComparison.OrdinalIgnoreCase); } catch { return String.Equals(left.TrimEnd('\\'), right.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase); } }
        private static bool PathWithin(string path, string root)
        {
            if (String.IsNullOrWhiteSpace(path) || String.IsNullOrWhiteSpace(root)) return false;
            try { string fullPath = Path.GetFullPath(path).TrimEnd('\\', '/'), fullRoot = Path.GetFullPath(root).TrimEnd('\\', '/'); return String.Equals(fullPath, fullRoot, StringComparison.OrdinalIgnoreCase) || fullPath.StartsWith(fullRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase); }
            catch { return false; }
        }
        private static bool IsPrivileged(string account) { return PathResolver.IsPrivilegedPrincipal(account); }
        private static void AddUnique(List<string> values, string value) { if (!String.IsNullOrWhiteSpace(value) && !values.Contains(value, StringComparer.OrdinalIgnoreCase)) values.Add(value); }

        private sealed class ProfileMatch
        {
            internal ProfileMatch() { Signals = new List<string>(); }
            internal SoftwareProfile Profile; internal bool Identified; internal bool StrongIdentification; internal int SignalFamilies; internal int PathSpecificity; internal List<string> Signals;
        }
    }
}
