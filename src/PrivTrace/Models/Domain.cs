using System;
using System.Collections.Generic;

namespace PrivTrace.Models
{
    public enum EvaluationStatus { Confirmed, Potential, Informational, RuledOut, Unknown }
    public enum Severity { Critical, High, Medium, Low, Informational }
    public enum Confidence { High, Medium, Low, Unknown }
    public enum TriState { Unknown, Yes, No }
    public enum TokenPrivilegeState { Unknown, Enabled, Disabled, Removed }
    public enum RelationshipState { Observed, Configured, Inferred, Unknown }
    public enum SoftwareClassification { Unclassified, WindowsComponent, ThirdPartySoftware }
    public enum SignatureStatus { Unknown, Valid, Invalid, Absent }
    public enum VersionConfidence { Unknown, High, Medium, Low }

    public sealed class TokenPrivilege
    {
        public string Name { get; set; }
        public bool Enabled { get; set; }
        public bool Present { get; set; }
        public TokenPrivilegeState State { get; set; }
    }

    public sealed class WindowsGroup
    {
        public string Sid { get; set; }
        public string Name { get; set; }
        public bool Enabled { get; set; }
        public bool DenyOnly { get; set; }
    }

    public sealed class TokenSnapshot
    {
        public TokenSnapshot()
        {
            Privileges = new List<TokenPrivilege>();
            Groups = new List<WindowsGroup>();
            Errors = new List<string>();
        }
        public string UserName { get; set; }
        public string UserSid { get; set; }
        public string IntegrityLevel { get; set; }
        public string ElevationType { get; set; }
        public TriState Elevated { get; set; }
        public TriState IsAppContainer { get; set; }
        public bool Restricted { get; set; }
        public TriState RestrictedState { get; set; }
        public List<TokenPrivilege> Privileges { get; set; }
        public List<WindowsGroup> Groups { get; set; }
        public List<string> Errors { get; set; }
    }

    public sealed class CollectorDiagnostic
    {
        public string Collector { get; set; }
        public string Stage { get; set; }
        public string Api { get; set; }
        public string ObjectName { get; set; }
        public string RequestedAccess { get; set; }
        public int Win32Error { get; set; }
        public int HResult { get; set; }
        public string Classification { get; set; }
        public string Detail { get; set; }
    }

    public sealed class SecurityPermission
    {
        public SecurityPermission() { AccessEntries = new List<AccessEntryEvidence>(); }
        public string Target { get; set; }
        public string ObjectType { get; set; }
        public TriState CanWrite { get; set; }
        public TriState CanCreate { get; set; }
        public TriState CanDelete { get; set; }
        public TriState CanDeleteChildren { get; set; }
        public TriState CanChangePermissions { get; set; }
        public string OwnerSid { get; set; }
        public string OwnerAccount { get; set; }
        public string IntegrityConstraint { get; set; }
        public TriState? MandatoryIntegrityAllowsWrite { get; set; }
        public List<AccessEntryEvidence> AccessEntries { get; set; }
        public string Detail { get; set; }
    }

    public sealed class AccessEntryEvidence
    {
        public string Sid { get; set; }
        public string Account { get; set; }
        public string Type { get; set; }
        public string Rights { get; set; }
        public bool Inherited { get; set; }
    }

    public sealed class WindowsProcess
    {
        public WindowsProcess() { ServiceNames = new List<string>(); Errors = new List<string>(); }
        public int ProcessId { get; set; }
        public string Name { get; set; }
        public string State { get; set; }
        public string ImagePath { get; set; }
        public string ImagePathSource { get; set; }
        public string OwnerSid { get; set; }
        public string OwnerAccount { get; set; }
        public string IntegrityLevel { get; set; }
        public string Architecture { get; set; }
        public int ParentProcessId { get; set; }
        public string ParentImagePath { get; set; }
        public string AccessStatus { get; set; }
        public List<string> ServiceNames { get; set; }
        public List<string> Errors { get; set; }
        public FileIdentityMetadata FileIdentity { get; set; }
    }

    public sealed class FileIdentityMetadata
    {
        public string CanonicalPath { get; set; }
        public string MetadataState { get; set; }
        public string CompanyName { get; set; }
        public string FileDescription { get; set; }
        public string OriginalFilename { get; set; }
        public string ProductName { get; set; }
        public string ProductVersion { get; set; }
        public string FileVersion { get; set; }
        public string VersionSource { get; set; }
        public VersionConfidence VersionConfidence { get; set; }
        public SoftwareClassification SoftwareClassification { get; set; }
        public string SoftwareClassificationName { get { return ClassificationText(SoftwareClassification); } }
        public SignatureStatus SignatureStatus { get; set; }
        public string SignatureStatusName { get { return SignatureStatus.ToString().ToUpperInvariant(); } }

        internal static string ClassificationText(SoftwareClassification value)
        {
            if (value == SoftwareClassification.WindowsComponent) return "WINDOWS_COMPONENT";
            if (value == SoftwareClassification.ThirdPartySoftware) return "THIRD_PARTY_SOFTWARE";
            return "UNCLASSIFIED";
        }
        public string SignerSubject { get; set; }
        public int SignatureHResult { get; set; }
        public string SignatureError { get; set; }
    }

    public sealed class SoftwareProfile
    {
        public SoftwareProfile() { ExecutableNames = new List<string>(); TrustedIdentificationHints = new List<string>(); ExpectedPathPatterns = new List<string>(); OptionalServiceNames = new List<string>(); OptionalVersionSources = new List<string>(); RelevantExistingRules = new List<string>(); ReferenceIds = new List<string>(); }
        public string ProfileId { get; set; }
        public string ProductName { get; set; }
        public string Vendor { get; set; }
        public string Category { get; set; }
        public string SoftwareContext { get; set; }
        public int InvestigationPriority { get; set; }
        public List<string> ExecutableNames { get; set; }
        public List<string> TrustedIdentificationHints { get; set; }
        public List<string> ExpectedPathPatterns { get; set; }
        public List<string> OptionalServiceNames { get; set; }
        public List<string> OptionalVersionSources { get; set; }
        public string Version { get; set; }
        public List<string> RelevantExistingRules { get; set; }
        public string ResearchReason { get; set; }
        public string FalsePositiveNotes { get; set; }
        public List<string> ReferenceIds { get; set; }
    }

    public sealed class SoftwareEvidence
    {
        public string Kind { get; set; }
        public string Value { get; set; }
        public RelationshipState State { get; set; }
        public string StateName { get { return State.ToString().ToUpperInvariant(); } }
        public string Source { get; set; }
    }

    public sealed class SoftwareVersionEvidence
    {
        public string ProductId { get; set; }
        public string InstallationRoot { get; set; }
        public string Version { get; set; }
        public string Source { get; set; }
        public VersionConfidence Confidence { get; set; }
        public string Error { get; set; }
        public string Value { get; set; }
        public string Product { get; set; }
        public string SourceType { get; set; }
        public string SourcePath { get; set; }
        public string RegistryKey { get; set; }
        public string SourceField { get; set; }
        public string ObservationStatus { get; set; }
        public string ReadStatus { get; set; }
        public string CollectionError { get; set; }
        public string EvidenceOrigin { get; set; }
    }

    public sealed class SoftwareObservation
    {
        public SoftwareObservation() { ProcessIds = new List<int>(); ProcessPaths = new List<string>(); ConfiguredExecutablePaths = new List<string>(); ObservationStates = new List<string>(); ServiceNames = new List<string>(); ScheduledTaskPaths = new List<string>(); ExecutionIdentities = new List<string>(); RelevantRuleIds = new List<string>(); ActiveRuleIds = new List<string>(); Evidence = new List<SoftwareEvidence>(); VersionEvidence = new List<SoftwareVersionEvidence>(); PendingConditions = new List<string>(); Trace = new List<string>(); }
        public string ObservationId { get; set; }
        public string ProfileId { get; set; }
        public string ProductName { get; set; }
        public string Vendor { get; set; }
        public string Category { get; set; }
        public string SoftwareContext { get; set; }
        public int InvestigationPriority { get; set; }
        public SoftwareClassification Classification { get; set; }
        public string ClassificationName { get { return FileIdentityMetadata.ClassificationText(Classification); } }
        public string IdentificationStatus { get; set; }
        public Confidence IdentificationConfidence { get; set; }
        public string InstallationRoot { get; set; }
        public string CanonicalExecutable { get; set; }
        public string State { get; set; }
        public string Version { get; set; }
        public string VersionSource { get; set; }
        public VersionConfidence VersionConfidence { get; set; }
        public SignatureStatus SignatureStatus { get; set; }
        public string SignerSubject { get; set; }
        public string EscalationStatus { get; set; }
        public bool PrivilegedContextObserved { get; set; }
        public List<int> ProcessIds { get; set; }
        public List<string> ProcessPaths { get; set; }
        public List<string> ConfiguredExecutablePaths { get; set; }
        public List<string> ObservationStates { get; set; }
        public List<string> ServiceNames { get; set; }
        public List<string> ScheduledTaskPaths { get; set; }
        public List<string> ExecutionIdentities { get; set; }
        public List<string> RelevantRuleIds { get; set; }
        public List<string> ActiveRuleIds { get; set; }
        public List<SoftwareEvidence> Evidence { get; set; }
        public List<SoftwareVersionEvidence> VersionEvidence { get; set; }
        public List<string> PendingConditions { get; set; }
        public List<string> Trace { get; set; }
    }

    public sealed class BinaryArtifact
    {
        public BinaryArtifact()
        {
            Sources = new List<string>(); ProcessIds = new List<int>(); ServiceNames = new List<string>();
            TaskPaths = new List<string>(); ExecutionIdentities = new List<string>(); Errors = new List<string>();
        }
        public string Path { get; set; }
        public string OriginalReference { get; set; }
        public TriState Exists { get; set; }
        public bool IsAmbiguous { get; set; }
        public bool ObservedProcessImage { get; set; }
        public List<string> Sources { get; set; }
        public List<int> ProcessIds { get; set; }
        public List<string> ServiceNames { get; set; }
        public List<string> TaskPaths { get; set; }
        public List<string> ExecutionIdentities { get; set; }
        public SecurityPermission FilePermission { get; set; }
        public SecurityPermission DirectoryPermission { get; set; }
        public List<string> Errors { get; set; }
    }

    public sealed class ExecutionRelationship
    {
        public ExecutionRelationship() { RuleIds = new List<string>(); }
        public string Classification { get; set; }
        public string RelationStatus { get; set; }
        public string SourceKind { get; set; }
        public string SourceId { get; set; }
        public string TargetPath { get; set; }
        public int HostProcessId { get; set; }
        public string EvidenceSource { get; set; }
        public Confidence Confidence { get; set; }
        public string ObjectIdentity { get; set; }
        public List<string> RuleIds { get; set; }
        public string Detail { get; set; }
    }

    public sealed class ServiceRegistryEvidence
    {
        public ServiceRegistryEvidence() { Errors = new List<string>(); }
        public string View { get; set; }
        public string ServiceKeyPath { get; set; }
        public string ParametersKeyPath { get; set; }
        public string ImagePath { get; set; }
        public string ServiceDll { get; set; }
        public string ServiceDllPath { get; set; }
        public TriState ServiceDllExists { get; set; }
        public SecurityPermission ServiceKeyPermission { get; set; }
        public SecurityPermission ParametersKeyPermission { get; set; }
        public SecurityPermission ServiceDllPermission { get; set; }
        public SecurityPermission ServiceDllDirectoryPermission { get; set; }
        public List<string> Errors { get; set; }
    }

    public sealed class CollectorTiming
    {
        public string Name { get; set; }
        public long ElapsedMilliseconds { get; set; }
        public int Items { get; set; }
    }

    public sealed class WindowsService
    {
        public WindowsService() { Errors = new List<string>(); UnquotedCandidates = new List<string>(); UnquotedCandidatePermissions = new List<SecurityPermission>(); RegistryEvidence = new List<ServiceRegistryEvidence>(); EffectiveRights = new List<EffectiveServiceRight>(); }
        public string Name { get; set; }
        public string DisplayName { get; set; }
        public string State { get; set; }
        public int ProcessId { get; set; }
        public string ServiceType { get; set; }
        public string StartType { get; set; }
        public string BinaryPath { get; set; }
        public string ExecutablePath { get; set; }
        public string Arguments { get; set; }
        public string Account { get; set; }
        public string SecurityDescriptorSddl { get; set; }
        public TriState CanChangeConfig { get; set; }
        public TriState CanStart { get; set; }
        public TriState CanStop { get; set; }
        public List<EffectiveServiceRight> EffectiveRights { get; set; }
        public SecurityPermission ExecutablePermission { get; set; }
        public SecurityPermission DirectoryPermission { get; set; }
        public FileIdentityMetadata FileIdentity { get; set; }
        public string RuntimeProtectionState { get; set; }
        public List<string> UnquotedCandidates { get; set; }
        public List<SecurityPermission> UnquotedCandidatePermissions { get; set; }
        public List<ServiceRegistryEvidence> RegistryEvidence { get; set; }
        public List<string> Errors { get; set; }
    }

    public sealed class EffectiveServiceRight
    {
        public string Right { get; set; }
        public TriState Granted { get; set; }
        public string EvaluationMethod { get; set; }
        public string Provenance { get; set; }
        public string TrusteeSid { get; set; }
        public string Detail { get; set; }
    }

    public sealed class DnsServerSnapshot
    {
        public DnsServerSnapshot() { Errors = new List<string>(); }
        public TriState Present { get; set; }
        public string ServiceName { get; set; }
        public string DisplayName { get; set; }
        public string State { get; set; }
        public string StartType { get; set; }
        public string Account { get; set; }
        public string ServerLevelPluginDll { get; set; }
        public string ConfigurationReadState { get; set; }
        public TriState CanConfigurePlugin { get; set; }
        public TriState CanChangeConfig { get; set; }
        public TriState CanStart { get; set; }
        public TriState CanStop { get; set; }
        public string RightProvenance { get; set; }
        public List<string> Errors { get; set; }
    }

    public sealed class CorrelationNode
    {
        public string NodeId { get; set; }
        public string Type { get; set; }
        public string Label { get; set; }
        public RelationshipState State { get; set; }
        public string StateName { get { return State.ToString().ToUpperInvariant(); } }
        public string Source { get; set; }
        public string EvidenceId { get; set; }
        public string Detail { get; set; }
    }

    public sealed class CorrelationEdge
    {
        public string SourceNodeId { get; set; }
        public string DestinationNodeId { get; set; }
        public string Relation { get; set; }
        public RelationshipState State { get; set; }
        public string StateName { get { return State.ToString().ToUpperInvariant(); } }
        public string EvidenceId { get; set; }
        public string RuleId { get; set; }
        public string FindingId { get; set; }
        public string Provenance { get; set; }
        public string Detail { get; set; }
    }

    public sealed class CorrelationTrace
    {
        public CorrelationTrace() { RuleIds = new List<string>(); EvaluatedRuleIds = new List<string>(); SupportingRuleIds = new List<string>(); RuledOutRuleIds = new List<string>(); FindingIds = new List<string>(); VerifiedConditions = new List<string>(); PendingConditions = new List<string>(); ConfirmedFacts = new List<string>(); ConditionalOutcomes = new List<string>(); Nodes = new List<CorrelationNode>(); Edges = new List<CorrelationEdge>(); Trace = new List<string>(); }
        public string TraceId { get; set; }
        public string ScenarioId { get; set; }
        public string Name { get; set; }
        public string Classification { get; set; }
        public EvaluationStatus Status { get; set; }
        public string StatusName { get { return Status.ToString().ToUpperInvariant(); } }
        public Severity Severity { get; set; }
        public string SeverityName { get { return Severity.ToString().ToUpperInvariant(); } }
        public Confidence Confidence { get; set; }
        public string ConfidenceName { get { return Confidence.ToString().ToUpperInvariant(); } }
        public List<string> RuleIds { get; set; }
        public List<string> EvaluatedRuleIds { get; set; }
        public List<string> SupportingRuleIds { get; set; }
        public List<string> RuledOutRuleIds { get; set; }
        public List<string> FindingIds { get; set; }
        public List<string> VerifiedConditions { get; set; }
        public List<string> PendingConditions { get; set; }
        public List<string> ConfirmedFacts { get; set; }
        public List<string> ConditionalOutcomes { get; set; }
        public bool ExploitationVerified { get; set; }
        public List<CorrelationNode> Nodes { get; set; }
        public List<CorrelationEdge> Edges { get; set; }
        public List<string> Trace { get; set; }
    }

    public sealed class ScheduledTaskAction
    {
        public ScheduledTaskAction() { HijackCandidates = new List<string>(); HijackCandidatePermissions = new List<SecurityPermission>(); }
        public string Type { get; set; }
        public string OriginalExecutable { get; set; }
        public string Executable { get; set; }
        public bool PathAmbiguous { get; set; }
        public string PathResolutionDetail { get; set; }
        public string Arguments { get; set; }
        public string WorkingDirectory { get; set; }
        public SecurityPermission TargetPermission { get; set; }
        public List<string> HijackCandidates { get; set; }
        public List<SecurityPermission> HijackCandidatePermissions { get; set; }
        public string ReferencedScript { get; set; }
        public SecurityPermission ScriptPermission { get; set; }
        public FileIdentityMetadata FileIdentity { get; set; }
    }

    public sealed class ScheduledTaskInfo
    {
        public ScheduledTaskInfo() { Actions = new List<ScheduledTaskAction>(); Triggers = new List<string>(); Errors = new List<string>(); }
        public string Name { get; set; }
        public string Path { get; set; }
        public bool Enabled { get; set; }
        public string State { get; set; }
        public string Principal { get; set; }
        public string RunLevel { get; set; }
        public TriState PrincipalIsHigher { get; set; }
        public TriState CanModify { get; set; }
        public List<ScheduledTaskAction> Actions { get; set; }
        public List<string> Triggers { get; set; }
        public List<string> Errors { get; set; }
    }

    public sealed class SystemSnapshot
    {
        public SystemSnapshot() { AlwaysInstallElevatedMachine = TriState.Unknown; AlwaysInstallElevatedUser = TriState.Unknown; }
        public string MachineName { get; set; }
        public string OsVersion { get; set; }
        public string Architecture { get; set; }
        public int ProcessId { get; set; }
        public bool IsWindows { get; set; }
        public TriState AlwaysInstallElevatedMachine { get; set; }
        public TriState AlwaysInstallElevatedUser { get; set; }
    }

    public sealed class Evidence
    {
        public string Kind { get; set; }
        public string Subject { get; set; }
        public string Value { get; set; }
        public bool Positive { get; set; }
    }

    public sealed class Finding
    {
        public Finding()
        {
            Evidence = new List<Evidence>();
            MissingConditions = new List<string>();
            Trace = new List<string>();
        }
        public string FindingId { get; set; }
        public string RuleId { get; set; }
        public string Name { get; set; }
        public string Category { get; set; }
        public Severity RuleSeverity { get; set; }
        public Severity Severity { get; set; }
        public Severity FindingSeverity { get { return Severity; } set { Severity = value; } }
        public Confidence Confidence { get; set; }
        public EvaluationStatus Status { get; set; }
        public string Target { get; set; }
        public string Recommendation { get; set; }
        public List<Evidence> Evidence { get; set; }
        public List<string> MissingConditions { get; set; }
        public List<string> Trace { get; set; }
        public string ObjectIdentity { get; set; }
        public string ServiceName { get; set; }
        public string PermissionState { get; set; }
        public string ConfigurationState { get; set; }
        public string ExecutionState { get; set; }
        public string RuntimeProtectionState { get; set; }
        public string VerifiedOperation { get; set; }
    }

    public sealed class ReferenceMetadata
    {
        public string SourceId { get; set; }
        public string Url { get; set; }
        public string Title { get; set; }
        public string Author { get; set; }
        public string Type { get; set; }
        public string Accessed { get; set; }
        public string Verification { get; set; }
    }

    public sealed class RuleDefinition
    {
        public RuleDefinition()
        {
            RequiredConditions = new List<string>(); OptionalConditions = new List<string>();
            InvalidatingConditions = new List<string>(); EvidenceRequirements = new List<string>(); RelatedLabs = new List<string>(); References = new List<ReferenceMetadata>();
        }
        public string Id { get; set; }
        public string Name { get; set; }
        public string Category { get; set; }
        public string Description { get; set; }
        public Severity Severity { get; set; }
        public string Evaluator { get; set; }
        public string Limitations { get; set; }
        public string Recommendation { get; set; }
        public string Verification { get; set; }
        public string Version { get; set; }
        public List<string> RequiredConditions { get; set; }
        public List<string> OptionalConditions { get; set; }
        public List<string> InvalidatingConditions { get; set; }
        public List<string> EvidenceRequirements { get; set; }
        public List<string> RelatedLabs { get; set; }
        public List<ReferenceMetadata> References { get; set; }
    }

    public sealed class AnalysisContext
    {
        public AnalysisContext()
        {
            Token = new TokenSnapshot(); System = new SystemSnapshot();
            Services = new List<WindowsService>(); Tasks = new List<ScheduledTaskInfo>(); Processes = new List<WindowsProcess>(); Binaries = new List<BinaryArtifact>();
            ExecutionRelationships = new List<ExecutionRelationship>(); Timings = new List<CollectorTiming>();
            Software = new List<SoftwareObservation>(); SoftwareVersionEvidence = new List<SoftwareVersionEvidence>();
            CorrelationTraces = new List<CorrelationTrace>(); DnsServer = new DnsServerSnapshot { Present = TriState.Unknown, CanConfigurePlugin = TriState.Unknown, ConfigurationReadState = "UNKNOWN" };
            Errors = new List<string>(); Diagnostics = new List<CollectorDiagnostic>();
        }
        public TokenSnapshot Token { get; set; }
        public string ScenarioId { get; set; }
        public string EvidenceOrigin { get; set; }
        public string ServiceEnumerationState { get; set; }
        public string TaskEnumerationState { get; set; }
        public SystemSnapshot System { get; set; }
        public List<WindowsService> Services { get; set; }
        public List<ScheduledTaskInfo> Tasks { get; set; }
        public List<WindowsProcess> Processes { get; set; }
        public List<BinaryArtifact> Binaries { get; set; }
        public List<ExecutionRelationship> ExecutionRelationships { get; set; }
        public List<SoftwareObservation> Software { get; set; }
        public List<SoftwareVersionEvidence> SoftwareVersionEvidence { get; set; }
        public DnsServerSnapshot DnsServer { get; set; }
        public List<CorrelationTrace> CorrelationTraces { get; set; }
        public List<CollectorTiming> Timings { get; set; }
        public List<string> Errors { get; set; }
        public List<CollectorDiagnostic> Diagnostics { get; set; }
    }

    public sealed class AnalysisResult
    {
        public AnalysisResult() { Findings = new List<Finding>(); CorrelationTraces = new List<CorrelationTrace>(); Errors = new List<string>(); }
        public DateTime GeneratedUtc { get; set; }
        public string Version { get; set; }
        public string SchemaVersion { get; set; }
        public int RulesEvaluated { get; set; }
        public AnalysisContext Context { get; set; }
        public List<Finding> Findings { get; set; }
        public List<CorrelationTrace> CorrelationTraces { get; set; }
        public List<string> Errors { get; set; }
    }
}
