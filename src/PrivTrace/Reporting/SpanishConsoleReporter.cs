using System;
using System.Collections.Generic;
using System.Linq;
using PrivTrace.Models;

namespace PrivTrace.Reporting
{
    // Spanish is an output projection only. It never changes collection, rules, or finding states.
    public static class SpanishConsoleReporter
    {
        public static void Print(AnalysisResult result, bool verbose)
        {
            PrintBanner();
            Console.WriteLine("[+] Usuario    : " + (result.Context.Token.UserName ?? "DESCONOCIDO"));
            Console.WriteLine("[+] Integridad : " + (result.Context.Token.IntegrityLevel ?? "DESCONOCIDA"));
            Console.WriteLine("[+] SO          : " + result.Context.System.OsVersion + " " + result.Context.System.Architecture);

            List<Finding> all = result.Findings ?? new List<Finding>();
            int unknownCount = all.Count(f => f.Status == EvaluationStatus.Unknown);
            Console.WriteLine();
            Console.WriteLine("Cobertura de recopilacion:");
            Console.WriteLine("Servicios: " + Observation(result.Context.ServiceEnumerationState));
            Console.WriteLine("Tareas programadas: " + Observation(result.Context.TaskEnumerationState));
            if (!Observed(result.Context.ServiceEnumerationState) || !Observed(result.Context.TaskEnumerationState))
                Console.WriteLine("Impacto: algunas comprobaciones no pudieron completarse; la evidencia restante sigue siendo valida.");

            PrintCorrelations(result.CorrelationTraces, verbose);
            Console.WriteLine();
            Separator();
            Console.WriteLine(verbose ? "HALLAZGOS (DIAGNOSTICO COMPLETO)" : "RUTAS DE ESCALADA DE PRIVILEGIOS");
            Separator();

            HashSet<string> correlated = new HashSet<string>((result.CorrelationTraces ?? new List<CorrelationTrace>()).SelectMany(t => t.FindingIds), StringComparer.OrdinalIgnoreCase);
            HashSet<string> grouped = verbose ? new HashSet<string>(StringComparer.OrdinalIgnoreCase) : PrintServiceGroups(result.Context.Services, all);
            List<Finding> visible = (verbose ? all : all.Where(f => !correlated.Contains(f.FindingId) && !grouped.Contains(f.FindingId) && ConsoleReporter.IsActionable(f)))
                .OrderBy(f => Rank(f.Status)).ThenBy(f => f.Severity).ToList();
            if (!verbose && visible.Count == 0 && grouped.Count == 0 && !(result.CorrelationTraces ?? new List<CorrelationTrace>()).Any(t => Actionable(t.Status)))
                Console.WriteLine("No se verificaron rutas de escalada accionables.");
            foreach (Finding finding in visible) PrintFinding(finding, verbose);

            PrintSoftware(result.Context.Software, verbose, result.Context.EvidenceOrigin);
            if (!verbose && unknownCount > 0)
            {
                Console.WriteLine();
                Console.WriteLine("Limitaciones de recopilacion:");
                Console.WriteLine("Servicios: " + Observation(result.Context.ServiceEnumerationState));
                Console.WriteLine("Tareas programadas: " + Observation(result.Context.TaskEnumerationState));
                foreach (IGrouping<string, Finding> group in all.Where(f => f.Status == EvaluationStatus.Unknown).GroupBy(f => f.RuleId).OrderBy(g => g.Key))
                    Console.WriteLine(group.Key + ": " + CountText(group.Count(), "comprobacion sin resolver", "comprobaciones sin resolver") + ".");
                Console.WriteLine();
                Console.WriteLine("Diagnostico: " + CountText(unknownCount, "comprobacion sin resolver", "comprobaciones sin resolver") + ".");
                Console.WriteLine("Ejecute --verbose para ver los detalles.");
            }

            Console.WriteLine();
            Separator(); Console.WriteLine("RESUMEN"); Separator();
            Console.WriteLine("Reglas evaluadas       : " + result.RulesEvaluated);
            Console.WriteLine("Confirmadas            : " + all.Count(f => f.Status == EvaluationStatus.Confirmed));
            Console.WriteLine("Potenciales            : " + all.Count(f => f.Status == EvaluationStatus.Potential && HasPositiveEvidence(f)));
            Console.WriteLine("Comprobaciones inciertas: " + unknownCount);
            Console.WriteLine("Cobertura de recopilacion: " + (unknownCount > 0 || !Observed(result.Context.ServiceEnumerationState) || !Observed(result.Context.TaskEnumerationState) ? "PARCIAL" : "COMPLETA"));
            if (verbose)
            {
                foreach (string error in result.Errors) Console.WriteLine("[!] " + error);
                foreach (CollectorDiagnostic diagnostic in result.Context.Diagnostics ?? new List<CollectorDiagnostic>())
                    Console.WriteLine("[!] Recopilador " + diagnostic.Collector + "/" + diagnostic.Stage + ": objeto=" + (diagnostic.ObjectName ?? "GLOBAL") + ", acceso=" + (diagnostic.RequestedAccess ?? "N/D") + ", clasificacion=" + diagnostic.Classification);
            }
        }

        private static HashSet<string> PrintServiceGroups(IEnumerable<WindowsService> services, IEnumerable<Finding> findings)
        {
            HashSet<string> grouped = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            List<Finding> candidates = (findings ?? Enumerable.Empty<Finding>()).Where(f =>
                (String.Equals(f.RuleId, "PT-013", StringComparison.OrdinalIgnoreCase) || String.Equals(f.RuleId, "PT-014", StringComparison.OrdinalIgnoreCase) || String.Equals(f.RuleId, "PT-016", StringComparison.OrdinalIgnoreCase)) &&
                !String.IsNullOrWhiteSpace(f.ServiceName) && ConsoleReporter.IsActionable(f)).ToList();
            foreach (IGrouping<string, Finding> group in candidates.GroupBy(f => f.ServiceName, StringComparer.OrdinalIgnoreCase).OrderBy(g => g.Key, StringComparer.OrdinalIgnoreCase))
            {
                WindowsService service = (services ?? Enumerable.Empty<WindowsService>()).FirstOrDefault(s => String.Equals(s.Name, group.Key, StringComparison.OrdinalIgnoreCase));
                Severity severity = group.Any(f => f.Severity == Severity.Critical) ? Severity.Critical : group.Any(f => f.Severity == Severity.High) ? Severity.High : group.Any(f => f.Severity == Severity.Medium) ? Severity.Medium : Severity.Low;
                Console.WriteLine();
                Console.WriteLine("[" + SeverityText(severity) + "] Servicio: " + group.Key);
                Console.WriteLine("    Cuenta de ejecucion       : " + (service == null ? "DESCONOCIDA" : service.Account ?? "DESCONOCIDA"));
                Console.WriteLine("    Ejecutable                : " + (service == null ? "DESCONOCIDO" : service.ExecutablePath ?? service.BinaryPath ?? "DESCONOCIDO"));
                Console.WriteLine("    Puede iniciar el servicio? : " + TriStateText(service == null ? TriState.Unknown : service.CanStart));
                Console.WriteLine("    Puede detener el servicio? : " + TriStateText(service == null ? TriState.Unknown : service.CanStop));
                Console.WriteLine("    Puede cambiar configuracion? : " + OperationAnswer(group, "SERVICE_CHANGE_CONFIG", service == null ? TriState.Unknown : service.CanChangeConfig));
                Console.WriteLine("    Puede escribir el binario? : " + OperationAnswer(group, "FILE_WRITE_DATA", service == null || service.ExecutablePermission == null ? TriState.Unknown : service.ExecutablePermission.CanWrite));
                Console.WriteLine("    Puede reemplazarlo?        : " + ReplacementAnswer(group, service));
                foreach (Finding finding in group.OrderBy(f => f.RuleId, StringComparer.OrdinalIgnoreCase))
                {
                    string operation = String.IsNullOrWhiteSpace(finding.VerifiedOperation) ? finding.PermissionState ?? StatusText(finding.Status) : finding.VerifiedOperation;
                    Console.WriteLine("    Evidencia " + finding.RuleId + "        : " + OperationText(operation) + " (" + StatusText(finding.Status) + ")");
                    if (!String.IsNullOrWhiteSpace(finding.FindingId)) grouped.Add(finding.FindingId);
                }
                Console.WriteLine("    Se probo la ejecucion?     : NO; la ejecucion privilegiada sigue siendo condicional");
                Console.WriteLine("    Proteccion en ejecucion    : " + RuntimeText(group.Select(f => f.RuntimeProtectionState).FirstOrDefault(s => !String.IsNullOrWhiteSpace(s))));
            }
            return grouped;
        }

        private static string OperationAnswer(IEnumerable<Finding> findings, string operation, TriState fallback)
        {
            Finding confirmed = findings.FirstOrDefault(f => String.Equals(f.VerifiedOperation, operation, StringComparison.OrdinalIgnoreCase) && f.Status == EvaluationStatus.Confirmed);
            if (confirmed != null) return "SI (confirmado)";
            Finding potential = findings.FirstOrDefault(f => String.Equals(f.VerifiedOperation, operation, StringComparison.OrdinalIgnoreCase) && f.Status == EvaluationStatus.Potential);
            if (potential != null) return "POSIBLE; requiere validacion adicional";
            return TriStateText(fallback);
        }

        private static string ReplacementAnswer(IEnumerable<Finding> findings, WindowsService service)
        {
            string answer = OperationAnswer(findings, "FILE_REPLACEMENT", TriState.Unknown);
            if (!answer.StartsWith("REVISAR", StringComparison.Ordinal)) return answer;
            if (service == null || service.DirectoryPermission == null) return answer;
            if (service.DirectoryPermission.CanCreate == TriState.No) return "NO (no se confirmo creacion en el directorio)";
            if (service.DirectoryPermission.CanCreate == TriState.Yes &&
                ((service.DirectoryPermission.CanDeleteChildren == TriState.No) && (service.ExecutablePermission == null || service.ExecutablePermission.CanDelete == TriState.No)))
                return "NO CONFIRMADO; solo se pueden crear archivos nuevos";
            return answer;
        }

        private static void PrintFinding(Finding finding, bool verbose)
        {
            Console.WriteLine();
            Console.WriteLine("[" + SeverityText(finding.Severity) + "] " + finding.RuleId + " - " + RuleName(finding.RuleId, finding.Name));
            if (!String.IsNullOrEmpty(finding.Target)) Console.WriteLine("Objetivo: " + finding.Target);
            Console.WriteLine("Estado: " + StatusText(finding.Status) + " | Confianza: " + ConfidenceText(finding.Confidence));
            Console.WriteLine("Severidad de la regla: " + SeverityText(finding.RuleSeverity) + " | Severidad del hallazgo: " + SeverityText(finding.Severity));
            foreach (Evidence evidence in finding.Evidence) Console.WriteLine((evidence.Positive ? "[+] " : "[-] ") + TranslateEvidence(evidence.Value));
            if (finding.Trace.Count > 0)
            {
                Console.WriteLine("TRAZABILIDAD:");
                foreach (string step in finding.Trace) Console.WriteLine("  -> " + TranslateTrace(step));
            }
            foreach (string missing in (verbose ? finding.MissingConditions : finding.MissingConditions.Take(1))) Console.WriteLine("[?] " + TranslateCondition(missing));
            if (!String.IsNullOrEmpty(finding.Recommendation)) Console.WriteLine("Recomendacion: " + Recommendation(finding));
        }

        private static void PrintSoftware(IEnumerable<SoftwareObservation> software, bool verbose, string evidenceOrigin)
        {
            List<SoftwareObservation> items = (software ?? Enumerable.Empty<SoftwareObservation>()).ToList();
            PrintSoftwareSection(items.Where(s => !String.Equals(s.SoftwareContext, "INFRASTRUCTURE", StringComparison.OrdinalIgnoreCase)), "SOFTWARE DE INTERES", verbose, evidenceOrigin);
            PrintSoftwareSection(items.Where(s => String.Equals(s.SoftwareContext, "INFRASTRUCTURE", StringComparison.OrdinalIgnoreCase)), "SOFTWARE DE INFRAESTRUCTURA", verbose, evidenceOrigin);
        }

        private static void PrintSoftwareSection(IEnumerable<SoftwareObservation> source, string title, bool verbose, string evidenceOrigin)
        {
            List<SoftwareObservation> items = source.ToList(); if (items.Count == 0) return;
            Console.WriteLine(); Separator(); Console.WriteLine(title); Separator();
            int index = 0;
            foreach (SoftwareObservation item in items.OrderByDescending(s => s.InvestigationPriority).ThenBy(s => s.ProductName, StringComparer.OrdinalIgnoreCase))
            {
                index++; Console.WriteLine(); Console.WriteLine("[" + index + "] " + item.ProductName);
                bool imported = String.Equals(evidenceOrigin, "IMPORTED_UNVERIFIED", StringComparison.OrdinalIgnoreCase);
                string process = imported ? "DESCONOCIDO (EVIDENCIA IMPORTADA SIN VERIFICAR)" : (item.ProcessPaths ?? new List<string>()).FirstOrDefault() ?? "DESCONOCIDO";
                Console.WriteLine("    Proceso    : " + process);
                if (item.ServiceNames.Count > 0) Console.WriteLine("    Servicio   : " + String.Join(", ", item.ServiceNames.ToArray()));
                Console.WriteLine("    Version    : " + (imported ? "DESCONOCIDA" : item.Version ?? "DESCONOCIDA"));
                Console.WriteLine("    Fuente     : " + (imported ? "EVIDENCIA IMPORTADA SIN VERIFICAR" : item.VersionSource ?? "DESCONOCIDA"));
                Console.WriteLine("    Escalada   : " + (item.ActiveRuleIds.Count > 0 ? String.Join(", ", item.ActiveRuleIds.OrderBy(r => r).ToArray()) : "NO VERIFICADA"));
                if (verbose) foreach (string pending in item.PendingConditions) Console.WriteLine("      [?] " + TranslateCondition(pending));
            }
        }

        private static void PrintCorrelations(IEnumerable<CorrelationTrace> correlations, bool verbose)
        {
            List<CorrelationTrace> items = (correlations ?? Enumerable.Empty<CorrelationTrace>()).Where(t => verbose || Actionable(t.Status)).ToList();
            if (items.Count == 0) return;
            Console.WriteLine(); Separator(); Console.WriteLine("RUTAS CORRELACIONADAS"); Separator();
            foreach (CorrelationTrace trace in items)
            {
                Console.WriteLine(); Console.WriteLine("[" + SeverityText(trace.Severity) + "] " + trace.Name + " (reglas: " + String.Join(" + ", trace.SupportingRuleIds.ToArray()) + ")");
                Console.WriteLine("Estado: " + StatusText(trace.Status) + " | Confianza: " + ConfidenceText(trace.Confidence) + " | Clasificacion: " + trace.Classification);
                Console.WriteLine("Se verifico la explotacion?: NO");
                foreach (string pending in (verbose ? trace.PendingConditions : trace.PendingConditions.Take(2))) Console.WriteLine("[?] " + TranslateCondition(pending));
            }
        }

        public static void PrintProcesses(IEnumerable<WindowsProcess> processes, bool verbose)
        {
            Console.WriteLine(); Separator(); Console.WriteLine("PROCESOS"); Separator();
            foreach (WindowsProcess process in (processes ?? Enumerable.Empty<WindowsProcess>()).OrderBy(p => p.ProcessId))
            {
                Console.WriteLine("PID " + process.ProcessId + "  " + (process.Name ?? "Desconocido") + "  [" + (process.AccessStatus ?? "DESCONOCIDO") + "]");
                Console.WriteLine("  Imagen: " + (process.ImagePath ?? "DESCONOCIDA"));
                Console.WriteLine("  Identidad: " + (process.OwnerAccount ?? process.OwnerSid ?? "DESCONOCIDA") + " | Integridad: " + (process.IntegrityLevel ?? "DESCONOCIDA"));
                if (process.ServiceNames.Count > 0) Console.WriteLine("  Servicios asociados por PID: " + String.Join(", ", process.ServiceNames.ToArray()));
            }
        }

        public static void PrintBinaries(IEnumerable<BinaryArtifact> binaries, bool verbose)
        {
            Console.WriteLine(); Separator(); Console.WriteLine("BINARIOS"); Separator();
            foreach (BinaryArtifact binary in (binaries ?? Enumerable.Empty<BinaryArtifact>()).OrderBy(b => b.Path, StringComparer.OrdinalIgnoreCase))
            {
                Console.WriteLine(binary.Path + "  [existe=" + TriStateText(binary.Exists) + "]");
                Console.WriteLine("  Fuentes: " + String.Join(", ", binary.Sources.ToArray()));
                if (binary.ServiceNames.Count > 0) Console.WriteLine("  Servicios: " + String.Join(", ", binary.ServiceNames.ToArray()));
                if (binary.FilePermission != null) Console.WriteLine("  Permisos del archivo: escritura=" + TriStateText(binary.FilePermission.CanWrite) + ", eliminacion=" + TriStateText(binary.FilePermission.CanDelete));
                if (binary.DirectoryPermission != null) Console.WriteLine("  Permisos del directorio: creacion=" + TriStateText(binary.DirectoryPermission.CanCreate) + ", eliminacion=" + TriStateText(binary.DirectoryPermission.CanDelete));
            }
        }

        public static void PrintRelationships(IEnumerable<ExecutionRelationship> relationships)
        {
            List<ExecutionRelationship> items = (relationships ?? Enumerable.Empty<ExecutionRelationship>()).ToList(); if (items.Count == 0) return;
            Console.WriteLine(); Separator(); Console.WriteLine("RELACIONES DE EJECUCION"); Separator();
            foreach (ExecutionRelationship relation in items.OrderBy(r => r.SourceId, StringComparer.OrdinalIgnoreCase))
                Console.WriteLine("[" + relation.Classification + "] " + relation.SourceKind + " " + relation.SourceId + " -> " + relation.TargetPath);
        }

        public static void PrintHelp()
        {
            PrintBanner();
            Console.WriteLine("Uso: PrivTrace.exe [opciones]");
            Console.WriteLine("  -es, --es                 Mostrar la salida de consola en espanol natural");
            Console.WriteLine("  --clean                   Salida resumida de alta senal (predeterminada)");
            Console.WriteLine("  --verbose                 Incluir estados inciertos, descartados y diagnosticos");
            Console.WriteLine("  --processes               Mostrar procesos observados");
            Console.WriteLine("  --binaries                Mostrar rutas de ejecucion y permisos efectivos");
            Console.WriteLine("  --json <informe.json>     Exportar el informe JSON estructurado");
            Console.WriteLine("  --rule <PT-001>           Evaluar una regla");
            Console.WriteLine("  --offline-fixture <file>  Analizar un fixture sin enumeracion en vivo");
            Console.WriteLine("  --help                    Mostrar esta ayuda");
        }

        private static void PrintBanner() { Separator(); Console.WriteLine("                PrivTrace v1.1.0"); Console.WriteLine("   Analizador de escalada de privilegios en Windows"); Separator(); }
        private static void Separator() { Console.WriteLine("================================================="); }
        private static string CountText(int count, string singular, string plural) { return count + " " + (count == 1 ? singular : plural); }
        private static bool Observed(string value) { return String.Equals(value, "OBSERVED", StringComparison.OrdinalIgnoreCase); }
        private static bool Actionable(EvaluationStatus status) { return status == EvaluationStatus.Confirmed || status == EvaluationStatus.Potential; }
        private static bool HasPositiveEvidence(Finding finding) { return finding.Evidence != null && finding.Evidence.Any(e => e.Positive); }
        private static int Rank(EvaluationStatus status) { return status == EvaluationStatus.Confirmed ? 0 : status == EvaluationStatus.Potential ? 1 : status == EvaluationStatus.Unknown ? 2 : 3; }
        private static string Observation(string value) { return Observed(value) ? "OBSERVADA" : String.Equals(value, "PARTIAL", StringComparison.OrdinalIgnoreCase) ? "PARCIAL" : "DESCONOCIDA"; }
        private static string TriStateText(TriState value) { return value == TriState.Yes ? "SI (confirmado)" : value == TriState.No ? "NO" : "REVISAR MANUALMENTE (sin evidencia suficiente)"; }
        private static string StatusText(EvaluationStatus value) { return value == EvaluationStatus.Confirmed ? "CONFIRMADO" : value == EvaluationStatus.Potential ? "POTENCIAL" : value == EvaluationStatus.Unknown ? "DESCONOCIDO" : value == EvaluationStatus.RuledOut ? "DESCARTADO" : "INFORMATIVO"; }
        private static string ConfidenceText(Confidence value) { return value == Confidence.High ? "ALTA" : value == Confidence.Medium ? "MEDIA" : value == Confidence.Low ? "BAJA" : "DESCONOCIDA"; }
        private static string SeverityText(Severity value) { return value == Severity.Critical ? "CRITICA" : value == Severity.High ? "ALTA" : value == Severity.Medium ? "MEDIA" : value == Severity.Low ? "BAJA" : "INFORMATIVA"; }
        private static string RuntimeText(string value) { return String.Equals(value, "UNKNOWN", StringComparison.OrdinalIgnoreCase) || String.IsNullOrWhiteSpace(value) ? "REVISAR MANUALMENTE (no evaluada)" : value; }
        private static string OperationText(string value) { return String.Equals(value, "FILE_WRITE_DATA", StringComparison.OrdinalIgnoreCase) ? "escritura directa del contenido del ejecutable" : String.Equals(value, "FILE_REPLACEMENT", StringComparison.OrdinalIgnoreCase) ? "reemplazo del ejecutable" : String.Equals(value, "FILE_ADD_FILE", StringComparison.OrdinalIgnoreCase) ? "creacion de archivos en el directorio" : String.Equals(value, "SERVICE_CHANGE_CONFIG", StringComparison.OrdinalIgnoreCase) ? "cambio de configuracion del servicio" : value; }

        private static string RuleName(string id, string fallback)
        {
            switch (id)
            {
                case "PT-001": return "Privilegio SeImpersonatePrivilege";
                case "PT-002": return "Privilegio SeAssignPrimaryTokenPrivilege";
                case "PT-003": return "Privilegio SeBackupPrivilege";
                case "PT-004": return "Privilegio SeRestorePrivilege";
                case "PT-005": return "Privilegio SeDebugPrivilege";
                case "PT-006": return "Privilegio SeTakeOwnershipPrivilege";
                case "PT-007": return "Privilegio SeLoadDriverPrivilege";
                case "PT-008": return "Privilegio SeManageVolumePrivilege";
                case "PT-009": return "Grupo Operadores de servidores";
                case "PT-010": return "Grupo Operadores de copia de seguridad";
                case "PT-011": return "Grupo DnsAdmins";
                case "PT-012": return "Grupo Operadores de impresion";
                case "PT-013": return "Binario de servicio escribible";
                case "PT-014": return "Permisos debiles de configuracion del servicio";
                case "PT-015": return "Ruta de servicio sin comillas";
                case "PT-016": return "Directorio escribible del ejecutable del servicio";
                case "PT-017": return "Binario escribible de tarea programada";
                case "PT-018": return "Permisos debiles de tarea programada";
                case "PT-019": return "Script escribible de tarea programada";
                case "PT-020": return "Secuestro de ruta de ejecucion de tarea programada";
                case "PT-021": return "AlwaysInstallElevated habilitado";
                case "PT-022": return "Grupo Lectores del registro de eventos";
                case "PT-023": return "Privilegio SeTcbPrivilege";
                case "PT-024": return "Superficie de suplantacion de la cola de impresion";
                case "PT-025": return "Privilegio SeCreateTokenPrivilege";
                case "PT-026": return "Permisos debiles del registro de configuracion del servicio";
                case "PT-027": return "ServiceDll privilegiada escribible";
                default: return fallback;
            }
        }

        private static string TranslateEvidence(string value)
        {
            if (String.Equals(value, "Present and enabled", StringComparison.OrdinalIgnoreCase)) return "El privilegio esta presente y habilitado.";
            if (String.Equals(value, "Present but disabled", StringComparison.OrdinalIgnoreCase)) return "El privilegio esta presente, pero deshabilitado.";
            return value;
        }
        private static string TranslateTrace(string value)
        {
            if (String.Equals(value, "Current token", StringComparison.OrdinalIgnoreCase)) return "Token de seguridad actual";
            if (value.IndexOf("(enabled)", StringComparison.OrdinalIgnoreCase) >= 0) return value.Replace("(enabled)", "(habilitado)");
            if (String.Equals(value, "Technique-specific preconditions remain", StringComparison.OrdinalIgnoreCase)) return "Aun faltan condiciones especificas de la tecnica";
            return value;
        }
        private static string TranslateCondition(string value)
        {
            if (String.Equals(value, "No exploitation precondition or privileged target was tested by the privilege-presence rule.", StringComparison.OrdinalIgnoreCase)) return "La regla solo comprobo la presencia del privilegio; no probo una condicion de explotacion ni un objetivo privilegiado.";
            if (value.IndexOf("Runtime or application self-protection", StringComparison.OrdinalIgnoreCase) >= 0) return "La autoproteccion de la aplicacion o en tiempo de ejecucion no fue evaluada.";
            if (value.IndexOf("no binary modification, restart, or payload execution", StringComparison.OrdinalIgnoreCase) >= 0) return "No se modifico el binario, no se reinicio el servicio y no se ejecuto ninguna carga.";
            return value;
        }
        private static string Recommendation(Finding finding)
        {
            if (String.Equals(finding.RuleId, "PT-001", StringComparison.OrdinalIgnoreCase)) return "Enumere servicios locales y fuentes de tokens alcanzables; despues valide las mitigaciones de la plataforma.";
            return finding.Recommendation;
        }
    }
}
