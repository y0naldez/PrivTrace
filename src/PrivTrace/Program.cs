using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Web.Script.Serialization;
using PrivTrace.Core;
using PrivTrace.Models;
using PrivTrace.Reporting;
using PrivTrace.Rules;

namespace PrivTrace
{
    internal class Program
    {
        static int Main(string[] args)
        {
            CommandLineOptions options; string error;
            if (!CommandLineParser.TryParse(args, out options, out error)) { Console.Error.WriteLine("Error: " + error); Console.Error.WriteLine("Use --help for usage."); return 2; }
            if (options.Help) { if (options.Spanish) SpanishConsoleReporter.PrintHelp(); else ConsoleReporter.PrintHelp(); return 0; }
            try
            {
                if (options.SanitizeReport != null) { ReportSanitizer.Sanitize(options.SanitizeReport, options.JsonPath); Console.WriteLine("Sanitized report: " + Path.GetFullPath(options.JsonPath)); return 0; }
                if (options.InspectReport != null)
                {
                    ReportInspection inspection = ReportImporter.Inspect(options.InspectReport);
                    Console.WriteLine("Report version: " + (inspection.Version ?? "MISSING") + " | schema: " + (inspection.SchemaVersion ?? "MISSING") + " | valid: " + inspection.SchemaValid);
                    Console.WriteLine("Findings: " + inspection.Findings + " | traces: " + inspection.CorrelationTraces + " | unknown/pending conditions: " + inspection.UnknownConditions);
                    Console.WriteLine("Active rules: " + (inspection.ActiveRules.Count == 0 ? "none" : String.Join(", ", inspection.ActiveRules.ToArray())));
                    foreach (string diagnostic in inspection.CollectorDiagnostics) Console.WriteLine("[?] Collector: " + diagnostic);
                    foreach (string issue in inspection.Errors) Console.WriteLine("[!] " + issue);
                    if (options.JsonPath != null) File.WriteAllText(options.JsonPath, new JavaScriptSerializer { MaxJsonLength = Int32.MaxValue }.Serialize(inspection), new UTF8Encoding(false));
                    return inspection.SchemaValid ? 0 : 1;
                }
                List<RuleDefinition> rules = new RuleCatalog().LoadEmbedded();
                if (options.ListRules) { foreach (RuleDefinition rule in rules) Console.WriteLine(rule.Id + "  " + rule.Category + "  " + rule.Name); return 0; }
                if (options.RuleInfoId != null)
                {
                    RuleDefinition info = rules.FirstOrDefault(r => r.Id.Equals(options.RuleInfoId, StringComparison.OrdinalIgnoreCase));
                    if (info == null) { Console.Error.WriteLine("Unknown rule: " + options.RuleInfoId); return 2; }
                    PrintRuleInfo(info); return 0;
                }
                if (options.RuleId != null) rules = rules.Where(r => r.Id.Equals(options.RuleId, StringComparison.OrdinalIgnoreCase)).ToList();
                if (options.Category != null) rules = rules.Where(r => r.Category.Equals(options.Category, StringComparison.OrdinalIgnoreCase)).ToList();
                if (rules.Count == 0) { Console.Error.WriteLine("No rules matched the requested filter."); return 2; }
                AnalyzerEngine analyzer = new AnalyzerEngine();
                AnalysisContext context = options.OfflineFixture == null ? analyzer.Collect() : analyzer.LoadFixture(options.OfflineFixture);
                AnalysisResult result = analyzer.Analyze(context, rules);
                if (options.Spanish) SpanishConsoleReporter.Print(result, options.Verbose); else ConsoleReporter.Print(result, options.Verbose);
                if (options.Processes || options.Verbose) { if (options.Spanish) SpanishConsoleReporter.PrintProcesses(context.Processes, options.Verbose); else ConsoleReporter.PrintProcesses(context.Processes, options.Verbose); }
                if (options.Binaries || options.Verbose)
                {
                    if (options.Spanish) { SpanishConsoleReporter.PrintBinaries(context.Binaries, options.Verbose); SpanishConsoleReporter.PrintRelationships(context.ExecutionRelationships); }
                    else { ConsoleReporter.PrintBinaries(context.Binaries, options.Verbose); ConsoleReporter.PrintRelationships(context.ExecutionRelationships); }
                }
                if (options.JsonPath != null) { JsonReporter.Write(result, options.JsonPath); Console.WriteLine((options.Spanish ? "Informe JSON: " : "JSON report: ") + Path.GetFullPath(options.JsonPath)); }
                return 0;
            }
            catch (Exception ex) { Console.Error.WriteLine("PrivTrace failed safely: " + ex.Message); if (options.Verbose) Console.Error.WriteLine(ex); return 1; }
        }

        private static void PrintRuleInfo(RuleDefinition rule)
        {
            Console.WriteLine(rule.Id + " - " + rule.Name); Console.WriteLine("Category: " + rule.Category); Console.WriteLine("Severity: " + rule.Severity); Console.WriteLine("Verification: " + rule.Verification); Console.WriteLine(rule.Description);
            Console.WriteLine("Required conditions:"); foreach (string c in rule.RequiredConditions) Console.WriteLine("  - " + c);
            Console.WriteLine("Evidence requirements:"); foreach (string c in rule.EvidenceRequirements) Console.WriteLine("  - " + c);
            Console.WriteLine("Related validation scenarios:"); if (rule.RelatedLabs.Count == 0) Console.WriteLine("  - None"); else foreach (string scenario in rule.RelatedLabs) Console.WriteLine("  - " + scenario);
            Console.WriteLine("Limitations: " + rule.Limitations); Console.WriteLine("References:"); foreach (ReferenceMetadata r in rule.References) Console.WriteLine("  - " + r.Title + " (" + r.Type + ", " + r.Verification + "): " + r.Url);
        }
    }
}
