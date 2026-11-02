using System;
using System.Collections.Generic;

namespace PrivTrace.Core
{
    public sealed class CommandLineOptions
    {
        public bool Help { get; set; }
        public bool Verbose { get; set; }
        public bool Clean { get; set; }
        public bool ListRules { get; set; }
        public bool Processes { get; set; }
        public bool Binaries { get; set; }
        public bool Spanish { get; set; }
        public string JsonPath { get; set; }
        public string RuleId { get; set; }
        public string RuleInfoId { get; set; }
        public string Category { get; set; }
        public string OfflineFixture { get; set; }
        public string SanitizeReport { get; set; }
        public string InspectReport { get; set; }
    }

    public static class CommandLineParser
    {
        public static bool TryParse(string[] args, out CommandLineOptions options, out string error)
        {
            options = new CommandLineOptions { Clean = true }; error = null;
            HashSet<string> single = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            for (int i = 0; i < args.Length; i++)
            {
                string arg = args[i];
                if (arg == "--help" || arg == "-h" || arg == "/?") options.Help = true;
                else if (arg == "--verbose") options.Verbose = true;
                else if (arg == "--clean") options.Clean = true;
                else if (arg == "--list-rules") options.ListRules = true;
                else if (arg == "--processes") options.Processes = true;
                else if (arg == "--binaries") options.Binaries = true;
                else if (arg == "-es" || arg == "--es") options.Spanish = true;
                else if (arg == "--json" || arg == "--rule" || arg == "--rule-info" || arg == "--category" || arg == "--offline-fixture" || arg == "--sanitize-report" || arg == "--inspect-report")
                {
                    if (!single.Add(arg)) { error = "Duplicate argument: " + arg; return false; }
                    if (i + 1 >= args.Length || args[i + 1].StartsWith("--", StringComparison.Ordinal)) { error = "Missing value for " + arg; return false; }
                    string value = args[++i];
                    if (arg == "--json") options.JsonPath = value;
                    else if (arg == "--rule") options.RuleId = value.ToUpperInvariant();
                    else if (arg == "--rule-info") options.RuleInfoId = value.ToUpperInvariant();
                    else if (arg == "--category") options.Category = value;
                    else if (arg == "--offline-fixture") options.OfflineFixture = value;
                    else if (arg == "--sanitize-report") options.SanitizeReport = value;
                    else options.InspectReport = value;
                }
                else { error = "Unknown argument: " + arg; return false; }
            }
            if (options.RuleId != null && options.RuleInfoId != null) { error = "--rule and --rule-info cannot be combined."; return false; }
            if (options.Verbose) options.Clean = false;
            if (options.SanitizeReport != null && options.InspectReport != null) { error = "--sanitize-report and --inspect-report cannot be combined."; return false; }
            if (options.SanitizeReport != null && options.JsonPath == null) { error = "--sanitize-report requires --json <output.json>."; return false; }
            return true;
        }
    }
}
