// Fixed collector-only SCM host. No HTTP listener, shell or arbitrary command API.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.ServiceProcess;
using System.Web.Script.Serialization;

sealed class SentinelService : ServiceBase {
    Process collector;
    volatile bool stopping;
    string stopFile;
    public SentinelService() { ServiceName = "ProjectSentinelCollector"; CanStop = true; AutoLog = true; }
    static string Quote(string path) {
        if (path.Contains("\"")) throw new ArgumentException("Invalid configured path");
        return "\"" + path.TrimEnd('\\') + "\"";
    }
    protected override void OnStart(string[] args) {
        string root = AppDomain.CurrentDomain.BaseDirectory;
        var config = new JavaScriptSerializer().Deserialize<Dictionary<string,string>>(
            File.ReadAllText(Path.Combine(root, "installation.json")));
        stopFile = Path.Combine(config["collector_data"], "stop.request");
        File.Delete(stopFile);
        var start = new ProcessStartInfo(Path.Combine(root, "runtime", "python.exe"));
        start.Arguments = "-I -m sentinel.collector --url http://127.0.0.1:8765 --data-dir " +
            Quote(config["collector_data"]) + " --credential-file " +
            Quote(Path.Combine(config["backend_data"], "ingestion.json")) + " --stop-file " + Quote(stopFile);
        start.WorkingDirectory = root;
        start.UseShellExecute = false; start.CreateNoWindow = true;
        start.RedirectStandardOutput = true; start.RedirectStandardError = true;
        start.EnvironmentVariables["SENTINEL_RESOURCE_ROOT"] = Path.Combine(root, "app");
        collector = new Process(); collector.StartInfo = start;
        // Consume output without unbounded real-telemetry logs. Detailed health is bounded on disk.
        collector.OutputDataReceived += delegate { };
        collector.ErrorDataReceived += delegate { };
        collector.EnableRaisingEvents = true;
        collector.Exited += delegate { if (!stopping) Environment.Exit(1); };
        collector.Start(); collector.BeginOutputReadLine(); collector.BeginErrorReadLine();
    }
    protected override void OnStop() {
        stopping = true;
        if (collector != null && !collector.HasExited) {
            RequestAdditionalTime(90000);
            File.WriteAllText(stopFile, "stop");
            // Source reads time out at 60s; bounded delivery drains can take longer.
            if (!collector.WaitForExit(75000)) {
                var kill = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "taskkill.exe"),
                    "/PID " + collector.Id + " /T /F");
                kill.UseShellExecute = false; kill.CreateNoWindow = true;
                using (var process = Process.Start(kill)) process.WaitForExit(10000);
            }
        }
        if (collector != null) collector.Dispose();
    }
    public static void Main() { ServiceBase.Run(new SentinelService()); }
}
