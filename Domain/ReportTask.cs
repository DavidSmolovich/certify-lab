using System.Diagnostics;
using System.Runtime.Serialization;

namespace CertifyLab.Domain;

/// <summary>
/// A legitimate-LOOKING automation type: "render a report by invoking a CLI tool".
/// Real codebases and their dependencies are full of types like this (PDF renderers,
/// notifiers, migration hooks). On its own it is harmless.
///
/// The danger appears when a deserializer is allowed to choose which type to build
/// from attacker-controlled input (Json.NET <c>TypeNameHandling.All</c>). The attacker
/// names this type in the payload, sets <see cref="Run"/>, and the deserialization
/// callback executes it — remote code execution. This is the "gadget".
/// </summary>
public class ReportTask
{
    public string Run { get; set; }      // command line the task would execute
    public string Output { get; set; }   // captured result (shown to prove execution)

    [OnDeserialized]
    internal void OnDeserialized(StreamingContext _)
    {
        if (string.IsNullOrWhiteSpace(Run)) return;
        try
        {
            var psi = new ProcessStartInfo("/bin/sh")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false
            };
            psi.ArgumentList.Add("-c");
            psi.ArgumentList.Add(Run);

            using var p = Process.Start(psi);
            Output = (p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd()).Trim();
            p.WaitForExit(5000);
        }
        catch (Exception ex)
        {
            Output = "exec error: " + ex.Message;
        }
    }
}
