var shell = new ActiveXObject("WScript.Shell");
var files = new ActiveXObject("Scripting.FileSystemObject");
var prefix = shell.ExpandEnvironmentStrings("%CHURRO_E2E_PREFIX%");
var marker = files.CreateTextFile(prefix + ".js", true);
marker.Write("JScript executed");
marker.Close();
