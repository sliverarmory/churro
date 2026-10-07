Dim shell, files, marker, prefix
Set shell = CreateObject("WScript.Shell")
Set files = CreateObject("Scripting.FileSystemObject")
prefix = shell.ExpandEnvironmentStrings("%CHURRO_E2E_PREFIX%")
Set marker = files.CreateTextFile(prefix & ".vbs", True)
marker.Write "VBScript executed"
marker.Close
