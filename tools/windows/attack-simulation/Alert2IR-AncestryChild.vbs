Option Explicit

Dim marker
marker = WScript.Arguments.Named("marker")

Dim markerPattern
Set markerPattern = New RegExp
markerPattern.Pattern = "^Alert2IR-Ancestry-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
markerPattern.IgnoreCase = True
If Not markerPattern.Test(marker) Then
    WScript.Quit 2
End If

Dim shell
Set shell = CreateObject("WScript.Shell")

Dim powerShellPath
powerShellPath = "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"

Dim command
command = """" & powerShellPath & """ -NoLogo -NoProfile -NonInteractive -Command ""$null = '" & marker & "'; Start-Sleep -Seconds 5"""

Dim exitCode
exitCode = shell.Run(command, 0, True)
WScript.Quit exitCode
