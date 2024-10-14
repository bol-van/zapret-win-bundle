Set args = WScript.Arguments
If args.count=0 Then
 wscript.echo "elevate.vbs <executable> <parameters>"
Else
 Set UAC = CreateObject("Shell.Application")
 cmd = args(0)
 If args.count>=2 Then
  param = args(1)
  For i = 2 to args.count-1
   param = param & " " & args(i)
  Next
 End If
 UAC.ShellExecute cmd, param, "", "runas", 1
End If
