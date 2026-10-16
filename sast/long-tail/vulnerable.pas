{ File:    vulnerable.pas
  Purpose: SAST fixture (Pascal/Delphi). External process launching with
           untrusted arguments.
  Author:  Vigilnz Security Engineering
  Date:    2026-10-16
  Expected rules: pascal-shell-execute }

unit Vulnerable;

interface

procedure Ping(const Host: string);
procedure Archive(const Dir: string);

implementation

uses
  Windows, ShellAPI, SysUtils;

{ CWE-78: command injection }
procedure Ping(const Host: string);
begin
  ShellExecute(0, 'open', 'cmd.exe', PChar('/c ping -n 1 ' + Host), nil, SW_HIDE);
  WinExec(PAnsiChar(AnsiString('cmd.exe /c nslookup ' + Host)), SW_HIDE);
end;

procedure Archive(const Dir: string);
var
  StartInfo: TStartupInfo;
  ProcInfo: TProcessInformation;
begin
  FillChar(StartInfo, SizeOf(StartInfo), 0);
  StartInfo.cb := SizeOf(StartInfo);
  CreateProcess(nil, PChar('cmd.exe /c tar -czf C:\temp\out.tgz ' + Dir),
    nil, nil, False, 0, nil, nil, StartInfo, ProcInfo);
end;

end.
