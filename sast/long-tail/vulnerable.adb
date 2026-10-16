--  File:    vulnerable.adb
--  Purpose: SAST fixture (Ada). Process spawn, weak hash, tainted file open.
--  Author:  Vigilnz Security Engineering
--  Date:    2026-10-16
--  Expected rules: ada-gnat-spawn, ada-md5, ada-file-open

with Ada.Text_IO;
with GNAT.OS_Lib;
with GNAT.MD5;

procedure Vulnerable is
   Success : Boolean;
   Args    : GNAT.OS_Lib.Argument_List (1 .. 1);
   F       : Ada.Text_IO.File_Type;
begin
   --  CWE-78: spawn with caller-controlled arguments
   Args (1) := new String'("-c");
   GNAT.OS_Lib.Spawn ("/bin/sh", Args, Success);

   --  CWE-327: MD5 used for a security decision
   Ada.Text_IO.Put_Line (GNAT.MD5.Digest ("password"));

   --  CWE-22: path from untrusted input
   Ada.Text_IO.Open (F, Ada.Text_IO.In_File, "/srv/files/" & "user_supplied");
   Ada.Text_IO.Close (F);
end Vulnerable;
