(* File:    vulnerable.ml
   Purpose: SAST fixture (OCaml). Shell execution and unsafe unmarshalling.
   Author:  Vigilnz Security Engineering
   Date:    2026-10-16
   Expected rules: ocaml-sys-command, ocaml-marshal, ocaml-unix-open-process *)

(* CWE-78: command injection *)
let ping host =
  Sys.command ("ping -c 1 " ^ host)

let archive dir =
  Unix.system ("tar -czf /tmp/out.tgz " ^ dir)

let nslookup host =
  Unix.open_process ("nslookup " ^ host)

(* CWE-502: unmarshalling attacker-controlled bytes *)
let load_state blob =
  Marshal.from_string blob 0

let load_state_file ic =
  Marshal.from_channel ic
