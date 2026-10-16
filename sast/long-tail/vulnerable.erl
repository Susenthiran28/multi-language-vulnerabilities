%% File:    vulnerable.erl
%% Purpose: SAST fixture (Erlang). Shell execution, unsafe term deserialization,
%%          port opening, tainted file read.
%% Author:  Vigilnz Security Engineering
%% Date:    2026-10-16
%% Expected rules: erlang-os-cmd, erlang-binary-to-term, erlang-open-port,
%%   erlang-file-read

-module(vulnerable).
-export([ping/1, load_state/1, spawn_helper/1, read_report/1]).

%% CWE-78: command injection
ping(Host) ->
    os:cmd("ping -c 1 " ++ Host).

%% CWE-502: deserializing an attacker-controlled term
load_state(Blob) ->
    erlang:binary_to_term(Blob).

%% CWE-78: external program launched with untrusted arguments
spawn_helper(Arg) ->
    open_port({spawn, "helper " ++ Arg}, [binary]).

%% CWE-22: path traversal
read_report(Name) ->
    file:read_file("/srv/files/" ++ Name).
