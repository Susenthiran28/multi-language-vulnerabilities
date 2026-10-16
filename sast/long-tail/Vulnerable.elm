-- File:    Vulnerable.elm
-- Purpose: SAST fixture (Elm). Debug statements left in and an unvalidated
--          outbound HTTP call.
-- Author:  Vigilnz Security Engineering
-- Date:    2026-10-16
-- Expected rules: elm-debug-todo, elm-debug-log, elm-http-get

module Vulnerable exposing (fetchProfile, parseToken, unimplemented)

import Http
import Json.Decode as Decode


-- CWE-489: debug output left in shipped code
parseToken : String -> String
parseToken token =
    Debug.log "auth token" token


unimplemented : a
unimplemented =
    Debug.todo "authorization check not implemented"


-- CWE-918: request target built from untrusted input
fetchProfile : String -> (Result Http.Error String -> msg) -> Cmd msg
fetchProfile userUrl toMsg =
    Http.get
        { url = userUrl
        , expect = Http.expectJson toMsg Decode.string
        }
