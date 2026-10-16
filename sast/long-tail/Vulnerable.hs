-- File:    Vulnerable.hs
-- Purpose: SAST fixture (Haskell). Unsafe IO escape hatches and process spawning.
-- Author:  Vigilnz Security Engineering
-- Date:    2026-10-16
-- Expected rules: haskell-unsafe-perform-io, haskell-unsafe-coerce,
--   haskell-create-process, haskell-read-process

module Vulnerable (ping, archive, cachedSecret, coerceToken) where

import System.IO.Unsafe (unsafePerformIO)
import System.Process (createProcess, readProcess, shell)
import Unsafe.Coerce (unsafeCoerce)

-- CWE-78: command injection
ping :: String -> IO String
ping host = readProcess "sh" ["-c", "ping -c 1 " ++ host] ""

archive :: String -> IO ()
archive dir = do
    _ <- createProcess (shell ("tar -czf /tmp/out.tgz " ++ dir))
    return ()

-- CWE-676: effects smuggled into pure code
cachedSecret :: String
cachedSecret = unsafePerformIO (readFile "/etc/app/secret")

-- CWE-704: type safety discarded
coerceToken :: a -> b
coerceToken = unsafeCoerce
