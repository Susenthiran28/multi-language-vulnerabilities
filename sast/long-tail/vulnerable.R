# File:    vulnerable.R
# Purpose: SAST fixture (R). Shell execution, parse+eval, remote source loading,
#          unsafe deserialization.
# Author:  Vigilnz Security Engineering
# Date:    2026-10-16
# Expected rules: r-system, r-eval-parse, r-source, r-readrds, r-download-file,
#   r-unserialize

args <- commandArgs(trailingOnly = TRUE)
user_input <- args[1]

# CWE-78: command injection
system(paste("ping -c 1", user_input))
system2("sh", c("-c", paste("nslookup", user_input)))

# CWE-95: parsing and evaluating untrusted source
eval(parse(text = user_input))

# CWE-494: code loaded from an unverified location
source(args[2])
download.file(args[2], destfile = "/tmp/pkg.R")

# CWE-502: deserializing attacker-controlled data
state <- readRDS("/tmp/state.rds")
blob <- unserialize(as.raw(c(0x58, 0x0a)))
