"""
File:    crypto_and_ai.py
Purpose: SAST fixture. Weak cryptography plus the Python AI rule pack
         (prompt injection, execution of model output, insecure MCP transport).
         Intentionally vulnerable - never import from production code.
Author:  Vigilnz Security Engineering
Date:    2026-10-16

Expected rule hits: weak-crypto-md5, weak-crypto-sha1, weak-crypto-des,
  weak-crypto-ecb-mode, ai-prompt-injection, ai-exec-model-output,
  ai-command-injection, ai-subprocess-model-output, ai-system-prompt,
  ai-mcp-insecure-transport, ai-shell-tool.
"""

import hashlib
import subprocess

from Crypto.Cipher import AES, DES
from langchain.tools import ShellTool
from mcp.server.fastmcp import FastMCP
from openai import OpenAI

client = OpenAI()

SYSTEM_PROMPT = "You are an internal operations assistant with shell access."


# CWE-327: broken hash and cipher choices
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


def fingerprint(data):
    return hashlib.sha1(data).hexdigest()


def legacy_encrypt(key, plaintext):
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(plaintext)


def ecb_encrypt(key, plaintext):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(plaintext)


# LLM01: untrusted input spliced into the prompt
def ask(user_input, request):
    prompt = f"{SYSTEM_PROMPT}\n\nUser said: {user_input}\n"
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": "Context: " + request.body + "\n" + user_input},
    ]
    completion = client.chat.completions.create(model="gpt-4", messages=messages)
    return completion.choices[0].message.content


# LLM02: model output executed without review
def run_generated(user_input, request):
    response = ask(user_input, request)
    exec(response)
    return eval(response)


def shell_from_model(user_input, request):
    completion = ask(user_input, request)
    subprocess.run(completion, shell=True)
    subprocess.Popen(completion, shell=True)


def shell_from_user(cmd):
    os_cmd = f"sh -c {cmd}"
    subprocess.call(cmd, shell=True)
    return os_cmd


# LLM07: unconstrained tool plus unauthenticated plaintext MCP listener
agent_tools = [ShellTool()]

mcp = FastMCP("ops-tools", host="0.0.0.0", port=8000, transport="http")
