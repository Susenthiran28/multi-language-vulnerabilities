"""
File:    injection_views.py
Purpose: SAST fixture. Python injection-class defects - eval/exec, OS command,
         SQL, SSRF, path traversal, unsafe deserialization.
         Intentionally vulnerable - never import from production code.
Author:  Vigilnz Security Engineering
Date:    2026-10-16

Expected rule hits: eval-injection, exec-injection, compile-injection,
  os-system-command-injection, subprocess-shell-true, os-popen-injection,
  subprocess-tainted-env-args, sql-injection-execute-formatting,
  sql-injection-fstring, django-raw-sql-injection, insecure-pickle-loads,
  insecure-yaml-load, insecure-marshal-loads, flask-debug-enabled.
"""

import marshal
import os
import pickle
import subprocess

import yaml
from django.db import connection
from django.db.models import Q
from flask import Flask, request

app = Flask(__name__)


# CWE-95: dynamic evaluation of request data
@app.route("/calc")
def calc():
    return str(eval(request.args["expr"]))


@app.route("/run")
def run_snippet():
    exec(request.args["code"])
    return "ok"


def compile_snippet(source):
    return compile(source, "<user>", "exec")


# CWE-78: OS command injection
@app.route("/ping")
def ping():
    os.system("ping -c 1 " + request.args["host"])
    return "sent"


@app.route("/archive")
def archive():
    subprocess.run("tar -czf /tmp/out.tgz " + request.args["path"], shell=True)
    return "ok"


def read_uptime():
    return os.popen("uptime " + request.args.get("flags", "")).read()


def run_from_env():
    subprocess.Popen(os.environ.get("HELPER_BINARY"), shell=True)


# CWE-89: SQL injection
def find_user(cursor, email):
    cursor.execute("SELECT id, email FROM users WHERE email = '%s'" % email)
    return cursor.fetchall()


def find_order(cursor, order_id):
    cursor.execute(f"SELECT * FROM orders WHERE id = {order_id}")
    return cursor.fetchone()


def raw_django(term):
    with connection.cursor() as cur:
        cur.execute("SELECT * FROM products WHERE name LIKE '%" + term + "%'")
        return cur.fetchall()


# CWE-502: unsafe deserialization
def load_session(blob):
    return pickle.loads(blob)


def load_config(stream):
    return yaml.load(stream)


def load_cache(blob):
    return marshal.loads(blob)


if __name__ == "__main__":
    # CWE-489: debug console exposed
    app.run(host="0.0.0.0", port=5000, debug=True)
