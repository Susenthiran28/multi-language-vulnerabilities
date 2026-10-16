/*
 * File:    vulnerable.cpp
 * Purpose: SAST fixture. C/C++ memory-safety and injection defects - stack
 *          overflow, format string, use-after-free, double free, integer
 *          overflow, command injection and weak crypto.
 *          Intentionally vulnerable - never compile into production code.
 * Author:  Vigilnz Security Engineering
 * Date:    2026-10-16
 *
 * Expected CWEs: 120, 121, 134, 416, 415, 190, 78, 89, 327, 798, 476, 22.
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <openssl/md5.h>
#include <string>

// CWE-798: credentials in source
static const char *kApiKey = "ak_live_cpp_0123456789abcdef";
static const char *kDbPassword = "Pr0dPassw0rd!";

// CWE-121: stack buffer overflow via unbounded copy
void copy_name(const char *input) {
    char name[32];
    strcpy(name, input);
    printf("name=%s\n", name);
}

void concat_path(const char *suffix) {
    char path[64];
    strcpy(path, "/srv/files/");
    strcat(path, suffix);
    FILE *f = fopen(path, "rb");
    if (f) fclose(f);
}

// CWE-120: gets() has no bound at all
void read_line() {
    char buf[128];
    gets(buf);
    printf("%s\n", buf);
}

// CWE-134: format string controlled by the caller
void log_message(const char *user_input) {
    printf(user_input);
    fprintf(stderr, user_input);
}

// CWE-416 / CWE-415: use-after-free and double free
void lifetime_bugs() {
    char *buf = (char *)malloc(64);
    strcpy(buf, "payload");
    free(buf);
    printf("%s\n", buf);
    free(buf);
}

// CWE-190: integer overflow feeding an allocation
void *allocate(int count, int size) {
    int total = count * size;
    return malloc(total);
}

// CWE-78: command injection
void ping(const char *host) {
    char cmd[256];
    sprintf(cmd, "ping -c 1 %s", host);
    system(cmd);
}

// CWE-89: SQL built by concatenation
std::string find_user_query(const std::string &email) {
    return "SELECT id, email FROM users WHERE email = '" + email + "'";
}

// CWE-327: broken hash
void hash_password(const char *password, unsigned char *out) {
    MD5((const unsigned char *)password, strlen(password), out);
}

// CWE-476: unchecked allocation result
void fill_buffer(size_t n) {
    char *p = (char *)malloc(n);
    memset(p, 0, n);
    free(p);
}

// CWE-22: path traversal
FILE *open_report(const char *name) {
    char path[256];
    sprintf(path, "/srv/files/%s", name);
    return fopen(path, "rb");
}
