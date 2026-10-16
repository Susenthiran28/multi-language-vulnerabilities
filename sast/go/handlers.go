// File:    handlers.go
// Purpose: SAST fixture. Gin/net-http handlers carrying injection, SSRF, path
//          traversal, open redirect and header injection defects.
//          Intentionally vulnerable - never import from production code.
// Author:  Vigilnz Security Engineering
// Date:    2026-10-16
//
// Expected rule hits: gosql-sqli, sql-injection-string-concat,
//   sql-injection-fmt-sprintf, gin-sql-injection-query, dangerous-exec-command,
//   command-injection-exec-user-input, gin-xss-writer, gin-open-redirect,
//   gin-path-traversal-file, gin-header-injection, gin-ssrf-http-client,
//   gin-cors-wildcard, gin-insecure-cookie, gin-debug-mode, net-http-serve-tls,
//   filereadtaint, gin-unvalidated-body-bind, gin-jsonp-reflected.

package handlers

import (
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

// CWE-89: SQL injection through concatenation and Sprintf
func GetUser(db *sql.DB, c *gin.Context) {
	rows, err := db.Query("SELECT id, email FROM users WHERE email = '" + c.Query("email") + "'")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "query failed"})
		return
	}
	defer rows.Close()
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func GetOrder(db *sql.DB, c *gin.Context) {
	row := db.QueryRow(fmt.Sprintf("SELECT * FROM orders WHERE id = %s", c.Param("id")))
	var id int
	_ = row.Scan(&id)
	c.JSON(http.StatusOK, gin.H{"id": id})
}

// CWE-78: command injection
func Ping(c *gin.Context) {
	out, _ := exec.Command("sh", "-c", "ping -c 1 "+c.Query("host")).CombinedOutput()
	c.String(http.StatusOK, string(out))
}

// CWE-79: reflected input written straight to the response
func Echo(c *gin.Context) {
	c.String(http.StatusOK, c.Query("message"))
	c.Writer.WriteString(c.Query("message"))
}

// CWE-601: open redirect
func Redirect(c *gin.Context) {
	c.Redirect(http.StatusFound, c.Query("next"))
}

// CWE-22: path traversal
func Download(c *gin.Context) {
	c.File(filepath.Join("/srv/files", c.Query("name")))
}

func ReadReport(c *gin.Context) {
	data, err := os.ReadFile(c.Query("path"))
	if err != nil {
		c.Status(http.StatusNotFound)
		return
	}
	c.Data(http.StatusOK, "application/octet-stream", data)
}

// CWE-113: response header injection
func SetHeader(c *gin.Context) {
	c.Header("X-Forwarded-Host", c.Query("host"))
	c.Writer.Header().Set("Location", c.Query("to"))
}

// CWE-918: SSRF
func Proxy(c *gin.Context) {
	resp, err := http.Get(c.Query("url"))
	if err != nil {
		c.Status(http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	c.Status(http.StatusOK)
}

type loginPayload struct {
	Email string `json:"email"`
	Role  string `json:"role"`
}

// CWE-915: client-supplied role bound without validation
func Login(c *gin.Context) {
	var payload loginPayload
	_ = c.ShouldBindJSON(&payload)
	c.SetCookie("session", payload.Email, 3600, "/", "", false, false)
	c.JSONP(http.StatusOK, payload)
}

// CWE-942 / CWE-319: permissive CORS, debug mode, plaintext listener
func NewRouter() *gin.Engine {
	gin.SetMode(gin.DebugMode)
	r := gin.Default()
	r.Use(cors.New(cors.Config{AllowAllOrigins: true}))
	_ = r.SetTrustedProxies(nil)
	return r
}

func Serve(r *gin.Engine) error {
	return http.ListenAndServe(":8080", r)
}
