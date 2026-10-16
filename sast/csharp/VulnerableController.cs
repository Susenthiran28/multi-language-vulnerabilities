/*
 * File:    VulnerableController.cs
 * Purpose: SAST fixture. ASP.NET controller with SQL/command injection, XXE,
 *          unsafe deserialization, SSRF, path traversal and weak crypto.
 *          Intentionally vulnerable - never deploy.
 * Author:  Vigilnz Security Engineering
 * Date:    2026-10-16
 *
 * Expected CWEs: 89, 78, 611, 502, 918, 22, 327, 798, 601, 79, 338, 295.
 */

using System;
using System.Data.SqlClient;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Xml;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;

namespace Vigilnz.Fixtures
{
    public class VulnerableController : Controller
    {
        // CWE-798: credentials in source
        private const string ConnectionString = "Server=db;Database=app;User Id=sa;Password=Pr0dPassw0rd!;";
        private const string ApiKey = "ak_live_csharp_0123456789abcdef";

        // CWE-89: SQL injection
        [HttpGet("/user")]
        public IActionResult FindUser(string email)
        {
            using var conn = new SqlConnection(ConnectionString);
            var cmd = new SqlCommand("SELECT Id, Email FROM Users WHERE Email = '" + email + "'", conn);
            conn.Open();
            using var reader = cmd.ExecuteReader();
            return Ok(reader.HasRows);
        }

        // CWE-78: command injection
        [HttpGet("/ping")]
        public IActionResult Ping(string host)
        {
            Process.Start("cmd.exe", "/c ping -n 1 " + host);
            return Ok();
        }

        // CWE-611: XXE - DTD resolution left enabled
        [HttpPost("/parse")]
        public IActionResult Parse(string xml)
        {
            var doc = new XmlDocument { XmlResolver = new XmlUrlResolver() };
            doc.LoadXml(xml);
            return Ok(doc.DocumentElement?.Name);
        }

        // CWE-502: unsafe deserialization
        [HttpPost("/state")]
        public IActionResult LoadState([FromBody] byte[] blob)
        {
            using var ms = new MemoryStream(blob);
            var formatter = new BinaryFormatter();
            var state = formatter.Deserialize(ms);
            var loose = JsonConvert.DeserializeObject(Encoding.UTF8.GetString(blob),
                new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All });
            return Ok(new { state, loose });
        }

        // CWE-918 and CWE-295
        [HttpGet("/proxy")]
        public IActionResult Proxy(string url)
        {
            var handler = new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = (m, c, ch, e) => true
            };
            using var client = new HttpClient(handler);
            var body = client.GetStringAsync(url).Result;
            return Content(body);
        }

        // CWE-22: path traversal
        [HttpGet("/download")]
        public IActionResult Download(string name)
        {
            var bytes = System.IO.File.ReadAllBytes("/srv/files/" + name);
            return File(bytes, "application/octet-stream");
        }

        // CWE-327: broken hashing
        public static string HashPassword(string password)
        {
            using var md5 = MD5.Create();
            return BitConverter.ToString(md5.ComputeHash(Encoding.UTF8.GetBytes(password)));
        }

        // CWE-338: predictable token
        public static string SessionToken() => new Random().Next().ToString("x8");

        // CWE-79 and CWE-601
        [HttpGet("/greet")]
        public IActionResult Greet(string name, string next)
        {
            Response.Headers["X-Greeting"] = name;
            if (!string.IsNullOrEmpty(next))
            {
                return Redirect(next);
            }
            return Content("<h1>Hello " + name + "</h1>", "text/html");
        }
    }
}
