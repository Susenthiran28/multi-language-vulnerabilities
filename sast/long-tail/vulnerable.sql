-- File:    vulnerable.sql
-- Purpose: SAST fixture (SQL/T-SQL). Shell access via xp_cmdshell, dynamic SQL,
--          over-broad grants, TRUSTWORTHY database.
-- Author:  Vigilnz Security Engineering
-- Date:    2026-10-16
-- Expected rules: sql-xp-cmdshell, sql-openrowset, sql-grant-all,
--   sql-trustworthy, sql-exec, sql-sp-executesql

-- CWE-78: OS command surface enabled on the database
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
EXEC xp_cmdshell 'whoami';

-- CWE-250: database marked TRUSTWORTHY, enabling privilege escalation
ALTER DATABASE AppDb SET TRUSTWORTHY ON;

-- CWE-732: over-broad grant
GRANT ALL PRIVILEGES ON AppDb.* TO 'app_user'@'%';

-- CWE-89: dynamic SQL concatenated from a parameter
CREATE PROCEDURE dbo.FindUser
    @Email NVARCHAR(256)
AS
BEGIN
    DECLARE @sql NVARCHAR(MAX);
    SET @sql = 'SELECT Id, Email FROM Users WHERE Email = ''' + @Email + '''';
    EXEC(@sql);
    EXEC sp_executesql @sql;
END;
GO

-- CWE-611 / CWE-918: ad-hoc remote data access
SELECT *
FROM OPENROWSET('SQLNCLI', 'Server=remote;Trusted_Connection=yes;',
                'SELECT * FROM Secrets');
