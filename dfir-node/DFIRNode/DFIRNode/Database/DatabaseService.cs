using Microsoft.Data.Sqlite;
using System;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;

namespace DFIRNode.Services
{
    public class DatabaseService
    {
        private readonly string _dbPath;
        private readonly string _connectionString;

        public DatabaseService()
        {
            var appData = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "DFIRNode");
            Directory.CreateDirectory(appData);
            _dbPath = Path.Combine(appData, "node.db");
            _connectionString = $"Data Source={_dbPath}";
        }

        public SqliteConnection GetConnection()
        {
            var conn = new SqliteConnection(_connectionString);
            conn.Open();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL;";
            cmd.ExecuteNonQuery();
            return conn;
        }

        public void InitializeDatabase()
        {
            var schemaPath = Path.Combine(
                AppDomain.CurrentDomain.BaseDirectory,
                "Database", "schema.sql");

            if (!File.Exists(schemaPath))
                throw new FileNotFoundException($"Schema not found: {schemaPath}");

            var sql = File.ReadAllText(schemaPath);
            using var conn = GetConnection();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = sql;
            cmd.ExecuteNonQuery();
        }

        // ── AUDIT ────────────────────────────────────────────
        public void WriteAudit(string eventType, string actorId, string actorType,
                               string targetType, string targetId, string description)
        {
            using var conn = GetConnection();
            var auditId = Guid.NewGuid().ToString();
            var now = DateTime.UtcNow.ToString("o");

            string previousHash = "GENESIS";
            using (var qCmd = conn.CreateCommand())
            {
                qCmd.CommandText =
                    "SELECT EntryHash FROM AuditLog ORDER BY CreatedAt DESC LIMIT 1";
                var result = qCmd.ExecuteScalar();
                if (result != null) previousHash = result.ToString()!;
            }

            var raw = $"{previousHash}|{eventType}|{actorId}|{targetId}|{description}|{now}";
            var entryHash = Convert.ToHexString(
                SHA256.HashData(Encoding.UTF8.GetBytes(raw)));

            using var cmd = conn.CreateCommand();
            cmd.CommandText = @"
                INSERT INTO AuditLog
                    (AuditId, EventType, ActorId, ActorType, TargetType,
                     TargetId, Description, PreviousHash, EntryHash, CreatedAt)
                VALUES
                    ($id, $et, $actor, $atype, $ttype,
                     $tid, $desc, $prev, $hash, $now)";
            cmd.Parameters.AddWithValue("$id", auditId);
            cmd.Parameters.AddWithValue("$et", eventType);
            cmd.Parameters.AddWithValue("$actor", actorId);
            cmd.Parameters.AddWithValue("$atype", actorType);
            cmd.Parameters.AddWithValue("$ttype", targetType ?? "");
            cmd.Parameters.AddWithValue("$tid", targetId ?? "");
            cmd.Parameters.AddWithValue("$desc", description);
            cmd.Parameters.AddWithValue("$prev", previousHash);
            cmd.Parameters.AddWithValue("$hash", entryHash);
            cmd.Parameters.AddWithValue("$now", now);
            cmd.ExecuteNonQuery();
        }
    }
}