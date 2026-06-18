using Microsoft.Data.Sqlite;
using System;
using System.IO;
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
            using var conn = GetConnection();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = GetSchema();
            cmd.ExecuteNonQuery();

            // Create default local admin if none exists
            using var check = conn.CreateCommand();
            check.CommandText = "SELECT COUNT(*) FROM Users";
            var count = (long)(check.ExecuteScalar() ?? 0L);
            if (count == 0)
            {
                var uid = Guid.NewGuid().ToString();
                var hash = Convert.ToHexString(
                    SHA256.HashData(Encoding.UTF8.GetBytes("admin")));
                var now = DateTime.UtcNow.ToString("o");
                using var insert = conn.CreateCommand();
                insert.CommandText = @"
            INSERT INTO Users (UserId, DisplayName, Email, PasswordHash, Role, CreatedAt, UpdatedAt)
            VALUES ($id, 'Local Admin', 'admin@node.local', $hash, 'DomainAdmin', $now, $now)";
                insert.Parameters.AddWithValue("$id", uid);
                insert.Parameters.AddWithValue("$hash", hash);
                insert.Parameters.AddWithValue("$now", now);
                insert.ExecuteNonQuery();
            }
        }

        private static string GetSchema() => @"
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS NodeIdentity (
    NodeId                      TEXT PRIMARY KEY,
    NodeName                    TEXT NOT NULL,
    DeviceFingerprint           TEXT NOT NULL,
    TPMAvailable                INTEGER NOT NULL DEFAULT 0,
    PublicKey                   TEXT,
    PrivateKeyRef               TEXT,
    State                       TEXT NOT NULL DEFAULT 'Unregistered',
    DomainId                    TEXT,
    DomainName                  TEXT,
    RegistrationExpiryUtc       TEXT,
    LastRegistrationAt          TEXT,
    ReRegistrationIntervalDays  INTEGER NOT NULL DEFAULT 90,
    CreatedAt                   TEXT NOT NULL DEFAULT (datetime('now','utc')),
    UpdatedAt                   TEXT NOT NULL DEFAULT (datetime('now','utc'))
);

CREATE TABLE IF NOT EXISTS Users (
    UserId          TEXT PRIMARY KEY,
    DisplayName     TEXT NOT NULL,
    Email           TEXT NOT NULL UNIQUE,
    PasswordHash    TEXT NOT NULL,
    BadgeId         TEXT,
    Agency          TEXT,
    Role            TEXT NOT NULL DEFAULT 'Investigator',
    Status          TEXT NOT NULL DEFAULT 'Active',
    CreatedAt       TEXT NOT NULL DEFAULT (datetime('now','utc')),
    UpdatedAt       TEXT NOT NULL DEFAULT (datetime('now','utc'))
);

CREATE TABLE IF NOT EXISTS EngagementCards (
    EngagementCardId    TEXT PRIMARY KEY,
    CardTitle           TEXT NOT NULL,
    ClientName          TEXT,
    IncidentType        TEXT,
    Severity            TEXT NOT NULL DEFAULT 'Medium',
    LifecycleState      TEXT NOT NULL DEFAULT 'Open',
    CreatingUserId      TEXT REFERENCES Users(UserId),
    AssignedLeadId      TEXT REFERENCES Users(UserId),
    EngagementStartUtc  TEXT,
    EngagementEndUtc    TEXT,
    ClientContact       TEXT,
    ClientEmail         TEXT,
    ExecutiveSummary    TEXT,
    CreatedAt           TEXT NOT NULL DEFAULT (datetime('now','utc')),
    UpdatedAt           TEXT NOT NULL DEFAULT (datetime('now','utc'))
);

CREATE TABLE IF NOT EXISTS JournalEntries (
    EntryId             TEXT PRIMARY KEY,
    EngagementCardId    TEXT NOT NULL REFERENCES EngagementCards(EngagementCardId),
    AuthorId            TEXT NOT NULL REFERENCES Users(UserId),
    NodeId              TEXT NOT NULL,
    EntryType           TEXT NOT NULL DEFAULT 'Observation',
    EpistemicState      TEXT NOT NULL DEFAULT 'Observation',
    Title               TEXT,
    Content             TEXT NOT NULL,
    Confidence          TEXT DEFAULT 'Medium',
    IsRedacted          INTEGER NOT NULL DEFAULT 0,
    PreviousHash        TEXT,
    EntryHash           TEXT NOT NULL,
    Signature           TEXT,
    TimestampUtc        TEXT NOT NULL DEFAULT (datetime('now','utc')),
    CreatedAt           TEXT NOT NULL DEFAULT (datetime('now','utc'))
);

CREATE TABLE IF NOT EXISTS EvidenceItems (
    EvidenceId          TEXT PRIMARY KEY,
    EngagementCardId    TEXT NOT NULL REFERENCES EngagementCards(EngagementCardId),
    EntryId             TEXT REFERENCES JournalEntries(EntryId),
    CollectedByUserId   TEXT REFERENCES Users(UserId),
    EvidenceType        TEXT NOT NULL DEFAULT 'File',
    FileName            TEXT,
    FilePath            TEXT,
    FileHash            TEXT,
    HashAlgorithm       TEXT DEFAULT 'SHA256',
    Description         TEXT,
    ChainOfCustody      TEXT,
    CollectedAtUtc      TEXT NOT NULL DEFAULT (datetime('now','utc')),
    CreatedAt           TEXT NOT NULL DEFAULT (datetime('now','utc'))
);

CREATE TABLE IF NOT EXISTS IOCItems (
    IOCId               TEXT PRIMARY KEY,
    EngagementCardId    TEXT NOT NULL REFERENCES EngagementCards(EngagementCardId),
    EntryId             TEXT REFERENCES JournalEntries(EntryId),
    AddedByUserId       TEXT REFERENCES Users(UserId),
    IOCType             TEXT NOT NULL DEFAULT 'Other',
    Value               TEXT NOT NULL,
    Context             TEXT,
    Confidence          TEXT DEFAULT 'Medium',
    Status              TEXT NOT NULL DEFAULT 'Active',
    CreatedAt           TEXT NOT NULL DEFAULT (datetime('now','utc')),
    UpdatedAt           TEXT NOT NULL DEFAULT (datetime('now','utc'))
);

CREATE TABLE IF NOT EXISTS TimelineEvents (
    TimelineEventId     TEXT PRIMARY KEY,
    EngagementCardId    TEXT NOT NULL REFERENCES EngagementCards(EngagementCardId),
    EntryId             TEXT REFERENCES JournalEntries(EntryId),
    AddedByUserId       TEXT REFERENCES Users(UserId),
    EventType           TEXT NOT NULL DEFAULT 'Other',
    EventTitle          TEXT NOT NULL,
    EventDescription    TEXT,
    EventTimestampUtc   TEXT NOT NULL,
    Source              TEXT,
    MITRETactic         TEXT,
    MITRETechnique      TEXT,
    Confidence          TEXT DEFAULT 'Medium',
    CreatedAt           TEXT NOT NULL DEFAULT (datetime('now','utc'))
);

CREATE TABLE IF NOT EXISTS AuditLog (
    AuditId         TEXT PRIMARY KEY,
    EventType       TEXT NOT NULL,
    ActorId         TEXT NOT NULL,
    ActorType       TEXT NOT NULL,
    TargetType      TEXT,
    TargetId        TEXT,
    Description     TEXT NOT NULL,
    PreviousHash    TEXT,
    EntryHash       TEXT NOT NULL,
    CreatedAt       TEXT NOT NULL DEFAULT (datetime('now','utc'))
);

CREATE TABLE IF NOT EXISTS RegistrationPackets (
    PacketId        TEXT PRIMARY KEY,
    PacketType      TEXT NOT NULL DEFAULT 'Registration',
    PayloadJson     TEXT NOT NULL,
    GeneratedAt     TEXT NOT NULL DEFAULT (datetime('now','utc')),
    ExportedAt      TEXT,
    Status          TEXT NOT NULL DEFAULT 'Pending'
);

CREATE TABLE IF NOT EXISTS InboundResponses (
    ResponseId      TEXT PRIMARY KEY,
    ResponseType    TEXT NOT NULL,
    PayloadJson     TEXT NOT NULL,
    ReceivedAt      TEXT NOT NULL DEFAULT (datetime('now','utc')),
    AppliedAt       TEXT,
    AppliedBy       TEXT REFERENCES Users(UserId)
);

CREATE TABLE IF NOT EXISTS RevocationCache (
    RevocationId        TEXT PRIMARY KEY,
    TargetType          TEXT NOT NULL,
    TargetId            TEXT NOT NULL,
    Reason              TEXT,
    EffectiveFromUtc    TEXT NOT NULL,
    ReceivedAt          TEXT NOT NULL DEFAULT (datetime('now','utc'))
);
";

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