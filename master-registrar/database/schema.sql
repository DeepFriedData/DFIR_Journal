-- ============================================================
-- DFIR Journal - Master Registrar Schema
-- WORM enforced: no UPDATE or DELETE on audit/ledger tables
-- ============================================================

PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

-- ============================================================
-- DOMAINS
-- Each domain = one corporate/org entity
-- ============================================================
CREATE TABLE IF NOT EXISTS Domains (
    DomainId        TEXT PRIMARY KEY,
    DomainName      TEXT NOT NULL UNIQUE,
    OrgName         TEXT NOT NULL,
    ContactName     TEXT NOT NULL,
    ContactEmail    TEXT NOT NULL,
    Status          TEXT NOT NULL DEFAULT 'Pending'
                        CHECK(Status IN ('Pending','Active','Suspended','Revoked')),
    DomainPublicKey TEXT,
    CreatedAt       TEXT NOT NULL DEFAULT (datetime('now','utc')),
    UpdatedAt       TEXT NOT NULL DEFAULT (datetime('now','utc'))
);

-- ============================================================
-- MASTER USERS
-- Only master-level identities live here
-- ============================================================
CREATE TABLE IF NOT EXISTS MasterUsers (
    MasterUserId    TEXT PRIMARY KEY,
    DisplayName     TEXT NOT NULL,
    Email           TEXT NOT NULL UNIQUE,
    PasswordHash    TEXT NOT NULL,
    Role            TEXT NOT NULL DEFAULT 'MasterAdmin'
                        CHECK(Role IN ('MasterAdmin','Auditor')),
    Status          TEXT NOT NULL DEFAULT 'Active'
                        CHECK(Status IN ('Active','Suspended','Revoked')),
    CreatedAt       TEXT NOT NULL DEFAULT (datetime('now','utc')),
    UpdatedAt       TEXT NOT NULL DEFAULT (datetime('now','utc'))
);

-- ============================================================
-- DOMAIN REGISTRATION PACKETS
-- Submitted by Domain Registrar instances seeking approval
-- WORM: insert only
-- ============================================================
CREATE TABLE IF NOT EXISTS DomainRegistrationPackets (
    PacketId            TEXT PRIMARY KEY,
    DomainId            TEXT REFERENCES Domains(DomainId),
    SubmittedAt         TEXT NOT NULL DEFAULT (datetime('now','utc')),
    DeviceFingerprint   TEXT,
    PublicKeyMaterial   TEXT,
    ProposedDomainName  TEXT NOT NULL,
    ProposedOrgName     TEXT NOT NULL,
    ProposedContact     TEXT NOT NULL,
    Status              TEXT NOT NULL DEFAULT 'Pending'
                            CHECK(Status IN ('Pending','Approved','Rejected')),
    ProcessedAt         TEXT,
    ProcessedBy         TEXT REFERENCES MasterUsers(MasterUserId),
    DecisionReason      TEXT
);

-- ============================================================
-- REVOCATION RECORDS
-- WORM: insert only - no updates, no deletes
-- ============================================================
CREATE TABLE IF NOT EXISTS RevocationRecords (
    RevocationId        TEXT PRIMARY KEY,
    TargetType          TEXT NOT NULL CHECK(TargetType IN ('Domain','MasterUser')),
    TargetId            TEXT NOT NULL,
    Reason              TEXT NOT NULL,
    EffectiveFromUtc    TEXT NOT NULL DEFAULT (datetime('now','utc')),
    IssuedByUserId      TEXT REFERENCES MasterUsers(MasterUserId),
    CreatedAt           TEXT NOT NULL DEFAULT (datetime('now','utc'))
);

-- ============================================================
-- AUDIT LOG
-- WORM: insert only - cryptographic hash chain
-- ============================================================
CREATE TABLE IF NOT EXISTS AuditLog (
    AuditId         TEXT PRIMARY KEY,
    EventType       TEXT NOT NULL,
    ActorId         TEXT NOT NULL,
    ActorType       TEXT NOT NULL CHECK(ActorType IN ('MasterUser','System')),
    TargetType      TEXT,
    TargetId        TEXT,
    Description     TEXT NOT NULL,
    PreviousHash    TEXT,
    EntryHash       TEXT NOT NULL,
    CreatedAt       TEXT NOT NULL DEFAULT (datetime('now','utc'))
);

-- ============================================================
-- REGISTRATION RESPONSES
-- Issued by master registrar to approved domains
-- WORM: insert only
-- ============================================================
CREATE TABLE IF NOT EXISTS RegistrationResponses (
    ResponseId          TEXT PRIMARY KEY,
    PacketId            TEXT NOT NULL REFERENCES DomainRegistrationPackets(PacketId),
    DomainId            TEXT NOT NULL REFERENCES Domains(DomainId),
    IssuedAt            TEXT NOT NULL DEFAULT (datetime('now','utc')),
    ExpiryUtc           TEXT NOT NULL,
    PolicyJson          TEXT NOT NULL,
    SignedToken         TEXT NOT NULL,
    IssuedByUserId      TEXT REFERENCES MasterUsers(MasterUserId)
);

-- ============================================================
-- REVOCATION BUNDLES
-- Exported bundles sent to domain registrars
-- WORM: insert only
-- ============================================================
CREATE TABLE IF NOT EXISTS RevocationBundles (
    BundleId        TEXT PRIMARY KEY,
    BundleVersion   INTEGER NOT NULL,
    IssuedAtUtc     TEXT NOT NULL DEFAULT (datetime('now','utc')),
    IssuedBy        TEXT REFERENCES MasterUsers(MasterUserId),
    PayloadJson     TEXT NOT NULL,
    Signature       TEXT NOT NULL
);
