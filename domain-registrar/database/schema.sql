-- ============================================================
-- DFIR Journal - Domain Registrar Schema
-- WORM enforced: no UPDATE or DELETE on audit/ledger tables
-- ============================================================

PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

-- ============================================================
-- DOMAIN IDENTITY
-- This registrar belongs to exactly one domain
-- ============================================================
CREATE TABLE IF NOT EXISTS DomainIdentity (
    DomainId                TEXT PRIMARY KEY,
    DomainName              TEXT NOT NULL,
    OrgName                 TEXT NOT NULL,
    ContactName             TEXT NOT NULL,
    ContactEmail            TEXT NOT NULL,
    Status                  TEXT NOT NULL DEFAULT 'Unregistered'
                                CHECK(Status IN ('Unregistered','Pending','Active','Suspended','Revoked')),
    MasterRegistrarId       TEXT,
    RegistrationExpiryUtc   TEXT,
    CreatedAt               TEXT NOT NULL DEFAULT (datetime('now','utc')),
    UpdatedAt               TEXT NOT NULL DEFAULT (datetime('now','utc'))
);

-- ============================================================
-- USERS
-- ============================================================
CREATE TABLE IF NOT EXISTS Users (
    UserId          TEXT PRIMARY KEY,
    DisplayName     TEXT NOT NULL,
    Email           TEXT NOT NULL UNIQUE,
    PasswordHash    TEXT NOT NULL,
    BadgeId         TEXT,
    Agency          TEXT,
    Role            TEXT NOT NULL DEFAULT 'Investigator'
                        CHECK(Role IN ('DomainAdmin','Supervisor','Investigator','Analyst','Auditor')),
    Status          TEXT NOT NULL DEFAULT 'Active'
                        CHECK(Status IN ('Active','Suspended','Blacklisted')),
    CreatedAt       TEXT NOT NULL DEFAULT (datetime('now','utc')),
    UpdatedAt       TEXT NOT NULL DEFAULT (datetime('now','utc'))
);

-- ============================================================
-- DEVICES
-- ============================================================
CREATE TABLE IF NOT EXISTS Devices (
    DeviceId            TEXT PRIMARY KEY,
    Hostname            TEXT NOT NULL,
    HardwareFingerprint TEXT,
    TPMAvailable        INTEGER NOT NULL DEFAULT 0,
    Status              TEXT NOT NULL DEFAULT 'Active'
                            CHECK(Status IN ('Active','Suspended','Revoked')),
    RegisteredAt        TEXT NOT NULL DEFAULT (datetime('now','utc')),
    UpdatedAt           TEXT NOT NULL DEFAULT (datetime('now','utc'))
);

-- ============================================================
-- NODES
-- ============================================================
CREATE TABLE IF NOT EXISTS Nodes (
    NodeId                      TEXT PRIMARY KEY,
    DeviceId                    TEXT REFERENCES Devices(DeviceId),
    PrimaryUserId               TEXT REFERENCES Users(UserId),
    NodeName                    TEXT,
    State                       TEXT NOT NULL DEFAULT 'Unregistered'
                                    CHECK(State IN ('Unregistered','Active','Suspended','Revoked')),
    RegistrationExpiryUtc       TEXT,
    LastRegistrationAt          TEXT,
    ReRegistrationIntervalDays  INTEGER NOT NULL DEFAULT 90,
    CreatedAt                   TEXT NOT NULL DEFAULT (datetime('now','utc')),
    UpdatedAt                   TEXT NOT NULL DEFAULT (datetime('now','utc'))
);

-- ============================================================
-- NODE REGISTRATION PACKETS
-- WORM: insert only
-- ============================================================
CREATE TABLE IF NOT EXISTS NodeRegistrationPackets (
    PacketId            TEXT PRIMARY KEY,
    NodeId              TEXT REFERENCES Nodes(NodeId),
    DeviceFingerprint   TEXT,
    Hostname            TEXT,
    TPMInfo             TEXT,
    PublicKeyMaterial   TEXT,
    ProposedNodeName    TEXT,
    ProposedUserId      TEXT,
    PacketType          TEXT NOT NULL DEFAULT 'Registration'
                            CHECK(PacketType IN ('Registration','Renewal')),
    Status              TEXT NOT NULL DEFAULT 'Pending'
                            CHECK(Status IN ('Pending','Approved','Rejected')),
    SubmittedAt         TEXT NOT NULL DEFAULT (datetime('now','utc')),
    ProcessedAt         TEXT,
    ProcessedBy         TEXT REFERENCES Users(UserId),
    DecisionReason      TEXT
);

-- ============================================================
-- ENGAGEMENT CARD METADATA
-- No client content - lifecycle and identity only
-- ============================================================
CREATE TABLE IF NOT EXISTS EngagementCards (
    EngagementCardId    TEXT PRIMARY KEY,
    CardTitle           TEXT NOT NULL,
    CreatingNodeId      TEXT REFERENCES Nodes(NodeId),
    CreatingUserId      TEXT REFERENCES Users(UserId),
    IncidentType        TEXT,
    Severity            TEXT CHECK(Severity IN ('Critical','High','Medium','Low','Informational')),
    LifecycleState      TEXT NOT NULL DEFAULT 'Open'
                            CHECK(LifecycleState IN ('Open','Active','Suspended','Closed','Archived','Cold')),
    CreatedAt           TEXT NOT NULL DEFAULT (datetime('now','utc')),
    UpdatedAt           TEXT NOT NULL DEFAULT (datetime('now','utc'))
);

-- ============================================================
-- ENGAGEMENT CARD NODE LINKS
-- ============================================================
CREATE TABLE IF NOT EXISTS EngagementCardNodeLinks (
    LinkId              TEXT PRIMARY KEY,
    EngagementCardId    TEXT NOT NULL REFERENCES EngagementCards(EngagementCardId),
    NodeId              TEXT NOT NULL REFERENCES Nodes(NodeId),
    RoleOnCard          TEXT NOT NULL DEFAULT 'Contributor'
                            CHECK(RoleOnCard IN ('Owner','Contributor','Viewer')),
    FirstTouchedAt      TEXT NOT NULL DEFAULT (datetime('now','utc')),
    LastTouchedAt       TEXT NOT NULL DEFAULT (datetime('now','utc'))
);

-- ============================================================
-- ENGAGEMENT CARD USER LINKS
-- ============================================================
CREATE TABLE IF NOT EXISTS EngagementCardUserLinks (
    LinkId              TEXT PRIMARY KEY,
    EngagementCardId    TEXT NOT NULL REFERENCES EngagementCards(EngagementCardId),
    UserId              TEXT NOT NULL REFERENCES Users(UserId),
    RoleOnCard          TEXT NOT NULL DEFAULT 'Contributor'
                            CHECK(RoleOnCard IN ('Owner','Contributor','Viewer')),
    FirstTouchedAt      TEXT NOT NULL DEFAULT (datetime('now','utc')),
    LastTouchedAt       TEXT NOT NULL DEFAULT (datetime('now','utc'))
);

-- ============================================================
-- REVOCATION RECORDS
-- WORM: insert only
-- ============================================================
CREATE TABLE IF NOT EXISTS RevocationRecords (
    RevocationId        TEXT PRIMARY KEY,
    TargetType          TEXT NOT NULL CHECK(TargetType IN ('User','Node','Device')),
    TargetId            TEXT NOT NULL,
    Reason              TEXT NOT NULL,
    EffectiveFromUtc    TEXT NOT NULL DEFAULT (datetime('now','utc')),
    IssuedByUserId      TEXT REFERENCES Users(UserId),
    CreatedAt           TEXT NOT NULL DEFAULT (datetime('now','utc'))
);

-- ============================================================
-- AUDIT LOG
-- WORM: insert only - hash chained
-- ============================================================
CREATE TABLE IF NOT EXISTS AuditLog (
    AuditId         TEXT PRIMARY KEY,
    EventType       TEXT NOT NULL,
    ActorId         TEXT NOT NULL,
    ActorType       TEXT NOT NULL CHECK(ActorType IN ('User','System')),
    TargetType      TEXT,
    TargetId        TEXT,
    Description     TEXT NOT NULL,
    PreviousHash    TEXT,
    EntryHash       TEXT NOT NULL,
    CreatedAt       TEXT NOT NULL DEFAULT (datetime('now','utc'))
);

-- ============================================================
-- OUTBOUND BUNDLES
-- Packages exported to Master Registrar - WORM: insert only
-- ============================================================
CREATE TABLE IF NOT EXISTS OutboundBundles (
    BundleId        TEXT PRIMARY KEY,
    BundleType      TEXT NOT NULL CHECK(BundleType IN ('NodeRegistration','EngagementCardMetadata','UsageTelemetry')),
    GeneratedAt     TEXT NOT NULL DEFAULT (datetime('now','utc')),
    PayloadJson     TEXT NOT NULL,
    Signature       TEXT,
    ExportedAt      TEXT,
    ExportedBy      TEXT REFERENCES Users(UserId)
);

-- ============================================================
-- INBOUND REVOCATION BUNDLES
-- Received from Master Registrar - WORM: insert only
-- ============================================================
CREATE TABLE IF NOT EXISTS InboundRevocationBundles (
    BundleId        TEXT PRIMARY KEY,
    BundleVersion   INTEGER NOT NULL,
    ReceivedAt      TEXT NOT NULL DEFAULT (datetime('now','utc')),
    IssuedAtUtc     TEXT NOT NULL,
    PayloadJson     TEXT NOT NULL,
    AppliedAt       TEXT
);
