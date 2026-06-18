-- ============================================================
-- DFIR Journal Node - Local Schema
-- WORM enforced: no UPDATE or DELETE on ledger tables
-- ============================================================

PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

-- ============================================================
-- NODE IDENTITY
-- Exactly one row - this node's cryptographic identity
-- ============================================================
CREATE TABLE IF NOT EXISTS NodeIdentity (
    NodeId                      TEXT PRIMARY KEY,
    NodeName                    TEXT NOT NULL,
    DeviceFingerprint           TEXT NOT NULL,
    TPMAvailable                INTEGER NOT NULL DEFAULT 0,
    PublicKey                   TEXT,
    PrivateKeyRef               TEXT,
    State                       TEXT NOT NULL DEFAULT 'Unregistered'
                                    CHECK(State IN ('Unregistered','Pending','Active',
                                                    'Expired','Suspended','Revoked')),
    DomainId                    TEXT,
    DomainName                  TEXT,
    RegistrationExpiryUtc       TEXT,
    LastRegistrationAt          TEXT,
    ReRegistrationIntervalDays  INTEGER NOT NULL DEFAULT 90,
    CreatedAt                   TEXT NOT NULL DEFAULT (datetime('now','utc')),
    UpdatedAt                   TEXT NOT NULL DEFAULT (datetime('now','utc'))
);

-- ============================================================
-- USERS
-- Investigators bound to this node
-- ============================================================
CREATE TABLE IF NOT EXISTS Users (
    UserId          TEXT PRIMARY KEY,
    DisplayName     TEXT NOT NULL,
    Email           TEXT NOT NULL UNIQUE,
    PasswordHash    TEXT NOT NULL,
    BadgeId         TEXT,
    Agency          TEXT,
    Role            TEXT NOT NULL DEFAULT 'Investigator'
                        CHECK(Role IN ('DomainAdmin','Supervisor','Investigator',
                                       'Analyst','Auditor')),
    Status          TEXT NOT NULL DEFAULT 'Active'
                        CHECK(Status IN ('Active','Suspended','Revoked')),
    CreatedAt       TEXT NOT NULL DEFAULT (datetime('now','utc')),
    UpdatedAt       TEXT NOT NULL DEFAULT (datetime('now','utc'))
);

-- ============================================================
-- ENGAGEMENT CARDS
-- Compound forensic case containers
-- ============================================================
CREATE TABLE IF NOT EXISTS EngagementCards (
    EngagementCardId    TEXT PRIMARY KEY,
    CardTitle           TEXT NOT NULL,
    ClientName          TEXT,
    IncidentType        TEXT,
    Severity            TEXT NOT NULL DEFAULT 'Medium'
                            CHECK(Severity IN ('Critical','High','Medium','Low','Informational')),
    LifecycleState      TEXT NOT NULL DEFAULT 'Open'
                            CHECK(LifecycleState IN ('Open','Active','Suspended',
                                                      'Closed','Archived','Cold')),
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

-- ============================================================
-- JOURNAL ENTRIES
-- WORM: insert only - hash chained - core ledger
-- ============================================================
CREATE TABLE IF NOT EXISTS JournalEntries (
    EntryId             TEXT PRIMARY KEY,
    EngagementCardId    TEXT NOT NULL REFERENCES EngagementCards(EngagementCardId),
    AuthorId            TEXT NOT NULL REFERENCES Users(UserId),
    NodeId              TEXT NOT NULL,
    EntryType           TEXT NOT NULL
                            CHECK(EntryType IN ('Observation','Action','Hypothesis',
                                                'Finding','Decision','ClientInteraction',
                                                'EvidenceNote','StatusUpdate','Note')),
    EpistemicState      TEXT NOT NULL DEFAULT 'Observation'
                            CHECK(EpistemicState IN ('Observation','Hypothesis',
                                                      'Supported','Refuted','Confirmed')),
    Title               TEXT,
    Content             TEXT NOT NULL,
    Confidence          TEXT DEFAULT 'Medium'
                            CHECK(Confidence IN ('High','Medium','Low','Unknown')),
    IsRedacted          INTEGER NOT NULL DEFAULT 0,
    PreviousHash        TEXT,
    EntryHash           TEXT NOT NULL,
    Signature           TEXT,
    TimestampUtc        TEXT NOT NULL DEFAULT (datetime('now','utc')),
    CreatedAt           TEXT NOT NULL DEFAULT (datetime('now','utc'))
);

-- ============================================================
-- EVIDENCE ITEMS
-- Artifacts attached to journal entries
-- ============================================================
CREATE TABLE IF NOT EXISTS EvidenceItems (
    EvidenceId          TEXT PRIMARY KEY,
    EngagementCardId    TEXT NOT NULL REFERENCES EngagementCards(EngagementCardId),
    EntryId             TEXT REFERENCES JournalEntries(EntryId),
    CollectedByUserId   TEXT REFERENCES Users(UserId),
    EvidenceType        TEXT NOT NULL
                            CHECK(EvidenceType IN ('File','Hash','Screenshot','Log',
                                                    'NetworkCapture','MemoryDump',
                                                    'Artifact','Note','Other')),
    FileName            TEXT,
    FilePath            TEXT,
    FileHash            TEXT,
    HashAlgorithm       TEXT DEFAULT 'SHA256',
    Description         TEXT,
    ChainOfCustody      TEXT,
    CollectedAtUtc      TEXT NOT NULL DEFAULT (datetime('now','utc')),
    CreatedAt           TEXT NOT NULL DEFAULT (datetime('now','utc'))
);

-- ============================================================
-- IOC TRACKING
-- Indicators of Compromise linked to engagements
-- ============================================================
CREATE TABLE IF NOT EXISTS IOCItems (
    IOCId               TEXT PRIMARY KEY,
    EngagementCardId    TEXT NOT NULL REFERENCES EngagementCards(EngagementCardId),
    EntryId             TEXT REFERENCES JournalEntries(EntryId),
    AddedByUserId       TEXT REFERENCES Users(UserId),
    IOCType             TEXT NOT NULL
                            CHECK(IOCType IN ('IPAddress','Domain','URL','Hash',
                                              'Email','Username','FilePath',
                                              'RegistryKey','Other')),
    Value               TEXT NOT NULL,
    Context             TEXT,
    Confidence          TEXT DEFAULT 'Medium'
                            CHECK(Confidence IN ('High','Medium','Low','Unknown')),
    Status              TEXT NOT NULL DEFAULT 'Active'
                            CHECK(Status IN ('Active','Mitigated','FalsePositive','Archived')),
    CreatedAt           TEXT NOT NULL DEFAULT (datetime('now','utc')),
    UpdatedAt           TEXT NOT NULL DEFAULT (datetime('now','utc'))
);

-- ============================================================
-- TIMELINE EVENTS
-- Reconstructed incident timeline
-- ============================================================
CREATE TABLE IF NOT EXISTS TimelineEvents (
    TimelineEventId     TEXT PRIMARY KEY,
    EngagementCardId    TEXT NOT NULL REFERENCES EngagementCards(EngagementCardId),
    EntryId             TEXT REFERENCES JournalEntries(EntryId),
    AddedByUserId       TEXT REFERENCES Users(UserId),
    EventType           TEXT NOT NULL
                            CHECK(EventType IN ('InitialAccess','Execution','Persistence',
                                                'PrivilegeEscalation','DefenseEvasion',
                                                'CredentialAccess','Discovery','LateralMovement',
                                                'Collection','Exfiltration','Impact','Other')),
    EventTitle          TEXT NOT NULL,
    EventDescription    TEXT,
    EventTimestampUtc   TEXT NOT NULL,
    Source              TEXT,
    MITRETactic         TEXT,
    MITRETechnique      TEXT,
    Confidence          TEXT DEFAULT 'Medium',
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
-- REGISTRATION PACKETS
-- Outbound packets to Domain Registrar - WORM: insert only
-- ============================================================
CREATE TABLE IF NOT EXISTS RegistrationPackets (
    PacketId        TEXT PRIMARY KEY,
    PacketType      TEXT NOT NULL DEFAULT 'Registration'
                        CHECK(PacketType IN ('Registration','Renewal')),
    PayloadJson     TEXT NOT NULL,
    GeneratedAt     TEXT NOT NULL DEFAULT (datetime('now','utc')),
    ExportedAt      TEXT,
    Status          TEXT NOT NULL DEFAULT 'Pending'
                        CHECK(Status IN ('Pending','Exported','Accepted','Rejected'))
);

-- ============================================================
-- INBOUND RESPONSES
-- Registration responses from Domain Registrar - WORM: insert only
-- ============================================================
CREATE TABLE IF NOT EXISTS InboundResponses (
    ResponseId      TEXT PRIMARY KEY,
    ResponseType    TEXT NOT NULL
                        CHECK(ResponseType IN ('RegistrationResponse','RevocationBundle')),
    PayloadJson     TEXT NOT NULL,
    ReceivedAt      TEXT NOT NULL DEFAULT (datetime('now','utc')),
    AppliedAt       TEXT,
    AppliedBy       TEXT REFERENCES Users(UserId)
);

-- ============================================================
-- REVOCATION CACHE
-- Known revoked nodes/users from Domain Registrar
-- ============================================================
CREATE TABLE IF NOT EXISTS RevocationCache (
    RevocationId        TEXT PRIMARY KEY,
    TargetType          TEXT NOT NULL CHECK(TargetType IN ('User','Node','Device')),
    TargetId            TEXT NOT NULL,
    Reason              TEXT,
    EffectiveFromUtc    TEXT NOT NULL,
    ReceivedAt          TEXT NOT NULL DEFAULT (datetime('now','utc'))
);