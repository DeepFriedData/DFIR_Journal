using DFIRNode.Models;
using Microsoft.Data.Sqlite;
using System;
using System.IO;
using System.Net.NetworkInformation;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace DFIRNode.Services
{
    public class RegistrationService
    {
        private readonly DatabaseService _db;

        public RegistrationService(DatabaseService db)
        {
            _db = db;
        }

        // ── DEVICE FINGERPRINT ───────────────────────────────
        public string GetDeviceFingerprint()
        {
            var sb = new StringBuilder();
            sb.Append(Environment.MachineName);
            sb.Append(Environment.ProcessorCount);
            sb.Append(Environment.OSVersion.ToString());

            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                    sb.Append(nic.GetPhysicalAddress().ToString());
            }

            var raw = sb.ToString();
            return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(raw)));
        }

        // ── NODE IDENTITY ────────────────────────────────────
        public NodeIdentity? GetNodeIdentity()
        {
            using var conn = _db.GetConnection();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT * FROM NodeIdentity LIMIT 1";
            using var reader = cmd.ExecuteReader();
            if (!reader.Read()) return null;

            return new NodeIdentity
            {
                NodeId = reader["NodeId"].ToString()!,
                NodeName = reader["NodeName"].ToString()!,
                DeviceFingerprint = reader["DeviceFingerprint"].ToString()!,
                State = reader["State"].ToString()!,
                DomainId = reader["DomainId"]?.ToString(),
                DomainName = reader["DomainName"]?.ToString(),
                RegistrationExpiryUtc = reader["RegistrationExpiryUtc"]?.ToString(),
                CreatedAt = reader["CreatedAt"].ToString()!
            };
        }

        // ── INITIALIZE NODE ──────────────────────────────────
        public NodeIdentity InitializeNode(string nodeName)
        {
            var nodeId = Guid.NewGuid().ToString();
            var fingerprint = GetDeviceFingerprint();
            var now = DateTime.UtcNow.ToString("o");

            using var conn = _db.GetConnection();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = @"
                INSERT INTO NodeIdentity
                    (NodeId, NodeName, DeviceFingerprint, State, CreatedAt, UpdatedAt)
                VALUES ($id, $name, $fp, 'Unregistered', $now, $now)";
            cmd.Parameters.AddWithValue("$id", nodeId);
            cmd.Parameters.AddWithValue("$name", nodeName);
            cmd.Parameters.AddWithValue("$fp", fingerprint);
            cmd.Parameters.AddWithValue("$now", now);
            cmd.ExecuteNonQuery();

            _db.WriteAudit("NODE_INITIALIZED", "system", "System",
                           "NodeIdentity", nodeId, $"Node initialized: {nodeName}");

            return new NodeIdentity
            {
                NodeId = nodeId,
                NodeName = nodeName,
                DeviceFingerprint = fingerprint,
                State = "Unregistered",
                CreatedAt = now
            };
        }

        // ── GENERATE REGISTRATION PACKET ─────────────────────
        public RegistrationPacket GenerateRegistrationPacket(
            NodeIdentity node, string proposedUserName, string proposedUserEmail)
        {
            var packetId = Guid.NewGuid().ToString();
            var now = DateTime.UtcNow.ToString("o");

            var payload = new
            {
                PacketId = packetId,
                PacketType = "Registration",
                NodeId = node.NodeId,
                NodeName = node.NodeName,
                DeviceFingerprint = node.DeviceFingerprint,
                Hostname = Environment.MachineName,
                OSVersion = Environment.OSVersion.ToString(),
                ProposedUserName = proposedUserName,
                ProposedUserEmail = proposedUserEmail,
                GeneratedAt = now,
                RegistrarTarget = "DomainRegistrar"
            };

            var payloadJson = JsonSerializer.Serialize(payload,
                new JsonSerializerOptions { WriteIndented = true });

            using var conn = _db.GetConnection();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = @"
                INSERT INTO RegistrationPackets
                    (PacketId, PacketType, PayloadJson, GeneratedAt, Status)
                VALUES ($id, 'Registration', $payload, $now, 'Pending')";
            cmd.Parameters.AddWithValue("$id", packetId);
            cmd.Parameters.AddWithValue("$payload", payloadJson);
            cmd.Parameters.AddWithValue("$now", now);
            cmd.ExecuteNonQuery();

            // Update node state to Pending
            using var cmd2 = conn.CreateCommand();
            cmd2.CommandText =
                "UPDATE NodeIdentity SET State='Pending', UpdatedAt=$now WHERE NodeId=$id";
            cmd2.Parameters.AddWithValue("$now", now);
            cmd2.Parameters.AddWithValue("$id", node.NodeId);
            cmd2.ExecuteNonQuery();

            _db.WriteAudit("PACKET_GENERATED", "system", "System",
                           "RegistrationPacket", packetId, "Registration packet generated");

            return new RegistrationPacket
            {
                PacketId = packetId,
                PayloadJson = payloadJson,
                GeneratedAt = now
            };
        }

        // ── EXPORT PACKET TO FILE ─────────────────────────────
        public void ExportPacketToFile(RegistrationPacket packet, string filePath)
        {
            File.WriteAllText(filePath, packet.PayloadJson);

            var now = DateTime.UtcNow.ToString("o");
            using var conn = _db.GetConnection();
            using var cmd = conn.CreateCommand();
            cmd.CommandText =
                "UPDATE RegistrationPackets SET Status='Exported', ExportedAt=$now WHERE PacketId=$id";
            cmd.Parameters.AddWithValue("$now", now);
            cmd.Parameters.AddWithValue("$id", packet.PacketId);
            cmd.ExecuteNonQuery();

            _db.WriteAudit("PACKET_EXPORTED", "system", "System",
                           "RegistrationPacket", packet.PacketId,
                           $"Packet exported to: {filePath}");
        }

        // ── IMPORT REGISTRATION RESPONSE ─────────────────────
        public bool ImportRegistrationResponse(string filePath, string importedByUserId)
        {
            if (!File.Exists(filePath)) return false;

            var json = File.ReadAllText(filePath);
            var now = DateTime.UtcNow.ToString("o");
            var responseId = Guid.NewGuid().ToString();

            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            var nodeId = root.GetProperty("NodeId").GetString() ?? "";
            var domainId = root.GetProperty("DomainId").GetString() ?? "";
            var domainName = root.GetProperty("DomainName").GetString() ?? "";
            var expiry = root.GetProperty("ExpiryUtc").GetString() ?? "";

            using var conn = _db.GetConnection();

            // Store inbound response
            using var cmd1 = conn.CreateCommand();
            cmd1.CommandText = @"
    INSERT INTO InboundResponses
        (ResponseId, ResponseType, PayloadJson, ReceivedAt, AppliedAt, AppliedBy)
    VALUES ($id, 'RegistrationResponse', $payload, $now, $now, NULL)";
            cmd1.Parameters.AddWithValue("$id", responseId);
            cmd1.Parameters.AddWithValue("$payload", json);
            cmd1.Parameters.AddWithValue("$now", now);
            cmd1.ExecuteNonQuery();

            // Activate node
            using var cmd2 = conn.CreateCommand();
            cmd2.CommandText = @"
                UPDATE NodeIdentity SET
                    State='Active',
                    DomainId=$domainId,
                    DomainName=$domainName,
                    RegistrationExpiryUtc=$expiry,
                    LastRegistrationAt=$now,
                    UpdatedAt=$now
                WHERE NodeId=$nodeId";
            cmd2.Parameters.AddWithValue("$domainId", domainId);
            cmd2.Parameters.AddWithValue("$domainName", domainName);
            cmd2.Parameters.AddWithValue("$expiry", expiry);
            cmd2.Parameters.AddWithValue("$now", now);
            cmd2.Parameters.AddWithValue("$nodeId", nodeId);
            cmd2.ExecuteNonQuery();

            _db.WriteAudit("NODE_ACTIVATED", importedByUserId, "User",
                           "NodeIdentity", nodeId,
                           $"Registration response imported. Domain: {domainName}");

            return true;
        }
    }
}