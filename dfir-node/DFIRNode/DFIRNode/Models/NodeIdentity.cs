namespace DFIRNode.Models
{
    public class NodeIdentity
    {
        public string NodeId { get; set; } = "";
        public string NodeName { get; set; } = "";
        public string DeviceFingerprint { get; set; } = "";
        public string State { get; set; } = "Unregistered";
        public string? DomainId { get; set; }
        public string? DomainName { get; set; }
        public string? RegistrationExpiryUtc { get; set; }
        public string CreatedAt { get; set; } = "";
    }

    public class RegistrationPacket
    {
        public string PacketId { get; set; } = "";
        public string PayloadJson { get; set; } = "";
        public string GeneratedAt { get; set; } = "";
    }
}