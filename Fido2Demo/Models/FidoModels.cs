using Fido2NetLib;

namespace Fido2Demo.Models
{
    public class FidoModels
    {
    }

    public class RegisterRequest
    {
        public string Username { get; set; }
    }

    public class LoginRequest
    {
        public string Username { get; set; }
    }

    public class StoredCredential
    {
        public byte[] DescriptorId { get; set; }
        public byte[] PublicKey { get; set; }
        public uint SignCount { get; set; }
        public byte[] UserHandle { get; set; }
        public string Username { get; set; }
    }

    public class LoginRequestDto
    {
        public string Username { get; set; }
        public AuthenticatorAssertionRawResponse Assertion { get; set; }
    }
}
