using Fido2NetLib;
using Fido2NetLib.Objects;
using Microsoft.Data.SqlClient;

namespace Fido2Demo.Service.Common
{
    public class Utils
    {
        private readonly string _connectionString;

        // IConfiguration is automatically provided by the dependency injection container
        public Utils(IConfiguration config)
        { 
            _connectionString = config.GetConnectionString("DefaultConnection");
        }

        private byte[] _currentUserHandle;
        public byte[] Base64UrlDecode(string input)
        {
            input = input.Replace('-', '+').Replace('_', '/');

            switch (input.Length % 4)
            {
                case 2: input += "=="; break;
                case 3: input += "="; break;
            }

            return Convert.FromBase64String(input);
        } 
        public Task<bool> IsUserHandleOwnerOfCredential(
    IsUserHandleOwnerOfCredentialIdParams args,
    CancellationToken cancellationToken)
        {
            // If no userHandle provided by authenticator → allow (standard behavior)
            if (args?.UserHandle == null || args.UserHandle.Length == 0)
                return Task.FromResult(true);

            if (_currentUserHandle == null || _currentUserHandle.Length == 0)
                return Task.FromResult(true);

            return Task.FromResult(
                args.UserHandle.SequenceEqual(_currentUserHandle)
            );
        }

        public async Task<bool> IsCredentialIdUnique(IsCredentialIdUniqueToUserParams args, CancellationToken cancellationToken)
        {
            using var conn = new SqlConnection(_connectionString);
            await conn.OpenAsync(cancellationToken);

            var cmd = new SqlCommand(
                "SELECT COUNT(*) FROM StoredCredentials WHERE DescriptorId = @id", conn);

            cmd.Parameters.AddWithValue("@id", args.CredentialId);

            int count = (int)await cmd.ExecuteScalarAsync(cancellationToken);
            return count == 0;
        }
    }
}
