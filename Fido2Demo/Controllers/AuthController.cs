using Fido2Demo.Service.Common;
using Fido2NetLib;
using Fido2NetLib.Objects; // Check if this exists, otherwise use Fido2NetLib
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.SqlClient;
using System.Security.Cryptography; 


namespace Fido2Demo.Controllers
{  
    public class AuthController : Controller
    {
        private readonly IFido2 _fido2;
        private readonly string _connectionString;
        private readonly Utils _utils;

        // IConfiguration is automatically provided by the dependency injection container
        public AuthController(IFido2 fido2, IConfiguration config,Utils utils)
        {
            _fido2 = fido2;
            _connectionString = config.GetConnectionString("DefaultConnection");
            _utils = utils;
        }


        public IActionResult Index() => View();
  

        // =========================
        // 🔐 REGISTER OPTIONS
        // =========================
        [HttpPost("register-options")]
        public async Task<IActionResult> RegisterOptions([FromBody] Fido2Demo.Models.RegisterRequest request)
        {
            if (string.IsNullOrWhiteSpace(request?.Username))
                return BadRequest("Username is required");

            byte[] userHandle;
            var excludeCredentials = new List<PublicKeyCredentialDescriptor>();

            using var conn = new SqlConnection(_connectionString);
            await conn.OpenAsync();

            // Get or create user
            var cmd = new SqlCommand("SELECT UserHandle FROM Users WHERE Username = @u", conn);
            cmd.Parameters.AddWithValue("@u", request.Username);

            var result = await cmd.ExecuteScalarAsync();

            if (result == null)
            {
                userHandle = RandomNumberGenerator.GetBytes(32);

                var insert = new SqlCommand(
                    "INSERT INTO Users (Username, UserHandle) VALUES (@u, @h)", conn);

                insert.Parameters.AddWithValue("@u", request.Username);
                insert.Parameters.AddWithValue("@h", userHandle);

                await insert.ExecuteNonQueryAsync();
            }
            else
            {
                userHandle = (byte[])result;
            }

            // Exclude existing credentials
            var credCmd = new SqlCommand(
                "SELECT DescriptorId FROM StoredCredentials WHERE Username = @u", conn);

            credCmd.Parameters.AddWithValue("@u", request.Username);

            using var reader = await credCmd.ExecuteReaderAsync();

            while (await reader.ReadAsync())
            {
                excludeCredentials.Add(
                    new PublicKeyCredentialDescriptor((byte[])reader["DescriptorId"])
                );
            }

            var fidoUser = new Fido2User
            {
                Name = request.Username,
                DisplayName = request.Username,
                Id = userHandle
            };

            var options = _fido2.RequestNewCredential(new RequestNewCredentialParams
            {
                User = fidoUser,
                ExcludeCredentials = excludeCredentials,
                AuthenticatorSelection = new AuthenticatorSelection
                {
                    UserVerification = UserVerificationRequirement.Required
                },
                AttestationPreference = AttestationConveyancePreference.None
            }); 


            HttpContext.Session.SetString("fido2.attestationOptions", options.ToJson());

            return Ok(options);
        }

         
        // =========================
        // 🔐 REGISTER COMPLETE
        // =========================
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] AuthenticatorAttestationRawResponse attestationResponse)
        {
            var json = HttpContext.Session.GetString("fido2.attestationOptions");
            if (json == null) return BadRequest("Session expired");

            var options = CredentialCreateOptions.FromJson(json);

            var result = await _fido2.MakeNewCredentialAsync(
               new MakeNewCredentialParams
               {
                   AttestationResponse = attestationResponse,
                   OriginalOptions = options,
                   IsCredentialIdUniqueToUserCallback = _utils.IsCredentialIdUnique
               });

            using var db = new SqlConnection(_connectionString);
            await db.OpenAsync();

            var insert = new SqlCommand(@"
            INSERT INTO StoredCredentials
            (Username, DescriptorId, PublicKey, UserHandle, SignCount)
            VALUES (@u, @id, @pk, @uh, @sc)", db);

            insert.Parameters.AddWithValue("@u", result.User.Name);
            insert.Parameters.AddWithValue("@id", result.Id);
            insert.Parameters.AddWithValue("@pk", result.PublicKey);
            insert.Parameters.AddWithValue("@uh", result.User.Id);
            insert.Parameters.AddWithValue("@sc", (int)result.SignCount);

            await insert.ExecuteNonQueryAsync();

            return Ok(result);
        }

        // =========================
        // 🔐 LOGIN OPTIONS
        // =========================
        [HttpPost("login-options")]
        public async Task<IActionResult> LoginOptions([FromBody] Fido2Demo.Models.LoginRequest request)
        {
            if (string.IsNullOrWhiteSpace(request?.Username))
                return BadRequest("Username required"); 

            var credentials = new List<PublicKeyCredentialDescriptor>();

            using var conn = new SqlConnection(_connectionString);
            await conn.OpenAsync();

            var cmd = new SqlCommand(
                "SELECT DescriptorId FROM StoredCredentials WHERE Username = @u", conn);

            cmd.Parameters.AddWithValue("@u", request.Username);

            using var reader = await cmd.ExecuteReaderAsync();

            while (await reader.ReadAsync())
            {
                credentials.Add(
                    new PublicKeyCredentialDescriptor((byte[])reader["DescriptorId"])
                );
            }

            var options = _fido2.GetAssertionOptions(
            new GetAssertionOptionsParams
            {
                AllowedCredentials = credentials,
                UserVerification = UserVerificationRequirement.Required
            });

            HttpContext.Session.SetString("fido2.assertionOptions", options.ToJson());

            return Ok(options);
        }
 
        // =========================
        // 🔐 LOGIN VERIFY
        // =========================
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] Fido2Demo.Models.LoginRequestDto clientResponse)
        {
            var json = HttpContext.Session.GetString("fido2.assertionOptions");
            if (json == null) return BadRequest("Session expired");

            var options = AssertionOptions.FromJson(json);

            Fido2Demo.Models.StoredCredential stored = null;

            using (var conn = new SqlConnection(_connectionString))
            {
                await conn.OpenAsync();
                var credentialId = _utils.Base64UrlDecode(clientResponse.Assertion.Id);
                var cmd = new SqlCommand(
                    "SELECT * FROM StoredCredentials WHERE DescriptorId = @id AND Username = @u", conn);

                cmd.Parameters.AddWithValue("@id", credentialId);
                cmd.Parameters.AddWithValue("@u", clientResponse.Username);
                using var reader = await cmd.ExecuteReaderAsync();

                if (await reader.ReadAsync())
                {
                    stored = new Fido2Demo.Models.StoredCredential
                    {
                        DescriptorId = (byte[])reader["DescriptorId"],
                        PublicKey = (byte[])reader["PublicKey"],
                        SignCount = (uint)(int)reader["SignCount"],
                        UserHandle = (byte[])reader["UserHandle"],
                        Username = reader["Username"].ToString()
                    };
                }
            }

            if (stored == null)
                return Unauthorized();
             
            var storedUserHandle = stored.UserHandle;

            var result = await _fido2.MakeAssertionAsync(
                new MakeAssertionParams
                {
                    AssertionResponse = clientResponse.Assertion,
                    OriginalOptions = options,
                    StoredPublicKey = stored.PublicKey,
                    StoredSignatureCounter = stored.SignCount,

                    IsUserHandleOwnerOfCredentialIdCallback = (args, ct) =>
                    {
                        return Task.FromResult(
                            args.UserHandle == null ||
                            args.UserHandle.SequenceEqual(storedUserHandle)
                        );
                    }
                });

            // Update counter (prevents replay attacks)
            using (var conn = new SqlConnection(_connectionString))
            {
                await conn.OpenAsync();

                var update = new SqlCommand(
                    "UPDATE StoredCredentials SET SignCount = @sc WHERE DescriptorId = @id and username = @u", conn);

                update.Parameters.AddWithValue("@sc", (int)result.SignCount);
                update.Parameters.AddWithValue("@id", stored.DescriptorId); 
                update.Parameters.AddWithValue("@u", stored.Username);

                await update.ExecuteNonQueryAsync();
            }

            HttpContext.Session.SetString("username", stored.Username);
            HttpContext.Session.SetString("fido2.authenticated", "true");

            return Ok(new
            {
                success = true,
                username = stored.Username
            });
        } 

        [HttpPost]
        public IActionResult Logout()
        {
            HttpContext.Session.Clear();
            return RedirectToAction("Index", "Auth");
        }
    }  
}
