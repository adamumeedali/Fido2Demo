# Fido2Demo (ASP.NET Core)

This project demonstrates passwordless authentication using FIDO2 / WebAuthn.

## Features
- FIDO2 Registration (Passkeys / Security Keys)
- FIDO2 Login
- SQL Server storage for credentials
- Session-based authentication

## Requirements
- .NET 10
- SQL Server
- Modern browser (Chrome, Edge, Firefox)

## Setup

### 1. Configure FIDO2
Update `Program.cs`:

```csharp
builder.Services.AddFido2(options =>
{
    options.ServerDomain = "localhost";
    options.ServerName = "My Secure App";
    options.Origins = new HashSet<string>
    {
        "https://localhost:7137"
    };
});
