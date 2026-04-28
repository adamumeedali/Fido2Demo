CREATE TABLE Users (
    Username NVARCHAR(100) PRIMARY KEY,
    UserHandle VARBINARY(64) NOT NULL
);

CREATE TABLE StoredCredentials (
    Id INT IDENTITY PRIMARY KEY,
    Username NVARCHAR(100),
    DescriptorId VARBINARY(MAX),
    PublicKey VARBINARY(MAX),
    UserHandle VARBINARY(MAX),
    SignCount INT
); 



SELECT * FROM Users

SELECT * FROM StoredCredentials

--delete from users