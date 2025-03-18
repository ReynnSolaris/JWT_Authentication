using JWTAuthentication.Framework.Models;

namespace JWTAuthentication.Framework.Interfaces
{
    public interface ITokenService
    {
        double RefreshTokenExpiryDuration { get; set; }
        string BuildToken(string key, string issuer, UserDTO user);

        string GenerateRefreshToken();
        bool ValidateToken(string key, string issuer, string token);
    }
}
