using JWTAuthentication.Framework.Interfaces;
using JWTAuthentication.Framework.Models;
using Microsoft.IdentityModel.Tokens;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace JWTAuthentication.Framework.Classes
{
    public class TokenService : ITokenService
    {
        private const double EXPIRY_DURATION_MINUTES = 15;

        double ITokenService.RefreshTokenExpiryDuration { get => EXPIRY_DURATION_MINUTES * (60); set => throw new NotImplementedException(); }

        public string BuildToken(string key, string issuer, UserDTO user)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user), "User is null in BuildToken()");
            }

            if (user.Role == null)
            {
                throw new ArgumentNullException(nameof(user.Role), "User Role is null in BuildToken()");
            }

            if (string.IsNullOrEmpty(key) || string.IsNullOrEmpty(issuer))
            {
                throw new ArgumentNullException("JWT Config", "JWT Key or Issuer is missing in BuildToken()");
            }

            var claims = new[] {
        new Claim(ClaimTypes.GivenName, user.Id.ToString()),
        new Claim(ClaimTypes.Name, user.UserName),
        new Claim(ClaimTypes.Role, user.Role.RoleName), // Issue happens if user.Role is null
        new Claim(ClaimTypes.NameIdentifier, Guid.NewGuid().ToString())
    };

            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var tokenDescriptor = new JwtSecurityToken(
                issuer,
                issuer,
                claims,
                expires: DateTime.Now.AddMinutes(EXPIRY_DURATION_MINUTES), 
                signingCredentials: credentials
            );

            return new JwtSecurityTokenHandler().WriteToken(tokenDescriptor);
        }
        public bool ValidateToken(string key, string issuer, string token)
        {
            var mySecret = Encoding.UTF8.GetBytes(key);
            var mySecurityKey = new SymmetricSecurityKey(mySecret);
            var tokenHandler = new JwtSecurityTokenHandler();
            try
            {
                tokenHandler.ValidateToken(token,
                new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidIssuer = issuer,
                    ValidAudience = issuer,
                    IssuerSigningKey = mySecurityKey,
                }, out SecurityToken validatedToken);
            }
            catch
            {
                return false;
            }
            return true;
        }

        public string GenerateRefreshToken()
        {
            var randomNumber = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomNumber);
                return Convert.ToBase64String(randomNumber);
            }
        }
    }
}
