using System.Security.Cryptography;
using System.Text;

namespace JWTAuthentication.Framework.Classes
{
    public class SHA_Manager
    {
        public int keySize = 64;
        public int iterations = 350000;
        public HashAlgorithmName hashAlgorithm = HashAlgorithmName.SHA512;
        public string HashPassword(string password, out string saltHex)
        {
            byte[] salt = RandomNumberGenerator.GetBytes(keySize);
            saltHex = Convert.ToHexString(salt);
            var hash = Rfc2898DeriveBytes.Pbkdf2(
                Encoding.UTF8.GetBytes(password),
                salt,
                iterations,
                hashAlgorithm,
                keySize);
            return Convert.ToHexString(hash);
        }

        public bool VerifyPassword(string password, string hashHex, string saltHex)
        {
            byte[] salt = Convert.FromHexString(saltHex);
            byte[] hashToCompare = Rfc2898DeriveBytes.Pbkdf2(
                password,
                salt,
                iterations,
                hashAlgorithm,
                keySize);
            return CryptographicOperations.FixedTimeEquals(hashToCompare, Convert.FromHexString(hashHex));
        }
    }
}
