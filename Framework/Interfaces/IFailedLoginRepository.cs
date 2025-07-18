using JWTAuthentication.Framework.Models;

namespace JWTAuthentication.Framework.Interfaces
{
    public interface IFailedLoginRepository
    {
        Task InsertAttempt(FailedLoginAttempt attempt);
        Task<List<FailedLoginAttempt>> GetAttempts(string ipAddress, TimeSpan within);
        Task DeleteOldAttempts(TimeSpan olderThan);
    }
}
