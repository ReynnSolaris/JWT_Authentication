namespace JWTAuthentication.Framework.Classes
{
    using JWTAuthentication.Framework.Database;
    using JWTAuthentication.Framework.Interfaces;
    using JWTAuthentication.Framework.Models;
    using Microsoft.EntityFrameworkCore;
    using System.Data;
    using System.Linq;

    public class FailedLoginRepository : IFailedLoginRepository
    {
        private readonly ApplicationDbContext _context;

        public FailedLoginRepository(ApplicationDbContext context)
        {
            _context = context;
        }

        public async Task InsertAttempt(FailedLoginAttempt attempt)
        {
            _context.FailedLoginAttempts.Add(attempt);
            await _context.SaveChangesAsync();
        }

        public async Task<List<FailedLoginAttempt>> GetAttempts(string ipAddress, TimeSpan within)
        {
            var since = DateTime.UtcNow.Subtract(within);
            return await _context.FailedLoginAttempts
                .Where(a => a.IPAddress == ipAddress && a.AttemptTime >= since)
                .ToListAsync();
        }

        public async Task DeleteOldAttempts(TimeSpan olderThan)
        {
            var cutoff = DateTime.UtcNow.Subtract(olderThan);
            var oldAttempts = _context.FailedLoginAttempts.Where(a => a.AttemptTime < cutoff);
            _context.FailedLoginAttempts.RemoveRange(oldAttempts);
            await _context.SaveChangesAsync();
        }
    }

}
