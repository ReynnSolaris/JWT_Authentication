using JWTAuthentication.Framework.Database;
using JWTAuthentication.Framework.Interfaces;
using JWTAuthentication.Framework.Models;
using Microsoft.EntityFrameworkCore;

namespace JWTAuthentication.Framework.Classes
{
    public class UserPermissionRepository : IUserPermissionRepository
    {
        private readonly ApplicationDbContext _context;

        public UserPermissionRepository(ApplicationDbContext context)
        {
            _context = context;
        }

        public IEnumerable<UserPermission> GetUserPermissions(int userId)
        {
            return _context.UserPermissions
                .Where(up => up.UserId == userId)
                .Include(up => up.Permission)
                .ToList();
        }

        public void AddUserPermission(UserPermission userPermission)
        {
            _context.UserPermissions.Add(userPermission);
            _context.SaveChanges();
        }

        public void RemoveUserPermission(int userPermissionId)
        {
            var userPermission = _context.UserPermissions.Find(userPermissionId);
            if (userPermission != null)
            {
                _context.UserPermissions.Remove(userPermission);
                _context.SaveChanges();
            }
        }
    }
}
