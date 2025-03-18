using JWTAuthentication.Framework.Models;

namespace JWTAuthentication.Framework.Interfaces
{
    public interface IUserPermissionRepository
    {
        IEnumerable<UserPermission> GetUserPermissions(int userId);
        void AddUserPermission(UserPermission userPermission);
        void RemoveUserPermission(int userPermissionId);
    }
}
