using JWTAuthentication.Framework.Models;

namespace JWTAuthentication.Framework.Interfaces
{
    public interface IUserRepository
    {
        UserDTO GetUser(UserModel userModel);
        UserDTO GetUser(string userName);
        void UpdateUser(UserDTO user);
        List<Permission> GetUserPermissions(int userId);
    }
}
