using JWTAuthentication.Framework.Interfaces;
using JWTAuthentication.Framework.Models;

namespace JWTAuthentication.Framework.Classes
{
    public class UserService
    {
        private readonly IUserRepository _userRepository;

        public UserService(IUserRepository userRepository)
        {
            _userRepository = userRepository;
        }

        public UserInfo GetUserInfo(UserModel userModel)
        {
            var user = _userRepository.GetUser(userModel);
            if (user == null) return null;

            var permissions = _userRepository.GetUserPermissions(user.Id);

            return new UserInfo
            {
                UserId = user.Id,
                UserName = user.UserName,
                RoleName = user.Role.RoleName,
                Permissions = permissions.Select(p => p.PermissionName).ToList()
            };
        }
    }
}
