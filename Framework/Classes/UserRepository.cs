using JWTAuthentication.Framework.Database;
using JWTAuthentication.Framework.Interfaces;
using JWTAuthentication.Framework.Models;
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;

namespace JWTAuthentication.Framework.Classes
{
    public class UserRepository : IUserRepository
    {
        private readonly List<UserDTO> users = new List<UserDTO>();
        private readonly SHA_Manager sha = new();
        private readonly DbContextOptions<ApplicationDbContext> _dbContextOptions;

        public UserRepository(DbContextOptions<ApplicationDbContext> dbContextOptions)
        {
            _dbContextOptions = dbContextOptions;
        }


        public UserDTO GetUser(string userName)
        {
            using var context = new ApplicationDbContext(_dbContextOptions);
            return context.Users.SingleOrDefault(u => u.UserName.ToLower() == userName.ToLower());
        }

        public UserDTO GetUser(UserModel userModel)
        {
            using var context = new ApplicationDbContext(_dbContextOptions);
            var user = context.Users
                .Include(u => u.JobTitles)
                .Include(u => u.Role)
                .ThenInclude(r => r.RolePermissions)
                .ThenInclude(rp => rp.Permission)
                .Include(u => u.Role)
                .ThenInclude(r => r.ChildRoles)
                .ThenInclude(cr => cr.ChildRole)
                .SingleOrDefault(x => x.UserName.ToLower() == userModel.UserName.ToLower());

            if (user == null) return null;

            bool isPasswordValid = sha.VerifyPassword(userModel.Password, user.Password, user.Salt);
            return isPasswordValid ? user : null;
        }

        public void AddUser(UserModel userModel, string roleName)
        {
            using var context = new ApplicationDbContext(_dbContextOptions);
            var role = context.Roles.SingleOrDefault(r => r.RoleName == roleName);
            if (role == null) throw new Exception("Role not found");

            var passwordHash = sha.HashPassword(userModel.Password, out string salt);

            var newUser = new UserDTO()
            {
                UserName = userModel.UserName,
                Password = passwordHash,
                Salt = salt,
                RoleId = role.RoleId
            };

            context.Users.Add(newUser);
            context.SaveChanges();
        }

        public void UpdateUser(UserDTO user)
        {
            using var context = new ApplicationDbContext(_dbContextOptions);
            context.Users.Update(user);
            context.SaveChanges();
        }

        public List<Permission> GetUserPermissions(int userId)
        {
            using var context = new ApplicationDbContext(_dbContextOptions);
            var user = context.Users
                .Include(u => u.Role)
                .ThenInclude(r => r.RolePermissions)
                .ThenInclude(rp => rp.Permission)
                .Include(u => u.Role)
                .ThenInclude(r => r.ChildRoles)
                .ThenInclude(cr => cr.ChildRole)
                .ThenInclude(r => r.RolePermissions)
                .ThenInclude(rp => rp.Permission)
                .SingleOrDefault(u => u.Id == userId);

            var permissions = new List<Permission>();

            void AddPermissions(Role role)
            {
                permissions.AddRange(role.RolePermissions.Select(rp => rp.Permission));
                foreach (var childRole in role.ChildRoles.Select(cr => cr.ChildRole))
                {
                    AddPermissions(childRole);
                }
            }

            if (user != null)
            {
                AddPermissions(user.Role);
            }

            return permissions.Distinct().ToList();
        }
    }
}
