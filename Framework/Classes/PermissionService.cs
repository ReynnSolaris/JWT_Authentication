using JWTAuthentication.Framework.Database;
using JWTAuthentication.Framework.Interfaces;
using JWTAuthentication.Framework.Models;
using Microsoft.EntityFrameworkCore;

namespace JWTAuthentication.Framework.Classes
{
    public class PermissionService
    {
        private readonly ApplicationDbContext _context;
        private readonly IUserPermissionRepository _userPermissionRepository;

        public PermissionService(ApplicationDbContext context, IUserPermissionRepository userPermissionRepository)
        {
            _context = context;
            _userPermissionRepository = userPermissionRepository;
        }

        public List<string> GetEffectivePermissions(int userId)
        {
            var user = _context.Users
                .Include(u => u.Role)
                    .ThenInclude(r => r.RolePermissions)
                        .ThenInclude(rp => rp.Permission)
                .Include(u => u.Role.ParentRoles)
                    .ThenInclude(pr => pr.ParentRole.ChildRoles)
                .SingleOrDefault(u => u.Id == userId);

            if (user == null)
            {
                return new List<string>();
            }

            var permissions = new HashSet<string>();

            void AddRolePermissions(Role role)
            {
                if (role != null)
                {
                    if (role.RolePermissions != null)
                    {
                        foreach (var rolePermission in role.RolePermissions)
                        {
                            permissions.Add(rolePermission.Permission.PermissionName);
                        }
                    }

                    var childRoles = _context.RoleHierarchy
                        .Where(rh => rh.ParentRoleId == role.RoleId)
                        .Select(rh => rh.ChildRoleId)
                        .ToList();

                    foreach (var childRoleId in childRoles)
                    {
                        var childRole = _context.Roles
                            .Include(r => r.RolePermissions)
                                .ThenInclude(rp => rp.Permission)
                            .SingleOrDefault(r => r.RoleId == childRoleId);

                        AddRolePermissions(childRole);
                    }
                }
            }

            AddRolePermissions(user.Role);

            // Add user-specific permissions
            var userPermissions = _userPermissionRepository.GetUserPermissions(userId);
            foreach (var userPermission in userPermissions)
            {
                permissions.Add(userPermission.Permission.PermissionName);
            }

            return permissions.ToList();
        }

        public List<string> GetRolePermissions(Role role)
        {
            var permissionsHash = new HashSet<string>();

            // Function to add permissions from a role
            void AddRolePermissions(Role role)
            {
                if (role != null && role.RolePermissions != null)
                {
                    foreach (var rolePermission in role.RolePermissions)
                    {
                        permissionsHash.Add(rolePermission.Permission.PermissionName);
                    }
                }
            }

            // Function to recursively add permissions from child roles
            void AddChildRolePermissions(Role role)
            {
                var childRoles = _context.RoleHierarchy
                    .Where(rh => rh.ParentRoleId == role.RoleId)
                    .Select(rh => rh.ChildRoleId)
                    .ToList();

                foreach (var childRoleId in childRoles)
                {
                    var childRole = _context.Roles
                        .Include(r => r.RolePermissions)
                            .ThenInclude(rp => rp.Permission)
                        .SingleOrDefault(r => r.RoleId == childRoleId);

                    if (childRole != null)
                    {
                        AddRolePermissions(childRole); // Add permissions of child role
                        AddChildRolePermissions(childRole); // Recursively add permissions from child role
                    }
                }
            }

            var mainParentRole = _context.Roles
                    .Include(r => r.RolePermissions)
                        .ThenInclude(rp => rp.Permission)
                    .SingleOrDefault(r => r.RoleId == role.RoleId);

            AddRolePermissions(mainParentRole);

            // Recursively add permissions from child roles
            AddChildRolePermissions(role);

            return permissionsHash.ToList();
        }
    }
}
