namespace JWTAuthentication.Framework.Models
{
    public class Role
    {
        public int RoleId { get; set; }
        public string RoleName { get; set; }
        public ICollection<RolePermission> RolePermissions { get; set; } = new List<RolePermission>();
        public ICollection<RoleHierarchy> ParentRoles { get; set; } = new List<RoleHierarchy>();
        public ICollection<RoleHierarchy> ChildRoles { get; set; } = new List<RoleHierarchy>();
    }
}
