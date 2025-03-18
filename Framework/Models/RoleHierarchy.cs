namespace JWTAuthentication.Framework.Models
{
    public class RoleHierarchy
    {
        public int ParentRoleId { get; set; }
        public Role ParentRole { get; set; }
        public int ChildRoleId { get; set; }
        public Role ChildRole { get; set; }
    }
}
