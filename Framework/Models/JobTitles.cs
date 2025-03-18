namespace JWTAuthentication.Framework.Models
{
    public class JobTitles
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public ICollection<UserDTO> Users { get; set; }
    }
}
