namespace JWTAuthentication.Framework.Models
{
    public class EmergencyContact
    {
        public int ContactId { get; set; }
        public int UserId { get; set; }
        public string FullName { get; set; }
        public string Phone { get; set; }

        public UserDTO User { get; set; }
    }
}
