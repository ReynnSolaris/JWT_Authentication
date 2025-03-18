namespace JWTAuthentication.Framework.Models
{
    public class Observation
    {
        public int Id { get; set; }

        public int UserId { get; set; }
        public UserDTO User { get; set; }  // Navigation property for the observed user

        public int ObserverId { get; set; }
        public UserDTO Observer { get; set; }  // Navigation property for the observer (manager or supervisor)

        public string Details { get; set; }
        public DateTime DateObserved { get; set; } = DateTime.Now;
    }

}
