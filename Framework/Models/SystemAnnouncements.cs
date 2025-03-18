namespace JWTAuthentication.Framework.Models
{
    public class SystemAnnouncements
    {
        public int Announcement_Id { get; set; }
        public string Message { get; set; }
        public string Title { get; set; }
        public int PosterId { get; set; }
        public DateTime Date_Of_Post { get; set; }
        public string Priority { get; set; }

        // Navigation property
        public UserDTO Poster { get; set; }
    }
}
