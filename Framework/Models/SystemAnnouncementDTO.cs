namespace JWTAuthentication.Framework.Models
{
    public class SystemAnnouncementDTO
    {
        public int AnnouncementId { get; set; }
        public string Message { get; set; }
        public string Title { get; set; }
        public DateTime DateOfPost { get; set; }
        public string Priority { get; set; }
        public string PosterName { get; set; }
        public int PosterId { get; set; }
    }
}
