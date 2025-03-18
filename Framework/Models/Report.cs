namespace JWTAuthentication.Framework.Models
{
    public class Report
    {
        public int Id { get; set; }

        public int UserId { get; set; }
        public UserDTO User { get; set; }  // Navigation property for User

        public string ReportType { get; set; }
        public string Details { get; set; }
        public DateTime DateFiled { get; set; } = DateTime.Now;

        public int FiledBy { get; set; }
        public UserDTO FiledByUser { get; set; }  // Navigation property for the person who filed the report
    }

}
