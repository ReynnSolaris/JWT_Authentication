namespace JWTAuthentication.Framework.Models
{
    public class PayInformation
    {
        public int PayInformationId { get; set; }
        public int UserId { get; set; }
        public decimal? HourlyRate { get; set; }
        public decimal? SalaryRate { get; set; }
        public string PositionType { get; set; }

        public UserDTO User { get; set; }
    }
}
