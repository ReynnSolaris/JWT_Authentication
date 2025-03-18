namespace JWTAuthentication.Framework.Models
{
    public class TestResult
    {
        public int Id { get; set; }

        public int UserId { get; set; }
        public UserDTO User { get; set; }  // Navigation property for the user (employee) who took the test

        public int TestId { get; set; }
        public Test Test { get; set; }  // Navigation property for the Test taken

        public decimal Score { get; set; }
        public string Status { get; set; } = "Pending";  // Default to "Pending"
        public DateTime DateTaken { get; set; } = DateTime.Now;
    }

}
