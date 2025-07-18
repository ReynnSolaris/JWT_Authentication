namespace JWTAuthentication.Framework.Models
{
    public class FailedLoginAttempt
    {
        public int Id { get; set; }

        public string IPAddress { get; set; }

        public string? CountryCode { get; set; }

        public string? Region { get; set; } 

        public string? City { get; set; } 

        public DateTime AttemptTime { get; set; } // Stored in UTC ideally

        public string? UsernameAttempted { get; set; } // Optional

        // Optional convenience method
        public bool IsExpired(TimeSpan window)
        {
            return AttemptTime < DateTime.UtcNow.Subtract(window);
        }
    }

}
