using JWTAuthentication.Framework.Models;
using System.Text.Json.Serialization;

public class UserDTO
{
    public int Id { get; set; }
    public string UserName { get; set; }
    public string FirstName { get; set; }
    public string LastName { get; set; }
    public string PreferredName { get; set; }
    public string Password { get; set; }
    public string Salt { get; set; }
    public int RoleId { get; set; }
    public int JobId { get; set; }

    public DateTime CreatedTime { get; set; }
    public DateTime? DeletedTime { get; set; }

    public string RefreshToken { get; set; }
    public DateTime RefreshTokenExpiryTime { get; set; }

    public virtual Role Role { get; set; }

    [JsonIgnore]
    public virtual JobTitles JobTitles { get; set; }

    [JsonIgnore]
    public virtual ICollection<SystemAnnouncements> Announcements { get; set; }

    public virtual ICollection<EmergencyContact> EmergencyContacts { get; set; }

    [JsonIgnore]
    public virtual Address CurrentAddress { get; set; }

    [JsonIgnore]
    public virtual PayInformation PayInformation { get; set; }

    public virtual ICollection<TestResult> TestResults { get; set; }

    public virtual ICollection<Incident> Incidents { get; set; }

    public virtual ICollection<Observation> Observations { get; set; }

}
