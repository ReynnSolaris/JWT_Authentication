using System.ComponentModel.DataAnnotations.Schema;

namespace JWTAuthentication.Framework.Models
{
    public class Incident
    {
        public int Id { get; set; }

        public int UserId { get; set; }

        public UserDTO User { get; set; }  // Navigation property for User

        public int IncidentTypeId { get; set; }
        public IncidentType IncidentType { get; set; }  // Navigation property for IncidentType
        public string Details { get; set; }
        public DateTime DateOccurred { get; set; } = DateTime.Now;

        public int ReportedBy { get; set; }


        public UserDTO ReportedByUser { get; set; }  // Navigation property for the user who reported it
        
    }

}
