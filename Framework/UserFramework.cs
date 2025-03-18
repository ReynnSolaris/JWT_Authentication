using JWTAuthentication.Framework.Classes;
using JWTAuthentication.Framework.Database;
using JWTAuthentication.Framework.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

namespace JWTAuthentication.Framework
{
    public class UserFramework
    {
        private readonly ApplicationDbContext _context;
        private readonly PermissionService _permissionService;
        public UserFramework(ApplicationDbContext context, PermissionService permissionService)
        {
            _context = context;
            _permissionService = permissionService;
        }


        public UserInfo getUserInfo(string userName)
        {
            var user = _context.Users
               .Include(u => u.Incidents)
               .ThenInclude(u => u.ReportedByUser)
               .Include(u => u.Incidents)
               .ThenInclude(u => u.IncidentType)
               .Include(u => u.JobTitles)
               .Include(u => u.CurrentAddress)
               .Include(u => u.EmergencyContacts)
               .Include(u => u.PayInformation)
               .Include(u => u.Role)
               .ThenInclude(r => r.RolePermissions)
               .ThenInclude(rp => rp.Permission)
               .SingleOrDefault(u => u.UserName.ToLower() == userName.ToLower() || u.Id.ToString() == userName);

            if (user == null) {
                return null;
            }

            var permissions = _permissionService.GetEffectivePermissions(user.Id);
            var now = DateTime.UtcNow;
            var firstDayOfMonth = new DateTime(now.Year, now.Month, 1);
            var lastDayOfMonth = firstDayOfMonth.AddMonths(1).AddDays(-1);

            // Fetch announcements posted by the user for the current month
            var announcements = _context.System_Announcements
                .Where(a => a.Date_Of_Post >= firstDayOfMonth && a.Date_Of_Post <= lastDayOfMonth)
                .Select(a => new SystemAnnouncementDTO
                {
                    AnnouncementId = a.Announcement_Id,
                    Message = a.Message,
                    Title = a.Title,
                    DateOfPost = a.Date_Of_Post,
                    PosterName = $"{a.Poster.FirstName} " + (a.Poster.PreferredName != "" ? "\"" + a.Poster.PreferredName + "\" " : "") + $"{a.Poster.LastName}",
                    PosterId = a.Poster.Id,
                    Priority = a.Priority
                })
                .ToList();

            var emergencyContacts = _context.EmergencyContacts
                .Where(a => a.UserId == user.Id)
                .Select(a => new EmergencyContactDTO
                {
                    ContactId = a.ContactId,
                    FullName = a.FullName,
                    Phone = a.Phone
                })
                .ToList();

            var userInfo = new UserInfo
            {
                UserId = user.Id,
                UserName = user.UserName,
                FirstName = user.FirstName,
                LastName = user.LastName,
                PreferredName = user.PreferredName,
                CreatedTime = user.CreatedTime,
                RoleName = user.Role.RoleName,
                JobTitle = user.JobTitles?.Name ?? "No job title", // Assuming JobTitleName is a property in JobTitles class
                Permissions = permissions,
                Announcements = announcements,  // Add announcements to the UserInfo object
                HourlyRate = user.PayInformation?.HourlyRate,
                SalaryRate = user.PayInformation?.SalaryRate,
                PositionType = user.PayInformation?.PositionType,
                Address = user.CurrentAddress?.Street != null ? $"{user.CurrentAddress.Street}, {user.CurrentAddress.City} {user.CurrentAddress.State}, {user.CurrentAddress.PostalCode}" : "No address",
                EmergencyContacts = emergencyContacts,
                TestResults = user.TestResults.IsNullOrEmpty() ? new() : user.TestResults.Select(tr => new TestResult
                {
                    Id = tr.Id,
                    UserId = tr.UserId,
                    TestId = tr.TestId,
                    Score = tr.Score,
                    Status = tr.Status,
                    DateTaken = tr.DateTaken
                }).ToList(),
                Incidents = user.Incidents.IsNullOrEmpty() ? new() : user.Incidents.Select(i => new Incident
                {
                    Id = i.Id,
                    UserId = i.UserId,
                    IncidentType = i.IncidentType,
                    Details = i.Details,
                    DateOccurred = i.DateOccurred,
                    ReportedBy = i.ReportedBy,
                    ReportedByUser = new UserDTO() { FirstName = user.FirstName, LastName = user.LastName, PreferredName = user.PreferredName, JobTitles = user.JobTitles, UserName = user.UserName}
                }).ToList(),
                Observations = user.Observations.IsNullOrEmpty() ? new() : user.Observations.Select(o => new Observation
                {
                    Id = o.Id,
                    UserId = o.UserId,
                    ObserverId = o.ObserverId,
                    Details = o.Details,
                    DateObserved = o.DateObserved
                }).ToList()
            };
            return userInfo;
        }
    }
}
