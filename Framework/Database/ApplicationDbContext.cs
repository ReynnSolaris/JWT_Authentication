using JWTAuthentication.Framework.Models;
using Microsoft.EntityFrameworkCore;

namespace JWTAuthentication.Framework.Database
{
    public class ApplicationDbContext : DbContext
    {
        public DbSet<UserDTO> Users { get; set; }
        public DbSet<Role> Roles { get; set; }
        public DbSet<Permission> Permissions { get; set; }
        public DbSet<RolePermission> RolePermissions { get; set; }
        public DbSet<RoleHierarchy> RoleHierarchy { get; set; }
        public DbSet<UserPermission> UserPermissions { get; set; }
        public DbSet<SystemAnnouncements> System_Announcements { get; set; }
        public DbSet<PayInformation> PayInformation { get; set; }
        public DbSet<JobTitles> Job_Titles { get; set; }
        public DbSet<Address> Addresses { get; set; }
        public DbSet<EmergencyContact> EmergencyContacts { get; set; }
        public DbSet<Incident> Incidents { get; set; }
        public DbSet<IncidentType> IncidentTypes { get; set; }
        public DbSet<Report> Reports { get; set; }
        public DbSet<Observation> Observations { get; set; }
        public DbSet<Test> Tests { get; set; }
        public DbSet<TestResult> TestResults { get; set; }
        public DbSet<FailedLoginAttempt> FailedLoginAttempts { get; set; }
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options)
        {
        }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            modelBuilder.Entity<Role>()
                .HasMany(r => r.RolePermissions)
                .WithOne(rp => rp.Role)
                .HasForeignKey(rp => rp.RoleId);

            modelBuilder.Entity<Permission>()
                .HasMany(p => p.RolePermissions)
                .WithOne(rp => rp.Permission)
                .HasForeignKey(rp => rp.PermissionId);

            modelBuilder.Entity<RoleHierarchy>()
                .HasKey(rh => new { rh.ParentRoleId, rh.ChildRoleId });

            modelBuilder.Entity<RoleHierarchy>()
                .HasOne(rh => rh.ParentRole)
                .WithMany(r => r.ChildRoles)
                .HasForeignKey(rh => rh.ParentRoleId)
                .OnDelete(DeleteBehavior.Restrict);

            modelBuilder.Entity<RoleHierarchy>()
                .HasOne(rh => rh.ChildRole)
                .WithMany(r => r.ParentRoles)
                .HasForeignKey(rh => rh.ChildRoleId)
                .OnDelete(DeleteBehavior.Restrict);

            modelBuilder.Entity<PayInformation>()
            .HasOne(pi => pi.User)
            .WithOne(u => u.PayInformation)
            .HasForeignKey<PayInformation>(pi => pi.UserId)
            .OnDelete(DeleteBehavior.Cascade);

            modelBuilder.Entity<UserDTO>()
            .Property(u => u.RefreshToken)
            .HasMaxLength(512);

            modelBuilder.Entity<UserDTO>()
                .Property(u => u.RefreshTokenExpiryTime);

            modelBuilder.Entity<UserDTO>()
                .HasOne(u => u.JobTitles)
                .WithMany(j => j.Users)
                .HasForeignKey(u => u.JobId)
                .OnDelete(DeleteBehavior.SetNull);

            modelBuilder.Entity<UserDTO>()
             .HasOne(u => u.CurrentAddress)
             .WithOne(j => j.User)
             .HasForeignKey<Address>(u => u.UserId)
             .OnDelete(DeleteBehavior.Cascade);

            modelBuilder.Entity<EmergencyContact>()
             .HasOne(u => u.User)
             .WithMany(j => j.EmergencyContacts)
             .HasForeignKey(u => u.UserId)
             .OnDelete(DeleteBehavior.Cascade);

             modelBuilder.Entity<SystemAnnouncements>()
                .HasOne(sa => sa.Poster)
                .WithMany(u => u.Announcements)
                .HasForeignKey(sa => sa.PosterId)  // Ensure foreign key is defined for PosterId if not in model
                .OnDelete(DeleteBehavior.SetNull);

            modelBuilder.Entity<SystemAnnouncements>()
                .HasKey(sa => sa.Announcement_Id);
            modelBuilder.Entity<EmergencyContact>()
                .HasKey(sa => sa.ContactId);

            modelBuilder.Entity<Incident>()
            .Ignore(i => i.ReportedByUser);

            modelBuilder.Entity<Incident>()
               .HasOne(sa => sa.User)
               .WithMany(u => u.Incidents)
               .HasForeignKey(sa => sa.UserId)  // Ensure foreign key is defined for PosterId if not in model
               .OnDelete(DeleteBehavior.SetNull);

            modelBuilder.Entity<Incident>()
               .HasOne(sa => sa.ReportedByUser)
               .WithMany()
               .HasForeignKey(sa => sa.ReportedBy)  // Ensure foreign key is defined for PosterId if not in model
               .OnDelete(DeleteBehavior.SetNull);

            modelBuilder.Entity<Incident>()
                .HasOne(u => u.IncidentType)
                .WithMany()
                .HasForeignKey(i => i.IncidentTypeId)
                .OnDelete(DeleteBehavior.SetNull);

            modelBuilder.Entity<Report>()
                .HasOne(r => r.User)
                .WithMany()
                .HasForeignKey(r => r.UserId)
                .OnDelete(DeleteBehavior.Cascade);

            modelBuilder.Entity<Report>()
                .HasOne(r => r.FiledByUser)
                .WithMany()
                .HasForeignKey(r => r.FiledBy)
                .OnDelete(DeleteBehavior.SetNull);

            modelBuilder.Entity<Observation>()
                .HasOne(o => o.User)
                .WithMany()
                .HasForeignKey(o => o.UserId)
                .OnDelete(DeleteBehavior.Cascade);

            modelBuilder.Entity<Observation>()
                .HasOne(o => o.Observer)
                .WithMany()
                .HasForeignKey(o => o.ObserverId)
                .OnDelete(DeleteBehavior.SetNull);

            modelBuilder.Entity<TestResult>()
                .HasOne(tr => tr.User)
                .WithMany()
                .HasForeignKey(tr => tr.UserId)
                .OnDelete(DeleteBehavior.Cascade);

            modelBuilder.Entity<TestResult>()
                .HasOne(tr => tr.Test)
                .WithMany()
                .HasForeignKey(tr => tr.TestId)
                .OnDelete(DeleteBehavior.Cascade);
        }

    }
}
