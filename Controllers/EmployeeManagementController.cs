using JWTAuthentication.Framework;
using JWTAuthentication.Framework.Classes;
using JWTAuthentication.Framework.Database;
using JWTAuthentication.Framework.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Collections.Generic;
using System.Linq;

[EnableCors]
[Authorize(Roles = "Manager,HR,Developer")]
[Route("api/employee-management")]
[ApiController]
public class EmployeeManagementController : ControllerBase
{
    private readonly ApplicationDbContext _context;
    private readonly UserFramework userFramework;
    public EmployeeManagementController(ApplicationDbContext context, PermissionService service)
    {
        _context = context;
        userFramework = new(context, service);
    }

    /// <summary>
    /// Get all employees
    /// </summary>
    [HttpGet("all")]
    public IActionResult GetAllEmployees()
    {
        var employees = _context.Users
            .AsNoTracking()
            .Include(u => u.Role)
            .Include(u => u.CurrentAddress)
            .Include(u => u.JobTitles)
            .Include(u => u.PayInformation)
            .Include(u => u.EmergencyContacts)
            .Include(u => u.Role.RolePermissions)
            .ThenInclude(rp => rp.Permission)
            .Where(u => u.Role.RoleName != "Debug")
            .Select(u => new
            {
                userId = u.Id,
                userName = u.UserName,
                firstName = u.FirstName,
                lastName = u.LastName,
                preferredName = u.PreferredName,
                roleName = u.Role != null ? u.Role.RoleName : "Unknown",
                createdTime = u.CreatedTime,
                deletedTime = u.DeletedTime,
                address = u.CurrentAddress != null
                    ? $"{u.CurrentAddress.Street}, {u.CurrentAddress.City} {u.CurrentAddress.State}, {u.CurrentAddress.PostalCode}"
                    : "No Address Listed",

                emergencyContacts = u.EmergencyContacts.Select(c => new
                {
                    contactId = c.ContactId,
                    fullName = c.FullName,
                    phone = c.Phone
                }).ToList(),

                jobTitle = u.JobTitles != null ? u.JobTitles.Name : "Unknown",

                permissions = u.Role.RolePermissions.Select(rp => rp.Permission.PermissionName).ToList(),

                salaryRate = u.PayInformation != null ? u.PayInformation.SalaryRate : (decimal?)null,
                hourlyRate = u.PayInformation != null ? u.PayInformation.HourlyRate : (decimal?)null,
                positionType = u.PayInformation != null ? u.PayInformation.PositionType : "Not Assigned"
            }).ToList();

        return Ok(employees);
    }

    /// <summary>
    /// Add a new employee
    /// </summary>
    [HttpPost("add")]
    public IActionResult AddEmployee([FromBody] UserDTO employeeData)
    {
        if (employeeData == null)
            return BadRequest("Invalid employee data");

        var newUser = new UserDTO
        {
            UserName = employeeData.UserName,
            FirstName = employeeData.FirstName,
            LastName = employeeData.LastName,
            PreferredName = employeeData.PreferredName,
            CreatedTime = DateTime.UtcNow,

            RoleId = _context.Roles.FirstOrDefault(r => r.RoleName == employeeData.Role.RoleName)?.RoleId ?? 0,

            JobId = _context.Job_Titles.FirstOrDefault(j => j.Name == employeeData.JobTitles.Name)?.Id ?? 0,

            PayInformation = employeeData.PayInformation != null
                ? new PayInformation
                {
                    SalaryRate = employeeData.PayInformation.SalaryRate,
                    HourlyRate = employeeData.PayInformation.HourlyRate,
                    PositionType = employeeData.PayInformation.PositionType
                }
                : null,

            CurrentAddress = employeeData.CurrentAddress != null
                ? new Address
                {
                    Street = employeeData.CurrentAddress.Street,
                    City = employeeData.CurrentAddress.City,
                    State = employeeData.CurrentAddress.State,
                    PostalCode = employeeData.CurrentAddress.PostalCode
                }
                : null
        };

        _context.Users.Add(newUser);
        _context.SaveChanges();

        return Ok(new { message = "Employee added successfully!" });
    }


    /// <summary>
    /// Update an existing employee
    /// </summary>
    [HttpPut("{userId}")]
    public IActionResult UpdateEmployee(int userId, [FromBody] UserDTO employeeData)
    {
        var existingUser = _context.Users
            .Include(u => u.PayInformation)
            .Include(u => u.CurrentAddress)
            .FirstOrDefault(u => u.Id == userId);

        if (existingUser == null)
            return NotFound("Employee not found");

        // ✅ Update only changed values

        // Personal Information
        if (!string.IsNullOrEmpty(employeeData.FirstName) && existingUser.FirstName != employeeData.FirstName)
            existingUser.FirstName = employeeData.FirstName;

        if (!string.IsNullOrEmpty(employeeData.LastName) && existingUser.LastName != employeeData.LastName)
            existingUser.LastName = employeeData.LastName;

        if (existingUser.PreferredName != employeeData.PreferredName)
            existingUser.PreferredName = employeeData.PreferredName;

        // ✅ Role & Job Title Updates
        if (!string.IsNullOrEmpty(employeeData.Role.RoleName) && existingUser.Role.RoleName != employeeData.Role.RoleName)
        {
            var newRole = _context.Roles.FirstOrDefault(r => r.RoleName == employeeData.Role.RoleName);
            if (newRole != null)
                existingUser.RoleId = newRole.RoleId;
        }

        if (!string.IsNullOrEmpty(employeeData.JobTitles?.Name) && existingUser.JobTitles?.Name != employeeData.JobTitles.Name)
        {
            var newJobTitle = _context.Job_Titles.FirstOrDefault(j => j.Name == employeeData.JobTitles.Name);
            if (newJobTitle != null)
                existingUser.JobId = newJobTitle.Id;
        }

        // ✅ Pay Information Updates
        if (existingUser.PayInformation != null && employeeData.PayInformation != null)
        {
            if (employeeData.PayInformation.SalaryRate.HasValue && existingUser.PayInformation.SalaryRate != employeeData.PayInformation.SalaryRate)
                existingUser.PayInformation.SalaryRate = employeeData.PayInformation.SalaryRate;

            if (employeeData.PayInformation.HourlyRate.HasValue && existingUser.PayInformation.HourlyRate != employeeData.PayInformation.HourlyRate)
                existingUser.PayInformation.HourlyRate = employeeData.PayInformation.HourlyRate;

            if (!string.IsNullOrEmpty(employeeData.PayInformation.PositionType) && existingUser.PayInformation.PositionType != employeeData.PayInformation.PositionType)
                existingUser.PayInformation.PositionType = employeeData.PayInformation.PositionType;
        }

        // ✅ Address Updates - No Redundant Parsing!
        if (existingUser.CurrentAddress != null && employeeData.CurrentAddress != null)
        {
            if (!string.IsNullOrEmpty(employeeData.CurrentAddress.Street) && existingUser.CurrentAddress.Street != employeeData.CurrentAddress.Street)
                existingUser.CurrentAddress.Street = employeeData.CurrentAddress.Street;

            if (!string.IsNullOrEmpty(employeeData.CurrentAddress.City) && existingUser.CurrentAddress.City != employeeData.CurrentAddress.City)
                existingUser.CurrentAddress.City = employeeData.CurrentAddress.City;

            if (!string.IsNullOrEmpty(employeeData.CurrentAddress.State) && existingUser.CurrentAddress.State != employeeData.CurrentAddress.State)
                existingUser.CurrentAddress.State = employeeData.CurrentAddress.State;

            if (!string.IsNullOrEmpty(employeeData.CurrentAddress.PostalCode) && existingUser.CurrentAddress.PostalCode != employeeData.CurrentAddress.PostalCode)
                existingUser.CurrentAddress.PostalCode = employeeData.CurrentAddress.PostalCode;
        }

        _context.SaveChanges();
        return Ok(new { message = "Employee updated successfully!" });
    }

    [HttpGet("roles")]
    public IActionResult GetRoles()
    {
        var roles = _context.Roles.Select(r => new { r.RoleId, r.RoleName }).ToList();
        return Ok(roles);
    }

    [HttpGet("employees/{userId}")]
    public IActionResult GetEmployee(int userId)
    {
        var userDTO = userFramework.getUserInfo(userId.ToString());
        return Ok(userDTO);
    }

    [HttpGet("jobTitles")]
    public IActionResult GetJobTitles()
    {
        var jobTitles = _context.Job_Titles.Select(j => new { j.Id, j.Name }).ToList();
        return Ok(jobTitles);
    }

    /// <summary>
    /// Delete an employee
    /// </summary>
    [HttpDelete("{userId}")]
    public IActionResult DeleteEmployee(int userId)
    {
        var existingUser = _context.Users.Find(userId);
        if (existingUser == null)
            return NotFound("Employee not found");

        existingUser.DeletedTime = DateTime.Now;
        _context.Users.Update(existingUser);
        _context.SaveChanges();
        return Ok(new { message = "Employee deleted successfully!" });
    }
}
