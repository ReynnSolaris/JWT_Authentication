using JWTAuthentication.Framework.Classes;
using JWTAuthentication.Framework.Database;
using JWTAuthentication.Framework.Interfaces;
using JWTAuthentication.Framework.Models;
using MaxMind.GeoIP2;
using MaxMind.GeoIP2.Exceptions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Text;
// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace JWTAuthentication.Controllers
{
    public class TokenInfo
    {
        public string GivenName { get; set; }
        public string Role { get; set; }
        public string Name { get; set; }
    }

    [EnableCors]
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly IConfiguration _config;
        private readonly IUserRepository _userRepository;
        private readonly ITokenService _tokenService;
        private readonly ApplicationDbContext _context;
        private readonly IFailedLoginRepository _failedLoginRepository;
        private readonly PermissionService _permissionService;
        private readonly SHA_Manager sha = new();

        public TokenInfo ReadTokenInfo(string authorization)
        {
            var token = authorization.Substring("Bearer ".Length).Trim();
            var secretKey = _config["Jwt:Key"];

            var principal = JwtHelper.DecodeJwtToken(token, secretKey);

            if (principal == null)
            {
                return new TokenInfo()
                {
                    GivenName = "",
                    Role = "",
                    Name = ""
                };
            }

            var givenName = JwtHelper.GetClaimValue(principal, ClaimTypes.GivenName);
            var role = JwtHelper.GetClaimValue(principal, ClaimTypes.Role);
            var name = JwtHelper.GetClaimValue(principal, ClaimTypes.Name);

            var result = new TokenInfo()
            {
                GivenName = givenName,
                Role = role,
                Name = name
            };
            return result;
        }

        public AuthenticationController(IConfiguration config, ITokenService tokenService, IUserRepository userRepository, ApplicationDbContext context, PermissionService permissionService, IFailedLoginRepository failedLoginRepository)
        {
            _config = config;
            _tokenService = tokenService;
            _userRepository = userRepository;
            _context = context;
            _permissionService = permissionService;
            _failedLoginRepository = failedLoginRepository;
        }

        private UserDTO GetUser(UserModel userModel)
        {
            // Write your code here to authenticate the user     
            return _userRepository.GetUser(userModel);
        }

        private async Task addFailedLoginAsync(IPAddress IP, string UserName)
        {
            try
            {
                using (var client = new WebServiceClient(int.Parse(_config["GEO_IP_ACC_ID"]), _config["GEO_IP_License"], host: "geolite.info"))
                {
                    // You can also use `client.CityAsync` or `client.InsightsAsync`
                    // `client.InsightsAsync` is not available to GeoLite users
                    var response = await client.CityAsync(IP);

                    await _failedLoginRepository.InsertAttempt(new FailedLoginAttempt
                    {
                        IPAddress = IP.ToString(),
                        CountryCode = response.Country.IsoCode,
                        Region = response.Postal.Code,
                        City = response.City.Name,
                        AttemptTime = DateTime.UtcNow,
                        UsernameAttempted = UserName
                    });
                }
            } catch (AddressNotFoundException e)
            {
                using (HttpClient http = new HttpClient())
                {
                    string sIPAddress = await http.GetStringAsync("https://api.ipify.org");
                    using (var client = new WebServiceClient(int.Parse(_config["GEO_IP_ACC_ID"]), _config["GEO_IP_License"], host: "geolite.info"))
                    {
                        // You can also use `client.CityAsync` or `client.InsightsAsync`
                        // `client.InsightsAsync` is not available to GeoLite users
                        var response = await client.CityAsync(sIPAddress);

                        await _failedLoginRepository.InsertAttempt(new FailedLoginAttempt
                        {
                            IPAddress = sIPAddress,
                            CountryCode = response.Country.IsoCode,
                            Region = response.Postal.Code,
                            City = response.City.Name,
                            AttemptTime = DateTime.UtcNow,
                            UsernameAttempted = UserName
                        });
                    }
                }

            }
        }

        // GET api/<AuthenticationController>/5
        [HttpPost("GetToken")]
        public async Task<IActionResult> PostAsync(UserModel userModel)
        {
            /*
             GET IP // CHECK DB
             */

            var IP = Request.HttpContext.Connection.RemoteIpAddress;
            if (IP == null)
            {
                return StatusCode(429, "Failed IP");
            }

            if (IP.ToString().StartsWith("192.168") || IP.ToString().Equals("127.0.0.1"))
            {
                using (HttpClient http = new HttpClient())
                {
                    string sIPAddress = await http.GetStringAsync("https://api.ipify.org");
                    IP = IPAddress.Parse(sIPAddress);
                }
            }

            var attempts = await _failedLoginRepository.GetAttempts(IP.ToString(), TimeSpan.FromMinutes(30));
            Debug.Print($"{attempts.Count} attempts; found");
            if (attempts.Count >= 5)
            {
                Debug.Print($"failed attempts...");
                return StatusCode(429, "Too many failed login attempts. Try again later.");
            }
            var validUser = GetUser(userModel);
            if (validUser == null)
            {
                await addFailedLoginAsync(IP, userModel.UserName);
                return Unauthorized("Invalid Password, or Username Provided!\nThis attempt has been logged.");
            }
            if (validUser.DeletedTime != null)
            {
                return Unauthorized("User account is terminated!\nPlease contact the system administrator.");
            }
            var generatedToken = _tokenService.BuildToken(_config["Jwt:Key"], _config["Jwt:Issuer"], validUser);
            if (generatedToken != null)
            {
                validUser.RefreshToken = _tokenService.GenerateRefreshToken();
                validUser.RefreshTokenExpiryTime = DateTime.Now.AddDays(7); // 1 day
                _userRepository.UpdateUser(validUser);

                return Ok(new
                {
                    Token = generatedToken,
                    RefreshToken = validUser.RefreshToken
                });
            }
            await addFailedLoginAsync(IP, userModel.UserName);
            return Unauthorized("Invalid Password, or Username Provided!\nThis attempt has been logged.");
        }

        [HttpPost("RefreshToken")]
        public IActionResult Refresh([FromBody] TokenRequest tokenRequest)
        {
            if (tokenRequest is null)
            {
                Console.WriteLine("🔴 ERROR: Token request is NULL");
                return Unauthorized("Invalid client request");
            }

            string accessToken = tokenRequest.Token;
            string refreshToken = tokenRequest.RefreshToken;
            Debug.WriteLine("ACCESS -> " + accessToken);
            Debug.WriteLine("REFRESH -> " + refreshToken);
            var secretKey = _config["Jwt:Key"];

            var principal = JwtHelper.DecodeJwtToken(accessToken, secretKey);
            if (principal == null)
            {
                return Unauthorized("Invalid access token or refresh token");
            }
            var userName = JwtHelper.GetClaimValue(principal, ClaimTypes.Name);

            if (string.IsNullOrEmpty(userName))
            {
                return Unauthorized("Invalid access token or refresh token");
            }

            var user = _context.Users
                .Include(u => u.Role) 
                .SingleOrDefault(u => u.UserName.ToLower() == userName.ToLower());
            if (user == null)
            {
                return Unauthorized();
            }

            if (_tokenService == null)
            {
                return StatusCode(500, "Token service is not initialized");
            }

            if (_config == null)
            {
                return StatusCode(500, "Configuration is not initialized");
            }

            if (string.IsNullOrEmpty(_config["Jwt:Key"]))
            {
                return StatusCode(500, "JWT Key is missing");
            }

            if (string.IsNullOrEmpty(_config["Jwt:Issuer"]))
            {
                return StatusCode(500, "JWT Issuer is missing");
            }

            var newAccessToken = _tokenService.BuildToken(_config["Jwt:Key"], _config["Jwt:Issuer"], user);
            var newRefreshToken = _tokenService.GenerateRefreshToken();

            user.RefreshToken = newRefreshToken;
            user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(7);
            _userRepository.UpdateUser(user);

            return Ok(new
            {
                Token = newAccessToken,
                RefreshToken = newRefreshToken
            });
        }


        [Authorize(Roles = "developer")]
        [HttpGet()]
        public IActionResult Get()
        {
            return Ok();
        }

        [HttpPost(), Route("CheckToken")]
        public IActionResult CheckPost([FromBody] string token)
        {
            if (_tokenService.ValidateToken(_config["Jwt:Key"].ToString(), _config["Jwt:Issuer"].ToString(), token))
            {
                return Ok();
            }
            return Unauthorized();
        }
        [Authorize(Roles = "Console")]
        [HttpPost("AssignRoleToUser")]
        public IActionResult AssignRoleToUser([FromBody] AssignRoleModel model)
        {
            var user = _context.Users.SingleOrDefault(u => u.UserName == model.UserName);
            var role = _context.Roles.SingleOrDefault(r => r.RoleName == model.RoleName);

            if (user == null || role == null)
            {
                return Unauthorized("User or role not found.");
            }

            user.RoleId = role.RoleId;
            _context.SaveChanges();

            return Ok($"Role '{role.RoleName}' assigned to user '{user.UserName}'.");
        }

        [HttpGet("SaltPassword")]
        public IActionResult SaltPassword(string password)
        {
            string salt = "";
            string passwordHash = "";
            if (!string.IsNullOrEmpty(password))
            {
                passwordHash = sha.HashPassword(password, out salt);
            }
            return Ok(new
            {
                passwordHash,
                salt
            });
        }

        [HttpGet("ReadToken")]
        public IActionResult ReadToken([FromHeader] string authorization)
        {
            if (string.IsNullOrEmpty(authorization) || !authorization.StartsWith("Bearer "))
            {
                return Unauthorized("Invalid token");
            }

            var token = authorization.Substring("Bearer ".Length).Trim();
            var secretKey = _config["Jwt:Key"];

            var principal = JwtHelper.DecodeJwtToken(token, secretKey);

            if (principal == null)
            {
                return Unauthorized();
            }

            var givenName = JwtHelper.GetClaimValue(principal, ClaimTypes.GivenName);
            var role = JwtHelper.GetClaimValue(principal, ClaimTypes.Role);
            var name = JwtHelper.GetClaimValue(principal, ClaimTypes.Name);

            var result = new
            {
                GivenName = givenName,
                Role = role,
                Name = name
            };

            return Ok(result);
        }

        [HttpPost("ChangePassword")]
        public IActionResult ChangePassword([FromHeader] string authorization, [FromHeader] string token, [FromHeader] string newPassword, [FromHeader] string oldPassword)
        {
            if (!_tokenService.ValidateToken(_config["Jwt:Key"].ToString(), _config["Jwt:Issuer"].ToString(), token))
            {
                System.Diagnostics.Debug.WriteLine("Invalid token");
                return Unauthorized();
            }

            var user = ReadTokenInfo(authorization).Name;

            if (user.Equals(null))
            {
                System.Diagnostics.Debug.WriteLine("No user name.");
                return Unauthorized();
            }
                

            var userModel = _context.Users.SingleOrDefault(u => u.UserName.ToLower() == user.ToLower());
            if (userModel == null)
            {
                System.Diagnostics.Debug.WriteLine("No user found.");
                return Unauthorized();
            }
            bool isPasswordValid = sha.VerifyPassword(oldPassword, userModel.Password, userModel.Salt);
            if (!isPasswordValid)
            {
                return Unauthorized(
                        new {
                            msg = "pass_error"
                        }
                    );
            }

            string salt = "";
            string passwordHash = "";
            if (!string.IsNullOrEmpty(newPassword))
            {
                passwordHash = sha.HashPassword(newPassword, out salt);
            } else
            {
                return Unauthorized(
                        new {
                            msg = "pass_notvalid"
                        }
                    );
            }

            userModel.Salt = salt;
            userModel.Password = passwordHash;
            _context.SaveChanges();

            return Ok(
                    new {
                        msg = "pass_changed"
                    }
                );
        }

            // Debug endpoint to get user info and permissions
        [HttpGet("GetUserInfo/")]
        public IActionResult GetUserInfo([FromHeader] string userName, [FromHeader] string token)
        {
            if (!_tokenService.ValidateToken(_config["Jwt:Key"].ToString(), _config["Jwt:Issuer"].ToString(), token))
            {
                return Unauthorized();
            }

            var user = _context.Users
                .Include(u => u.JobTitles)
                .Include(u => u.CurrentAddress)
                .Include(u => u.EmergencyContacts)
                .Include(u => u.PayInformation)
                .Include(u => u.Role)
                .ThenInclude(r => r.RolePermissions)
                .ThenInclude(rp => rp.Permission)
                .SingleOrDefault(u => u.UserName.ToLower() == userName.ToLower());

            if (user == null)
            {
                return NotFound("User not found");
            }

            if (user.DeletedTime != null)
            {
                return Unauthorized("User is terminated.");
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
                    PosterName = $"{a.Poster.FirstName} " + (a.Poster.PreferredName != "" ? "\""+ a.Poster.PreferredName +"\" " : "") + $"{a.Poster.LastName}",
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
                EmergencyContacts = emergencyContacts
            };

            return Ok(userInfo);
        }

        // Debug endpoint to list all roles and their permissions
        [Authorize(Roles = "Console")]
        [HttpGet("ListRolesAndPermissions")]
        public IActionResult ListRolesAndPermissions()
        {
            var roles = _context.Roles.ToList();

            var rolesWithPermissions = roles.Select(role => new
            {
                roleName = role.RoleName,
                permissions = _permissionService.GetRolePermissions(role)
            }).ToList();

            return Ok(rolesWithPermissions);
        }


        public class AssignRoleModel
        {
            public string UserName { get; set; }
            public string RoleName { get; set; }
        }

        public class TokenRequest
        {
            public string Token { get; set; }
            public string RefreshToken { get; set; }
        }
    }
}
