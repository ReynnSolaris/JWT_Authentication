namespace JWTAuthentication.Framework.Classes;

using JWTAuthentication.Framework.Database;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using System.Threading.Tasks;

public class CustomClaimsTransformation : IClaimsTransformation
{
    private readonly ApplicationDbContext _context;

    public CustomClaimsTransformation(ApplicationDbContext context)
    {
        _context = context;
    }

    public async Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal)
    {
        var identity = (ClaimsIdentity)principal.Identity;
        var userName = identity.Name;

        if (string.IsNullOrEmpty(userName))
        {
            return principal;
        }

        var user = _context.Users
            .Include(u => u.Role)
            .FirstOrDefault(u => u.UserName == userName);

        if (user != null && user.Role != null)
        {
            var existingRoles = identity.Claims.Where(c => c.Type == ClaimTypes.Role).ToList();
            foreach (var role in existingRoles)
            {
                identity.RemoveClaim(role);
            }
            identity.AddClaim(new Claim(ClaimTypes.Role, user.Role.RoleName));
        }

        return principal;
    }
}
