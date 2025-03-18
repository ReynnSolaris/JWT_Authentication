using System.ComponentModel.DataAnnotations;

namespace JWTAuthentication.Framework.Models
{
    public class UserModel
    {
        [Required]
        public string UserName { get; set; }

        [Required]
        public string Password { get; set; }

    }
}
