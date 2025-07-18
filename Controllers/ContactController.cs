using JWTAuthentication.Framework.Classes;
using JWTAuthentication.Framework.Models;
using Microsoft.AspNetCore.Mvc;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace JWTAuthentication.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ContactController : ControllerBase
    {
        private readonly EmailService _emailService;

        public ContactController(EmailService emailService)
        {
            _emailService = emailService;
        }

        [HttpPost]
        public async Task<IActionResult> SendForm(ContactFormDTO dto)
        {
            await _emailService.SendContactFormEmails(dto.FullName, dto.Phone, dto.Email, dto.Message);
            return Ok(new { success = true });
        }
    }
}
