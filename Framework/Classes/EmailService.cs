using System.Net;
using System.Net.Mail;
using Microsoft.Extensions.Configuration;

namespace JWTAuthentication.Framework.Classes
{
    public class EmailService
    {
        private readonly IConfiguration _config;

        public EmailService(IConfiguration config)
        {
            _config = config;
        }
        public async Task SendContactFormEmails(string fullName, string phone, string email, string message)
        {
            // Sanitize
            fullName = WebUtility.HtmlEncode(fullName);
            phone = WebUtility.HtmlEncode(phone);
            email = WebUtility.HtmlEncode(email);
            message = WebUtility.HtmlEncode(message);

            var timestamp = DateTime.Now.ToString("f");

            // Load templates
            var internalHtml = LoadTemplate("Templates/ContactNotificationTemplate.html")
                .Replace("{{FULL_NAME}}", fullName)
                .Replace("{{PHONE}}", phone)
                .Replace("{{EMAIL}}", email)
                .Replace("{{MESSAGE}}", message)
                .Replace("{{TIMESTAMP}}", timestamp);

            var userReplyHtml = LoadTemplate("Templates/AutoReplyTemplate.html")
                .Replace("{{FULL_NAME}}", fullName)
                .Replace("{{EMAIL}}", email)
                .Replace("{{MESSAGE}}", message);

            using var smtp = new SmtpClient(_config["EmailSettings:SmtpServer"])
            {
                Port = int.Parse(_config["EmailSettings:SmtpPort"]),
                Credentials = new NetworkCredential(_config["EmailSettings:SenderEmail"], _config["EmailSettings:Password"]),
                EnableSsl = true
            };

            // Email to you
            var mailToYou = new MailMessage
            {
                From = new MailAddress(_config["EmailSettings:SenderEmail"], "Contact Form"),
                Subject = "New Contact Form Submission",
                Body = internalHtml,
                IsBodyHtml = true
            };
            mailToYou.To.Add(_config["EmailSettings:SupportTeamEmail"]);
            await smtp.SendMailAsync(mailToYou);

            // Auto-reply to user
            var mailToUser = new MailMessage
            {
                From = new MailAddress(_config["EmailSettings:SenderEmail"], "EmberFrameworks LLC"),
                Subject = "Thanks for contacting us!",
                Body = userReplyHtml,
                IsBodyHtml = true
            };
            mailToUser.To.Add(email);
            await smtp.SendMailAsync(mailToUser);
        }

        private string LoadTemplate(string path)
        {
            return File.ReadAllText(Path.Combine(AppContext.BaseDirectory, path));
        }

    }
}
