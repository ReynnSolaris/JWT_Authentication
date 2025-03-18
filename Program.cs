using JWTAuthentication.Framework.Classes;
using JWTAuthentication.Framework.Database;
using JWTAuthentication.Framework.Interfaces;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Net;
using System.Text;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddCors((options) =>
{
    options.AddPolicy(name: "_myAllowSpecificOrigins",
        policy =>
        {
            policy.WithOrigins("http://localhost:4200",
                "https://emberframeworks.xyz",
                "https://emberframeworks.xyz/",
                "https://management.emberframeworks.xyz",
                "https://api.emberframeworks.xyz");
            policy.WithMethods("GET", "POST", "OPTIONS");
            policy.AllowAnyHeader();
        });
});
builder.Services.AddTransient<IUserRepository, UserRepository>();
builder.Services.AddTransient<ITokenService, TokenService>();
builder.Services.AddTransient<PermissionService>();
builder.Services.AddTransient<IUserPermissionRepository, UserPermissionRepository>();


IConfiguration Configuration = builder.Configuration;
bool inDev = true;

builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    options.UseMySQL(Configuration.GetConnectionString("RaspberryPi"));
});

builder.Services.AddTransient<IClaimsTransformation, CustomClaimsTransformation>();

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = Configuration["Jwt:Issuer"],
        ValidAudience = Configuration["Jwt:Issuer"],
        IssuerSigningKey = new
        SymmetricSecurityKey
        (Encoding.UTF8.GetBytes
        (Configuration["Jwt:Key"]))
    };
});


// Add services to the container.

builder.Services.AddControllers().AddJsonOptions(options =>
{
    options.JsonSerializerOptions.ReferenceHandler = System.Text.Json.Serialization.ReferenceHandler.IgnoreCycles;
    options.JsonSerializerOptions.WriteIndented = true;
    options.JsonSerializerOptions.DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull;
});
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.WebHost.ConfigureKestrel((Options) => { });
builder.WebHost.UseUrls("http://0.0.0.0:5002", "https://0.0.0.0:5003");
builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    options.KnownProxies.Add(IPAddress.Parse("192.168.1.135"));
});


var app = builder.Build();
app.UseAuthentication();
// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

//app.UseHttpsRedirection();
app.UseForwardedHeaders();
app.UseAuthorization();
app.UseCors();
app.MapControllers();

app.Run();
