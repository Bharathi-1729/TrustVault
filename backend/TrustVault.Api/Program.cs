using System.Security.Claims;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.RateLimiting;
using System.Threading.RateLimiting;
using Microsoft.EntityFrameworkCore;
using TrustVault.Api;

var b = WebApplication.CreateBuilder(args);
var connStr = b.Configuration.GetConnectionString("Default") ?? "Data Source=trustvault.db";
b.Services.AddDbContext<AppDb>(o => {
    if (connStr.Contains("Data Source=", StringComparison.OrdinalIgnoreCase) || connStr.EndsWith(".db", StringComparison.OrdinalIgnoreCase)) {
        o.UseSqlite(connStr);
    } else {
        o.UseSqlServer(connStr);
    }
});
b.Services.AddSingleton(TimeProvider.System);
b.Services.AddSingleton<FileStore>();
b.Services.AddScoped<AccessService>();
b.Services.AddScoped<AuditService>();
b.Services.AddScoped<IPasswordHasher<User>, PasswordHasher<User>>();
b.Services.ConfigureHttpJsonOptions(o => o.SerializerOptions.Converters.Add(new JsonStringEnumConverter()));
b.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme).AddCookie(o => {
    o.Cookie.HttpOnly = true;
    o.Cookie.SameSite = SameSiteMode.Strict;                       // CSRF defense
    o.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;      // behind HTTPS in prod
    o.Events.OnRedirectToLogin = c => { c.Response.StatusCode = 401; return Task.CompletedTask; };
    o.Events.OnRedirectToAccessDenied = c => { c.Response.StatusCode = 403; return Task.CompletedTask; };
    o.Events.OnValidatePrincipal = async c => {                    // disabled user's old session dies here
        var id = c.Principal!.GetId();
        var db = c.HttpContext.RequestServices.GetRequiredService<AppDb>();
        if (!await db.Users.AnyAsync(u => u.Id == id && u.IsActive)) { c.RejectPrincipal(); await c.HttpContext.SignOutAsync(); }
    };
});
b.Services.AddAuthorization(o => o.AddPolicy("Admin", p => p.RequireRole("Admin")));
b.Services.AddRateLimiter(o => {
    o.RejectionStatusCode = 429;
    o.AddPolicy("login", ctx => RateLimitPartition.GetFixedWindowLimiter(          // per client IP
        ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown",
        _ => new FixedWindowRateLimiterOptions { PermitLimit = ctx.RequestServices.GetRequiredService<IConfiguration>().GetValue("RateLimit:Login", 10), Window = TimeSpan.FromMinutes(1) }));
});

var app = b.Build();
if (!app.Environment.IsDevelopment()) { app.UseHsts(); app.UseHttpsRedirection(); }
app.Use(async (c, n) => { c.Response.Headers["X-Content-Type-Options"] = "nosniff"; await n(); });
app.UseDefaultFiles(); app.UseStaticFiles();   // serves wwwroot/index.html (the UI)
app.UseRateLimiter(); app.UseAuthentication(); app.UseAuthorization();
Endpoints.Map(app);

using (var scope = app.Services.CreateScope()) {            // MVP: EnsureCreated. Switch to EF migrations before real use.
    var db = scope.ServiceProvider.GetRequiredService<AppDb>();
    await db.Database.EnsureCreatedAsync();
    if (app.Environment.IsDevelopment() && !await db.Users.AnyAsync()) {
        var h = scope.ServiceProvider.GetRequiredService<IPasswordHasher<User>>();
        void Add(string e, string n, GlobalRole r, string pw) { var u = new User { Email = e, DisplayName = n, GlobalRole = r }; u.PasswordHash = h.HashPassword(u, pw); db.Users.Add(u); }
        Add("admin@trustvault.local", "Admin", GlobalRole.Admin, "Admin#12345");
        Add("owner@trustvault.local", "Owner", GlobalRole.Owner, "Owner#12345");
        Add("viewer@trustvault.local", "Viewer", GlobalRole.Viewer, "Viewer#12345");
        await db.SaveChangesAsync();
    }
}
app.Run();
public partial class Program { }
