using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

public class ApiFactory : WebApplicationFactory<Program> {
    private readonly string _dbPath = Path.Combine(Path.GetTempPath(), $"trustvault_test_{Guid.NewGuid():N}.db");
    protected override void ConfigureWebHost(IWebHostBuilder b) {
        var conn = Environment.GetEnvironmentVariable("TRUSTVAULT_TEST_CONN")
            ?? $"Data Source={_dbPath}";
        b.UseSetting("ConnectionStrings:Default", conn);
        b.UseSetting("RateLimit:Login", "1000");
        b.UseSetting("Storage:Root", Path.Combine(Path.GetTempPath(), "tv-" + Guid.NewGuid()));
    }
}

public class AuthzTests(ApiFactory f) : IClassFixture<ApiFactory> {
    async Task<HttpClient> As(string who) {
        var c = f.CreateClient();
        (await c.PostAsJsonAsync("/api/auth/login", new { email = $"{who}@trustvault.local", password = char.ToUpper(who[0]) + who[1..] + "#12345" })).EnsureSuccessStatusCode();
        return c;
    }
    static MultipartFormDataContent Pdf(byte[] bytes) {
        var m = new MultipartFormDataContent(); var fc = new ByteArrayContent(bytes); fc.Headers.ContentType = new("application/pdf"); m.Add(fc, "file", "a.pdf"); return m;
    }
    async Task<Guid> Upload(HttpClient owner) {
        var r = await owner.PostAsync("/api/documents", Pdf(Encoding.ASCII.GetBytes("%PDF-1.4 hello")));
        r.EnsureSuccessStatusCode();
        return (await r.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetGuid();
    }
    static Task<HttpResponseMessage> Patch(HttpClient c, string url, object body) =>
        c.SendAsync(new HttpRequestMessage(HttpMethod.Patch, url) { Content = JsonContent.Create(body) });
    async Task<Guid> MyId(HttpClient c) => (await c.GetFromJsonAsync<JsonElement>("/api/users/me")).GetProperty("id").GetGuid();

    [Fact] public async Task UserWithoutGrant_CannotDownload_IDOR() {
        var owner = await As("owner"); var viewer = await As("viewer"); var id = await Upload(owner);
        Assert.Equal(HttpStatusCode.NotFound, (await viewer.GetAsync($"/api/documents/{id}/download")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await viewer.GetAsync($"/api/documents/{id}")).StatusCode);
    }
    [Fact] public async Task RevokedGrant_IsDeniedOnNextRequest() {
        var owner = await As("owner"); var viewer = await As("viewer"); var id = await Upload(owner); var vid = await MyId(viewer);
        (await owner.PutAsJsonAsync($"/api/documents/{id}/permissions/{vid}", new { level = "Read" })).EnsureSuccessStatusCode();
        Assert.Equal(HttpStatusCode.OK, (await viewer.GetAsync($"/api/documents/{id}/download")).StatusCode);
        (await owner.DeleteAsync($"/api/documents/{id}/permissions/{vid}")).EnsureSuccessStatusCode();
        Assert.Equal(HttpStatusCode.NotFound, (await viewer.GetAsync($"/api/documents/{id}/download")).StatusCode);
    }
    [Fact] public async Task ReadGrantee_CannotEditOrShare() {
        var owner = await As("owner"); var viewer = await As("viewer"); var id = await Upload(owner); var vid = await MyId(viewer);
        (await owner.PutAsJsonAsync($"/api/documents/{id}/permissions/{vid}", new { level = "Read" })).EnsureSuccessStatusCode();
        Assert.Equal(HttpStatusCode.Forbidden, (await Patch(viewer, $"/api/documents/{id}", new { name = "x" })).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await viewer.PutAsJsonAsync($"/api/documents/{id}/permissions/{vid}", new { level = "Edit" })).StatusCode);
    }
    [Fact] public async Task FakePdf_And_ViewerUpload_AreRejected() {
        var owner = await As("owner"); var viewer = await As("viewer");
        Assert.Equal(HttpStatusCode.BadRequest, (await owner.PostAsync("/api/documents", Pdf(Encoding.ASCII.GetBytes("not a pdf")))).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await viewer.PostAsync("/api/documents", Pdf(Encoding.ASCII.GetBytes("%PDF-1.4")))).StatusCode);
    }
    [Fact] public async Task Admin_HasNoDocumentContentAccess_And_AuditChainVerifies() {
        var owner = await As("owner"); var admin = await As("admin"); var id = await Upload(owner);
        Assert.Equal(HttpStatusCode.NotFound, (await admin.GetAsync($"/api/documents/{id}/download")).StatusCode);
        Assert.True((await admin.GetFromJsonAsync<JsonElement>("/api/admin/audit/verify")).GetProperty("ok").GetBoolean());
    }

    [Fact] public async Task Search_NeverLeaksOthersDocuments() {
        var owner = await As("owner"); var viewer = await As("viewer"); var id = await Upload(owner); var oid = await MyId(owner);
        var r = await viewer.GetFromJsonAsync<JsonElement>($"/api/documents?ownerId={oid}&pageSize=100");
        Assert.DoesNotContain(r.GetProperty("items").EnumerateArray(), d => d.GetProperty("id").GetGuid() == id);
    }
    [Fact] public async Task DisabledUser_ExistingSession_IsRejected() {
        var viewer = await As("viewer"); var admin = await As("admin"); var vid = await MyId(viewer);
        try {
            (await Patch(admin, $"/api/users/{vid}/status", new { isActive = false })).EnsureSuccessStatusCode();
            Assert.Equal(HttpStatusCode.Unauthorized, (await viewer.GetAsync("/api/users/me")).StatusCode);
        } finally { await Patch(admin, $"/api/users/{vid}/status", new { isActive = true }); }
    }
    [Fact] public async Task TraversalFilename_IsSanitized() {
        var owner = await As("owner"); var m = new MultipartFormDataContent();
        m.Add(new ByteArrayContent(Encoding.ASCII.GetBytes("%PDF-1.4 x")), "file", "..\\..\\evil.pdf");
        var r = await owner.PostAsync("/api/documents", m); r.EnsureSuccessStatusCode();
        var name = (await r.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("name").GetString()!;
        Assert.DoesNotContain("..", name); Assert.DoesNotContain("\\", name);
    }
    [Fact] public async Task PublicRegistration_CannotAssignAdminRole_And_OwnerRegistrationSucceeds() {
        var client = f.CreateClient();
        var adminReg = await client.PostAsJsonAsync("/api/auth/register", new { displayName = "Hacker", email = "hacker@test.local", password = "Password123!", role = "Admin" });
        Assert.Equal(HttpStatusCode.BadRequest, adminReg.StatusCode);

        var ownerReg = await client.PostAsJsonAsync("/api/auth/register", new { displayName = "New Owner", email = $"newowner_{Guid.NewGuid():N}@test.local", password = "Password123!", role = "Owner" });
        Assert.Equal(HttpStatusCode.Created, ownerReg.StatusCode);
    }
    [Fact] public async Task UnauthorizedUser_CannotDeleteOrEdit_Document() {
        var owner = await As("owner"); var viewer = await As("viewer"); var id = await Upload(owner);
        Assert.Equal(HttpStatusCode.NotFound, (await viewer.DeleteAsync($"/api/documents/{id}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await Patch(viewer, $"/api/documents/{id}", new { name = "Hacked" })).StatusCode);
    }
    [Fact] public async Task StatsAndSecurityEvents_EnforceRolePolicies() {
        var admin = await As("admin"); var viewer = await As("viewer");
        Assert.Equal(HttpStatusCode.OK, (await admin.GetAsync("/api/stats/admin")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await admin.GetAsync("/api/admin/security-events")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await viewer.GetAsync("/api/stats/admin")).StatusCode);
    }
    [Fact] public async Task DocumentDetails_ReturnsMetadata_ForAuthorizedUser() {
        var owner = await As("owner"); var id = await Upload(owner);
        var r = await owner.GetAsync($"/api/documents/{id}/details");
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        var json = await r.Content.ReadFromJsonAsync<JsonElement>();
        Assert.True(json.GetProperty("isOwner").GetBoolean());
        Assert.NotEmpty(json.GetProperty("sha256").GetString()!);
    }
}
