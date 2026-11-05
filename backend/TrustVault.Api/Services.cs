using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
namespace TrustVault.Api;

public record Access(bool IsOwner, bool CanRead, bool CanEdit, Document? Doc);

/// Single place for ALL document authorization. Default deny.
public class AccessService(AppDb db, TimeProvider clock) {
    public async Task<Access> ForAsync(Guid userId, Guid docId) {
        var none = new Access(false, false, false, null);
        if (!await db.Users.AnyAsync(u => u.Id == userId && u.IsActive)) return none;   // disabled => deny (even owner)
        var doc = await db.Documents.FirstOrDefaultAsync(d => d.Id == docId);            // deleted docs filtered out
        if (doc is null) return none;
        if (doc.OwnerId == userId) return new(true, true, true, doc);
        var now = clock.GetUtcNow().UtcDateTime;
        var g = await db.Permissions.FirstOrDefaultAsync(p => p.DocumentId == docId && p.UserId == userId
            && p.RevokedAtUtc == null && (p.ExpiresAtUtc == null || p.ExpiresAtUtc > now));
        if (g is null) return none;
        return new(false, true, g.Level == PermissionLevel.Edit, doc);                   // Read grant never implies Edit
    }
}

public class AuditService(AppDb db, TimeProvider clock) {
    static readonly SemaphoreSlim Gate = new(1, 1); // single-instance chain ordering; see THREATS.md
    public async Task WriteAsync(string action, Guid? actor, Guid? doc, Guid? target, string outcome, string? reason = null) {
        await Gate.WaitAsync();
        try {
            var prev = await db.AuditEvents.OrderByDescending(e => e.Id).Select(e => e.EventHash).FirstOrDefaultAsync() ?? "GENESIS";
            var e = new AuditEvent { ActorUserId = actor, Action = action, DocumentId = doc, TargetUserId = target,
                OccurredAtUtc = clock.GetUtcNow().UtcDateTime, Outcome = outcome, Reason = reason, PreviousHash = prev };
            e.EventHash = Hash(e);
            db.AuditEvents.Add(e);
            await db.SaveChangesAsync();
        } finally { Gate.Release(); }
    }
    public static string Hash(AuditEvent e) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(
        $"{e.PreviousHash}|{e.ActorUserId}|{e.Action}|{e.DocumentId}|{e.TargetUserId}|{e.OccurredAtUtc.Ticks}|{e.Outcome}|{e.Reason}")));
    public async Task<(bool Ok, long? BrokenAtId)> VerifyAsync() {
        var prev = "GENESIS";
        await foreach (var e in db.AuditEvents.AsNoTracking().OrderBy(x => x.Id).AsAsyncEnumerable()) {
            if (e.PreviousHash != prev || e.EventHash != Hash(e)) return (false, e.Id);
            prev = e.EventHash;
        }
        return (true, null);
    }
}

public class FileStore(IConfiguration cfg) {
    const long MaxBytes = 10 * 1024 * 1024;
    static readonly Dictionary<string, (string Ct, byte[] Sig)> Allowed = new() {
        [".pdf"] = ("application/pdf", "%PDF"u8.ToArray()),
        [".png"] = ("image/png", new byte[] { 0x89, 0x50, 0x4E, 0x47 }),
        [".jpg"] = ("image/jpeg", new byte[] { 0xFF, 0xD8, 0xFF }),
        [".jpeg"] = ("image/jpeg", new byte[] { 0xFF, 0xD8, 0xFF }),
        [".docx"] = ("application/vnd.openxmlformats-officedocument.wordprocessingml.document", new byte[] { 0x50, 0x4B, 3, 4 }),
        [".xlsx"] = ("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", new byte[] { 0x50, 0x4B, 3, 4 }),
    };
    string Root => Path.GetFullPath(cfg["Storage:Root"] ?? "private-storage");

    public async Task<(string? Error, string Name, string ContentType)> ValidateAsync(IFormFile f) {
        if (f.Length == 0) return ("Empty file", "", "");
        if (f.Length > MaxBytes) return ("File too large (max 10 MB)", "", "");
        var name = new string(Path.GetFileName(f.FileName).Where(c => !char.IsControl(c)).ToArray());
        if (name.Length is 0 or > 200) return ("Invalid filename", "", "");
        if (!Allowed.TryGetValue(Path.GetExtension(name).ToLowerInvariant(), out var t)) return ("File type not allowed", "", "");
        var head = new byte[t.Sig.Length];
        await using var s = f.OpenReadStream();
        if (await s.ReadAsync(head) != head.Length || !head.SequenceEqual(t.Sig)) return ("File content does not match its type", "", "");
        return (null, name, t.Ct);   // content-type is server-decided, never client-declared
    }
    public async Task<(string Key, string Sha)> SaveAsync(IFormFile f) {
        Directory.CreateDirectory(Root);
        var key = Guid.NewGuid().ToString("N");
        var path = Path.Combine(Root, key);
        await using (var o = File.Create(path)) await f.CopyToAsync(o);
        await using var r = File.OpenRead(path);
        return (key, Convert.ToHexString(await SHA256.HashDataAsync(r)));
    }
    public Stream Open(string key) => File.OpenRead(Path.Combine(Root, Path.GetFileName(key)));
    public void Delete(string key) { try { File.Delete(Path.Combine(Root, Path.GetFileName(key))); } catch { } }
}
