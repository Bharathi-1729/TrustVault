using Microsoft.EntityFrameworkCore;
namespace TrustVault.Api;

public enum GlobalRole { Admin, Owner, Viewer }
public enum PermissionLevel { Read = 1, Edit = 2 }

public class User {
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Email { get; set; } = "";
    public string DisplayName { get; set; } = "";
    public string PasswordHash { get; set; } = "";
    public GlobalRole GlobalRole { get; set; }
    public bool IsActive { get; set; } = true;
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
}
public class Document {
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid OwnerId { get; set; }
    public string Name { get; set; } = "";
    public string? Category { get; set; }
    public string? Description { get; set; }
    public string StorageKey { get; set; } = "";   // random, never the filename
    public string ContentType { get; set; } = "";
    public long SizeBytes { get; set; }
    public string Sha256 { get; set; } = "";
    public int Version { get; set; } = 1;
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime? DeletedAtUtc { get; set; }
}
public class DocumentPermission {
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid DocumentId { get; set; }
    public Guid UserId { get; set; }
    public PermissionLevel Level { get; set; }
    public Guid GrantedByUserId { get; set; }
    public DateTime GrantedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime? RevokedAtUtc { get; set; }
    public DateTime? ExpiresAtUtc { get; set; }
    public byte[]? RowVersion { get; set; }
}
public class AuditEvent {
    public long Id { get; set; }
    public Guid? ActorUserId { get; set; }
    public string Action { get; set; } = "";
    public Guid? DocumentId { get; set; }
    public Guid? TargetUserId { get; set; }
    public DateTime OccurredAtUtc { get; set; }
    public string Outcome { get; set; } = "";
    public string? Reason { get; set; }
    public string PreviousHash { get; set; } = "";
    public string EventHash { get; set; } = "";
}

public class AppDb(DbContextOptions<AppDb> o) : DbContext(o) {
    public DbSet<User> Users => Set<User>();
    public DbSet<Document> Documents => Set<Document>();
    public DbSet<DocumentPermission> Permissions => Set<DocumentPermission>();
    public DbSet<AuditEvent> AuditEvents => Set<AuditEvent>();
    protected override void OnModelCreating(ModelBuilder m) {
        m.Entity<User>(e => { e.HasIndex(x => x.Email).IsUnique(); e.Property(x => x.GlobalRole).HasConversion<string>().HasMaxLength(20); });
        m.Entity<Document>(e => {
            e.HasQueryFilter(d => d.DeletedAtUtc == null); // soft-deleted docs vanish from every query
            e.HasOne<User>().WithMany().HasForeignKey(d => d.OwnerId).OnDelete(DeleteBehavior.Restrict);
        });
        m.Entity<DocumentPermission>(e => {
            e.Property(x => x.Level).HasConversion<string>().HasMaxLength(10);
            if (Database.IsSqlServer()) {
                e.Property(x => x.RowVersion).IsRowVersion();
                e.HasIndex(x => new { x.DocumentId, x.UserId }).IsUnique().HasFilter("[RevokedAtUtc] IS NULL"); // one active grant
            } else {
                e.HasIndex(x => new { x.DocumentId, x.UserId });
            }
            e.HasOne<Document>().WithMany().HasForeignKey(x => x.DocumentId).OnDelete(DeleteBehavior.Restrict);
            e.HasOne<User>().WithMany().HasForeignKey(x => x.UserId).OnDelete(DeleteBehavior.Restrict);
            e.HasOne<User>().WithMany().HasForeignKey(x => x.GrantedByUserId).OnDelete(DeleteBehavior.Restrict);
        });
    }
}
