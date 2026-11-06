CREATE TABLE "audit_logs" (
	"sequence" bigint PRIMARY KEY,
	"id" text NOT NULL UNIQUE,
	"timestamp" text NOT NULL,
	"user_id" text,
	"username" text,
	"action" text NOT NULL,
	"document_id" text,
	"ip_address" text,
	"status" text NOT NULL,
	"details" text NOT NULL,
	"prev_hash" text NOT NULL,
	"current_hash" text NOT NULL UNIQUE,
	"user_agent" text,
	CONSTRAINT "audit_status" CHECK ("status" in ('success','failure','denied')),
	CONSTRAINT "audit_details" CHECK (jsonb_typeof("details"::jsonb) = 'object')
);
--> statement-breakpoint
CREATE TABLE "document_permissions" (
	"id" text PRIMARY KEY,
	"document_id" text NOT NULL,
	"user_id" text NOT NULL,
	"granted_by" text NOT NULL,
	"permission" text NOT NULL,
	"granted_at" text NOT NULL,
	"expires_at" text,
	"revoked_at" text,
	CONSTRAINT "permissions_type" CHECK ("permission" in ('read','edit')),
	CONSTRAINT "permissions_expiry" CHECK ("expires_at" is null or "expires_at" > "granted_at")
);
--> statement-breakpoint
CREATE TABLE "documents" (
	"id" text PRIMARY KEY,
	"owner_id" text NOT NULL,
	"storage_key" text NOT NULL UNIQUE,
	"name" text NOT NULL,
	"description" text DEFAULT '' NOT NULL,
	"category" text DEFAULT 'general' NOT NULL,
	"mime_type" text NOT NULL,
	"size_bytes" bigint NOT NULL,
	"sha256" text NOT NULL,
	"scan_status" text DEFAULT 'pending' NOT NULL,
	"created_at" text NOT NULL,
	"updated_at" text NOT NULL,
	"deleted_at" text,
	CONSTRAINT "documents_name" CHECK (length(trim("name")) between 1 and 255),
	CONSTRAINT "documents_description" CHECK (length("description") <= 2000),
	CONSTRAINT "documents_category" CHECK (length(trim("category")) between 1 and 64),
	CONSTRAINT "documents_size" CHECK ("size_bytes" >= 0),
	CONSTRAINT "documents_scan" CHECK ("scan_status" in ('pending','approved','rejected'))
);
--> statement-breakpoint
CREATE TABLE "login_attempts" (
	"id" text PRIMARY KEY,
	"username_key" text NOT NULL,
	"source_ip" text NOT NULL,
	"attempted_at" text NOT NULL,
	"outcome" text NOT NULL,
	CONSTRAINT "attempts_outcome" CHECK ("outcome" in ('failed','success','blocked'))
);
--> statement-breakpoint
CREATE TABLE "registration_invites" (
	"id" text PRIMARY KEY,
	"token_hash" text NOT NULL UNIQUE,
	"role" text DEFAULT 'viewer' NOT NULL,
	"created_at" text NOT NULL,
	"expires_at" text NOT NULL,
	"consumed_at" text,
	"created_by" text,
	CONSTRAINT "invites_role" CHECK ("role" in ('administrator','document_owner','viewer')),
	CONSTRAINT "invites_expiry" CHECK ("expires_at" > "created_at")
);
--> statement-breakpoint
CREATE TABLE "server_sessions" (
	"sid_hash" text PRIMARY KEY,
	"user_id" text NOT NULL,
	"auth_version" integer NOT NULL,
	"expires_at" text NOT NULL,
	"created_at" text NOT NULL
);
--> statement-breakpoint
CREATE TABLE "users" (
	"id" text PRIMARY KEY,
	"email" text NOT NULL UNIQUE,
	"name" text NOT NULL,
	"password_hash" text NOT NULL,
	"role" text DEFAULT 'viewer' NOT NULL,
	"status" text DEFAULT 'active' NOT NULL,
	"auth_version" integer DEFAULT 1 NOT NULL,
	"created_at" text NOT NULL,
	"updated_at" text NOT NULL,
	CONSTRAINT "users_role" CHECK ("role" in ('administrator','document_owner','viewer')),
	CONSTRAINT "users_status" CHECK ("status" in ('active','disabled')),
	CONSTRAINT "users_email" CHECK ("email" = lower(trim("email")) and length("email") between 3 and 254),
	CONSTRAINT "users_name" CHECK (length(trim("name")) between 1 and 120),
	CONSTRAINT "users_auth_version" CHECK ("auth_version" > 0)
);
--> statement-breakpoint
CREATE INDEX "audit_actor_time" ON "audit_logs" ("user_id","timestamp");--> statement-breakpoint
CREATE INDEX "audit_document_time" ON "audit_logs" ("document_id","timestamp");--> statement-breakpoint
CREATE UNIQUE INDEX "permissions_one_unrevoked" ON "document_permissions" ("document_id","user_id") WHERE "revoked_at" is null;--> statement-breakpoint
CREATE INDEX "permissions_user_document" ON "document_permissions" ("user_id","document_id");--> statement-breakpoint
CREATE INDEX "documents_owner_created" ON "documents" ("owner_id","created_at");--> statement-breakpoint
CREATE INDEX "attempts_username_time" ON "login_attempts" ("username_key","attempted_at");--> statement-breakpoint
CREATE INDEX "attempts_ip_time" ON "login_attempts" ("source_ip","attempted_at");--> statement-breakpoint
CREATE INDEX "invites_expiry" ON "registration_invites" ("expires_at","consumed_at");--> statement-breakpoint
CREATE INDEX "sessions_expiry" ON "server_sessions" ("expires_at");--> statement-breakpoint
CREATE INDEX "users_status_role" ON "users" ("status","role");--> statement-breakpoint
ALTER TABLE "audit_logs" ADD CONSTRAINT "audit_logs_user_id_users_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE RESTRICT;--> statement-breakpoint
ALTER TABLE "audit_logs" ADD CONSTRAINT "audit_logs_document_id_documents_id_fkey" FOREIGN KEY ("document_id") REFERENCES "documents"("id") ON DELETE RESTRICT;--> statement-breakpoint
ALTER TABLE "document_permissions" ADD CONSTRAINT "document_permissions_document_id_documents_id_fkey" FOREIGN KEY ("document_id") REFERENCES "documents"("id") ON DELETE RESTRICT;--> statement-breakpoint
ALTER TABLE "document_permissions" ADD CONSTRAINT "document_permissions_user_id_users_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE RESTRICT;--> statement-breakpoint
ALTER TABLE "document_permissions" ADD CONSTRAINT "document_permissions_granted_by_users_id_fkey" FOREIGN KEY ("granted_by") REFERENCES "users"("id") ON DELETE RESTRICT;--> statement-breakpoint
ALTER TABLE "documents" ADD CONSTRAINT "documents_owner_id_users_id_fkey" FOREIGN KEY ("owner_id") REFERENCES "users"("id") ON DELETE RESTRICT;--> statement-breakpoint
ALTER TABLE "registration_invites" ADD CONSTRAINT "registration_invites_created_by_users_id_fkey" FOREIGN KEY ("created_by") REFERENCES "users"("id") ON DELETE RESTRICT;--> statement-breakpoint
ALTER TABLE "server_sessions" ADD CONSTRAINT "server_sessions_user_id_users_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE;