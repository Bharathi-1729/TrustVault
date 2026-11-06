import { getDatabase } from '@netlify/database';
import { drizzle } from 'drizzle-orm/netlify-db';
import { and, or, eq, ne, gt, inArray, isNull, ilike, asc, desc, sql, count, getTableColumns } from 'drizzle-orm';
import { createHash } from 'node:crypto';
import * as schema from './schema.ts';

function databaseError(error) {
  return error?.cause?.code ? error.cause : error;
}
function failure(code, message) {
  return Object.assign(new Error(message), { code });
}
export function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

// A small query facade keeps the existing route validations and response contracts intact.
// Identifiers come exclusively from the Drizzle schema; all user values are bound parameters.
class Query {
  constructor(database, name) {
    this.db = database;
    this.table = schema[name];
    if (!this.table) throw new Error('Unknown table');
    this.filters = [];
    this.orders = [];
    this.mode = 'select';
    this.fields = '*';
  }
  column(name) {
    const column = getTableColumns(this.table)[name];
    if (!column) throw new Error('Unknown column');
    return column;
  }
  select(fields = '*', options = {}) { this.fields = fields; this.options = options; return this; }
  insert(values) { this.mode = 'insert'; this.values = values; return this; }
  update(values) { this.mode = 'update'; this.values = values; return this; }
  delete() { this.mode = 'delete'; return this; }
  eq(name, value) { this.filters.push(eq(this.column(name), value)); return this; }
  neq(name, value) { this.filters.push(ne(this.column(name), value)); return this; }
  gt(name, value) { this.filters.push(gt(this.column(name), value)); return this; }
  is(name, value) {
    if (value !== null) throw new Error('Only null checks are supported');
    this.filters.push(isNull(this.column(name))); return this;
  }
  in(name, values) { this.filters.push(inArray(this.column(name), values)); return this; }
  ilike(name, pattern) { this.filters.push(ilike(this.column(name), pattern)); return this; }
  or(expression) {
    // Only the fixed permission-expiration expression is needed by the dashboard.
    const match = /^expires_at\.is\.null,expires_at\.gt\.(.+)$/.exec(expression);
    if (!match) throw new Error('Unsupported filter');
    this.filters.push(or(isNull(this.column('expires_at')), gt(this.column('expires_at'), match[1])));
    return this;
  }
  order(name, { ascending = true } = {}) {
    this.orders.push(ascending ? asc(this.column(name)) : desc(this.column(name))); return this;
  }
  range(from, to) { this.offset = from; this.max = to - from + 1; return this; }
  limit(max) { this.max = max; return this; }
  single() { this.one = true; this.required = true; return this; }
  maybeSingle() { this.one = true; return this; }
  throwOnError() { this.throwErrors = true; return this; }
  then(resolve, reject) { return this.execute().then(resolve, reject); }
  selection() {
    if (this.fields === '*') return getTableColumns(this.table);
    const nested = /,?users\(([^)]+)\)/.exec(this.fields);
    const fields = nested ? this.fields.replace(nested[0], '') : this.fields;
    const selection = Object.fromEntries(fields.split(',').filter(Boolean).map(name => [name, this.column(name)]));
    if (nested) {
      if (![schema.documents, schema.document_permissions].includes(this.table)) {
        throw new Error('Unsupported join');
      }
      selection.users = Object.fromEntries(nested[1].split(',').map(name => {
        const column = getTableColumns(schema.users)[name];
        if (!column) throw new Error('Unknown joined column');
        return [name, column];
      }));
    }
    return { selection, nested: Boolean(nested) };
  }
  async execute() {
    try {
      const selected = this.selection();
      const selection = selected.selection || selected;
      const where = and(...this.filters);
      let total = null;
      if (this.options?.count === 'exact') {
        const [result] = await this.db.select({ count: count() }).from(this.table).where(where);
        total = Number(result.count);
      }
      if (this.options?.head) return { data: null, error: null, count: total };
      let query;
      if (this.mode === 'select') {
        query = this.db.select(selection).from(this.table);
        if (selected.nested) {
          const foreign = this.table === schema.documents ? this.table.owner_id : this.table.user_id;
          query = query.leftJoin(schema.users, eq(foreign, schema.users.id));
        }
        query = query.where(where).$dynamic();
        if (this.orders.length) query = query.orderBy(...this.orders);
        if (this.max !== undefined) query = query.limit(this.max);
        if (this.offset !== undefined) query = query.offset(this.offset);
      } else {
        if (!Object.keys(this.values || {}).every(name => name in getTableColumns(this.table))) {
          throw new Error('Unknown write column');
        }
        if (this.mode === 'insert') query = this.db.insert(this.table).values(this.values);
        if (this.mode === 'update') query = this.db.update(this.table).set(this.values).where(where);
        if (this.mode === 'delete') query = this.db.delete(this.table).where(where);
        query = query.returning(selection);
      }
      const rows = await query;
      if (this.one && (rows.length > 1 || (this.required && rows.length !== 1))) {
        throw failure('P0002', 'Expected one record');
      }
      return { data: this.one ? (rows[0] || null) : rows, error: null, count: total };
    } catch (error) {
      const normalized = databaseError(error);
      if (this.throwErrors) throw normalized;
      return { data: null, error: normalized, count: null };
    }
  }
}
export class Repository {
  constructor(database) { this.db = database; }
  from(name) { return new Query(this.db, name); }
  async transaction(work) {
    return this.db.transaction(tx => work(new Repository(tx)));
  }
  async appendAudit(event) {
    return this.db.transaction(async tx => {
      // One lock serializes appends across all function instances.
      await tx.execute(sql`select pg_advisory_xact_lock(73510422)`);
      const [last] = await tx.select().from(schema.audit_logs).orderBy(desc(schema.audit_logs.sequence)).limit(1);
      const record = {
        sequence: (last?.sequence || 0) + 1, ...event,
        details: canonical(event.details || {}),
        prev_hash: last?.current_hash || '0'.repeat(64),
      };
      record.current_hash = createHash('sha256').update(canonical(record)).digest('hex');
      const [row] = await tx.insert(schema.audit_logs).values(record).returning();
      return row;
    });
  }
  async adminUpdate({ actorId, targetId, field, value, timestamp }) {
    try {
      return await this.db.transaction(async tx => {
        // Serialize account-management operations so the last admin cannot disappear.
        await tx.execute(sql`select pg_advisory_xact_lock(73510423)`);
        const [actor] = await tx.select().from(schema.users).where(eq(schema.users.id, actorId));
        if (actor?.role !== 'administrator' || actor.status !== 'active') throw failure('42501', 'Administrator required');
        if (actorId === targetId) throw failure('42501', 'Self changes are prohibited');
        if (!['role','status'].includes(field)) throw failure('23514', 'Invalid field');
        if (!(field === 'role' ? ['administrator','document_owner','viewer'] : ['active','disabled']).includes(value)) {
          throw failure('23514', 'Invalid value');
        }
        const [target] = await tx.select().from(schema.users).where(eq(schema.users.id, targetId));
        if (!target) throw failure('P0002', 'User not found');
        if (target.role === 'administrator' && target.status === 'active' &&
            ((field === 'role' && value !== 'administrator') || (field === 'status' && value !== 'active'))) {
          const [admins] = await tx.select({ count: count() }).from(schema.users)
            .where(and(eq(schema.users.role, 'administrator'), eq(schema.users.status, 'active')));
          if (admins.count <= 1) throw failure('23514', 'Last administrator');
        }
        const [user] = await tx.update(schema.users).set({ [field]: value,
          auth_version: target.auth_version + 1, updated_at: timestamp,
        }).where(eq(schema.users.id, targetId)).returning({
          id: schema.users.id, name: schema.users.name, email: schema.users.email,
          role: schema.users.role, status: schema.users.status,
        });
        await tx.delete(schema.server_sessions).where(eq(schema.server_sessions.user_id, targetId));
        // Revoke elevated edit grants when an account becomes a viewer.
        if (field === 'role' && value === 'viewer') {
          await tx.update(schema.document_permissions).set({ revoked_at: timestamp })
            .where(and(eq(schema.document_permissions.user_id, targetId),
              eq(schema.document_permissions.permission, 'edit'), isNull(schema.document_permissions.revoked_at)));
        }
        return { data: { user }, error: null };
      });
    } catch (error) { return { data: null, error: databaseError(error) }; }
  }
}
// Reuse the managed connection pool across warm function invocations.
let cachedRepository;
export function createRepository() {
  return cachedRepository ??= new Repository(drizzle({ client: getDatabase(), schema }));
}
