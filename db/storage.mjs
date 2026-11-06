import { getStore } from '@netlify/blobs';

export function privateDocuments(context = {}) {
  // Preview files cannot overwrite or delete production files. Rows use opaque keys.
  const production = context.deploy?.context === 'production' || process.env.CONTEXT === 'production';
  const namespace = production ? 'trustvault-private' : 'trustvault-preview-private';
  // Downloads immediately follow uploads; strong consistency prevents transient missing files.
  const store = getStore({ name: namespace, consistency: 'strong' });
  return {
    async upload(key, content) {
      try {
        await store.set(key, new Uint8Array(content));
        return { error: null };
      } catch (error) { return { error }; }
    },
    async download(key) {
      try {
        const data = await store.get(key, { type: 'blob' });
        return data ? { data, error: null } : { data: null, error: new Error('Missing object') };
      } catch (error) { return { data: null, error }; }
    },
    async remove(keys) {
      try {
        await Promise.all(keys.map(key => store.delete(key)));
        return { error: null };
      } catch (error) { return { error }; }
    },
  };
}
