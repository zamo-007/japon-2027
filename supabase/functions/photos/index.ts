// Photos du voyage : session personnelle obligatoire (code du voyage + jeton PIN), originaux sans compression.
import { createClient } from "npm:@supabase/supabase-js@2.45.4";

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const admin = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);
const BUCKET = "photos";
const MAX = 50 * 1024 * 1024;
const json = (b: unknown, s = 200) => new Response(JSON.stringify(b), { status: s, headers: { ...cors, "Content-Type": "application/json" } });
const safeName = (v: unknown) => {
  const n = String(v ?? "photo").normalize("NFD").replace(/[̀-ͯ]/g, "");
  return n.replace(/[^A-Za-z0-9._-]/g, "_").replace(/_+/g, "_").slice(-80) || "photo.jpg";
};

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  if (req.method !== "POST") return json({ error: "method" }, 405);
  try {
    const body = await req.json();
    const { data: s } = await admin.rpc("session_info", { p_code: String(body.code ?? ""), p_token: String(body.token ?? "") });
    if (!s?.trip_id) return json({ error: "session" }, 401);
    const tid = s.trip_id as string, me = String(s.me), isAdmin = !!s.admin;
    const store = admin.storage.from(BUCKET);

    if (body.action === "upload") {
      const size = Number(body.size) || 0;
      if (size > MAX) return json({ error: "too_big" }, 413);
      const key = `${tid}/${me}/${Date.now()}-${crypto.randomUUID().slice(0, 8)}-${safeName(body.name)}`;
      const thumbKey = key.replace(`${tid}/`, `${tid}/_thumbs/`) + ".jpg";
      const o = await store.createSignedUploadUrl(key);
      const t = await store.createSignedUploadUrl(thumbKey);
      if (o.error || t.error) return json({ error: "storage" }, 500);
      return json({ path: key, token: o.data.token, thumbPath: thumbKey, thumbToken: t.data.token });
    }

    if (body.action === "list") {
      const top = await store.list(tid, { limit: 1000 });
      const folders = (top.data ?? []).filter((f) => !f.id && f.name !== "_thumbs").map((f) => f.name);
      const items: { path: string; who: string; name: string; size: number; created: string }[] = [];
      for (const who of folders) {
        const r = await store.list(`${tid}/${who}`, { limit: 1000, sortBy: { column: "created_at", order: "desc" } });
        for (const f of r.data ?? []) {
          if (!f.id) continue;
          items.push({ path: `${tid}/${who}/${f.name}`, who, name: f.name.replace(/^\d+-[0-9a-f]{8}-/, ""), size: Number(f.metadata?.size) || 0, created: f.created_at });
        }
      }
      items.sort((a, b) => (a.created < b.created ? 1 : -1));
      if (!items.length) return json({ items: [] });
      const thumbPaths = items.map((i) => i.path.replace(`${tid}/`, `${tid}/_thumbs/`) + ".jpg");
      const [full, thumbs] = await Promise.all([
        store.createSignedUrls(items.map((i) => i.path), 86400),
        store.createSignedUrls(thumbPaths, 86400),
      ]);
      return json({ items: items.map((i, k) => ({ ...i, url: full.data?.[k]?.signedUrl ?? null, thumb: thumbs.data?.[k]?.signedUrl ?? null })) });
    }

    if (body.action === "delete") {
      // Seul l'auteur de la photo (ou l'organisateur) peut la supprimer.
      const path = String(body.path ?? "");
      if (!path.startsWith(`${tid}/`) || path.startsWith(`${tid}/_thumbs/`) || path.includes("..")) return json({ error: "forbidden" }, 403);
      const owner = path.slice(tid.length + 1).split("/")[0];
      if (owner !== me && !isAdmin) return json({ error: "forbidden" }, 403);
      const thumb = path.replace(`${tid}/`, `${tid}/_thumbs/`) + ".jpg";
      await store.remove([path, thumb]);
      return json({ ok: true });
    }
    return json({ error: "action" }, 400);
  } catch (_e) {
    return json({ error: "server" }, 500);
  }
});
