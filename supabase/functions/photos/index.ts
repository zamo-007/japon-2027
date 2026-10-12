// Photos du voyage : session personnelle obligatoire (code du voyage + jeton PIN), quota de 1 Go pour tout le voyage.
// Si l'organisateur a relié son Google Drive, l'original intact y est rangé (via un script Apps Script),
// et l'appli ne garde qu'une version optimisée + une miniature.
import { createClient } from "npm:@supabase/supabase-js@2.45.4";

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const admin = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);
const BUCKET = "photos";
const MAX = 50 * 1024 * 1024;
const DRIVE_MAX = 36 * 1024 * 1024; // envoi en base64 vers Apps Script : 50 Mo maximum par requête
const QUOTA = 1024 * 1024 * 1024; // 1 Go gratuit pour tout le voyage (photos + miniatures)
const DRIVE_RE = /^https:\/\/script\.google\.com\/macros\/s\/[A-Za-z0-9_-]{20,}\/exec$/;
const usage = async (tid: string) => Number((await admin.rpc("photos_usage", { p_trip: tid })).data) || 0;
const json = (b: unknown, s = 200) => new Response(JSON.stringify(b), { status: s, headers: { ...cors, "Content-Type": "application/json" } });
const safeName = (v: unknown) => {
  const n = String(v ?? "photo").normalize("NFD").replace(/[̀-ͯ]/g, "");
  return n.replace(/[^A-Za-z0-9._-]/g, "_").replace(/_+/g, "_").slice(-80) || "photo.jpg";
};
const rand = () => Array.from(crypto.getRandomValues(new Uint8Array(32)), (b) => b.toString(16).padStart(2, "0")).join("");
async function ticket(tid: string, kind: "put" | "get" | "del", minutes: number, extra: Record<string, unknown>) {
  const token = rand();
  await admin.from("drive_tickets").insert({ token, trip_id: tid, kind, expires_at: new Date(Date.now() + minutes * 60000).toISOString(), ...extra });
  return token;
}
async function driveUrl(tid: string): Promise<string | null> {
  const { data } = await admin.from("trips").select("drive_url").eq("id", tid).maybeSingle();
  return data?.drive_url && DRIVE_RE.test(data.drive_url) ? data.drive_url : null;
}
async function callScript(url: string, body: unknown) {
  const r = await fetch(url, { method: "POST", headers: { "Content-Type": "text/plain;charset=utf-8" }, body: JSON.stringify(body), redirect: "follow" });
  const t = await r.text();
  try { return JSON.parse(t); } catch { return { ok: false, error: "réponse illisible" }; }
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  if (req.method !== "POST") return json({ error: "method" }, 405);
  try {
    const body = await req.json();

    // Appelé par le script Google Apps Script : le ticket fait office d'autorisation.
    if (body.action === "drive_check") {
      const { data: t } = await admin.from("drive_tickets").select("*").eq("token", String(body.ticket ?? "")).maybeSingle();
      if (!t || new Date(t.expires_at).getTime() < Date.now()) return json({ error: "ticket" }, 403);
      if (body.done && t.kind === "put" && t.path) {
        const id = String(body.done).replace(/[^A-Za-z0-9_-]/g, "").slice(0, 100);
        await admin.from("photo_files").update({ drive_id: id }).eq("path", t.path).eq("trip_id", t.trip_id);
        await admin.from("drive_tickets").update({ expires_at: new Date().toISOString() }).eq("token", t.token);
      }
      return json({ ok: true, kind: t.kind, name: t.name, drive_id: t.drive_id });
    }

    const { data: s } = await admin.rpc("session_info", { p_code: String(body.code ?? ""), p_token: String(body.token ?? "") });
    if (!s?.trip_id) return json({ error: "session" }, 401);
    const tid = s.trip_id as string, me = String(s.me), isAdmin = !!s.admin;
    const store = admin.storage.from(BUCKET);

    if (body.action === "upload") {
      const size = Number(body.size) || 0;
      if (size > MAX) return json({ error: "too_big" }, 413);
      const used = await usage(tid);
      if (used + size * 1.05 > QUOTA) return json({ error: "full", used, limit: QUOTA }, 507);
      const key = `${tid}/${me}/${Date.now()}-${crypto.randomUUID().slice(0, 8)}-${safeName(body.name)}`;
      const thumbKey = key.replace(`${tid}/`, `${tid}/_thumbs/`) + ".jpg";
      const o = await store.createSignedUploadUrl(key);
      const t = await store.createSignedUploadUrl(thumbKey);
      if (o.error || t.error) return json({ error: "storage" }, 500);
      const res: Record<string, unknown> = { path: key, token: o.data.token, thumbPath: thumbKey, thumbToken: t.data.token };
      const durl = body.orig_size ? await driveUrl(tid) : null;
      if (durl && Number(body.orig_size) <= DRIVE_MAX) {
        const origName = String(body.orig_name ?? body.name ?? "photo").slice(0, 120);
        await admin.from("photo_files").insert({ path: key, trip_id: tid, orig_name: origName, orig_size: Number(body.orig_size) || 0, orig_mime: String(body.orig_mime ?? "").slice(0, 60) });
        res.drive = { url: durl, ticket: await ticket(tid, "put", 20, { path: key, name: origName }) };
      }
      return json(res);
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
      const used = await usage(tid);
      const durl = await driveUrl(tid);
      const { data: files } = await admin.from("photo_files").select("path,drive_id,orig_name,orig_size").eq("trip_id", tid).not("drive_id", "is", null);
      const fm = new Map((files ?? []).map((f) => [f.path, f]));
      const driveBytes = (files ?? []).reduce((a, f) => a + (Number(f.orig_size) || 0), 0);
      const meta = { used, limit: QUOTA, drive: !!durl, driveBytes };
      if (!items.length) return json({ items: [], ...meta });
      const thumbPaths = items.map((i) => i.path.replace(`${tid}/`, `${tid}/_thumbs/`) + ".jpg");
      const [full, thumbs] = await Promise.all([
        store.createSignedUrls(items.map((i) => i.path), 86400),
        store.createSignedUrls(thumbPaths, 86400),
      ]);
      return json({
        ...meta,
        items: items.map((i, k) => {
          const f = fm.get(i.path);
          return { ...i, url: full.data?.[k]?.signedUrl ?? null, thumb: thumbs.data?.[k]?.signedUrl ?? null,
            ...(f ? { orig: true, origName: f.orig_name, origSize: Number(f.orig_size) || 0 } : {}) };
        }),
      });
    }

    if (body.action === "original") {
      const path = String(body.path ?? "");
      if (!path.startsWith(`${tid}/`)) return json({ error: "forbidden" }, 403);
      const durl = await driveUrl(tid);
      const { data: f } = await admin.from("photo_files").select("drive_id,orig_name").eq("path", path).eq("trip_id", tid).maybeSingle();
      if (!durl || !f?.drive_id) return json({ error: "no_original" }, 404);
      return json({ url: durl, name: f.orig_name, ticket: await ticket(tid, "get", 10, { drive_id: f.drive_id, name: f.orig_name }) });
    }

    if (body.action === "delete") {
      // Seul l'auteur de la photo (ou l'organisateur) peut la supprimer.
      const path = String(body.path ?? "");
      if (!path.startsWith(`${tid}/`) || path.startsWith(`${tid}/_thumbs/`) || path.includes("..")) return json({ error: "forbidden" }, 403);
      const owner = path.slice(tid.length + 1).split("/")[0];
      if (owner !== me && !isAdmin) return json({ error: "forbidden" }, 403);
      const thumb = path.replace(`${tid}/`, `${tid}/_thumbs/`) + ".jpg";
      await store.remove([path, thumb]);
      const { data: f } = await admin.from("photo_files").select("drive_id").eq("path", path).eq("trip_id", tid).maybeSingle();
      const durl = await driveUrl(tid);
      if (f?.drive_id && durl) {
        try { await callScript(durl, { action: "del", ticket: await ticket(tid, "del", 5, { drive_id: f.drive_id }) }); } catch (_e) { /* l'original reste dans le Drive */ }
      }
      await admin.from("photo_files").update({ drive_id: null }).eq("path", path).eq("trip_id", tid);
      return json({ ok: true });
    }

    // Organisateur : relier ou délier le script Google Drive.
    if (body.action === "drive_config") {
      if (!isAdmin) return json({ error: "forbidden" }, 403);
      const url = String(body.url ?? "").trim();
      if (url === "") {
        await admin.from("trips").update({ drive_url: null }).eq("id", tid);
        return json({ ok: true, drive: false });
      }
      if (!DRIVE_RE.test(url)) return json({ error: "url" }, 400);
      const r = await callScript(url, { action: "ping" });
      if (!r?.ok || r.app !== "japon-2027") return json({ error: "ping", detail: r?.error ?? null }, 400);
      await admin.from("trips").update({ drive_url: url }).eq("id", tid);
      return json({ ok: true, drive: true });
    }
    return json({ error: "action" }, 400);
  } catch (_e) {
    return json({ error: "server" }, 500);
  }
});
