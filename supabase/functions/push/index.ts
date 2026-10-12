// Notifications du voyage : abonnements et envoi Web Push. Session personnelle obligatoire.
import { createClient } from "npm:@supabase/supabase-js@2.45.4";
import webpush from "npm:web-push@3.6.7";

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const admin = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);
const json = (b: unknown, s = 200) => new Response(JSON.stringify(b), { status: s, headers: { ...cors, "Content-Type": "application/json" } });
const clip = (v: unknown, n: number) => String(v ?? "").slice(0, n);
const ICONS = ["torii", "fuji", "lanterne", "sakura", "pagode", "tour", "kinkakuji", "shibuya"];
const TABS = ["prep", "plan", "budget", "split", "photos"];

let keys: { publicKey: string; privateKey: string } | null = null;
async function vapid() {
  if (keys) return keys;
  const { data } = await admin.from("app_secrets").select("name,value").in("name", ["vapid_public", "vapid_private"]);
  const m = Object.fromEntries((data ?? []).map((r) => [r.name, r.value]));
  if (m.vapid_public && m.vapid_private) {
    keys = { publicKey: m.vapid_public, privateKey: m.vapid_private };
  } else {
    const k = webpush.generateVAPIDKeys();
    await admin.from("app_secrets").upsert([{ name: "vapid_public", value: k.publicKey }, { name: "vapid_private", value: k.privateKey }]);
    keys = k;
  }
  webpush.setVapidDetails("mailto:japon2027@users.noreply.github.com", keys.publicKey, keys.privateKey);
  return keys;
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  if (req.method !== "POST") return json({ error: "method" }, 405);
  try {
    const body = await req.json();
    const { data: s } = await admin.rpc("session_info", { p_code: String(body.code ?? ""), p_token: String(body.token ?? "") });
    if (!s?.trip_id) return json({ error: "session" }, 401);
    const tid = s.trip_id as string, me = String(s.me);
    const k = await vapid();

    if (body.action === "key") return json({ publicKey: k.publicKey });

    if (body.action === "subscribe") {
      const sub = body.sub;
      if (!sub?.endpoint || !/^https:\/\//.test(sub.endpoint)) return json({ error: "sub" }, 400);
      const icon = ICONS.includes(body.icon) ? body.icon : "torii";
      await admin.from("push_subs").upsert({ endpoint: sub.endpoint, trip_id: tid, who: me, icon, sub });
      return json({ ok: true });
    }

    if (body.action === "unsubscribe") {
      await admin.from("push_subs").delete().eq("endpoint", clip(body.endpoint, 1000)).eq("trip_id", tid);
      return json({ ok: true });
    }

    if (body.action === "notify") {
      const tab = TABS.includes(body.tab) ? body.tab : "prep";
      const title = clip(body.title, 80) || "Japon 2027";
      const text = clip(body.body, 200);
      const { data: subs } = await admin.from("push_subs").select("endpoint,sub,icon,who").eq("trip_id", tid);
      const targets = (subs ?? []).filter((x) => x.who !== me);
      let sent = 0;
      await Promise.all(targets.map(async (x) => {
        try {
          await webpush.sendNotification(x.sub, JSON.stringify({ title, body: text, tab, icon: x.icon, tag: tab }), { TTL: 86400 });
          sent++;
        } catch (e) {
          const code = (e as { statusCode?: number }).statusCode;
          if (code === 404 || code === 410) await admin.from("push_subs").delete().eq("endpoint", x.endpoint);
        }
      }));
      return json({ ok: true, sent });
    }
    return json({ error: "action" }, 400);
  } catch (_e) {
    return json({ error: "server" }, 500);
  }
});
