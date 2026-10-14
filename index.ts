// Supabase Edge Function: admin-users
// ใช้ให้ Admin สร้าง / รีเซ็ตรหัสผ่าน / ลบ user (ต้องใช้ service role จึงทำจากหน้าเว็บตรง ๆ ไม่ได้)
// Deploy:  supabase functions deploy admin-users
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { ...cors, "Content-Type": "application/json" },
  });

const ROLES = ["admin", "requester", "marketing", "dentcloud", "cfo", "ceo", "excom"];

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });

  try {
    const url = Deno.env.get("https://hintkgegebsssmamoxdx.supabase.co/rest/v1/")!;
    const anon = Deno.env.get("sb_publishable_qJhXFbbJ7HBDiagllvWGHg_ddSB4xPX")!;
    const service = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

    // 1) ตรวจว่าผู้เรียกล็อกอินอยู่ และเป็น admin ที่ active
    const caller = createClient(url, anon, {
      global: { headers: { Authorization: req.headers.get("Authorization") ?? "" } },
    });
    const { data: { user } } = await caller.auth.getUser();
    if (!user) return json({ error: "ยังไม่ได้เข้าสู่ระบบ" }, 401);

    const admin = createClient(url, service);
    const { data: me } = await admin.from("profiles").select("role,active").eq("id", user.id).single();
    if (!me || me.role !== "admin" || !me.active) return json({ error: "เฉพาะ Admin เท่านั้น" }, 403);

    // 2) ทำตาม action
    const body = await req.json();

    if (body.action === "create") {
      const email = String(body.email ?? "").trim().toLowerCase();
      const password = String(body.password ?? "");
      const full_name = String(body.full_name ?? "").trim();
      const role = String(body.role ?? "requester");
      if (!email || password.length < 8) return json({ error: "กรอกอีเมล และรหัสผ่านอย่างน้อย 8 ตัวอักษร" }, 400);
      if (!ROLES.includes(role)) return json({ error: "role ไม่ถูกต้อง" }, 400);

      const { data, error } = await admin.auth.admin.createUser({
        email, password, email_confirm: true, user_metadata: { full_name },
      });
      if (error) return json({ error: error.message }, 400);

      const { error: pErr } = await admin.from("profiles").upsert({
        id: data.user.id, email, full_name, role, active: true,
      });
      if (pErr) return json({ error: pErr.message }, 400);
      return json({ ok: true });
    }

    if (body.action === "reset_password") {
      const password = String(body.password ?? "");
      if (password.length < 8) return json({ error: "รหัสผ่านต้องอย่างน้อย 8 ตัวอักษร" }, 400);
      const { error } = await admin.auth.admin.updateUserById(String(body.id), { password });
      if (error) return json({ error: error.message }, 400);
      return json({ ok: true });
    }

    if (body.action === "delete") {
      if (body.id === user.id) return json({ error: "ลบบัญชีตัวเองไม่ได้" }, 400);
      const { error } = await admin.auth.admin.deleteUser(String(body.id));
      if (error) return json({ error: error.message }, 400);
      return json({ ok: true });
    }

    return json({ error: "action ไม่ถูกต้อง" }, 400);
  } catch (e) {
    return json({ error: (e as Error).message }, 500);
  }
});
