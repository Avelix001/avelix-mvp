const esc = (s) =>
  String(s ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  }[c]));

const makeId = () =>
  `AVX-${crypto.randomUUID().replaceAll("-", "").slice(0, 6).toUpperCase()}`;

async function handler(request, env) {
  const url = new URL(request.url);

  // CREATE AVELIX PROFILE
  if (url.pathname === "/api/create" && request.method === "POST") {

    const data = await request.json();

    if (!data.full_name) {
      return Response.json(
        { error: "Name is required" },
        { status: 400 }
      );
    }

    const avxId = makeId();

    await env.DB.prepare(`
      INSERT INTO profiles
      (
        avx_id,
        full_name,
        title,
        organization,
        industry,
        location,
        email,
        phone,
        website,
        bio
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `)
    .bind(
      avxId,
      data.full_name || "",
      data.title || "",
      data.organization || "",
      data.industry || "",
      data.location || "",
      data.email || "",
      data.phone || "",
      data.website || "",
      data.bio || ""
    )
    .run();

    return Response.json({
      avx_id: avxId,
      url: `${url.origin}/v/${avxId}`
    });
  }

  // PUBLIC VERIFICATION PROFILE
  if (url.pathname.startsWith("/v/")) {

    const avxId = url.pathname
      .split("/")[2]
      .toUpperCase();

    const profile = await env.DB
      .prepare("SELECT * FROM profiles WHERE avx_id = ?")
      .bind(avxId)
      .first();

    if (!profile) {
      return new Response(
        "AVELIX credential not found",
        { status: 404 }
      );
    }

    return new Response(`
      <!doctype html>

      <html>

      <head>

      <meta name="viewport"
      content="width=device-width">

      <title>
      ${esc(profile.full_name)} · AVELIX
      </title>

      <style>

      body {
        margin: 0;
        background: #050817;
        color: #f7f8ff;
        font: 16px Arial;
        padding: 25px;
      }

      .card {
        max-width: 680px;
        margin: auto;
        background: #0b1125;
        border: 1px solid #26304b;
        border-radius: 24px;
        padding: 30px;
      }

      .logo {
        font-weight: 900;
        letter-spacing: 6px;
        color: #b45cff;
      }

      .verified {
        display: inline-block;
        margin-top: 30px;
        padding: 8px 13px;
        border-radius: 99px;
        color: #8ff0bd;
        background: #55d99b12;
        border: 1px solid #55d99b55;
      }

      .id {
        font-family: monospace;
        border: 1px solid #26304b;
        padding: 12px;
        border-radius: 10px;
        display: inline-block;
      }

      .grid {
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 12px;
        margin-top: 25px;
      }

      .box {
        border: 1px solid #26304b;
        border-radius: 14px;
        padding: 18px;
      }

      .muted {
        color: #a9b2ca;
      }

      @media(max-width:600px) {
        .grid {
          grid-template-columns: 1fr;
        }
      }

      </style>

      </head>

      <body>

      <div class="card">

      <div class="logo">
      AVELIX
      </div>

      <div class="verified">
      ✓ VERIFIED PROFILE
      </div>

      <h1>
      ${esc(profile.full_name)}
      </h1>

      <h3>
      ${esc(profile.title)}
      </h3>

      <p>
      ${esc(profile.organization)}
      </p>

      <div class="id">
      AVELIX ID ·
      <b>${esc(profile.avx_id)}</b>
      </div>

      <div class="grid">

      <div class="box">
      <b>Industry</b>
      <p class="muted">
      ${esc(profile.industry)}
      </p>
      </div>

      <div class="box">
      <b>Location</b>
      <p class="muted">
      ${esc(profile.location)}
      </p>
      </div>

      <div class="box">
      <b>Email</b>
      <p class="muted">
      ${esc(profile.email)}
      </p>
      </div>

      <div class="box">
      <b>Phone</b>
      <p class="muted">
      ${esc(profile.phone)}
      </p>
      </div>

      </div>

      ${
        profile.bio
        ? `
        <div
        class="box"
        style="margin-top:12px">

        <b>About</b>

        <p class="muted">
        ${esc(profile.bio)}
        </p>

        </div>
        `
        : ""
      }

      <p class="muted">
      This is an AVELIX MVP prototype.
      </p>

      </div>

      </body>

      </html>
    `, {
      headers: {
        "content-type": "text/html;charset=UTF-8"
      }
    });
  }

  return env.ASSETS.fetch(request);
}

export default {
  fetch: handler
};
