import nodemailer from 'nodemailer'

let transporter = null

export function initMail() {
  if (!process.env.MAIL_HOST || process.env.MAIL_HOST === 'smtp.example.com') {
    console.log('[Mail] SMTP nicht konfiguriert — Mails werden nur geloggt')
    return
  }

  transporter = nodemailer.createTransport({
    host: process.env.MAIL_HOST,
    port: parseInt(process.env.MAIL_PORT || '587'),
    secure: process.env.MAIL_PORT === '465',
    auth: {
      user: process.env.MAIL_USER,
      pass: process.env.MAIL_PASS,
    },
  })

  transporter.verify()
    .then(() => console.log('[Mail] SMTP verbunden'))
    .catch(err => console.error('[Mail] SMTP Fehler:', err.message))
}

export function reloadMail() {
  transporter = null
  initMail()
}

export async function sendTestMail(to) {
  return sendMail({
    to,
    subject: 'Heildepot — SMTP Test',
    html: '<h2 style="color:#7dab5a">SMTP funktioniert!</h2><p>Diese Test-Mail wurde vom Heildepot-Server gesendet.</p>',
    text: 'SMTP funktioniert! Diese Test-Mail wurde vom Heildepot-Server gesendet.',
  })
}

export async function sendMail({ to, subject, html, text }) {
  const mailOptions = {
    from: process.env.MAIL_FROM || 'Heildepot <noreply@heildepot.de>',
    to,
    subject,
    html,
    text,
  }

  if (!transporter) {
    console.log('[Mail] (Simulation)', subject, '→', to)
    console.log('[Mail] Text:', text?.substring(0, 200) || html?.substring(0, 200))
    return { simulated: true }
  }

  return transporter.sendMail(mailOptions)
}

// ─── MAIL TEMPLATES ──────────────────────────────────────

export function verifyEmail(email, token, frontendUrl) {
  const link = `${frontendUrl}#verify/${token}`
  return sendMail({
    to: email,
    subject: 'Heildepot — Bitte bestaetige deine E-Mail',
    html: `
      <div style="font-family: sans-serif; max-width: 500px; margin: 0 auto;">
        <h2 style="color: #7dab5a;">Willkommen im Freundeskreis!</h2>
        <p>Bitte bestaetige deine E-Mail-Adresse, indem du auf den folgenden Link klickst:</p>
        <p><a href="${link}" style="display: inline-block; padding: 12px 24px; background: #7dab5a; color: white; text-decoration: none; border-radius: 8px; font-weight: bold;">E-Mail bestaetigen</a></p>
        <p style="color: #888; font-size: 12px;">Falls der Button nicht funktioniert, kopiere diesen Link: ${link}</p>
        <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
        <p style="color: #888; font-size: 11px;">Du erhaeltst diese E-Mail, weil du dich beim Heildepot Freundeskreis registriert hast.</p>
      </div>
    `,
    text: `Willkommen im Freundeskreis! Bestaetige deine E-Mail: ${link}`,
  })
}

export function orderNotification(anfrage, user) {
  const items = JSON.parse(anfrage.items)
  const itemLines = items.map(i => `  ${i.qty}x ${i.name} — ${i.preis}`).join('\n')

  return sendMail({
    to: process.env.ADMIN_EMAIL,
    subject: `Neue Anfrage von ${user?.vorname || ''} ${user?.nachname || user?.email}`,
    html: `
      <div style="font-family: sans-serif; max-width: 500px; margin: 0 auto;">
        <h2 style="color: #7dab5a;">Neue Anfrage eingegangen</h2>
        <p><strong>Von:</strong> ${user?.vorname || ''} ${user?.nachname || ''} (${user?.email})</p>
        <p><strong>Adresse:</strong> ${anfrage.adresse || 'Nicht angegeben'}</p>
        <h3>Produkte:</h3>
        <pre style="background: #f5f5f5; padding: 12px; border-radius: 8px;">${itemLines}</pre>
        <p><strong>Gesamt:</strong> ${anfrage.total} EUR</p>
        ${anfrage.nachricht ? `<p><strong>Nachricht:</strong> ${anfrage.nachricht}</p>` : ''}
        ${anfrage.optionen ? `<p><strong>Optionen:</strong> ${anfrage.optionen}</p>` : ''}
      </div>
    `,
    text: `Neue Anfrage von ${user?.email}\n\n${itemLines}\n\nGesamt: ${anfrage.total} EUR`,
  })
}

export function orderConfirmation(anfrage, user) {
  const items = JSON.parse(anfrage.items)
  const itemLines = items.map(i => `${i.qty}x ${i.name}`).join(', ')

  return sendMail({
    to: user.email,
    subject: 'Deine Anfrage beim Heildepot Freundeskreis',
    html: `
      <div style="font-family: sans-serif; max-width: 500px; margin: 0 auto;">
        <h2 style="color: #7dab5a;">Danke fuer deine Anfrage!</h2>
        <p>Wir haben deine Anfrage erhalten und kuemmern uns darum.</p>
        <p><strong>Produkte:</strong> ${itemLines}</p>
        <p><strong>Gesamt:</strong> ${anfrage.total} EUR</p>
        <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
        <h3 style="color: #7dab5a;">Wertausgleich</h3>
        <p>IBAN: DE84 4765 0130 1110 3213 51<br>BIC: WELADE3LXXX<br>Sparkasse Paderborn-Detmold</p>
        <p style="color: #888; font-size: 12px;">Bitte gib deinen Namen als Verwendungszweck an.</p>
      </div>
    `,
    text: `Danke fuer deine Anfrage!\n\nProdukte: ${itemLines}\nGesamt: ${anfrage.total} EUR\n\nIBAN: DE84 4765 0130 1110 3213 51`,
  })
}

export async function sendNewsletter(newsletter, subscribers) {
  let sent = 0
  for (const sub of subscribers) {
    try {
      await sendMail({
        to: sub.email,
        subject: newsletter.betreff,
        html: newsletter.inhalt,
        text: newsletter.inhalt.replace(/<[^>]+>/g, ''),
      })
      sent++
    } catch (err) {
      console.error(`[Newsletter] Fehler bei ${sub.email}:`, err.message)
    }
  }
  return sent
}
