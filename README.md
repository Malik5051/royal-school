# Royal International Schools - website, admission form and admin

One Node.js server (no npm install needed) that serves:

| Address | What it is |
|---|---|
| `http://localhost:3000/` | Home page (your royal.html) |
| `http://localhost:3000/admission` | Admission form - saves every application on the server |
| `http://localhost:3000/admin` | Admin dashboard - password protected |

## Run it
1. Install Node.js 16 or newer from https://nodejs.org (once).
2. **Windows:** double-click `START.bat`. **Any system:** run `node server.js` in this folder.
3. The first time, the window shows the admin password. Write it down.

To change the password later: double-click `SET-PASSWORD.bat`, or run
`node server.js --set-password "new password"`. You can also set the `ADMIN_PASSWORD`
environment variable, which overrides the saved one.

Other computers on the same network can open `http://<this-computer-IP>:3000/`.
Change the port with the `PORT` environment variable (e.g. `set PORT=8080`).

## Admin dashboard
- See every submitted application, newest first, with counts for New / Under review / Accepted / Tour requests
- Search by student, parent, phone or reference; filter by status, section or tour requests
- Click an application to see all details, set its status, add staff-only notes, print it, or delete it
- Export everything to CSV (opens in Excel)
- The list refreshes itself every 30 seconds and the browser tab title shows how many are New

## Where the data is
Applications are stored in `data/applications.json`. Copy this file to back it up.
The admin password is stored (hashed) in `data/admin.json`. Do not share the `data` folder.

## Files
- `server.js` - the server (form API, admin API, login, CSV export)
- `public/index.html` - home page
- `public/admission.html` - admission form
- `public/admin.html` - admin dashboard

## Before putting it on the internet
The server speaks plain HTTP. For a public site, put it behind HTTPS (for example a reverse
proxy such as Caddy or nginx, or a host that provides HTTPS) so the admin password and
parents' details are encrypted in transit.
