/* Tiny JSON-file database. No native modules, works on every OS. */
const fs = require("fs");
const path = require("path");

const DIR = path.join(__dirname, "data");
const FILE = path.join(DIR, "db.json");

const data = { users: [], donations: [] };

function load() {
  fs.mkdirSync(DIR, { recursive: true });
  if (fs.existsSync(FILE)) {
    const parsed = JSON.parse(fs.readFileSync(FILE, "utf8"));
    data.users = parsed.users || [];
    data.donations = parsed.donations || [];
  }
}

function save() {
  const tmp = FILE + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2));
  fs.renameSync(tmp, FILE); // atomic replace so the file never gets corrupted
}

load();

module.exports = { data, save };