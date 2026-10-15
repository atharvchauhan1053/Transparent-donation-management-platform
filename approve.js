/*
 *   npm run accounts list               -> show pending accounts
 *   npm run accounts approve <email>    -> activate an account
 *   npm run accounts reject <email>     -> delete an account
 *
 * Stop the server before running this, then start it again.
 */
const { data, save } = require("./db");

const [cmd, email] = process.argv.slice(2);

if (cmd === "list") {
  const pending = data.users.filter((u) => !u.approved);
  if (!pending.length) console.log("No pending accounts.");
  pending.forEach((u) =>
    console.log(`${u.role.padEnd(13)} ${u.email}  ${u.organizationName || ""} ${u.registrationNumber || u.caMembership || ""}`)
  );
} else if ((cmd === "approve" || cmd === "reject") && email) {
  const user = data.users.find((u) => u.email === email.toLowerCase());
  if (!user) {
    console.log("No account found for", email);
  } else if (cmd === "approve") {
    user.approved = true;
    save();
    console.log("Approved:", user.email);
  } else {
    data.users = data.users.filter((u) => u !== user);
    save();
    console.log("Removed:", user.email);
  }
} else {
  console.log("Usage:\n  npm run accounts list\n  npm run accounts approve <email>\n  npm run accounts reject <email>");
}