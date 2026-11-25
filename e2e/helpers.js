const { randomUUID } = require("node:crypto");

const DEMO_PASSWORD = "PhishGuard-Demo!2026";

async function registerAndLogin(page) {
  const username = `pg${randomUUID().replaceAll("-", "").slice(0, 12)}`;
  const account = {
    username,
    email: `${username}@example.test`,
    password: DEMO_PASSWORD
  };

  await page.goto("/register");
  await page.getByLabel("Username").fill(account.username);
  await page.getByLabel("Email").fill(account.email);
  await page.getByLabel("Password").fill(account.password);
  await page.getByRole("button", { name: "Register" }).click();
  await page.waitForURL(/\/login\?registered=true/);

  await page.getByLabel("Username").fill(account.username);
  await page.getByLabel("Password").fill(account.password);
  await page.getByRole("button", { name: "Sign in" }).click();
  await page.waitForURL(/\/dashboard$/);
  return account;
}

async function logout(page) {
  await page.getByRole("button", { name: "Logout" }).click();
  await page.waitForURL(/\/login\?logout=true/);
}

module.exports = { DEMO_PASSWORD, logout, registerAndLogin };
