const { test, expect } = require("@playwright/test");
const { DEMO_PASSWORD, logout, registerAndLogin } = require("./helpers");

test("registers, authenticates, and protects pages after logout", async ({ page }) => {
  const account = await registerAndLogin(page);

  await page.goto("/profile");
  await expect(page.getByLabel("Username")).toHaveValue(account.username);
  await expect(page.getByLabel("Email")).toHaveValue(account.email);

  await logout(page);
  await page.goto("/dashboard");
  await expect(page).toHaveURL(/\/login/);
});

test("uses the same login failure message for unknown and incorrect credentials", async ({ page }) => {
  const account = await registerAndLogin(page);
  await logout(page);

  await page.getByLabel("Username").fill(`missing-${account.username}`);
  await page.getByLabel("Password").fill(DEMO_PASSWORD);
  await page.getByRole("button", { name: "Sign in" }).click();
  await page.waitForURL(/\/login\?error=true/);
  const unknownAccountMessage = await page.locator(".alert-danger").innerText();

  await page.goto("/login");
  await page.getByLabel("Username").fill(account.username);
  await page.getByLabel("Password").fill("Incorrect-Demo!2026");
  await page.getByRole("button", { name: "Sign in" }).click();
  await page.waitForURL(/\/login\?error=true/);
  await expect(page.locator(".alert-danger")).toHaveText(unknownAccountMessage);

  await page.goto("/login");
  await page.getByLabel("Username").fill(account.username);
  await page.getByLabel("Password").fill(account.password);
  await page.getByRole("button", { name: "Sign in" }).click();
  await page.waitForURL(/\/dashboard$/);
  await expect(page.getByRole("heading", { name: "Security Dashboard" })).toBeVisible();
});

test("redirects unauthenticated history requests to login", async ({ page }) => {
  await page.goto("/history");

  await expect(page).toHaveURL(/\/login/);
  await expect(page.getByRole("button", { name: "Sign in" })).toBeVisible();

  await registerAndLogin(page);
  await page.goto("/scan/url");
  await page.getByLabel("URL").fill("https://new-user.example.com");
  await page.getByRole("button", { name: "Analyze URL" }).click();
  await expect(page.locator("#url-result")).toContainText("LEGITIMATE");
  await page.goto("/history");
  await expect(page.locator("#history-content")).toContainText("new-user.example.com");
});
