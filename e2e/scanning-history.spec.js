const { test, expect } = require("@playwright/test");
const { logout, registerAndLogin } = require("./helpers");

test("scans safe and suspicious URLs and shows sanitized persisted history", async ({ page }) => {
  await registerAndLogin(page);
  await page.goto("/scan/url");

  await page.getByLabel("URL").fill("https://example.com");
  await page.getByRole("button", { name: "Analyze URL" }).click();
  await expect(page.locator("#url-result")).toContainText("LEGITIMATE");

  await page.getByLabel("URL").fill("http://login-secure.example.test/verify?token=demo");
  await page.getByRole("button", { name: "Analyze URL" }).click();
  await expect(page.locator("#url-result")).toContainText("PHISHING");

  await page.getByLabel("URL").fill("http://127.0.0.1/admin");
  await page.getByRole("button", { name: "Analyze URL" }).click();
  await expect(page.locator("#url-result .alert-danger"))
    .toContainText("Local and private IP addresses cannot be analyzed");

  await page.goto("/history");
  await expect(page.locator("#history-content")).toContainText("example.com");
  await expect(page.locator("#history-content")).not.toContainText("token=demo");
  await expect(page.locator("#history-content")).toContainText("login-secure.example.test");
  await expect(page.locator("#history-content")).toContainText("URL");
  await expect(page).toHaveURL(/\/history/);
  await expect(page.locator("#history-content tbody tr")).toHaveCount(2);
});

test("scans email text and persists only the subject in history", async ({ page }) => {
  await registerAndLogin(page);
  await page.goto("/scan/email");

  await page.getByLabel("Sender").fill("colleague@example.com");
  await page.getByLabel("Subject").fill("Team meeting update");
  await page.getByLabel("Plain text or HTML body").fill("The meeting is moved to Thursday afternoon.");
  await page.getByRole("button", { name: "Analyze Email" }).click();
  await expect(page.locator("#email-result")).toContainText("LEGITIMATE");

  await page.getByLabel("Sender").fill("attacker@example.test");
  await page.getByLabel("Subject").fill("Urgent account verification");
  await page.getByLabel("Plain text or HTML body")
    .fill("Reply with your password and one-time code immediately to avoid suspension.");
  await page.getByRole("button", { name: "Analyze Email" }).click();
  await expect(page.locator("#email-result")).toContainText("PHISHING");

  await page.goto("/history");
  await expect(page.locator("#history-content")).toContainText("Team meeting update");
  await expect(page.locator("#history-content")).toContainText("Urgent account verification");
  await expect(page.locator("#history-content")).not.toContainText("one-time code");
  await expect(page.locator("#history-content")).not.toContainText("attacker@example.test");
  await expect(page.locator("#history-content tbody tr")).toHaveCount(2);
});

test("does not expose one user's history to another account", async ({ page }) => {
  await registerAndLogin(page);
  await page.goto("/scan/url");
  await page.getByLabel("URL").fill("https://first-owner.example.com");
  await page.getByRole("button", { name: "Analyze URL" }).click();
  await expect(page.locator("#url-result")).toContainText("LEGITIMATE");

  await page.goto("/history");
  const row = page.locator("#history-content tbody tr").first();
  await expect(row).toBeVisible();
  const scanId = await row.locator("td").first().innerText();

  await logout(page);
  await registerAndLogin(page);
  await page.goto("/history");
  await expect(page.locator("#history-content")).toContainText("No scan records yet.");

  const crossAccountStatus = await page.evaluate(async id => {
    return (await fetch(`/api/history/${id}`)).status;
  }, scanId);
  expect(crossAccountStatus).toBe(404);
});
