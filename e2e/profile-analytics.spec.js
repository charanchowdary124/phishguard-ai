const { test, expect } = require("@playwright/test");
const { DEMO_PASSWORD, logout, registerAndLogin } = require("./helpers");

test("profile and analytics reflect this account's persisted scan activity", async ({ page }) => {
  await registerAndLogin(page);
  await expect(page.locator("#dashboard-status")).toContainText("No scans recorded yet.");

  await page.goto("/scan/url");
  await page.getByLabel("URL").fill("https://example.com");
  await page.getByRole("button", { name: "Analyze URL" }).click();
  await expect(page.locator("#url-result")).toContainText("LEGITIMATE");

  await page.goto("/scan/email");
  await page.getByLabel("Subject").fill("Meeting schedule");
  await page.getByLabel("Plain text or HTML body").fill("The meeting starts at ten.");
  await page.getByRole("button", { name: "Analyze Email" }).click();
  await expect(page.locator("#email-result")).toContainText("LEGITIMATE");

  await page.goto("/analytics");
  await expect(page.locator("#analytics-status")).toBeHidden();
  await expect(page.locator("#total-scans")).toHaveText("2");
  await expect(page.locator("#analytics-url-scans")).toHaveText("1");
  await expect(page.locator("#analytics-email-scans")).toHaveText("1");

  await page.goto("/profile");
  const updatedUsername = `updated${Date.now()}`;
  await page.getByLabel("Username").fill(updatedUsername);
  await page.getByLabel("Email").fill(`${updatedUsername}@example.test`);
  await page.getByRole("button", { name: "Save profile" }).click();
  await expect(page.locator("#profile-update-result")).toContainText("Profile updated.");
  await expect(page.getByLabel("Username")).toHaveValue(updatedUsername);

  await page.getByLabel("Current password").fill(DEMO_PASSWORD);
  await page.locator("#new-password").fill("Updated-Demo!2026");
  await page.getByLabel("Confirm new password").fill("Updated-Demo!2026");
  await page.getByRole("button", { name: "Change password" }).click();
  await expect(page.locator("#password-change-result"))
    .toContainText("Password changed successfully.");

  await logout(page);
  await page.getByLabel("Username").fill(updatedUsername);
  await page.getByLabel("Password").fill("Updated-Demo!2026");
  await page.getByRole("button", { name: "Sign in" }).click();
  await page.waitForURL(/\/dashboard$/);
  await expect(page.locator("#total-scan-count")).toHaveText("2");
});

test("keeps dashboard and navigation within a mobile viewport", async ({ page }) => {
  const pageErrors = [];
  page.on("pageerror", error => pageErrors.push(error.message));
  await registerAndLogin(page);
  await page.setViewportSize({ width: 375, height: 812 });
  await page.goto("/scan/url");
  await page.getByLabel("URL").fill("https://mobile.example.com");
  await page.getByRole("button", { name: "Analyze URL" }).click();
  await expect(page.locator("#url-result")).toContainText("LEGITIMATE");
  await page.goto("/dashboard");
  await expect(page.locator("#total-scan-count")).toHaveText("1");

  for (const [label, path, heading] of [
    ["Dashboard", "/dashboard", "Security Dashboard"],
    ["Website Scanner", "/scan/url", "Website Scanner"],
    ["Email Scanner", "/scan/email", "Email Scanner"],
    ["Scan History", "/history", "Scan History"],
    ["Threat Analytics", "/analytics", "Threat Analytics"],
    ["Profile", "/profile", "User Profile"]
  ]) {
    await page.getByRole("link", { name: label }).click();
    await expect(page).toHaveURL(new RegExp(`${path.replaceAll("/", "\\/")}$`));
    await expect(page.getByRole("heading", { name: heading })).toBeVisible();
    const horizontalOverflow = await page.evaluate(
      () => document.documentElement.scrollWidth > document.documentElement.clientWidth
    );
    expect(horizontalOverflow, `${label} should fit the mobile viewport`).toBe(false);
  }
  expect(pageErrors).toEqual([]);
});
