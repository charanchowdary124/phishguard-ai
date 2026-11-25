const { defineConfig } = require("@playwright/test");

const baseURL = process.env.PHISHGUARD_BASE_URL || "http://127.0.0.1:8081";
const isWindows = process.platform === "win32";

module.exports = defineConfig({
  testDir: "./e2e",
  fullyParallel: false,
  workers: 1,
  timeout: 30_000,
  expect: {
    timeout: 10_000
  },
  reporter: "list",
  use: {
    baseURL,
    browserName: "chromium",
    headless: true,
    screenshot: "only-on-failure"
  },
  webServer: {
    command: isWindows ? ".\\mvnw.cmd spring-boot:run" : "./mvnw spring-boot:run",
    url: `${baseURL}/login`,
    timeout: 120_000,
    reuseExistingServer: false,
    env: {
      ...process.env,
      SERVER_PORT: "8081",
      SPRING_PROFILES_ACTIVE: "default",
      SPRING_DATASOURCE_URL:
        "jdbc:h2:mem:phishguard-e2e;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE;MODE=PostgreSQL",
      SPRING_DATASOURCE_DRIVER_CLASS_NAME: "org.h2.Driver",
      SPRING_DATASOURCE_USERNAME: "sa",
      SPRING_DATASOURCE_PASSWORD: ""
    }
  }
});
