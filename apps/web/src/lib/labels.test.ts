import { describe, expect, it } from "vitest";
import { statusLabel } from "./labels";

describe("statusLabel", () => {
  it("maps the four honest states", () => {
    expect(["operational", "experimental", "planned", "unavailable"].map(statusLabel)).toEqual([
      "Operational", "Experimental", "Planned", "Unavailable",
    ]);
  });
  it("never upgrades unknown statuses", () => {
    expect(statusLabel("totally-secure")).toBe("Unavailable");
  });
});
