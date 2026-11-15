import { describe, expect, it } from "vitest";
import { label, relativeTime } from "./format";

describe("format", () => {
  it("turns state codes into words and leaves sentences alone", () => {
    expect(label("EXCEPTION_ACTIVE")).toBe("Exception active");
    expect(label("CHG0030001 closed successful")).toBe("CHG0030001 closed successful");
    expect(label(null)).toBe("—");
  });
  it("says how long ago, or how long until", () => {
    const now = new Date("2026-11-14T12:00:00Z");
    expect(relativeTime("2026-11-14T09:00:00Z", now)).toBe("3h ago");
    expect(relativeTime("2026-11-16T12:00:00Z", now)).toBe("in 2d");
  });
});
