import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { VERSION } from "../app/js/version.js";

const read = (rel) => readFileSync(new URL(`../${rel}`, import.meta.url), "utf8");

test("the version Settings shows matches the build that ships it", () => {
  const gradle = read("android/app/build.gradle.kts").match(/versionName = "([^"]+)"/)[1];
  const pkg = JSON.parse(read("package.json")).version;
  assert.equal(VERSION, gradle);
  assert.equal(VERSION, pkg);
});

test("Settings reads the version instead of spelling one out", () => {
  assert.doesNotMatch(read("app/js/ui.js"), /"Starling \d+\.\d+/);
});
