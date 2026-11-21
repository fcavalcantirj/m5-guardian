import { test } from "node:test";
import assert from "node:assert/strict";
import { moods, getPresentation } from "./guardian.ts";

test("all five approved expressions retain their order", () => {
  assert.deepEqual(
    moods.map((mood) => mood.name),
    ["Very good", "Good", "Medium", "Bad", "Horrible"],
  );
});

test("nearby activity does not downgrade the selected advertised-settings rating", () => {
  const view = getPresentation(moods[0], "nearby");
  assert.equal(view.rating, "Very good");
  assert.equal(view.image, moods[0].image);
  assert.equal(view.label, "Nearby activity");
});

test("an incident has a separate alert portrait and unknown cause", () => {
  const view = getPresentation(moods[0], "alert");
  assert.equal(view.label, "Network alert");
  assert.equal(view.image, "/images/very-good-alert.png");
  assert.match(view.description, /cause unknown/i);
  assert.equal(view.rating, "Very good");
});

test("incident expressions preserve every selected mood", () => {
  for (const mood of moods) {
    assert.equal(
      getPresentation(mood, "alert").image,
      `/images/${mood.id}-alert.png`,
    );
  }
});

test("stale observations never display a rated face or all-clear claim", () => {
  const view = getPresentation(moods[0], "stale");
  assert.equal(view.image, null);
  assert.equal(view.rating, "Unavailable");
  assert.equal(view.label, "No fresh data");
  assert.doesNotMatch(view.description, /all clear|safe|secure/i);
});

test("normal mode displays the selected mood without claiming real monitoring", () => {
  for (const mood of moods) {
    const view = getPresentation(mood, "normal");
    assert.equal(view.label, mood.name);
    assert.equal(view.image, mood.image);
    assert.equal(view.demo, true);
  }
});
