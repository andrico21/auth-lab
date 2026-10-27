import assert from 'node:assert/strict';

const calibrations = new WeakMap();
const correctionLimit = 6;

// Use Playwright's measured pointer coordinate space for native input.
// Evaluation only reads CSS geometry, playback status, focus and actual value.
export async function seekNativeRange(page, value, {click, record}) {
  assert.ok(Number.isInteger(value) && value >= 0 && value <= 1000, 'Native range 0..1000');
  assert.equal(typeof click, 'function', 'Genuine pause-control helper required');
  assert.equal(typeof record, 'function', 'Evidence recorder required');
  const control = page.locator('#seek');
  const evidence = {kind: 'interaction', mechanism: 'native-range-keyboard', selector: '#seek', value, url: page.url(), pausedBeforeSeek: false, calibration: null, pointers: [], keys: {}, keyboard: [], counts: {calibrationSamples: 0, pointer: 0, key: 0}, passed: false};
  let session, pressed = false, touch = false;
  const actual = async () => Number(await control.inputValue());
  const press = async key => {
    evidence.keys[key] = (evidence.keys[key] || 0) + 1;
    evidence.counts.key++;
    const before = await actual();
    await page.keyboard.press(key);
    const after = await actual();
    evidence.keyboard.push({key, before, after});
    return after;
  };
  try {
    if (await page.evaluate(() => document.querySelector('auth-flow-studio').player.status === 'playing')) {
      await click('#play');
      assert.equal(await page.evaluate(() => document.querySelector('auth-flow-studio').player.status), 'paused', 'Pause before native seek');
      evidence.pausedBeforeSeek = true;
    }
    await control.focus();
    await control.scrollIntoViewIfNeeded();
    evidence.before = await actual();
    if (value === 0 || value === 1000) {
      await press(value === 0 ? 'Home' : 'End');
    } else {
      if (!await page.evaluate(() => matchMedia('(pointer: coarse)').matches)) {
        await control.hover();
        evidence.counts.pointer++;
      }
      const properties = await control.evaluate(element => {
        const rect = element.getBoundingClientRect(), style = getComputedStyle(element);
        return {clientRect: {x: rect.x, y: rect.y, width: rect.width, height: rect.height}, touch: matchMedia('(pointer: coarse)').matches, dpr: devicePixelRatio, viewportScale: visualViewport.scale, direction: style.direction, writingMode: style.writingMode, min: element.min, max: element.max, step: element.step};
      });
      const box = await control.boundingBox();
      assert.ok(box, 'Visible native pointer bounding box');
      const geometry = {...properties, ...box, coordinateBasis: 'Playwright locator.boundingBox'};
      assert.ok(geometry.width > 0 && geometry.height > 0, 'Visible native range');
      assert.equal(geometry.direction, 'ltr');
      assert.equal(geometry.writingMode, 'horizontal-tb');
      assert.equal(geometry.min, '0'); assert.equal(geometry.max, '1000'); assert.equal(geometry.step, '1');
      evidence.geometry = geometry;
      touch = geometry.touch;
      evidence.mechanism = touch ? 'native-range-cdp-touch-drag-and-keyboard' : 'native-range-mouse-drag-and-keyboard';
      if (touch) session = await page.context().newCDPSession(page);
      const pointer = async (type, offset) => {
        const point = {x: geometry.x + offset, y: geometry.y + geometry.height / 2};
        assert.ok(offset >= 0 && offset <= geometry.width, 'Measured pointer stays inside range');
        evidence.counts.pointer++;
        if (touch) {
          await session.send('Input.dispatchTouchEvent', {type: {down: 'touchStart', move: 'touchMove', up: 'touchEnd'}[type], touchPoints: type === 'up' ? [] : [{...point, id: 0}]});
        } else {
          if (type === 'down') { await page.mouse.move(point.x, point.y); evidence.counts.pointer++; await page.mouse.down(); }
          else if (type === 'move') await page.mouse.move(point.x, point.y);
          else await page.mouse.up();
        }
        pressed = type !== 'up';
        const observed = await actual();
        evidence.pointers.push({type, ...point, actual: observed});
        return observed;
      };
      const key = JSON.stringify([geometry.width, geometry.height, touch, geometry.dpr, geometry.viewportScale]);
      let calibration = calibrations.get(page);
      if (calibration?.key !== key) {
        // Two interior samples in one real drag fit the native track mapping.
        // No thumb dimensions or UA/CSS scale factors are assumed.
        const firstX = geometry.width / 4, secondX = geometry.width * 3 / 4;
        const firstValue = await pointer('down', firstX);
        const secondValue = await pointer('move', secondX);
        assert.ok(secondValue > firstValue && firstValue > 0 && secondValue < 1000, 'Trusted drag calibrates an interior native track');
        const pixelsPerValue = (secondX - firstX) / (secondValue - firstValue);
        calibration = {key, origin: firstX - firstValue * pixelsPerValue, pixelsPerValue, samples: [{offset: firstX, actual: firstValue}, {offset: secondX, actual: secondValue}]};
        calibrations.set(page, calibration);
        evidence.counts.calibrationSamples = 2;
        evidence.calibration = {cached: false, ...calibration};
      } else {
        evidence.calibration = {cached: true, ...calibration};
        const startX = calibration.origin + await actual() * calibration.pixelsPerValue;
        await pointer('down', startX);
        if (touch) {
          // A nearby target can remain inside Chromium's touch slop. Activate
          // the real drag with the farther measured sample before returning
          // to the target; do not disguise a tap as a successful seek.
          const activation = calibration.samples.reduce((farther, sample) => Math.abs(sample.offset - startX) > Math.abs(farther.offset - startX) ? sample : farther);
          await pointer('move', activation.offset);
          evidence.touchActivation = {offset: activation.offset, actual: await actual()};
        }
      }
      // A single target movement, followed by a bounded keyboard correction.
      const targetX = calibration.origin + value * calibration.pixelsPerValue;
      await pointer('move', targetX);
      await pointer('up', targetX);
      let current = await actual();
      evidence.pointerActual = current;
      assert.ok(Math.abs(current - value) <= correctionLimit, 'Measured native drag requires at most six correction keys');
      if (current === value) {
        current = await press(value < 500 ? 'ArrowRight' : 'ArrowLeft');
        assert.notEqual(current, value, 'Genuine finishing keyboard action changes value');
      }
      let corrections = 0;
      while (current !== value) {
        assert.ok(corrections++ < correctionLimit, 'Native keyboard correction bounded');
        const previous = current;
        current = await press(current < value ? 'ArrowRight' : 'ArrowLeft');
        assert.equal(Math.abs(current - previous), 1, 'Native correction progresses by one');
      }
      evidence.correctionKeys = corrections;
    }
    evidence.actual = await actual();
    evidence.focused = await control.evaluate(element => document.activeElement === element);
    assert.equal(evidence.actual, value, 'Exact final native range value');
    assert.equal(evidence.focused, true, 'Native range retains keyboard focus');
    assert.ok(evidence.counts.key > 0, 'Every seek finishes through genuine keyboard input');
    evidence.passed = true;
    return evidence;
  } catch (error) {
    evidence.error = error.stack || String(error);
    throw error;
  } finally {
    try {
      if (pressed) {
        if (touch) await session.send('Input.dispatchTouchEvent', {type: 'touchCancel', touchPoints: []});
        else await page.mouse.up();
        evidence.counts.pointer++;
        evidence.pointers.push({type: touch ? 'cancel' : 'up', cleanup: true});
      }
    } finally {
      try { await session?.detach(); }
      finally { await record(evidence); }
    }
  }
}
