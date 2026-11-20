#!/usr/bin/env python3
"""G16C: derive the StickS3 IMU -> screen axis map from RECORDED serial IMU traces.

The Guardian's face and HUD react to the stick being handled (firmware motion
model). Which BMI270 axis points to the screen's right, top and viewer is a
physical fact of the board, so it is measured, never assumed:

  1. Stand the stick upright, USB down, still on the table. Record ~3 s:
       serial: IMU 3      -> save the lines to standing.log
  2. Lay it flat, screen facing the ceiling, still. Record ~3 s -> lying.log
  3. (optional cross-check) Lay it on its RIGHT edge (as seen from the front),
     still. Record ~3 s -> right-edge.log

  python3 tools/imu_axis_map.py --standing standing.log --lying lying.log [--right-edge right-edge.log]

Without the cable (review 2026-11-17; the real upright pose has the USB port on the table):
in one tools/tune_session.py session, put the stick in each pose, wait ~3 s still, send
"IMU POSE" and save that reply line as the pose's file. A file may hold several POSE lines;
the last one is used. The same stillness, 1 g and dominant-axis rules apply.

At rest the accelerometer reads +1 g along world-up, so the standing trace's
dominant axis (with its sign) is the screen's UP and the lying trace's is OUT
(towards the viewer). RIGHT = UP x OUT in the BMI270's right-handed frame
(Bosch BMI270 datasheet, axes of sensitivity). The optional right-edge trace
must then show world-up along -RIGHT (screen left).

Output: the three TUNE lines to send over serial (signed axis 1=x, 2=y, 3=z)
plus a JSON evidence summary on stderr. Any doubtful trace (too short,
moving, not ~1 g, no dominant axis, both poses on one axis) is refused with a
reason and no TUNE line is printed. Pure file processing: no serial port, no
device access.
"""
import argparse, json, math, re, sys
from pathlib import Path

MIN_SAMPLES = 200          # 1 s at 200 Hz
MAX_GYRO_DPS = 3.0         # mean |gyro| while still
G_TOLERANCE = 0.15         # |acc| must be 1 g +- this
DOMINANT_G = 0.80          # the dominant axis carries at least this much of gravity
OTHER_G = 0.45             # ... and each other axis at most this much
GYR_LSB_PER_DPS = 16.384
_SAMPLE = re.compile(r'^IMU (-?\d+) (\d+) (-?\d+) (-?\d+) (-?\d+) (-?\d+) (-?\d+) (-?\d+)\s*$')
_HEADER = re.compile(r'acc_lsb_per_g=([0-9.]+)')
_HEADER_GYR = re.compile(r'gyr_lsb_per_dps=([0-9.]+)')
# Review 2026-11-17: one Wi-Fi/USB "IMU POSE" line (firmware adapters/imu/pose.hpp): the mean
# acceleration (LSB) and mean |gyro| (deg/s) of the stick's latest 2 s block.
_POSE = re.compile(r'G16C IMU POSE samples=(\d+) age_ms=\d+ acc_mean=(-?[0-9.]+),(-?[0-9.]+),(-?[0-9.]+) '
                   r'gyro_dps=([0-9.]+) acc_lsb_per_g=([0-9.]+)\s*$')


class TraceError(Exception):
    pass


def read_trace(path):
    acc_lsb, gyr_lsb, rows, pose = 4096.0, GYR_LSB_PER_DPS, [], None
    for line in Path(path).read_text(errors='replace').splitlines():
        m = _POSE.search(line.strip())
        if m:   # the last pose line wins (earlier ones may show the stick still settling)
            n, ax, ay, az, gyro, lsb = m.groups()
            pose = {'samples': int(n), 'mean_g': [float(v) / float(lsb) for v in (ax, ay, az)],
                    'gyro_dps': float(gyro), 'acc_lsb_per_g': float(lsb), 'source': 'IMU POSE'}
            continue
        if 'IMU STREAM' in line:
            m = _HEADER.search(line)
            if m: acc_lsb = float(m.group(1))
            m = _HEADER_GYR.search(line)
            if m: gyr_lsb = float(m.group(1))
            continue
        m = _SAMPLE.match(line.strip())
        if m: rows.append([int(v) for v in m.groups()[2:]])
    if not rows and pose:
        return pose
    if not rows:
        raise TraceError(f'{path}: no IMU samples (expected "IMU <t_us> <sensortime> ax ay az gx gy gz" lines or a "G16C IMU POSE samples=..." line)')
    n = len(rows)
    mean = [sum(r[k] for r in rows) / n / acc_lsb for k in range(3)]
    gyro = sum(math.sqrt(sum((r[3 + k] / gyr_lsb) ** 2 for k in range(3))) for r in rows) / n
    return {'samples': n, 'mean_g': mean, 'gyro_dps': gyro, 'acc_lsb_per_g': acc_lsb}


def dominant_axis(name, t):
    if t['samples'] < MIN_SAMPLES:
        raise TraceError(f'{name}: {t["samples"]} samples, need at least {MIN_SAMPLES} (record ~3 s with IMU 3)')
    if t['gyro_dps'] > MAX_GYRO_DPS:
        raise TraceError(f'{name}: the stick was moving (mean rotation {t["gyro_dps"]:.1f} deg/s > {MAX_GYRO_DPS})')
    g = t['mean_g']; mag = math.sqrt(sum(v * v for v in g))
    if abs(mag - 1.0) > G_TOLERANCE:
        raise TraceError(f'{name}: |acc| = {mag:.2f} g, not ~1 g at rest')
    k = max(range(3), key=lambda i: abs(g[i]))
    if abs(g[k]) < DOMINANT_G or any(abs(g[i]) > OTHER_G for i in range(3) if i != k):
        raise TraceError(f'{name}: no dominant axis (mean {g[0]:+.2f}, {g[1]:+.2f}, {g[2]:+.2f} g): hold the pose squarely')
    return (k + 1) * (1 if g[k] > 0 else -1)


def _vec(a):
    v = [0, 0, 0]; v[abs(a) - 1] = 1 if a > 0 else -1; return v


def _axis(v):
    k = max(range(3), key=lambda i: abs(v[i])); return (k + 1) * (1 if v[k] > 0 else -1)


def derive(standing, lying, right_edge=None):
    st, ly = read_trace(standing), read_trace(lying)
    up, out = dominant_axis('standing trace', st), dominant_axis('lying trace', ly)
    if abs(up) == abs(out):
        raise TraceError(f'standing and lying traces share the same axis ({up:+d} vs {out:+d}): re-record both poses')
    u, o = _vec(up), _vec(out)
    right = _axis([u[1] * o[2] - u[2] * o[1], u[2] * o[0] - u[0] * o[2], u[0] * o[1] - u[1] * o[0]])
    result = {'right': right, 'up': up, 'out': out, 'standing': st, 'lying': ly,
              'rule': 'up = standing dominant axis, out = lying (screen up) dominant axis, right = up x out (right-handed BMI270 frame)'}
    if right_edge is not None:
        side = read_trace(right_edge); seen = dominant_axis('right-edge trace', side)
        if seen != -right:
            raise TraceError(f'right-edge trace shows world-up on axis {seen:+d}, expected {-right:+d} (screen left): the map is inconsistent')
        result['right_edge'] = side; result['cross_check'] = 'right-edge trace agrees'
    return result


def tune_lines(r):
    return [f'TUNE imu.right={r["right"]}', f'TUNE imu.up={r["up"]}', f'TUNE imu.out={r["out"]}']


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    ap.add_argument('--standing', required=True, help='IMU stream log, stick upright, USB down, still')
    ap.add_argument('--lying', required=True, help='IMU stream log, stick flat, screen facing up, still')
    ap.add_argument('--right-edge', help='optional IMU stream log, stick on its right edge, still (cross-check)')
    a = ap.parse_args(argv)
    try:
        r = derive(a.standing, a.lying, a.right_edge)
    except (TraceError, OSError) as e:
        print(f'imu_axis_map: REFUSED: {e}', file=sys.stderr); return 2
    print('\n'.join(tune_lines(r)))
    print(json.dumps(r, indent=1, default=str), file=sys.stderr)
    return 0


if __name__ == '__main__':
    sys.exit(main())
