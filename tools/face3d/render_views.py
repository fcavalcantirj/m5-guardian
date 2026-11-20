"""Render the Meshy head from a grid of angles at the StickS3 portrait size (135x160, black matte).
Run: blender -b -P render_views.py -- MODEL.glb OUTDIR [--yaw -30,30,7] [--pitch -15,15,3] [--scale 4]
The camera is fixed; the HEAD turns (yaw about the vertical, pitch about the left-right axis), so the
light stays put like a room light while the face turns through it. Emission-first shading keeps the
Meshy texture's own colours (the v2 art's cyan/red); a soft key light adds real 3D shape."""
import sys, math, os
import bpy
from mathutils import Vector, Euler

argv = sys.argv[sys.argv.index('--') + 1:]
model, outdir = argv[0], argv[1]
def opt(name, default):
    return argv[argv.index(name) + 1] if name in argv else default
y0, y1, yn = (float(v) for v in opt('--yaw', '-30,30,7').split(','))
p0, p1, pn = (float(v) for v in opt('--pitch', '-15,15,3').split(','))
scale = int(opt('--scale', '4'))
lights = opt('--lights', '1') != '0'   # 0 = texture only (no key, no cyan/red rims), the Meshy thumbnail look
os.makedirs(outdir, exist_ok=True)

bpy.ops.wm.read_factory_settings(use_empty=True)
bpy.ops.import_scene.gltf(filepath=model)
meshes = [o for o in bpy.context.scene.objects if o.type == 'MESH']
# A pivot empty at the head's centre: everything turns about it.
mn = Vector((1e9, 1e9, 1e9)); mx = Vector((-1e9, -1e9, -1e9))
for o in meshes:
    for c in o.bound_box:
        w = o.matrix_world @ Vector(c); mn = Vector(map(min, mn, w)); mx = Vector(map(max, mx, w))
centre = (mn + mx) / 2; size = mx - mn
pivot = bpy.data.objects.new('pivot', None); bpy.context.scene.collection.objects.link(pivot); pivot.location = centre
for o in meshes:
    if o.parent is None:
        o.parent = pivot; o.matrix_parent_inverse = pivot.matrix_world.inverted()

# Camera looking at the face (glTF imports +Y up -> Blender +Z up; Meshy faces -Y in Blender).
cam_data = bpy.data.cameras.new('cam'); cam_data.type = 'ORTHO'
cam = bpy.data.objects.new('cam', cam_data); bpy.context.scene.collection.objects.link(cam)
cam.location = centre + Vector((0, -max(size) * 4, 0)); cam.rotation_euler = Euler((math.radians(90), 0, 0))
bpy.context.scene.camera = cam
aspect = 135 / 160
cam_data.ortho_scale = max(size.z, size.x / aspect) * 1.04   # fill the portrait frame like the v2 art

# Light: a soft key from upper front-left plus the texture as emission (keeps the art's colours).
key = bpy.data.lights.new('key', 'AREA'); key.energy = 400 if lights else 0; key.size = max(size) * 2
kobj = bpy.data.objects.new('key', key); bpy.context.scene.collection.objects.link(kobj)
kobj.location = centre + Vector((-max(size) * 1.5, -max(size) * 2.5, max(size) * 1.5))
kobj.rotation_euler = (centre - kobj.location).to_track_quat('-Z', 'Y').to_euler()
# The v2 look: cyan light from the left, red from the right (rim lights behind the hood edges).
for name, colour, side in (('cyan', (0.0, 0.85, 1.0), -1), ('red', (1.0, 0.08, 0.05), 1)):
    l = bpy.data.lights.new(name, 'AREA'); l.energy = 900 if lights else 0; l.color = colour; l.size = max(size)
    lo = bpy.data.objects.new(name, l); bpy.context.scene.collection.objects.link(lo)
    lo.location = centre + Vector((side * max(size) * 2.2, max(size) * 0.6, max(size) * 0.8))
    lo.rotation_euler = (centre - lo.location).to_track_quat('-Z', 'Y').to_euler()
for o in meshes:
    for slot in o.material_slots:
        m = slot.material
        if not m or not m.use_nodes: continue
        nt = m.node_tree; bsdf = next((n for n in nt.nodes if n.type == 'BSDF_PRINCIPLED'), None)
        if not bsdf: continue
        base = bsdf.inputs['Base Color']
        if base.is_linked:
            nt.links.new(base.links[0].from_socket, bsdf.inputs['Emission Color'])
            bsdf.inputs['Emission Strength'].default_value = float(opt('--emit', '0.25'))

sc = bpy.context.scene
sc.render.engine = 'BLENDER_EEVEE_NEXT' if 'BLENDER_EEVEE_NEXT' in [e.identifier for e in bpy.types.RenderSettings.bl_rna.properties['engine'].enum_items] else 'BLENDER_EEVEE'
sc.render.resolution_x, sc.render.resolution_y = 135 * scale, 160 * scale
sc.render.film_transparent = False
sc.world = bpy.data.worlds.new('w'); sc.world.use_nodes = True
sc.world.node_tree.nodes['Background'].inputs['Color'].default_value = (0, 0, 0, 1)
sc.view_settings.view_transform = 'Standard'
sc.render.image_settings.file_format = 'PNG'

def steps(a, b, n):
    n = int(n); return [a + (b - a) * i / (n - 1) for i in range(n)] if n > 1 else [a]
for p in steps(p0, p1, pn):
    for y in steps(y0, y1, yn):
        pivot.rotation_euler = Euler((math.radians(p), 0, math.radians(y)), 'XYZ')
        sc.render.filepath = os.path.join(outdir, f'yaw{y:+05.1f}_pitch{p:+05.1f}.png')
        bpy.ops.render.render(write_still=True)
print('rendered', outdir)
