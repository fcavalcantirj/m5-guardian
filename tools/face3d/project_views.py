"""Project the ORIGINAL 2D master onto the Meshy head geometry and render it from a grid of angles.
Run: blender -b -P project_views.py -- MODEL.glb MASTER.png OUTDIR [--yaw -30,30,7] [--pitch -15,15,3] [--scale 4] [--shade 0.0]
The Meshy texture is never used: the master (512x512 RGBA, the repo art) is UV-projected from the front onto the mesh
at the identity pose and baked into the UVs, so yaw 0 reproduces the painting and other angles bend it with the head.
--shade 0..1 mixes in a little lit shading for depth (0 = the exact painting colours, emission only).
The fit is by silhouette: the mesh's front bounding box is matched to the master's alpha bounding box (both printed).
Surfaces the projector cannot paint honestly (seen at a grazing angle, or hidden behind the front surfaces at the
identity pose) are NOT stretched: a per-vertex "projok" weight (facing x visible, baked once) fades them to the
master's own dark hood colour (--fill r,g,b overrides, 0..255). --graze lo,hi sets the facing fade (cosines)."""
import sys, math, os
import bpy
from mathutils import Vector, Euler

argv = sys.argv[sys.argv.index('--') + 1:]
model, master, outdir = argv[0], argv[1], argv[2]
def opt(name, default):
    return argv[argv.index(name) + 1] if name in argv else default
y0, y1, yn = (float(v) for v in opt('--yaw', '-30,30,7').split(','))
p0, p1, pn = (float(v) for v in opt('--pitch', '-15,15,3').split(','))
scale = int(opt('--scale', '4')); shade = float(opt('--shade', '0'))
graze_lo, graze_hi = (float(v) for v in opt('--graze', '0.2,0.5').split(','))
os.makedirs(outdir, exist_ok=True)

bpy.ops.wm.read_factory_settings(use_empty=True)
bpy.ops.import_scene.gltf(filepath=model)
meshes = [o for o in bpy.context.scene.objects if o.type == 'MESH']
mn = Vector((1e9, 1e9, 1e9)); mx = Vector((-1e9, -1e9, -1e9))
for o in meshes:
    for c in o.bound_box:
        w = o.matrix_world @ Vector(c); mn = Vector(map(min, mn, w)); mx = Vector(map(max, mx, w))
centre = (mn + mx) / 2; size = mx - mn
print(f'mesh bbox x {mn.x:.4f}..{mx.x:.4f} z {mn.z:.4f}..{mx.z:.4f} (w {size.x:.4f} h {size.z:.4f})')

# Master alpha bounding box (image y grows downwards).
img = bpy.data.images.load(master); W, H = img.size; px = img.pixels[:]
ax0, ay0, ax1, ay1 = W, H, -1, -1
for y in range(H):
    row = px[y * W * 4 + 3: (y + 1) * W * 4: 4]
    xs = [x for x, a in enumerate(row) if a > 0.5]
    if xs:
        iy = H - 1 - y   # Blender stores rows bottom-up
        ax0 = min(ax0, xs[0]); ax1 = max(ax1, xs[-1]); ay0 = min(ay0, iy); ay1 = max(ay1, iy)
aw, ah = ax1 - ax0 + 1, ay1 - ay0 + 1
print(f'master alpha bbox x {ax0}..{ax1} y {ay0}..{ay1} (w {aw} h {ah})')
ppw_x, ppw_z = aw / size.x, ah / size.z
print(f'pixels per world unit: x {ppw_x:.2f} z {ppw_z:.2f} (ratio {ppw_x / ppw_z:.3f}; 1.0 = same aspect as the master)')
ppw = (ppw_x + ppw_z) / 2
acx, acy = (ax0 + ax1 + 1) / 2, (ay0 + ay1 + 1) / 2
if '--fill' in argv:
    fill = tuple(int(v) / 255 for v in opt('--fill', '').split(','))
else:
    dark = sorted((px[i] + px[i + 1] + px[i + 2], px[i], px[i + 1], px[i + 2]) for i in range(0, len(px), 4 * 7) if px[i + 3] > 0.5)
    dark = dark[: max(1, len(dark) // 5)]; m = dark[len(dark) // 2]; fill = (m[1], m[2], m[3])
print(f'fill colour (sRGB) {tuple(round(c * 255) for c in fill)}')

# Projector: a square ortho camera on the front axis (-Y), framing exactly the 512x512 master.
proj_data = bpy.data.cameras.new('proj'); proj_data.type = 'ORTHO'; proj_data.ortho_scale = W / ppw
proj = bpy.data.objects.new('proj', proj_data); bpy.context.scene.collection.objects.link(proj)
proj.location = Vector((centre.x - (acx - W / 2) / ppw, centre.y - max(size) * 4, centre.z + (acy - H / 2) / ppw))
proj.rotation_euler = Euler((math.radians(90), 0, 0))
sc = bpy.context.scene
sc.render.resolution_x = sc.render.resolution_y = W   # UV Project uses the render aspect while applying

# Material: the master as emission (exact colours), optionally mixed with a lit principled shader.
mat = bpy.data.materials.new('master'); mat.use_nodes = True; nt = mat.node_tree
for n in list(nt.nodes): nt.nodes.remove(n)
tex = nt.nodes.new('ShaderNodeTexImage'); tex.image = img; tex.extension = 'EXTEND'
emit = nt.nodes.new('ShaderNodeEmission'); emit.inputs['Strength'].default_value = 1.0
bsdf = nt.nodes.new('ShaderNodeBsdfPrincipled'); bsdf.inputs['Roughness'].default_value = 0.8
mix = nt.nodes.new('ShaderNodeMixShader'); mix.inputs['Fac'].default_value = shade
out = nt.nodes.new('ShaderNodeOutputMaterial')
vc = nt.nodes.new('ShaderNodeVertexColor'); vc.layer_name = 'projok'
mixc = nt.nodes.new('ShaderNodeMix'); mixc.data_type = 'RGBA'; mixc.inputs[6].default_value = (*fill, 1.0)
nt.links.new(vc.outputs['Color'], mixc.inputs['Factor']); nt.links.new(tex.outputs['Color'], mixc.inputs[7])
nt.links.new(mixc.outputs[2], emit.inputs['Color']); nt.links.new(mixc.outputs[2], bsdf.inputs['Base Color'])
nt.links.new(emit.outputs[0], mix.inputs[1]); nt.links.new(bsdf.outputs[0], mix.inputs[2]); nt.links.new(mix.outputs[0], out.inputs['Surface'])
for o in meshes:
    o.data.materials.clear(); o.data.materials.append(mat)
    if not o.data.uv_layers: o.data.uv_layers.new(name='proj')
    m = o.modifiers.new('proj', 'UV_PROJECT'); m.uv_layer = o.data.uv_layers[0].name
    m.projector_count = 1; m.projectors[0].object = proj; m.aspect_x = m.aspect_y = 1.0
    bpy.context.view_layer.objects.active = o
    bpy.ops.object.modifier_apply(modifier='proj')   # bake: the painting now rides on the mesh

# Bake projok: facing = cos(normal, towards projector) faded over --graze; visible = a ray from the projector reaches it.
# The rays go through a BVH tree (mathutils.bvhtree), one per mesh.
# MEASURED 2026-11-18 (G21; `sample <pid>` of two runs that never produced a frame, one of them 2 h 35 min old): the time
# was not in the ray cast. The loop read `v.normal` right after writing the vertex's colour, and every such write
# invalidates the mesh's normals cache, so each vertex recomputed the normals of the WHOLE mesh
# (Mesh::vert_normals -> normals_calc_corners, all cores busy). So: read every position and normal first, compute the
# weights in plain Python, and write the attribute once at the end.
from mathutils.bvhtree import BVHTree
import time
fwd = Vector((0, 1, 0)); eps = max(size) * 0.004; t_bake = time.time()
dg = bpy.context.evaluated_depsgraph_get()
trees = [(o, BVHTree.FromObject(o, dg), o.matrix_world.copy(), o.matrix_world.inverted()) for o in meshes]
for o in meshes:
    me = o.data; world = o.matrix_world.copy(); rot = world.to_3x3(); n = len(me.vertices)
    cos = [0.0] * (n * 3); me.vertices.foreach_get('co', cos)
    nors = [0.0] * (n * 3); me.vertices.foreach_get('normal', nors)
    colours = [0.0] * (n * 4)
    n_graze = n_hidden = 0
    for i in range(n):
        wn = (rot @ Vector(nors[3 * i: 3 * i + 3])).normalized(); facing = max(0.0, -wn.dot(fwd))   # the projector looks along +Y
        f = min(1.0, max(0.0, (facing - graze_lo) / (graze_hi - graze_lo)))
        wp = world @ Vector(cos[3 * i: 3 * i + 3])
        origin = Vector((wp.x, proj.location.y, wp.z)); vis = 1.0
        for oo, tree, to_world, to_local in trees:   # BVH works in each object's local space
            loc, _, _, dist = tree.ray_cast(to_local @ origin, (to_local.to_3x3() @ fwd).normalized())
            if loc is not None and ((to_world @ loc) - wp).length > eps and (to_world @ loc - origin).length < (wp - origin).length - eps:
                vis = 0.0; break
        if f < 1.0: n_graze += 1
        if not vis: n_hidden += 1
        w = f * vis; colours[4 * i: 4 * i + 4] = (w, w, w, 1.0)
    attr = me.color_attributes.new(name='projok', type='FLOAT_COLOR', domain='POINT')
    attr.data.foreach_set('color', colours)
    print(f'{o.name}: {n} vertices, grazing {n_graze}, hidden from the projector {n_hidden}', flush=True)
print(f'projok bake {time.time() - t_bake:.1f} s', flush=True)

pivot = bpy.data.objects.new('pivot', None); bpy.context.scene.collection.objects.link(pivot); pivot.location = centre
for o in meshes:
    if o.parent is None:
        o.parent = pivot; o.matrix_parent_inverse = pivot.matrix_world.inverted()

# Render camera: the portrait frame (135:160), filled like the v2 art.
cam_data = bpy.data.cameras.new('cam'); cam_data.type = 'ORTHO'
cam = bpy.data.objects.new('cam', cam_data); bpy.context.scene.collection.objects.link(cam)
# 2026-11-18 (owner: "exactly like the approved image"): the render camera frames the MASTER's own portrait crop
# (build_assets.py crop box (40,0,472,512) = 432x512 = 135:160), not the mesh's box, so at yaw 0 every surface that
# faces the projector lands on the same screen pixel as the shipped 2D portrait. Sensor fit is vertical: the crop's
# 512 px of master height fill the 160-row band.
cam.location = Vector((proj.location.x, centre.y - max(size) * 4, proj.location.z)); cam.rotation_euler = Euler((math.radians(90), 0, 0))
sc.camera = cam
cam_data.sensor_fit = 'VERTICAL'; cam_data.ortho_scale = 512 / ppw
if shade > 0:
    key = bpy.data.lights.new('key', 'AREA'); key.energy = 600; key.size = max(size) * 2
    kobj = bpy.data.objects.new('key', key); sc.collection.objects.link(kobj)
    kobj.location = centre + Vector((-max(size) * 1.5, -max(size) * 2.5, max(size) * 1.5))
    kobj.rotation_euler = (centre - kobj.location).to_track_quat('-Z', 'Y').to_euler()
engines = [e.identifier for e in bpy.types.RenderSettings.bl_rna.properties['engine'].enum_items]
sc.render.engine = 'BLENDER_EEVEE_NEXT' if 'BLENDER_EEVEE_NEXT' in engines else 'BLENDER_EEVEE'
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
