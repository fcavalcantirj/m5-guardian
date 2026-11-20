#!/usr/bin/env python3
"""Build 5 security moods x 3 normal/alert-pulse states from the original
AI-rendered 3D portrait contact sheet. Uses the repository's own export tool
for device-ready RGB565 (little endian) and contact sheets.
This is a static rendered-art pipeline, not a new rigged Blender model.
"""
from PIL import Image, ImageDraw, ImageEnhance, ImageFilter
import numpy as np, os, json, hashlib, math, subprocess, shutil, pathlib, sys
S=pathlib.Path(__file__).resolve().parent

# ---- G16A: upright portrait crop of the accepted v2 Very good master --------
# python3 build_assets.py portrait <masters_png/VeryGood.png>
#   master: $GUARDIAN_STORE/art-exports/G15/20261116-v2/masters_png/VeryGood.png (512x512 RGBA)
#   writes  portrait/VeryGood_portrait.rgb565 (135x160 little-endian RGB565,
#           43,200 bytes) + portrait/VeryGood_portrait_preview565.png, and
#           records both sha256 values plus the crop in manifest.json.
# Deterministic: fixed crop box, LANCZOS resize, black matte (the panel
# background), make_sheets.to565 rounding. Rebuilding must reproduce the hashes.
PORTRAIT_SIZE=(135,160)              # StickS3 upright face zone (full width, 160 px tall)
PORTRAIT_CROP=(40,0,472,512)         # 432x512 keeps the 135:160 aspect and the whole hood (alpha bbox x 48..462)
PORTRAIT_MASTER_SHA256='4b08abc456264c138f03e3be9e75b62aa96717c4ae5666c5bf623d2574120b7b'
# G16Q part 2 (owner's pick on the art bench, 2026-11-18, "its the difuser. perfect";
# firmware/evidence/sticks3-G16Q-artbench-20261118.log): candidate D. The crop is resized in LINEAR light
# (sRGB decoded, premultiplied by alpha = the black matte, LANCZOS, encoded), then an unsharp mask
# (radius, percent, threshold), then Floyd-Steinberg error diffusion to RGB565 instead of rounding.
# The steps are tools/art/candidates.py's own functions (one implementation; its test pins candidate D
# byte for byte against these portraits). Before G16Q: LANCZOS on sRGB codes, unsharp 1.0/90/2, rounded.
PORTRAIT_SHARPEN=(0.6,120,1)
def _candidates():
    tools_art=str(S.parents[3]/'tools'/'art')
    if tools_art not in sys.path: sys.path.insert(0,tools_art)
    import candidates; return candidates
def crop_art(master):
    """The accepted G16A crop of the RGBA master (fixed box, LANCZOS to 135x160): only its alpha is used,
    for the no-data silhouette's outline."""
    im=Image.open(master).convert('RGBA'); assert im.size==(512,512)
    box=PORTRAIT_CROP; assert (box[2]-box[0])*PORTRAIT_SIZE[1]==(box[3]-box[1])*PORTRAIT_SIZE[0]
    return im.crop(box).resize(PORTRAIT_SIZE,Image.Resampling.LANCZOS)
def preview565(raw,size):
    """What the RGB565 bytes show, expanded like make_sheets.to565's preview (bit replication)."""
    w=np.frombuffer(raw,dtype='<u2').astype(np.uint16).reshape(size[1],size[0])
    r5,g6,b5=w>>11,(w>>5)&63,w&31
    rgb=np.stack([(r5<<3)|(r5>>2),(g6<<2)|(g6>>4),(b5<<3)|(b5>>2)],axis=-1).astype('uint8')
    return Image.fromarray(rgb)
def portrait_565(master):
    """Candidate D of a 512x512 RGBA master: (135x160 little-endian RGB565 bytes, preview image)."""
    c=_candidates()
    im=Image.open(master).convert('RGBA'); assert im.size==(512,512)
    raw=c.dither565(c.unsharp(c.linear_resize(im,PORTRAIT_CROP,PORTRAIT_SIZE),PORTRAIT_SHARPEN))
    return raw,preview565(raw,PORTRAIT_SIZE)
PORTRAIT_PIPELINE={'resample':'LANCZOS in linear light, premultiplied alpha (black matte)',
                   'unsharp_radius_percent_threshold':list(PORTRAIT_SHARPEN),'to565':'Floyd-Steinberg',
                   'pick':'G16Q candidate D, owner 2026-11-18'}
def build_portrait(master):
    master=pathlib.Path(master)
    digest=hashlib.sha256(master.read_bytes()).hexdigest()
    if digest!=PORTRAIT_MASTER_SHA256:
        raise SystemExit(f'unexpected master {master}: sha256 {digest} (expected the accepted v2 VeryGood.png)')
    box=PORTRAIT_CROP
    raw,preview=portrait_565(master)
    assert len(raw)==PORTRAIT_SIZE[0]*PORTRAIT_SIZE[1]*2==43200
    out=S/'portrait'; out.mkdir(exist_ok=True)
    (out/'VeryGood_portrait.rgb565').write_bytes(raw)
    preview.save(out/'VeryGood_portrait_preview565.png',optimize=False)
    manifest=json.loads((S/'manifest.json').read_text())
    for name in ['VeryGood_portrait.rgb565','VeryGood_portrait_preview565.png']:
        manifest['files'][f'portrait/{name}']=hashlib.sha256((out/name).read_bytes()).hexdigest()
    manifest['sources']['masters_png/VeryGood.png']=digest
    manifest['portrait']={'frame':list(PORTRAIT_SIZE),'crop_box_in_master':list(box),**PORTRAIT_PIPELINE,
                          'matte':'black','rgb565_byte_order':'little-endian','rgb565_bytes':len(raw),
                          'master':'$GUARDIAN_STORE/art-exports/G15/20261116-v2/masters_png/VeryGood.png'}
    (S/'manifest.json').write_text(json.dumps(manifest,indent=1)+'\n')
    print('PORTRAIT',out/'VeryGood_portrait.rgb565',len(raw),manifest['files']['portrait/VeryGood_portrait.rgb565'])
# ---- G16C: every rating, its two ALERT pulses and the no-data silhouette ------
# python3 build_assets.py portraits <masters_png dir>
#   masters: $GUARDIAN_STORE/art-exports/G15/20261117-v4/masters_png/ from alert_eyes.py over the accepted v2 masters: Good/Medium/Bad
#   unchanged (cyan eyes), Very good GREEN eyes, Horrible RED eyes, ALERT frames = red eyes (no corona); owner row B,
#   2026-11-17; sha256-pinned below
#   writes  portrait/<Name>_portrait.rgb565 (135x160 little-endian RGB565, 43,200 bytes each) and
#           portrait/<Name>_portrait_preview565.png for the 15 masters (5 ratings + 2 ALERT pulses each)
#           plus portrait/NoData_portrait.rgb565: an expression-free silhouette (hood/mask outline only,
#           from the Medium crop's alpha) for "not rated" / "no fresh data". It shows no rated face.
# Same crop and matte as the G16A Very good portrait; since G16Q part 2 every rated/ALERT portrait is candidate D
# (portrait_565); the no-data silhouette is flat colour and keeps make_sheets.to565 rounding.
PORTRAIT_MASTERS_SHA256={
 'VeryGood':'234557de1c9209d3826b67fa4ec5868adfb6896f6e22f6b08e0d78a554751eb5',
 'Good':'a6c9290feb0fb24ae77d853061b95153ca0f21bf14745915836f1033d22001d1',
 'Medium':'803cb9b9161d8ade7b970c7a7922c238d5da76208d84882d93028de27258d6a1',
 'Bad':'20a84050abdbf1ee9dd02b70428d1bf9a6118bc3247f0ba246246b4350b7a881',
 'Horrible':'b6efb06b4eb3cf2295deda11a53ffe7235f3d506cfc854132667b5bedddb64c8',
 'VeryGood_ALERT_p0':'3209e5c80a24ecb3ee466a39dcd1e471d8823b5b0a498ef1f3e599ac7674311e',
 'VeryGood_ALERT_p1':'d7880f359633b236a5dacd60cde60eaa3bb68ad4dd96e47f5c425ce48cf96d3f',
 'Good_ALERT_p0':'7ef8da9453eff272fab55f215298e6d7ef39672893f7e98a9997ba8c75832c77',
 'Good_ALERT_p1':'6aa5e46599579f4b4bebc87c10e06abea72ebae54831c16a65798f44ab86b333',
 'Medium_ALERT_p0':'d227bcfa116b402e8786883dcfa48875247670ff7150272b4375ed1ca516d2eb',
 'Medium_ALERT_p1':'90b58e1d1ba2bc9c4f4a1c96ef777a666f1a4ea09d55f6aa4b1fa4f07eb4c9ec',
 'Bad_ALERT_p0':'c7d144ccf40a6b0a84b8c8746e8470ef1ef6fd1669b03027cf4a771b2d64b9cb',
 'Bad_ALERT_p1':'312dd5d6fc52b808c602db716eb1682386b47cf9b4580473154869a200258269',
 'Horrible_ALERT_p0':'b6efb06b4eb3cf2295deda11a53ffe7235f3d506cfc854132667b5bedddb64c8',
 'Horrible_ALERT_p1':'95a2d05bff898fb5b50ebafe966ad4ecacd17dcd94bdc29904cd7f1f8d6a3ab7',
}
NODATA_FROM='Medium'
NODATA_FILL=(16,20,26); NODATA_RIM=(46,74,88)
def nodata_silhouette(art):
    """Expression-free silhouette: only the OUTER outline of the crop's alpha survives
    (everything not reachable from the frame border through transparent pixels is filled),
    so no colour, eye, mouth or mask detail of any rating can show through."""
    from PIL import ImageFilter, ImageDraw
    solid=art.getchannel('A').point(lambda v:255 if v>=128 else 0)
    ImageDraw.floodfill(solid,(0,0),128)            # the outside, reached from a corner (the crop's corners are transparent)
    inside=solid.point(lambda v:0 if v==128 else 255)
    edge=np.asarray(inside.filter(ImageFilter.MaxFilter(3)),dtype=np.float32)-np.asarray(inside.filter(ImageFilter.MinFilter(3)),dtype=np.float32)
    m=np.asarray(inside,dtype=np.float32)/255.0; e=np.clip(edge/255.0,0,1)
    rgb=np.zeros((PORTRAIT_SIZE[1],PORTRAIT_SIZE[0],3),dtype=np.float32)
    for c in range(3): rgb[:,:,c]=NODATA_FILL[c]*m*(1-e)+NODATA_RIM[c]*e
    return Image.fromarray(np.clip(np.rint(rgb),0,255).astype('uint8'))
def build_portraits(masters_dir):
    masters_dir=pathlib.Path(masters_dir)
    sys.path.insert(0,str(S)); from make_sheets import to565
    out=S/'portrait'; out.mkdir(exist_ok=True)
    manifest=json.loads((S/'manifest.json').read_text())
    outputs={}
    for name,want in PORTRAIT_MASTERS_SHA256.items():
        master=masters_dir/f'{name}.png'
        digest=hashlib.sha256(master.read_bytes()).hexdigest()
        if digest!=want: raise SystemExit(f'unexpected master {master}: sha256 {digest} (expected {want})')
        outputs[name]=portrait_565(master)
        manifest['sources'][f'masters_png/{name}.png']=digest
        if name==NODATA_FROM: outputs['NoData']=to565(nodata_silhouette(crop_art(master)))
    for name,(raw,preview) in outputs.items():
        assert len(raw)==PORTRAIT_SIZE[0]*PORTRAIT_SIZE[1]*2==43200
        (out/f'{name}_portrait.rgb565').write_bytes(raw)
        preview.save(out/f'{name}_portrait_preview565.png',optimize=False)
        for f in [f'{name}_portrait.rgb565',f'{name}_portrait_preview565.png']:
            manifest['files'][f'portrait/{f}']=hashlib.sha256((out/f).read_bytes()).hexdigest()
    manifest['portraits']={'names':list(outputs),'frame':list(PORTRAIT_SIZE),'crop_box_in_master':list(PORTRAIT_CROP),
        **PORTRAIT_PIPELINE,'matte':'black','rgb565_byte_order':'little-endian','rgb565_bytes_each':43200,
        'total_rgb565_bytes':43200*len(outputs),
        'no_data':{'from_alpha_of':f'masters_png/{NODATA_FROM}.png','fill_rgb':list(NODATA_FILL),'rim_rgb':list(NODATA_RIM),
                   'note':'outer outline only (flood fill from the transparent frame corner): no colour, eyes, mouth or mask detail of any rating'},
        'masters':'$GUARDIAN_STORE/art-exports/G15/20261117-v4/masters_png/'}
    (S/'manifest.json').write_text(json.dumps(manifest,indent=1)+'\n')
    for name in outputs: print('PORTRAIT',name,manifest['files'][f'portrait/{name}_portrait.rgb565'])
if __name__=='__main__' and len(sys.argv)>1 and sys.argv[1]=='portraits':
    if len(sys.argv)!=3: raise SystemExit('usage: build_assets.py portraits <masters_png dir>')
    build_portraits(sys.argv[2]); sys.exit(0)
if __name__=='__main__' and len(sys.argv)>1 and sys.argv[1]=='portrait':
    if len(sys.argv)!=3: raise SystemExit('usage: build_assets.py portrait <masters_png/VeryGood.png>')
    build_portrait(sys.argv[2]); sys.exit(0)
source=S/'source'/'moods_contact_sheet.png'
art_root=S
for folder in ['source','render_4x','masters_png','masters_webp','icons_128','exports','animations']:
    (S/folder).mkdir(parents=True,exist_ok=True)
# Both source sheet and original export script are shipped in this pack.
MOODS=['VeryGood','Good','Medium','Bad','Horrible']
assert Image.open(source).size==(1536,1024)

def matting(im):
    """Soft alpha around black matte, retain interior lowlights."""
    a=np.asarray(im.convert('RGB'),dtype=np.float32)
    # dark colors are background; keep lower contrast shadows except true black
    mx=a.max(axis=2)
    alpha=np.clip((mx-3.0)/18.0*255.0,0,255).astype('uint8')
    # feather only matte borders, keep 3D details sharp
    out=np.dstack([a.astype('uint8'),alpha])
    return Image.fromarray(out,'RGBA')

def draw_alert_ring(img,pulse):
    """Angular back-of-hood threat corona: conveys alert without relying on red."""
    out=Image.new('RGBA',(512,512),(0,0,0,0))
    d=ImageDraw.Draw(out,'RGBA')
    cx,cy=256,252
    rx=225*(1+.068*pulse); ry=234*(1+.065*pulse)
    # graphic behind face; multiple nested sharp-line octagonal contours
    def poly(radius_shift=0):
        return [(int(cx+(rx+radius_shift)*math.cos(k*math.pi/8-math.pi/2)),
                 int(cy+(ry+radius_shift)*math.sin(k*math.pi/8-math.pi/2)))
                 for k in range(16)]
    # ambient bloom behind mask
    glow=Image.new('RGBA',(512,512),(0,0,0,0)); gd=ImageDraw.Draw(glow,'RGBA')
    gd.line(poly(2)+poly(2)[:1],fill=(255,15,30,180),width=9+pulse*3,joint='curve')
    glow=glow.filter(ImageFilter.GaussianBlur(12+3*pulse)); out=Image.alpha_composite(out,glow)
    d=ImageDraw.Draw(out,'RGBA')
    d.line(poly()+poly()[:1],fill=(255,35,40,155+60*pulse),width=2+2*pulse,joint='curve')
    # angular spike notches through the ring (shape cue distinct from mood)
    for angle_deg in [12,38,68,112,142,168,192,218,322,348]:
        an=math.radians(angle_deg-90)
        nx,ny=math.cos(an),math.sin(an)
        tang=(-ny,nx)
        x,y=cx+rx*nx,cy+ry*ny
        L=10+5*pulse
        base=5
        pts=[(int(x+tang[0]*base),int(y+tang[1]*base)),
             (int(x+nx*L),int(y+ny*L)),
             (int(x-tang[0]*base),int(y-tang[1]*base))]
        d.polygon(pts,fill=(255,38,34,170+65*pulse))
    return out

def eyes_alert(im,pulse):
    """Turn eye highlights crimson; preserve cracks, shape, shadows."""
    a=np.array(im.convert('RGBA'))
    rgb=a[:,:,:3].astype(np.float32)
    yy,xx=np.mgrid[:512,:512]
    region=(yy>149)&(yy<264)&(xx>95)&(xx<418)
    # blue-cyan emissive pixels only
    em=region & (rgb[:,:,2]>70) & (rgb[:,:,1]>55) & (rgb[:,:,2] > rgb[:,:,0]*1.35) & (rgb[:,:,1]>rgb[:,:,0]*1.25)
    v=rgb[em]
    if len(v):
        r=np.clip(np.maximum(165,v[:,2]*1.25)+pulse*43,0,255)
        g=np.clip(v[:,1]*0.12+pulse*12,0,255)
        b=np.clip(v[:,2]*0.21+pulse*8,0,255)
        rgb[em]=np.stack([r,g,b],axis=1)
    a[:,:,:3]=rgb.clip(0,255).astype('uint8')
    return Image.fromarray(a,'RGBA')

meta={'version':'2026-11-16-v2','source':'source/moods_contact_sheet.png',
      'model_type':'rendered_3d_style_illustration_not_GLTF_or_blender_mesh',
      'moods':MOODS,'states':[],'screen':[240,135],'face_zone_x':[0,151],
      'text_zone_x':[152,239],'rgb565_byte_order':'little-endian','rgb565_bytes':64800,
      'pulse_phases':[0,1],
      'mood_map':{'VeryGood':'celebrating/cigar','Good':'confident smile','Medium':'skeptical','Bad':'worried','Horrible':'angry/clenched teeth'},
      'unsupported_expressions':['generic Happy','Sad','Neutral','Offline: policy suppresses the face'],
      'alert':'incident overlay, not a sixth rating'}
for idx,m in enumerate(MOODS):
    col,row=idx%3,idx//3
    im=Image.open(source).crop((col*512,row*512,(col+1)*512,(row+1)*512)).convert('RGBA')
    base=matting(im)
    allstates=[(m,base)]
    for pulse in [0,1]:
        eye=eyes_alert(base,pulse)
        ring=draw_alert_ring(base,pulse)
        frame=Image.alpha_composite(ring,eye)
        allstates.append((f'{m}_ALERT_p{pulse}',frame))
    for name,art in allstates:
        art.save(S/'masters_png'/f'{name}.png')
        art.save(S/'masters_webp'/f'{name}.webp',quality=90,method=2)
        art.resize((128,128),Image.Resampling.LANCZOS).save(S/'icons_128'/f'{name}.png')
        # G15 expected 4x 960x540 render; area x 0..607 reserved for mask, others black
        lay=Image.new('RGBA',(960,540),(0,0,0,255))
        drawn=art.resize((540,540),Image.Resampling.LANCZOS)
        lay.alpha_composite(drawn,((608-540)//2,0))
        lay.convert('RGB').save(S/'render_4x'/f'{name}.png',optimize=True)
        meta['states'].append({'name':name,'rating':m,'alert':name!=m,'pulse':int(name[-1]) if name!=m else None})
    a0=Image.open(S/'masters_png'/f'{m}_ALERT_p0.png').convert('RGBA')
    a1=Image.open(S/'masters_png'/f'{m}_ALERT_p1.png').convert('RGBA')
    frames=[a0,a1,a0]
    frames[0].save(S/'animations'/f'{m}_ALERT.gif',save_all=True,append_images=frames[1:],duration=[220,220,220],loop=0,disposal=2,transparency=0)
    frames[0].save(S/'animations'/f'{m}_ALERT.webp',save_all=True,append_images=frames[1:],duration=[220,220,220],loop=0,quality=82,method=2)
# call repo's real pipeline to match names, poster, RGB565 byte convention
subprocess.run(['python',str(S/'make_sheets.py'),'--render',str(S/'render_4x'),
                '--out',str(S/'exports'),'--script',str(S/'source'/'moods_contact_sheet.png')],check=True)
for state in meta['states']:
    name=state['name']
    state['png_240x135']=f'exports/frames/{name}.png'
    state['rgb565']=f'exports/rgb565/{name}.rgb565'
    state['preview_rgb565']=f'exports/preview565/{name}.png'
    state['master_png']=f'masters_png/{name}.png'
    state['master_webp']=f'masters_webp/{name}.webp'
with open(S/'asset-map.json','w') as f:json.dump(meta,f,indent=2)
# validated 240x135 and byte order (pixel-by-pixel equal rgb565 preview)
from sys import path
path.insert(0,str(S))
from make_sheets import to565
for state in meta['states']:
    name=state['name']; im=Image.open(S/'exports'/'frames'/f'{name}.png')
    assert im.size==(240,135)
    raw,pre=to565(im)
    assert len(raw)==64800 and raw==open(S/'exports'/'rgb565'/f'{name}.rgb565','rb').read()
    assert np.array_equal(np.asarray(pre),np.asarray(Image.open(S/'exports'/'preview565'/f'{name}.png')))
# Horizontal real-display quick comparison in larger view
im=Image.open(S/'exports'/'sheet-moods-1x.png')
im.resize((im.width*2,im.height*2),Image.Resampling.NEAREST).save(S/'moods_at_2x.png')

readme='''# M5 Guardian — Cyber Guardian v2 asset pack

Generated against the source of `m5-guardian.zip` (2026-11-16). This is a **rendered 3D-looking 2D art pack**, not a rigged `.blend` or `.glb` mesh. It is a visual replacement concept based on the FIRST cyan/red, lock-crested Guy Fawkes image in the chat.

## Security policy respected

Exactly five ratings, matching `guardian::Mood`: `VeryGood`, `Good`, `Medium`, `Bad`, `Horrible`. Expression identity comes from the actual repo's G15 contract (`docs/G15-persona.md`). VeryGood celebrates with cigar; Good smiles; Medium is skeptical; Bad frowns; Horrible bares teeth. **ALERT is an independent incident overlay for every rating** (two visual pulse phases, red eyes and a distinctive angular/spiked warning corona). It is NOT a sixth rating. The facial expression under ALERT is preserved.

`Unknown`, checking, stale and degraded must NOT be presented as fresh ratings. The existing Presenter determines whether the portrait can be shown. Do not map `Unknown` to a generic happy/neutral portrait. DEMO needs an explicit 'not a real reading' label owned by the renderer, not baked into the PNG.

## Assets

- `masters_png/`: 15 transparent 512x512 PNG art renders (5 ratings + 5 x ALERT p0/p1)
- `masters_webp/`: same in WebP (for website / preview)
- `icons_128/`: small RGBA PNG avatars
- `render_4x/`: 15 960x540 RGB compositions ready as input to original repo's `make_sheets.py`
- `exports/frames/`: 15 240x135 PNG, screen aspect, text zone black and empty
- `exports/rgb565/`: 15 **64,800-byte** little-endian packed RGB565 frames
- `exports/preview565/`: images expanded from RGB565, for inspection before flashing
- `exports/sheet-moods-1x.png`, `exports/sheet-alert-1x.png`, `exports/sheet-mock-labels-1x.png`
- `animations/`: 5 alert-pulse GIF and animated WebP previews (NOT required by firmware)
- `asset-map.json`: mapping and file metadata
- `source/moods_contact_sheet.png`: original AI-rendered 5-mood contact sheet
- `build_assets.py`, `make_sheets.py`: reproducible postprocessing pipeline

## Display and integration constraints

**Not integrated or flashed.** `firmware/adapters/companion/screens.cpp::draw()` still draws a placeholder 64x64 block at `(4,16)`; actual `Frame::face_x=4,face_y=16,face_size=64` in `companion.hpp`. The G15 art plan assumes a full-height face on **x=0..151**, and text on **x=152..239**. This conflicts with the existing full-width header and bottom status/hint text and requires explicit screen-layout changes before using a full-size face. Do not silently paste these full-screen images on top of those fields.

The board display is 240x135 RGB565 with a 64,800-byte DMA framebuffer; `Canvas` can encode big-endian values when pushing SPI, while `make_sheets.py` produces **little-endian raw RGB565**. If blitting raw bytes verbatim, match byte order to the display transfer mode; a host unit test + physical display test is required. `assets` partition currently reserved but not mounted, so the existence of raw frames does NOT mean firmware can load them. All 15 frames require ~972,000 bytes of raw stored flash (~950 KiB).

On ALERT, the firmware must still show its live alert reason and evidence/coverage state. These renders contain **no text**. `Horrible` is non-alert with cyan eyes; an ALERT has bright crimson eyes and an angular corona even when the underlying rating is VeryGood.

## Rebuild

`python3 build_assets.py` (requires Pillow and NumPy; input sheet and make_sheets.py included).

## Notes

Contact sheets are quality review artifacts. The rendered masks have facial/hood detail that will be lost at 240x135; review the actual RGB565 previews at 1x on the StickS3 before accepting G15. The G15 `.blend` in the supplied repository is an *older, different* 3D model; these new images do not update its geometry and should not be described as a rigged 3D replacement.
'''
(S/'README.md').write_text(readme)
# Generator is already here; do not copy onto itself.
print('PACK',len(meta['states']),'states')
print('PRINT',[(f.name,f.stat().st_size) for f in (S/'exports'/'rgb565').glob('*.rgb565')][:2])
