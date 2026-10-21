# Collecting real photos for the sticker model (M2)

Why: the shipped model is trained on simulated photos. A real dataset turns the evaluation's "simulated" label into a
real number you can defend. The plan's target is about 400 genuine + 400 tampered photos; even 150-200 across several
sessions gives a meaningful grouped result.

## What to photograph

* **Surfaces (at least 6):** matte paper notice, glossy laminated poster, brushed metal (cardboard "meter" wrapped in foil
  is fine), wood (table), glass/acrylic, plastic stand.
* **Genuine class:** codes printed directly on the surface, laminated prints, framed table tents - **and genuine stickers
  stuck on clean surfaces (hard negatives).** Without those the model just learns "sticker = bad".
* **Tampered class:** print a *different* QR sticker and paste it over a code in different ways: exact fit, slightly
  smaller (original corners peek out), slightly larger, rotated/offset, wrinkled / with air bubbles; matte paper, glossy
  vinyl and paper + tape.
* **Diversity (the only way to generalise):** 3 phones, 3 lighting conditions (daylight, warm indoor, flash), 3 angles
  (0, 15, 30 degrees), different distances. Keep the whole code and the area around it in frame (about one code-width of
  surface on every side).

## Metadata (`data/cv_images/metadata.csv`)

| Column | Meaning |
|---|---|
| `image_id` | file name inside `data/cv_images/` |
| `class_label` | `0` genuine, `1` tampered |
| `session_id` | one physical setup (same surface instance, lighting, phone batch). **Evaluation is grouped by this** |
| `surface` | `matte_paper`, `glossy_poster`, `metal`, `wood`, `glass`, `plastic`, ... |
| `sticker_material` | `none`, `matte_paper`, `glossy_vinyl`, `laminated` |
| `phone_model`, `lighting`, `angle_deg` | capture conditions |
| `tamper_style` | `none`, `exact_fit`, `smaller`, `larger`, `offset_rotated`, `wrinkled` |

## Rules

1. **Never evaluate with a random split.** Photos of the same surface/session are near-duplicates; a random split
   memorises the table grain or the phone. `train-cv` groups by `session_id` (and the simulated part by surface).
2. Photograph the *same* physical scene twice from two angles for some sessions - it tests the second-photo flow.
3. Do not photograph other people's property without permission; run the collection in your own college/lab.
4. Test the decoder first: at least 95 % of your photos should decode (`python -m qrshield doctor`, then upload a few).

## Then

```
python -m qrshield train-cv --real data/cv_images
python -m scripts.make_eval_report
```

The report gains a **real-photos grouped cross-validation** block; quote that, not the simulated figure, for real-world accuracy.
