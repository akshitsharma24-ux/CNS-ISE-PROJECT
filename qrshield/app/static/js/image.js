// Client-side image preparation: respect EXIF orientation and cap the size before upload.
const MAX_SIDE = 2000;
const MAX_BYTES = 5 * 1024 * 1024;

export async function prepareImage(file) {
  if (!file.type.startsWith("image/")) throw new Error("That file is not an image.");
  let bitmap;
  try {
    bitmap = await createImageBitmap(file, { imageOrientation: "from-image" });
  } catch {
    return file; // let the server try (e.g. unusual formats)
  }
  const longest = Math.max(bitmap.width, bitmap.height);
  if (longest <= MAX_SIDE && file.size <= MAX_BYTES) {
    bitmap.close?.();
    return file;
  }
  const scale = Math.min(1, MAX_SIDE / longest);
  const canvas = document.createElement("canvas");
  canvas.width = Math.round(bitmap.width * scale);
  canvas.height = Math.round(bitmap.height * scale);
  canvas.getContext("2d").drawImage(bitmap, 0, 0, canvas.width, canvas.height);
  bitmap.close?.();
  const blob = await new Promise((resolve) => canvas.toBlob(resolve, "image/jpeg", 0.92));
  if (!blob) return file;
  return new File([blob], (file.name || "photo").replace(/\.[^.]+$/, "") + ".jpg", { type: "image/jpeg" });
}
