// Live camera capture. Browsers only expose getUserMedia in a secure context (HTTPS or localhost),
// so on a phone opening http://<laptop-ip>:8000 the "Take photo" button (native camera app) is the
// fallback - and the UI says so instead of failing silently.
import { $ } from "./util.js";

let stream = null;

export function cameraSupport() {
  if (!navigator.mediaDevices?.getUserMedia) {
    return { ok: false, message: "This browser cannot open the camera from a web page. Use 'Photo' > 'Take photo' instead." };
  }
  if (!window.isSecureContext) {
    return {
      ok: false,
      message: "Browsers only allow live camera access on HTTPS or localhost. Use 'Photo' > 'Take photo' (opens your camera app), or start the server with `python -m qrshield serve --https` and trust its certificate.",
    };
  }
  return { ok: true };
}

export async function startCamera() {
  const video = $("#camera-video");
  stream = await navigator.mediaDevices.getUserMedia({
    audio: false,
    video: { facingMode: { ideal: "environment" }, width: { ideal: 1920 }, height: { ideal: 1080 } },
  });
  video.srcObject = stream;
  await video.play();
}

export function stopCamera() {
  stream?.getTracks().forEach((t) => t.stop());
  stream = null;
  const video = $("#camera-video");
  if (video) video.srcObject = null;
}

export function isRunning() {
  return !!stream;
}

export async function captureFrame() {
  const video = $("#camera-video");
  const w = video.videoWidth, h = video.videoHeight;
  if (!w || !h) throw new Error("The camera is not ready yet.");
  const canvas = document.createElement("canvas");
  canvas.width = w;
  canvas.height = h;
  canvas.getContext("2d").drawImage(video, 0, 0, w, h);
  const blob = await new Promise((resolve) => canvas.toBlob(resolve, "image/jpeg", 0.92));
  return new File([blob], "camera.jpg", { type: "image/jpeg" });
}
