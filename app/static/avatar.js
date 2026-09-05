(() => {
  'use strict';

  const root = document.querySelector('[data-avatar-editor]');
  if (!root) return;
  const form = root.querySelector('[data-avatar-form]');
  const input = root.querySelector('[data-avatar-input]');
  const preview = root.querySelector('[data-avatar-preview]');
  const canvas = root.querySelector('[data-avatar-canvas]');
  const zoom = root.querySelector('[data-avatar-zoom]');
  const zoomWrap = root.querySelector('[data-avatar-zoom-wrap]');
  const colorInput = root.querySelector('input[name="avatar_color"]');
  const context = canvas.getContext('2d');
  let image = null;
  let objectUrl = null;
  let offsetX = 0;
  let offsetY = 0;
  let dragging = false;
  let pointerX = 0;
  let pointerY = 0;

  function draw() {
    if (!image) return;
    const size = canvas.width;
    const base = Math.max(size / image.naturalWidth, size / image.naturalHeight);
    const scale = base * Number(zoom.value);
    const width = image.naturalWidth * scale;
    const height = image.naturalHeight * scale;
    const limitX = Math.max(0, (width - size) / 2);
    const limitY = Math.max(0, (height - size) / 2);
    offsetX = Math.max(-limitX, Math.min(limitX, offsetX));
    offsetY = Math.max(-limitY, Math.min(limitY, offsetY));
    context.clearRect(0, 0, size, size);
    context.drawImage(image, (size - width) / 2 + offsetX, (size - height) / 2 + offsetY, width, height);
    preview.innerHTML = '';
    const rendered = document.createElement('img');
    rendered.src = canvas.toDataURL('image/webp', 0.86);
    rendered.alt = '待上传头像预览';
    preview.append(rendered);
  }

  function loadFile(file) {
    if (!file) return;
    if (objectUrl) URL.revokeObjectURL(objectUrl);
    objectUrl = URL.createObjectURL(file);
    const candidate = new Image();
    candidate.onload = () => {
      image = candidate;
      offsetX = 0;
      offsetY = 0;
      zoom.value = '1';
      zoomWrap.hidden = false;
      draw();
    };
    candidate.src = objectUrl;
  }

  preview.addEventListener('click', () => input.click());
  input.addEventListener('change', () => loadFile(input.files?.[0]));
  zoom.addEventListener('input', draw);
  colorInput?.addEventListener('input', () => {
    preview.style.setProperty('--avatar-color', colorInput.value);
  });
  preview.addEventListener('pointerdown', (event) => {
    if (!image) return;
    dragging = true;
    pointerX = event.clientX;
    pointerY = event.clientY;
    preview.setPointerCapture(event.pointerId);
  });
  preview.addEventListener('pointermove', (event) => {
    if (!dragging) return;
    const ratio = canvas.width / preview.clientWidth;
    offsetX += (event.clientX - pointerX) * ratio;
    offsetY += (event.clientY - pointerY) * ratio;
    pointerX = event.clientX;
    pointerY = event.clientY;
    draw();
  });
  preview.addEventListener('pointerup', () => { dragging = false; });
  preview.addEventListener('pointercancel', () => { dragging = false; });
  form.addEventListener('submit', (event) => {
    if (!image) return;
    event.preventDefault();
    canvas.toBlob((blob) => {
      if (!blob) {
        form.submit();
        return;
      }
      try {
        const transfer = new DataTransfer();
        transfer.items.add(new File([blob], 'avatar.webp', { type: 'image/webp' }));
        input.files = transfer.files;
      } catch (_) {
        // Older browsers submit the selected source; the server still crops and validates it.
      }
      form.submit();
    }, 'image/webp', 0.86);
  });
})();
