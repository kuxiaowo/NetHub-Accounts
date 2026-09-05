(() => {
  'use strict';

  const root = document.querySelector('[data-avatar-editor]');
  if (!root) return;

  const form = root.querySelector('[data-avatar-form]');
  const input = root.querySelector('[data-avatar-input]');
  const stage = root.querySelector('[data-avatar-crop-stage]');
  const canvas = root.querySelector('[data-avatar-canvas]');
  const livePreview = root.querySelector('[data-avatar-live-preview]');
  const liveCanvas = root.querySelector('[data-avatar-live-canvas]');
  const currentImage = root.querySelector('[data-avatar-current-image]');
  const zoom = root.querySelector('[data-avatar-zoom]');
  const zoomWrap = root.querySelector('[data-avatar-zoom-wrap]');
  const fileName = root.querySelector('[data-avatar-file-name]');
  const saveButton = root.querySelector('[data-avatar-save]');
  const status = root.querySelector('[data-avatar-status]');
  const colorInput = root.querySelector('input[name="avatar_color"]');
  if (!form || !input || !stage || !canvas || !liveCanvas || !zoom || !saveButton) return;

  const context = canvas.getContext('2d');
  const liveContext = liveCanvas.getContext('2d');
  const cropInset = canvas.width * 0.08;
  const cropSize = canvas.width - cropInset * 2;
  let image = null;
  let loadVersion = 0;
  let offsetX = 0;
  let offsetY = 0;
  let dragging = false;
  let pointerX = 0;
  let pointerY = 0;

  function setStatus(message, isError = false) {
    if (!status) return;
    status.textContent = message;
    status.classList.toggle('error', isError);
  }

  function render() {
    if (!image) return;
    const scale = Math.max(cropSize / image.naturalWidth, cropSize / image.naturalHeight)
      * Number(zoom.value);
    const width = image.naturalWidth * scale;
    const height = image.naturalHeight * scale;
    const limitX = Math.max(0, (width - cropSize) / 2);
    const limitY = Math.max(0, (height - cropSize) / 2);
    offsetX = Math.max(-limitX, Math.min(limitX, offsetX));
    offsetY = Math.max(-limitY, Math.min(limitY, offsetY));

    context.clearRect(0, 0, canvas.width, canvas.height);
    context.drawImage(
      image,
      (canvas.width - width) / 2 + offsetX,
      (canvas.height - height) / 2 + offsetY,
      width,
      height,
    );
    liveContext.clearRect(0, 0, liveCanvas.width, liveCanvas.height);
    liveContext.drawImage(
      canvas,
      cropInset,
      cropInset,
      cropSize,
      cropSize,
      0,
      0,
      liveCanvas.width,
      liveCanvas.height,
    );
    liveCanvas.hidden = false;
    if (currentImage) currentImage.hidden = true;
  }

  function loadFile(file) {
    if (!file) return;
    const version = ++loadVersion;
    if (!['image/jpeg', 'image/png', 'image/webp'].includes(file.type)) {
      input.value = '';
      setStatus('请选择 JPEG、PNG 或 WebP 图片。', true);
      return;
    }
    if (file.size > 5 * 1024 * 1024) {
      input.value = '';
      setStatus('源图片不能超过 5 MiB。', true);
      return;
    }
    const reader = new FileReader();
    const candidate = new Image();
    candidate.onload = () => {
      if (version !== loadVersion) return;
      image = candidate;
      offsetX = 0;
      offsetY = 0;
      zoom.value = '1';
      stage.hidden = false;
      zoomWrap.hidden = false;
      saveButton.disabled = false;
      if (fileName) fileName.textContent = file.name;
      setStatus('图片已载入，可拖动和缩放调整圆框选区。');
      render();
    };
    candidate.onerror = () => {
      if (version !== loadVersion) return;
      image = null;
      input.value = '';
      saveButton.disabled = true;
      setStatus('无法读取这张图片，请换一张重试。', true);
    };
    reader.onload = () => {
      if (version !== loadVersion || typeof reader.result !== 'string') return;
      candidate.src = reader.result;
    };
    reader.onerror = () => {
      if (version !== loadVersion) return;
      image = null;
      input.value = '';
      saveButton.disabled = true;
      setStatus('无法读取这张图片，请换一张重试。', true);
    };
    reader.readAsDataURL(file);
  }

  input.addEventListener('change', () => loadFile(input.files?.[0]));
  zoom.addEventListener('input', render);
  colorInput?.addEventListener('input', () => {
    livePreview?.style.setProperty('--avatar-color', colorInput.value);
  });

  canvas.addEventListener('pointerdown', (event) => {
    if (!image) return;
    event.preventDefault();
    dragging = true;
    pointerX = event.clientX;
    pointerY = event.clientY;
    stage.classList.add('is-dragging');
    canvas.setPointerCapture(event.pointerId);
  });
  canvas.addEventListener('pointermove', (event) => {
    if (!dragging) return;
    const ratio = canvas.width / canvas.getBoundingClientRect().width;
    offsetX += (event.clientX - pointerX) * ratio;
    offsetY += (event.clientY - pointerY) * ratio;
    pointerX = event.clientX;
    pointerY = event.clientY;
    render();
  });
  function stopDragging() {
    dragging = false;
    stage.classList.remove('is-dragging');
  }
  canvas.addEventListener('pointerup', stopDragging);
  canvas.addEventListener('pointercancel', stopDragging);
  canvas.addEventListener('wheel', (event) => {
    if (!image) return;
    event.preventDefault();
    const next = Number(zoom.value) + (event.deltaY < 0 ? 0.08 : -0.08);
    zoom.value = String(Math.max(Number(zoom.min), Math.min(Number(zoom.max), next)));
    render();
  }, { passive: false });

  form.addEventListener('submit', (event) => {
    if (!image) return;
    event.preventDefault();
    saveButton.disabled = true;
    setStatus('正在生成并压缩头像…');
    const output = document.createElement('canvas');
    output.width = 512;
    output.height = 512;
    output.getContext('2d').drawImage(
      canvas,
      cropInset,
      cropInset,
      cropSize,
      cropSize,
      0,
      0,
      output.width,
      output.height,
    );
    output.toBlob((blob) => {
      if (!blob) {
        saveButton.disabled = false;
        setStatus('浏览器无法生成裁剪结果，请换一个浏览器重试。', true);
        return;
      }
      try {
        const transfer = new DataTransfer();
        transfer.items.add(new File([blob], 'avatar.webp', { type: 'image/webp' }));
        input.files = transfer.files;
      } catch (_) {
        saveButton.disabled = false;
        setStatus('浏览器不支持提交裁剪结果，请升级浏览器后重试。', true);
        return;
      }
      HTMLFormElement.prototype.submit.call(form);
    }, 'image/webp', 0.86);
  });
})();
