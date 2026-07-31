// Clustara Interactive Features & AEO Accordion Logic

document.addEventListener('DOMContentLoaded', () => {
  // Tab Switcher for Showcase
  const tabBtns = document.querySelectorAll('.tab-btn');
  const showcaseViews = document.querySelectorAll('.showcase-view');

  tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const targetTab = btn.getAttribute('data-tab');

      tabBtns.forEach(b => b.classList.remove('active'));
      showcaseViews.forEach(v => v.classList.remove('active'));

      btn.classList.add('active');
      const activeView = document.getElementById(`tab-${targetTab}`);
      if (activeView) {
        activeView.classList.add('active');
      }
    });
  });

  // FAQ Accordion Interactivity for AEO
  const faqItems = document.querySelectorAll('.faq-item');
  faqItems.forEach(item => {
    const questionBtn = item.querySelector('.faq-question');
    if (questionBtn) {
      questionBtn.addEventListener('click', () => {
        const isActive = item.classList.contains('active');
        
        // Close all other accordion items
        faqItems.forEach(i => i.classList.remove('active'));

        // Toggle clicked item
        if (!isActive) {
          item.classList.add('active');
        }
      });
    }
  });

  // Code Copy Snippet Function
  window.copyCode = function(button, elementId) {
    const codeElem = document.getElementById(elementId);
    if (!codeElem) return;

    const textToCopy = codeElem.innerText;
    navigator.clipboard.writeText(textToCopy).then(() => {
      const originalText = button.innerText;
      button.innerText = '복사됨! ✓';
      button.style.color = '#10b981';
      button.style.borderColor = '#10b981';

      setTimeout(() => {
        button.innerText = originalText;
        button.style.color = '';
        button.style.borderColor = '';
      }, 2000);
    }).catch(err => {
      console.error('Failed to copy text: ', err);
    });
  };

  // Image Lightbox Modal
  const showcaseImgs = document.querySelectorAll('.showcase-img-wrapper img');
  
  const lightbox = document.createElement('div');
  lightbox.id = 'lightbox-modal';
  lightbox.style.cssText = `
    position: fixed;
    top: 0;
    left: 0;
    width: 100vw;
    height: 100vh;
    background: rgba(0, 0, 0, 0.92);
    backdrop-filter: blur(12px);
    z-index: 1000;
    display: none;
    align-items: center;
    justify-content: center;
    cursor: zoom-out;
    padding: 24px;
  `;

  const lightboxImg = document.createElement('img');
  lightboxImg.style.cssText = `
    max-width: 92vw;
    max-height: 92vh;
    border-radius: 12px;
    box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.9);
    border: 1px solid rgba(255, 255, 255, 0.12);
    object-fit: contain;
  `;

  lightbox.appendChild(lightboxImg);
  document.body.appendChild(lightbox);

  showcaseImgs.forEach(img => {
    img.addEventListener('click', () => {
      lightboxImg.src = img.src;
      lightbox.style.display = 'flex';
    });
  });

  lightbox.addEventListener('click', () => {
    lightbox.style.display = 'none';
  });
});
