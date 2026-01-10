import './profile.css';

document.addEventListener('DOMContentLoaded', () => {
    const copyButton = document.getElementById('nhrrob-secure-copy-recovery-codes');
    if (!copyButton) return;

    copyButton.addEventListener('click', () => {
        const codesList = document.querySelectorAll('.nhrrob-secure-recovery-codes-item');
        const codes = Array.from(codesList).map(li => li.innerText.trim()).join('\n');

        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(codes).then(() => {
                showSuccess(copyButton);
            }).catch(err => {
                console.error('Failed to copy: ', err);
            });
        } else {
            // Fallback for older browsers
            const textArea = document.createElement('textarea');
            textArea.value = codes;
            document.body.appendChild(textArea);
            textArea.select();
            try {
                document.execCommand('copy');
                showSuccess(copyButton);
            } catch (err) {
                console.error('Fallback copy failed: ', err);
            }
            document.body.removeChild(textArea);
        }
    });

    function showSuccess(button) {
        const originalText = button.querySelector('span:last-child').innerText;
        const originalIcon = button.querySelector('.dashicons');
        
        button.querySelector('span:last-child').innerText = 'Copied!';
        button.classList.add('nhrrob-secure-copy-success');
        
        if (originalIcon) {
            originalIcon.classList.remove('dashicons-clipboard');
            originalIcon.classList.add('dashicons-yes');
        }

        setTimeout(() => {
            button.querySelector('span:last-child').innerText = originalText;
            button.classList.remove('nhrrob-secure-copy-success');
            if (originalIcon) {
                originalIcon.classList.remove('dashicons-yes');
                originalIcon.classList.add('dashicons-clipboard');
            }
        }, 2000);
    }
});
