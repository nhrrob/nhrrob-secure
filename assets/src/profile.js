import './profile.css';

document.addEventListener('DOMContentLoaded', () => {
    const copyButton = document.getElementById('nhrrob-secure-copy-recovery-codes');
    const downloadButton = document.getElementById('nhrrob-secure-download-recovery-codes');

    /**
     * Get all recovery codes from the list
     */
    const getCodes = () => {
        const codesList = document.querySelectorAll('.nhrrob-secure-recovery-codes-item');
        return Array.from(codesList).map(li => li.innerText.trim()).join('\n');
    };

    /**
     * Copy codes to clipboard
     */
    if (copyButton) {
        copyButton.addEventListener('click', () => {
            const codes = getCodes();

            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(codes).then(() => {
                    showSuccess(copyButton);
                }).catch(err => {
                    console.error('Failed to copy: ', err);
                });
            } else {
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
    }

    /**
     * Download codes as .txt file
     */
    if (downloadButton) {
        downloadButton.addEventListener('click', () => {
            const codes = getCodes();
            const blob = new Blob([codes], { type: 'text/plain' });
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            
            a.href = url;
            a.download = 'nhrrob-secure-recovery-codes.txt';
            document.body.appendChild(a);
            a.click();
            
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);
            
            showSuccess(downloadButton);
        });
    }

    /**
     * Show success state on button
     * @param {HTMLElement} button 
     */
    function showSuccess(button) {
        const textSpan = button.querySelector('span:last-child');
        const iconSpan = button.querySelector('.dashicons');
        
        if (!textSpan) return;

        const originalText = textSpan.innerText;
        const originalIconClass = iconSpan ? Array.from(iconSpan.classList).find(c => c.startsWith('dashicons-')) : null;
        
        textSpan.innerText = (button.id === 'nhrrob-secure-copy-recovery-codes') ? 'Copied!' : 'Saved!';
        button.classList.add('nhrrob-secure-action-success');
        
        if (iconSpan) {
            iconSpan.classList.remove(originalIconClass);
            iconSpan.classList.add('dashicons-yes');
        }

        setTimeout(() => {
            textSpan.innerText = originalText;
            button.classList.remove('nhrrob-secure-action-success');
            if (iconSpan) {
                iconSpan.classList.remove('dashicons-yes');
                iconSpan.classList.add(originalIconClass);
            }
        }, 2000);
    }
});
