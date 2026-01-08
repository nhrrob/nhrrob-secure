/** @type {import('tailwindcss').Config} */
module.exports = {
    content: [
        './assets/src/**/*.{js,jsx,ts,tsx}',
    ],
    theme: {
        extend: {
            colors: {
                'wp-blue': '#2271b1',
                'wp-blue-dark': '#135e96',
            },
        },
    },
    plugins: [],
    corePlugins: {
        preflight: false, // Disable Tailwind's base styles to avoid conflicts with WordPress
    },
}

