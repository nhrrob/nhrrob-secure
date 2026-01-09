/** @type {import('tailwindcss').Config} */
module.exports = {
    content: [
        './assets/src/**/*.{js,jsx,ts,tsx}',
        './templates/**/*.php',
        './includes/**/*.php',
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
        preflight: false,
    },
}

