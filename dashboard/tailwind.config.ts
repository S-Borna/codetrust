/** @type {import('tailwindcss').Config} */
module.exports = {
    content: [
        "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
        "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
        "./app/**/*.{js,ts,jsx,tsx,mdx}",
    ],
    theme: {
        extend: {
            colors: {
                brand: {
                    "50": "#f0f7ff",
                    "100": "#e0effe",
                    "200": "#bae0fd",
                    "300": "#7cc8fb",
                    "400": "#36adf7",
                    "500": "#0c93e8",
                    "600": "#0074c6",
                    "700": "#015da1",
                    "800": "#064f85",
                    "900": "#0b426e",
                    "950": "#072a49",
                },
            },
        },
    },
    plugins: [],
};
