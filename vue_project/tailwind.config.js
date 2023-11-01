/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./index.html",
    "./src/**/*.{vue,js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
      "space-cadet": "#25283d",
      "plum": "#8f3985"
    }},
  },
  plugins: [],
}

