let risk = 0;

if (window.location.href.includes("@")) risk += 30;
if (!window.location.href.startsWith("https")) risk += 20;

let inputs = document.querySelectorAll("input[type='password']");
if (inputs.length > 0) risk += 30;

console.log("Risk Score:", risk);