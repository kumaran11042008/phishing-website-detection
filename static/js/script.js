// Phishing Website Detection System

console.log("Phishing Website Detection System Loaded Successfully");

document.addEventListener("DOMContentLoaded", function () {

    const form = document.querySelector("form");

    if (form) {

        form.addEventListener("submit", function () {

            const input = document.querySelector(".form-control");

            if (input.value.trim() === "") {

                alert("Please enter a website URL.");

                return false;

            }

        });

    }

});

// =========================================
// SECURITY DASHBOARD
// =========================================

let totalScans = 0;
let safeSites = 0;
let phishingSites = 0;
let highRisk = 0;


function updateDashboard(prediction, risk) {

    totalScans++;

    if (prediction === "Legitimate Website") {
        safeSites++;
    }

    if (prediction === "Phishing Website") {
        phishingSites++;
    }

    if (risk === "High") {
        highRisk++;
    }

    document.getElementById("totalScans").textContent = totalScans;

    document.getElementById("safeSites").textContent = safeSites;

    document.getElementById("phishingSites").textContent = phishingSites;

    document.getElementById("highRisk").textContent = highRisk;
}