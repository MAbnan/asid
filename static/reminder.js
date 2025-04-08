// JS popup reminders
// Show alert for upcoming medicines
document.addEventListener("DOMContentLoaded", function () {
    const reminderItems = document.querySelectorAll(".reminder-item");

    reminderItems.forEach(item => {
        const scheduleTime = item.dataset.schedule;
        const medicineName = item.dataset.medicine;

        // Optional: check if the alert should pop up based on time
        // This is just an example; real-time checking would require server-side or PWA-level logic
        const currentTime = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

        if (currentTime === scheduleTime) {
            showReminder(medicineName, scheduleTime);
        }
    });
});

function showReminder(name, time) {
    const alertBox = document.createElement("div");
    alertBox.className = "reminder-alert";
    alertBox.innerHTML = `
        ⏰ It's time to take your medicine: <strong>${name}</strong> (Scheduled at ${time})
        <span class="dismiss-btn" onclick="this.parentElement.remove()">✖</span>
    `;
    document.body.appendChild(alertBox);
}
