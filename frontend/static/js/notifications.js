// ==========================================
// INNOVATECH SOAR - SECURITY NOTIFICATIONS
// ==========================================

document.addEventListener("DOMContentLoaded", function () {

    // ELEMENT REFERENCES

    const searchInput = document.getElementById("notificationSearch");
    const severityFilter = document.getElementById("notificationSeverityFilter");
    const statusFilter = document.getElementById("notificationStatusFilter");
    const resetButton = document.getElementById("resetNotificationFilters");

    const notificationRows = Array.from(
        document.querySelectorAll("#notificationsTable .notification-row")
    );

    const resultsCount = document.getElementById("notificationResultsCount");
    const noMatchingNotifications = document.getElementById("noMatchingNotifications");

    const detailsDialog = document.getElementById("notificationDetailsDialog");
    const closeButton = document.getElementById("closeNotificationDetails");
    const closeFooterButton = document.getElementById("closeNotificationDetailsFooter");


    // ======================================
    // SEARCH AND FILTER NOTIFICATIONS
    // ======================================

    function filterNotifications() {

        const searchValue = searchInput.value.trim().toLowerCase();
        const selectedSeverity = severityFilter.value.toLowerCase();
        const selectedStatus = statusFilter.value.toLowerCase();

        let visibleCount = 0;

        notificationRows.forEach(function (row) {

            const notification = row.dataset;

            const searchFields = [
                notification.notificationId || "",
                notification.title || "",
                notification.message || "",
                notification.eventId || "",
                notification.incidentId || ""
            ];

            const matchesSearch = searchFields.some(function (value) {
                return value.toLowerCase().includes(searchValue);
            });

            const matchesSeverity =
                selectedSeverity === "all" ||
                notification.severity === selectedSeverity;

            const matchesStatus =
                selectedStatus === "all" ||
                notification.status === selectedStatus;

            const shouldShow =
                matchesSearch &&
                matchesSeverity &&
                matchesStatus;

            row.hidden = !shouldShow;

            if (shouldShow) {
                visibleCount++;
            }
        });

        resultsCount.textContent =
            `Showing ${visibleCount} of ${notificationRows.length} retrieved notifications`;

        noMatchingNotifications.hidden =
            visibleCount !== 0 || notificationRows.length === 0;
    }


    // ======================================
    // RESET FILTERS
    // ======================================

    function resetFilters() {
        searchInput.value = "";
        severityFilter.value = "all";
        statusFilter.value = "all";

        filterNotifications();
    }


    // ======================================
    // NOTIFICATION DETAILS
    // ======================================

    function openNotificationDetails(row) {

        const notification = row.dataset;

        document.getElementById("detailNotificationId").textContent =
            notification.notificationId
                ? `#${notification.notificationId}`
                : "N/A";

        document.getElementById("detailNotificationTitle").textContent =
            notification.title || "Untitled";

        document.getElementById("detailNotificationSeverity").textContent =
            (notification.severity || "N/A").toUpperCase();

        document.getElementById("detailNotificationStatus").textContent =
            notification.status || "N/A";

        document.getElementById("detailNotificationEventId").textContent =
            notification.eventId
                ? `#${notification.eventId}`
                : "N/A";

        document.getElementById("detailNotificationIncidentId").textContent =
            notification.incidentId
                ? `#${notification.incidentId}`
                : "N/A";

        document.getElementById("detailNotificationCreated").textContent =
            notification.created || "N/A";

        document.getElementById("detailNotificationMessage").textContent =
            notification.message || "No message available.";

        detailsDialog.showModal();
    }


    // ======================================
    // EVENT LISTENERS
    // ======================================

    searchInput.addEventListener("input", filterNotifications);
    severityFilter.addEventListener("change", filterNotifications);
    statusFilter.addEventListener("change", filterNotifications);
    resetButton.addEventListener("click", resetFilters);

    notificationRows.forEach(function (row) {

        const viewButton = row.querySelector(".notification-details-button");

        if (viewButton) {
            viewButton.addEventListener("click", function () {
                openNotificationDetails(row);
            });
        }
    });

    closeButton.addEventListener("click", function () {
        detailsDialog.close();
    });

    closeFooterButton.addEventListener("click", function () {
        detailsDialog.close();
    });

    // Close when clicking outside the dialog content
    detailsDialog.addEventListener("click", function (event) {
        if (event.target === detailsDialog) {
            detailsDialog.close();
        }
    });

});