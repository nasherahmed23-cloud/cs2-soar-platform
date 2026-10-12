// ==========================================
// INNOVATECH SOAR - EMPLOYEE SECURITY ALERTS
// ==========================================

document.addEventListener("DOMContentLoaded", function () {

    // ELEMENT REFERENCES

    const searchInput = document.getElementById("alertSearch");
    const severityFilter = document.getElementById("alertSeverityFilter");
    const statusFilter = document.getElementById("alertStatusFilter");
    const resetButton = document.getElementById("resetAlertFilters");

    const alertRows = Array.from(
        document.querySelectorAll("#employeeAlertsTable .employee-alert-row")
    );

    const resultsCount = document.getElementById("alertResultsCount");
    const noMatchingAlerts = document.getElementById("noMatchingAlerts");

    const detailsDialog = document.getElementById("employeeAlertDetailsDialog");
    const closeButton = document.getElementById("closeEmployeeAlertDetails");
    const closeFooterButton = document.getElementById("closeEmployeeAlertDetailsFooter");


    // ======================================
    // SEARCH AND FILTER
    // ======================================

    function filterAlerts() {

        const searchValue = searchInput.value.trim().toLowerCase();
        const selectedSeverity = severityFilter.value.toLowerCase();
        const selectedStatus = statusFilter.value.toLowerCase();

        let visibleCount = 0;

        alertRows.forEach(function (row) {

            const alert = row.dataset;

            const searchFields = [
                alert.alertId || "",
                alert.title || "",
                alert.message || "",
                alert.eventId || "",
                alert.incidentId || ""
            ];

            const matchesSearch = searchFields.some(function (value) {
                return value.toLowerCase().includes(searchValue);
            });

            const matchesSeverity =
                selectedSeverity === "all" ||
                alert.severity === selectedSeverity;

            const matchesStatus =
                selectedStatus === "all" ||
                alert.status === selectedStatus;

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
            `Showing ${visibleCount} of ${alertRows.length} retrieved alerts`;

        noMatchingAlerts.hidden =
            visibleCount !== 0 || alertRows.length === 0;
    }


    // ======================================
    // RESET FILTERS
    // ======================================

    function resetFilters() {

        searchInput.value = "";
        severityFilter.value = "all";
        statusFilter.value = "all";

        filterAlerts();
    }


    // ======================================
    // ALERT DETAILS
    // ======================================

    function openAlertDetails(row) {

        const alert = row.dataset;

        document.getElementById("detailEmployeeAlertId").textContent =
            alert.alertId ? `#${alert.alertId}` : "N/A";

        document.getElementById("detailEmployeeAlertTitle").textContent =
            alert.title || "Untitled";

        document.getElementById("detailEmployeeAlertSeverity").textContent =
            (alert.severity || "N/A").toUpperCase();

        document.getElementById("detailEmployeeAlertStatus").textContent =
            alert.status || "N/A";

        document.getElementById("detailEmployeeAlertEventId").textContent =
            alert.eventId ? `#${alert.eventId}` : "N/A";

        document.getElementById("detailEmployeeAlertIncidentId").textContent =
            alert.incidentId ? `#${alert.incidentId}` : "N/A";

        document.getElementById("detailEmployeeAlertCreated").textContent =
            alert.created || "N/A";

        document.getElementById("detailEmployeeAlertMessage").textContent =
            alert.message || "No alert message available.";

        detailsDialog.showModal();
    }


    // ======================================
    // EVENT LISTENERS
    // ======================================

    searchInput.addEventListener("input", filterAlerts);

    severityFilter.addEventListener("change", filterAlerts);

    statusFilter.addEventListener("change", filterAlerts);

    resetButton.addEventListener("click", resetFilters);


    alertRows.forEach(function (row) {

        const viewButton = row.querySelector(
            ".employee-alert-details-button"
        );

        if (viewButton) {
            viewButton.addEventListener("click", function () {
                openAlertDetails(row);
            });
        }
    });


    closeButton.addEventListener("click", function () {
        detailsDialog.close();
    });

    closeFooterButton.addEventListener("click", function () {
        detailsDialog.close();
    });


    // Close dialog when clicking outside its content

    detailsDialog.addEventListener("click", function (event) {

        if (event.target === detailsDialog) {
            detailsDialog.close();
        }
    });

});