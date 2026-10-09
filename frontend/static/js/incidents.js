// ==========================================
// INNOVATECH SOAR - INCIDENT MANAGEMENT
// ==========================================

document.addEventListener("DOMContentLoaded", function () {

    // ======================================
    // ELEMENT REFERENCES
    // ======================================

    const searchInput = document.getElementById("incidentSearch");
    const severityFilter = document.getElementById("incidentSeverityFilter");
    const statusFilter = document.getElementById("incidentStatusFilter");
    const resetButton = document.getElementById("resetIncidentFilters");

    const incidentRows = Array.from(
        document.querySelectorAll("#incidentsTable .incident-row")
    );

    const resultsCount = document.getElementById("incidentResultsCount");
    const noMatchingIncidents = document.getElementById("noMatchingIncidents");

    const detailsDialog = document.getElementById("incidentDetailsDialog");
    const closeButton = document.getElementById("closeIncidentDetails");
    const closeFooterButton = document.getElementById("closeIncidentDetailsFooter");


    // ======================================
    // SEARCH AND FILTER INCIDENTS
    // ======================================

    function filterIncidents() {

        const searchValue = searchInput.value.trim().toLowerCase();
        const selectedSeverity = severityFilter.value.toLowerCase();
        const selectedStatus = statusFilter.value.toLowerCase();

        let visibleCount = 0;

        incidentRows.forEach(function (row) {

            const incidentId = row.dataset.incidentId || "";
            const eventId = row.dataset.eventId || "";
            const ruleName = row.dataset.ruleName || "";

            const severity = row.dataset.severity || "";
            const status = row.dataset.status || "";

            const matchesSearch = [
                incidentId,
                eventId,
                ruleName
            ].some(function (value) {
                return value.toLowerCase().includes(searchValue);
            });

            const matchesSeverity =
                selectedSeverity === "all" ||
                severity === selectedSeverity;

            const matchesStatus =
                selectedStatus === "all" ||
                status === selectedStatus;

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
            `Showing ${visibleCount} of ${incidentRows.length} retrieved incidents`;

        noMatchingIncidents.hidden =
            visibleCount !== 0 || incidentRows.length === 0;

    }


    // ======================================
    // RESET FILTERS
    // ======================================

    function resetFilters() {

        searchInput.value = "";
        severityFilter.value = "all";
        statusFilter.value = "all";

        filterIncidents();

    }


    // ======================================
    // INCIDENT DETAILS
    // ======================================

    function openIncidentDetails(row) {

        const incident = row.dataset;

        document.getElementById("detailIncidentId").textContent =
            `#${incident.incidentId || "N/A"}`;

        document.getElementById("detailIncidentEventId").textContent =
            `#${incident.eventId || "N/A"}`;

        document.getElementById("detailIncidentRule").textContent =
            incident.ruleName || "N/A";

        document.getElementById("detailIncidentSeverity").textContent =
            (incident.severity || "N/A").toUpperCase();

        document.getElementById("detailIncidentStatus").textContent =
            incident.status || "N/A";

        document.getElementById("detailIncidentCreated").textContent =
            incident.created || "N/A";

        document.getElementById("detailIncidentAction").textContent =
            incident.action || "Not recorded";

        detailsDialog.showModal();

    }


    // ======================================
    // CLOSE INCIDENT DETAILS
    // ======================================

    function closeIncidentDetails() {
        detailsDialog.close();
    }


    // ======================================
    // EVENT LISTENERS
    // ======================================

    searchInput.addEventListener("input", filterIncidents);

    severityFilter.addEventListener("change", filterIncidents);

    statusFilter.addEventListener("change", filterIncidents);

    resetButton.addEventListener("click", resetFilters);


    // Incident details buttons
    incidentRows.forEach(function (row) {

        const detailsButton = row.querySelector(
            ".incident-details-button"
        );

        if (detailsButton) {

            detailsButton.addEventListener("click", function () {
                openIncidentDetails(row);
            });

        }

    });


    // Close dialog buttons
    closeButton.addEventListener("click", closeIncidentDetails);

    closeFooterButton.addEventListener("click", closeIncidentDetails);


    // Close dialog when clicking outside
    detailsDialog.addEventListener("click", function (event) {

        if (event.target === detailsDialog) {
            closeIncidentDetails();
        }

    });

});