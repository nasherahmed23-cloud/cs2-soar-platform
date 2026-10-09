// ==========================================
// INNOVATECH SOAR - SECURITY EVENTS
// ==========================================

document.addEventListener("DOMContentLoaded", function () {

    // ======================================
    // ELEMENT REFERENCES
    // ======================================

    const searchInput = document.getElementById("eventSearch");
    const severityFilter = document.getElementById("severityFilter");
    const statusFilter = document.getElementById("statusFilter");
    const resetButton = document.getElementById("resetFilters");

    const eventRows = Array.from(
        document.querySelectorAll("#securityEventsTable .event-row")
    );

    const resultsCount = document.getElementById("eventResultsCount");
    const noMatchingEvents = document.getElementById("noMatchingEvents");

    const detailsDialog = document.getElementById("eventDetailsDialog");
    const closeButton = document.getElementById("closeEventDetails");
    const closeFooterButton = document.getElementById("closeEventDetailsFooter");


    // ======================================
    // SEARCH AND FILTER EVENTS
    // ======================================

    function filterEvents() {

        const searchValue = searchInput.value.trim().toLowerCase();
        const selectedSeverity = severityFilter.value.toLowerCase();
        const selectedStatus = statusFilter.value.toLowerCase();

        let visibleCount = 0;

        eventRows.forEach(function (row) {

            const eventId = row.dataset.eventId || "";
            const eventType = row.dataset.eventType || "";
            const source = row.dataset.source || "";
            const sourceIp = row.dataset.sourceIp || "";

            const severity = row.dataset.severity || "";
            const status = row.dataset.status || "";

            // Search across event fields
            const matchesSearch = [
                eventId,
                eventType,
                source,
                sourceIp
            ].some(function (value) {
                return value.toLowerCase().includes(searchValue);
            });

            // Severity filter
            const matchesSeverity =
                selectedSeverity === "all" ||
                severity === selectedSeverity;

            // Status filter
            const matchesStatus =
                selectedStatus === "all" ||
                status === selectedStatus;

            // Combine all filters
            const shouldShow =
                matchesSearch &&
                matchesSeverity &&
                matchesStatus;

            row.hidden = !shouldShow;

            if (shouldShow) {
                visibleCount++;
            }

        });

        // Update results count
        resultsCount.textContent =
            `Showing ${visibleCount} of ${eventRows.length} retrieved events`;

        // Display empty-state message if filters return no matches
        noMatchingEvents.hidden =
            visibleCount !== 0 || eventRows.length === 0;

    }


    // ======================================
    // RESET FILTERS
    // ======================================

    function resetFilters() {

        searchInput.value = "";
        severityFilter.value = "all";
        statusFilter.value = "all";

        filterEvents();

    }


    // ======================================
    // EVENT DETAILS
    // ======================================

    function openEventDetails(row) {

        const eventData = row.dataset;

        document.getElementById("detailEventId").textContent =
            `#${eventData.eventId || "N/A"}`;

        document.getElementById("detailEventType").textContent =
            eventData.eventType || "N/A";

        document.getElementById("detailSource").textContent =
            eventData.source || "N/A";

        document.getElementById("detailSourceIp").textContent =
            eventData.sourceIp || "N/A";

        document.getElementById("detailSeverity").textContent =
            (eventData.severity || "N/A").toUpperCase();

        document.getElementById("detailStatus").textContent =
            eventData.status || "N/A";

        document.getElementById("detailTimestamp").textContent =
            eventData.timestamp || "N/A";

        document.getElementById("detailMessage").textContent =
            eventData.message || "No event message available.";

        detailsDialog.showModal();

    }


    // ======================================
    // CLOSE EVENT DETAILS
    // ======================================

    function closeEventDetails() {

        detailsDialog.close();

    }


    // ======================================
    // EVENT LISTENERS
    // ======================================

    searchInput.addEventListener("input", filterEvents);

    severityFilter.addEventListener("change", filterEvents);

    statusFilter.addEventListener("change", filterEvents);

    resetButton.addEventListener("click", resetFilters);


    // Event details buttons
    eventRows.forEach(function (row) {

        const detailsButton = row.querySelector(".event-details-button");

        if (detailsButton) {

            detailsButton.addEventListener("click", function () {
                openEventDetails(row);
            });

        }

    });


    // Close dialog buttons
    closeButton.addEventListener("click", closeEventDetails);

    closeFooterButton.addEventListener("click", closeEventDetails);


    // Close dialog when clicking outside its content
    detailsDialog.addEventListener("click", function (event) {

        if (event.target === detailsDialog) {
            closeEventDetails();
        }

    });

});