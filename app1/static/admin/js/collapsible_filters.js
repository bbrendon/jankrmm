// Make Django admin filters collapsible
(function() {
    // Wait for DOM to be ready and jQuery to be available
    var initFilters = function() {
        var $ = django.jQuery || jQuery || window.jQuery;
        if (!$) {
            console.error('jQuery not found for collapsible filters');
            return;
        }
    // Detect dark mode
    var isDarkMode = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;

    // Create a toggle button
    var toggleBtn = $('<button>')
        .attr('type', 'button')
        .attr('id', 'filter-toggle')
        .text('Filters ▼')
        .css({
            'position': 'fixed',
            'right': '10px',
            'top': '60px',  // Moved down from 10px to avoid navbar
            'z-index': '1000',
            'padding': '8px 16px',
            'background': isDarkMode ? '#2b5b75' : '#417690',
            'color': 'white',
            'border': isDarkMode ? '1px solid #5a9bb8' : 'none',
            'border-radius': '4px',
            'cursor': 'pointer',
            'font-size': '13px',
            'font-weight': '500',
            'box-shadow': '0 2px 8px rgba(0,0,0,0.3)'
        });

    // Add the button to the page
    $('body').append(toggleBtn);

    // Initially hide the filter sidebar
    $('#changelist-filter').css({
        'position': 'fixed',
        'right': '0',
        'top': '0',
        'height': '100%',
        'overflow-y': 'auto',
        'z-index': '999',
        'background': isDarkMode ? '#1a1a1a' : 'white',
        'box-shadow': '-2px 0 12px rgba(0,0,0,' + (isDarkMode ? '0.5' : '0.2') + ')',
        'border-left': isDarkMode ? '1px solid #444' : 'none',
        'display': 'none'
    });

    // Adjust the main content area
    $('#changelist').css('margin-right', '0');

    // Toggle functionality
    var filterVisible = false;
    toggleBtn.click(function() {
        filterVisible = !filterVisible;
        if (filterVisible) {
            $('#changelist-filter').slideDown(200);
            $(this).text('Filters ▲');
        } else {
            $('#changelist-filter').slideUp(200);
            $(this).text('Filters ▼');
        }
    });

    // Close filters when clicking outside
    $(document).click(function(event) {
        if (filterVisible &&
            !$(event.target).closest('#changelist-filter').length &&
            !$(event.target).closest('#filter-toggle').length) {
            $('#changelist-filter').slideUp(200);
            toggleBtn.text('Filters ▼');
            filterVisible = false;
        }
    });
    };

    // Try to initialize when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initFilters);
    } else {
        initFilters();
    }
})();
