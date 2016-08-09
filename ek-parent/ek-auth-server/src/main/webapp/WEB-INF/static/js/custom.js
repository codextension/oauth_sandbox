jQuery(function ($) {
    var panelList = $('.draggablePanelList');

    panelList.sortable({
        handle: '.panel-heading',
        update: function () {
            $('.panel', panelList).each(function (index, elem) {
                var $listItem = $(elem),
                    newIndex = $listItem.index();

                // Persist the new indices.
            });
        }
    });
});