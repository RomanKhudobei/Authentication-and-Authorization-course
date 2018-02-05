// search
$(document).ready(function(){
  $("#input-search").on("keyup", function() {
    var value = $(this).val().toLowerCase();
    $("#list-of-items li").filter(function() {
      $(this).toggle($(this).text().toLowerCase().indexOf(value) > -1)
    });
  });
});

// adds margin-bottom to buttons
$(document).ready(function() {
	if ($(window).width() < 992) {
		$.each($('#buttons-bar > div'), function() {
			if ($(this).text().trim(' ') !== '') {
				$(this).css('margin-bottom', '4px');
			};
		});
	};
});

// adds and deletes margin-bottom to buttons
$(window).resize(function() {
	if ($(window).width() < 992) {
		$.each($('#buttons-bar > div'), function() {
			if ($(this).text().trim(' ') !== '') {
				$(this).css('margin-bottom', '4px');
			};
		});
	} else {
		$.each($('#buttons-bar > div'), function() {
			if ($(this).text().trim(' ') !== '') {
				$(this).css('margin-bottom', '0px');
			};
		});
	};
});
