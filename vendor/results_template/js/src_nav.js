$(function() {
    $("li > a").click(function() {
        if ($(this).parent().hasClass("open")) {
            $(this).parent().removeClass("open");
        } else if ($(this).parent().children("ul").length > 0) {
            $(this).parent().addClass("open");
        }
    })
});
