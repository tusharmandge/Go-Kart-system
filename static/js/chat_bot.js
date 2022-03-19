showUsuario: function (id) {
console.log(id);
},
expandTextArea: function () {
$('#chatBox-textbox').height(80);
$('#chatTextarea').height(60);
},
dexpandTetArea: function () {
$('#chatBox-textbox').height(60);
$('#chatTextarea').height(40);
},
$(".toggleChatDialog").click(function () {
  alert(1);
  if ($("#chatbox-area").is(":visible")) {
    $('#chatbox-area').hide();
    $('.header-title').hide();
    $('.card').css('box-shadow', "none");
    $('.float').show();
  } else {
    $('.header-title').show();
    $('#chatbox-area').show();
    $('.card').css('box-shadow', " 0 2px 3px rgb(10 10 10 / 10%), 0 0 0 1px rgb(10 10 10 / 10%)");
    $('.float').hide();
  }
  this.chatBoxArea = !this.chatBoxArea;
  });
openChatBox: function (info) {

},
startChat: function (user) {

},
expandChatList: function () {$("#userListBox").slideToggle();
this.showChatList = !this.showChatList;

} } });