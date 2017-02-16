/**
 * DKIM Status check plus for Roundcube
 * Version:
 * Author: Hiroki Minematsu <mine@lancard.com>
 * https://www.lancard.com
 *
 */
function rcm_dkimstatus_plus_insert(uid, row)
{
  if (typeof rcmail.env == 'undefined' || typeof rcmail.env.messages == 'undefined') {
    return;
  }
  var message = rcmail.env.messages[uid];
  var rowobj = $(row.obj);
  // add span container for status icon
  rowobj.find("td.fromto").prepend("<span class='dkimstatus_plus'></span>");
  console.log(message.flags);

  if (message.flags && message.flags.dkimstatus_results) {
    if (message.flags.dkimstatus_results.length) {
      var spanobj = rowobj.find("td.fromto span.dkimstatus_plus");
       //spanobj.append("<span class='label"+message.flags.tb_labels[idx]+"'>&#8226;</span>");
       spanobj.append("<span class='label'>" + message.flags.dkimstatus_results + "</span>");
    }
  }
}

$(document).ready(function() {
  rcmail.addEventListener('insertrow', function(event) { rcm_dkimstatus_plus_insert(event.uid, event.row); });
});
