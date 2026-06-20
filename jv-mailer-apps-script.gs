var LOG_SHEET_ID = '13YGookxb_NwU3541IiD799AK94H7_288rFd98mtc2vE';

// Sheets auto-parses any cell value starting with +, -, or = as a formula
// (e.g. a phone number like "+44 7123456789" triggers "Formula parse error").
// Prefixing with a leading apostrophe forces Sheets to store it as literal text.
function safeText(v) {
  v = String(v == null ? '' : v);
  return /^[+\-=]/.test(v) ? "'" + v : v;
}

// One-time repair for rows already broken by the formula-parse bug.
// Run this manually once from the Apps Script editor (select it in the
// function dropdown, click Run) — it fixes existing rows; new rows are
// already safe via safeText() above.
function fixBrokenPhoneCells() {
  var sheet = SpreadsheetApp.openById(LOG_SHEET_ID).getSheetByName('JV Submissions');
  if (!sheet) return;
  var col = 4; // Phone column
  var lastRow = sheet.getLastRow();
  if (lastRow < 2) return;
  var range = sheet.getRange(2, col, lastRow - 1, 1);
  var formulas = range.getFormulas();
  for (var i = 0; i < formulas.length; i++) {
    var f = formulas[i][0];
    if (f) range.getCell(i + 1, 1).setValue(safeText(f));
  }
}

function doPost(e) {
  try {
    var p = e.parameter;
    var submitterEmail = p.email || '(not provided)';

    var subject = '[Joint Venture Proposal] ' + (p.project_name || '') + ' — ' + (p.from_name || '');

    var body =
      'SUBMITTED BY: ' + (p.from_name || '') + '\n' +
      'EMAIL: ' + submitterEmail + '\n' +
      'PHONE: ' + (p.phone || '') + '\n' +
      'COMPANY: ' + (p.company || '') + '\n' +
      'WEBSITE: ' + (p.website || '') + '\n' +
      '----------------------------------------\n' +
      'PROJECT NAME: ' + (p.project_name || '') + '\n' +
      'SECTOR: ' + (p.sector || '') + '\n' +
      'STAGE: ' + (p.stage || '') + '\n' +
      'LOCATION: ' + (p.location || '') + '\n' +
      'NEEDS FROM CU29: ' + (p.needs_from_cu29 || '') + '\n' +
      'HOW THEY HEARD ABOUT US: ' + (p.source || '') + '\n' +
      '----------------------------------------\n' +
      'PROJECT DESCRIPTION:\n' + (p.description || '') + '\n\n' +
      'WHAT THEY ARE OFFERING:\n' + (p.offering || '') + '\n';

    MailApp.sendEmail({
      to: 'impact@investcu29.com',
      replyTo: submitterEmail,
      name: 'CU29 Investments',
      subject: subject,
      body: body
    });

    var ss = SpreadsheetApp.openById(LOG_SHEET_ID);
    var sheet = ss.getSheetByName('JV Submissions');
    if (!sheet) {
      sheet = ss.insertSheet('JV Submissions');
      sheet.appendRow(['Date', 'Name', 'Email', 'Phone', 'Company', 'Website', 'Project', 'Sector', 'Stage', 'Location', 'Needs', 'Source', 'Description', 'Offering']);
    }
    sheet.appendRow([
      new Date(), p.from_name, submitterEmail, safeText(p.phone), p.company, p.website,
      p.project_name, p.sector, p.stage, p.location, p.needs_from_cu29, p.source,
      p.description, p.offering
    ]);

    return ContentService.createTextOutput(JSON.stringify({ success: true }))
      .setMimeType(ContentService.MimeType.JSON);
  } catch (err) {
    return ContentService.createTextOutput(JSON.stringify({ success: false, error: err.toString() }))
      .setMimeType(ContentService.MimeType.JSON);
  }
}
