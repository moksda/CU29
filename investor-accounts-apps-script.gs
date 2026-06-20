var ACCOUNTS_SHEET_ID = '16FqyKKc0S-fGVeP_dcK1pSI1t3IpmBJ9YTNW6K-nmm4';
var FALLBACK_ADMIN = { name: 'Admin', email: 'mooks.bucataru@gmail.com', password: 'Admin2026!', role: 'admin' };

// One-time: run this manually from the editor (function dropdown > Run) to
// trigger Google's permission consent screen for the Mail scope. Delete
// once authorized.
function _authorizeMail() {
  MailApp.sendEmail('mooks.bucataru@gmail.com', 'CU29 script authorization test', 'If you got this email, the script is authorized to send mail.');
}

function doGet(e) {
  var action = e.parameter.action;
  var callback = e.parameter.callback;
  var result;

  if (action === 'login') {
    result = handleLogin(e.parameter.email, e.parameter.password);
  } else if (action === 'market_data') {
    result = handleGetMarketData();
  } else {
    result = { error: 'unknown action' };
  }

  var json = JSON.stringify(result);
  if (callback) {
    return ContentService.createTextOutput(callback + '(' + json + ')').setMimeType(ContentService.MimeType.JAVASCRIPT);
  }
  return ContentService.createTextOutput(json).setMimeType(ContentService.MimeType.JSON);
}

function doPost(e) {
  try {
    var p = e.parameter;
    if (p.action === 'apply_investor') {
      return ContentService.createTextOutput(JSON.stringify(applyInvestor(p))).setMimeType(ContentService.MimeType.JSON);
    }
    if (p.action === 'contact') {
      return ContentService.createTextOutput(JSON.stringify(handleContact(p))).setMimeType(ContentService.MimeType.JSON);
    }
    return ContentService.createTextOutput(JSON.stringify({ success: false, error: 'unknown action' })).setMimeType(ContentService.MimeType.JSON);
  } catch (err) {
    return ContentService.createTextOutput(JSON.stringify({ success: false, error: err.toString() })).setMimeType(ContentService.MimeType.JSON);
  }
}

function handleContact(p) {
  var deptEmails = {
    'General Inquiries':          'info@investcu29.com',
    'Compliance & Verification':  'compliance@investcu29.com',
    'Charity & Impact':           'impact@investcu29.com'
  };
  var dept     = p.department || 'General Inquiries';
  var toEmail  = deptEmails[dept] || 'info@investcu29.com';
  var fromName = p.name || 'Website Visitor';
  var fromEmail = p.email || '';
  var subject  = '[' + dept + '] ' + (p.subject || 'New Inquiry') + ' — InvestCu29';

  var body =
    'CONTACT FORM SUBMISSION\n' +
    '========================\n' +
    'NAME: ' + fromName + '\n' +
    'EMAIL: ' + fromEmail + '\n' +
    'PHONE: ' + (p.phone || '') + '\n' +
    'DEPARTMENT: ' + dept + '\n' +
    'SUBJECT: ' + (p.subject || '') + '\n' +
    '------------------------\n' +
    'MESSAGE:\n' + (p.message || '');

  MailApp.sendEmail({
    to: toEmail,
    replyTo: fromEmail,
    name: 'CU29 Investments',
    subject: subject,
    body: body
  });

  var ss = SpreadsheetApp.openById(ACCOUNTS_SHEET_ID);
  var sheet = ss.getSheetByName('Contact Submissions');
  if (!sheet) {
    sheet = ss.insertSheet('Contact Submissions');
    sheet.appendRow(['Date', 'Name', 'Email', 'Phone', 'Department', 'Subject', 'Message']);
  }
  sheet.appendRow([new Date(), fromName, fromEmail, safeText(p.phone), dept, p.subject || '', p.message || '']);

  return { success: true };
}

function handleGetMarketData() {
  var MARKET_SHEET_ID = '1lLyaaasXtAEmq12zhtE26_ckR2-FwaZ1oI10NGtLDgo';
  var syms = ['SPY', 'VNQ', 'GLD', 'USO', 'SCCO', 'QQQ', 'TLT'];
  try {
    var sheet = SpreadsheetApp.openById(MARKET_SHEET_ID).getSheets()[0];
    // Only write formulas if not already present — after first run Google Sheets
    // keeps GOOGLEFINANCE live automatically, so we just read instantly each time.
    var existing = sheet.getRange(2, 3).getFormula();
    if (!existing || existing.indexOf('GOOGLEFINANCE') === -1) {
      for (var i = 0; i < syms.length; i++) {
        var r = i + 2;
        sheet.getRange(r, 3).setFormula('=IFERROR(GOOGLEFINANCE("' + syms[i] + '","price"),0)');
        sheet.getRange(r, 4).setFormula('=IFERROR(GOOGLEFINANCE("' + syms[i] + '","closeyest"),0)');
      }
      SpreadsheetApp.flush();
      Utilities.sleep(5000);
    }
    var values = sheet.getRange(2, 1, syms.length, 4).getValues();
    var out = {};
    values.forEach(function(row) {
      var sym = String(row[0]).trim();
      if (!sym) return;
      var price = Number(row[2]) || null;
      var prev  = Number(row[3]) || null;
      var pct   = (price && prev && prev !== 0)
                  ? Math.round((price - prev) / prev * 10000) / 100
                  : null;
      out[sym] = { price: price, pct: pct };
    });
    return { ok: true, quotes: out };
  } catch (ex) {
    return { ok: false, error: ex.toString() };
  }
}

function getAccountsSheet() {
  return SpreadsheetApp.openById(ACCOUNTS_SHEET_ID).getSheets()[0];
}

// Server-side credential check. Only ever returns name/email/role for a
// successful match — never the password, and never the full account list.
function handleLogin(email, password) {
  if (!email || !password) return { success: false };
  email = email.trim().toLowerCase();

  if (email === FALLBACK_ADMIN.email.toLowerCase() && password === FALLBACK_ADMIN.password) {
    return { success: true, name: FALLBACK_ADMIN.name, role: FALLBACK_ADMIN.role, email: FALLBACK_ADMIN.email };
  }

  var rows = getAccountsSheet().getDataRange().getValues();
  for (var i = 1; i < rows.length; i++) {
    var row = rows[i];
    var rowEmail = String(row[1] || '').trim().toLowerCase();
    var rowPass = String(row[2] || '');
    if (rowEmail === email && rowPass === password) {
      return { success: true, name: row[0], role: row[3] || 'investor', email: row[1] };
    }
  }
  return { success: false };
}

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
  fixSheetPhoneColumn(getAccountsSheet(), 5); // Accounts sheet, column E = Phone
  var appSheet = SpreadsheetApp.openById(ACCOUNTS_SHEET_ID).getSheetByName('Investor Applications');
  if (appSheet) fixSheetPhoneColumn(appSheet, 4); // column D = Phone
}

function fixSheetPhoneColumn(sheet, col) {
  var lastRow = sheet.getLastRow();
  if (lastRow < 2) return;
  var range = sheet.getRange(2, col, lastRow - 1, 1);
  var formulas = range.getFormulas();
  for (var i = 0; i < formulas.length; i++) {
    var f = formulas[i][0];
    if (f) range.getCell(i + 1, 1).setValue(safeText(f));
  }
}

function applyInvestor(p) {
  var name = ((p.first_name || '') + ' ' + (p.last_name || '')).trim();
  var email = p.email;
  var phone = safeText(p.phone);

  var accounts = getAccountsSheet();
  accounts.appendRow([name, email, p.password, 'investor', phone, 'Investor application', new Date()]);

  var ss = SpreadsheetApp.openById(ACCOUNTS_SHEET_ID);
  var appSheet = ss.getSheetByName('Investor Applications');
  if (!appSheet) {
    appSheet = ss.insertSheet('Investor Applications');
    appSheet.appendRow(['Date', 'Name', 'Email', 'Phone', 'DOB', 'Nationality', 'Country', 'Investor Type', 'Experience', 'History', 'Capital', 'Horizon', 'Interests', 'Risk', 'Expected Return', 'Source of Funds', 'PEP']);
  }
  appSheet.appendRow([
    new Date(), name, email, phone, p.dob, p.nationality, p.country,
    p.investor_type, p.experience, p.history, p.capital, p.horizon,
    p.interests, p.risk, p.expected_return, p.source_of_funds, p.pep
  ]);

  var body =
    'NEW INVESTOR APPLICATION\n' +
    '========================\n' +
    'NAME: ' + name + '\n' +
    'EMAIL: ' + email + '\n' +
    'PHONE: ' + (p.phone || '') + '\n' +
    'DOB: ' + (p.dob || '') + '\n' +
    'NATIONALITY: ' + (p.nationality || '') + '\n' +
    'COUNTRY OF RESIDENCE: ' + (p.country || '') + '\n' +
    '------------------------\n' +
    'INVESTOR TYPE: ' + (p.investor_type || '') + '\n' +
    'EXPERIENCE: ' + (p.experience || '') + '\n' +
    'INVESTMENT HISTORY: ' + (p.history || '') + '\n' +
    'AVAILABLE CAPITAL: ' + (p.capital || '') + '\n' +
    'TIME HORIZON: ' + (p.horizon || '') + '\n' +
    'AREAS OF INTEREST: ' + (p.interests || '') + '\n' +
    'RISK TOLERANCE: ' + (p.risk || '') + '\n' +
    'EXPECTED RETURN: ' + (p.expected_return || '') + '\n' +
    '------------------------\n' +
    'SOURCE OF FUNDS: ' + (p.source_of_funds || '') + '\n' +
    'PEP (POLITICALLY EXPOSED PERSON): ' + (p.pep || '') + '\n' +
    '------------------------\n' +
    'An account has already been created for this applicant (role: investor).';

  MailApp.sendEmail({
    to: 'compliance@investcu29.com',
    replyTo: email,
    name: 'CU29 Investments',
    subject: '[Investor Application] ' + name,
    body: body
  });

  return { success: true };
}
