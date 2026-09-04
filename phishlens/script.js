/* PhishGuard AI — script.js
 *
 * Everything below is a MOCK analysis. No real ML model is connected.
 * `analyzeEmail()` is written so the mock logic inside it can later be
 * swapped for a real request to a backend, e.g.:
 *
 *   async function analyzeEmail(input) {
 *     const res = await fetch("/analyze", {
 *       method: "POST",
 *       headers: { "Content-Type": "application/json" },
 *       body: JSON.stringify(input)
 *     });
 *     return res.json();
 *   }
 *
 * The expected response shape is documented right above the mock
 * implementation further down this file.
 */

const form = document.getElementById("analyzer-form");
const senderInput = document.getElementById("sender-email");
const subjectInput = document.getElementById("email-subject");
const bodyInput = document.getElementById("email-body");
const clearBtn = document.getElementById("clear-btn");
const downloadBtn = document.getElementById("download-report-btn");

const resultEmpty = document.getElementById("result-empty");
const resultContent = document.getElementById("result-content");
const verdictRow = document.getElementById("verdict-row");
const verdictValue = document.getElementById("verdict-value");
const riskScoreEl = document.getElementById("risk-score");
const confidenceScoreEl = document.getElementById("confidence-score");
const reasonList = document.getElementById("reason-list");
const urlsDetectedEl = document.getElementById("urls-detected");
const urlsSuspiciousEl = document.getElementById("urls-suspicious");
const keywordList = document.getElementById("keyword-list");

let lastAnalysis = null; // holds the most recent result + inputs, used for the PDF report

form.addEventListener("submit", function (event) {
  event.preventDefault();
  runAnalysis();
});

clearBtn.addEventListener("click", function () {
  form.reset();
  clearFieldErrors();
  resetResults();
  lastAnalysis = null;
});

downloadBtn.addEventListener("click", function () {
  if (lastAnalysis) {
    generateReport(lastAnalysis);
  }
});

/* ---------- Validation ---------- */

function clearFieldErrors() {
  document.querySelectorAll(".field").forEach(function (field) {
    field.classList.remove("has-error");
  });
}

function setFieldError(fieldId) {
  document.getElementById(fieldId).classList.add("has-error");
}

function validateInputs(sender, subject, body) {
  clearFieldErrors();
  let isValid = true;

  const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

  if (!sender.trim() || !emailPattern.test(sender.trim())) {
    setFieldError("field-sender");
    isValid = false;
  }

  if (!subject.trim()) {
    setFieldError("field-subject");
    isValid = false;
  }

  if (!body.trim()) {
    setFieldError("field-body");
    isValid = false;
  }

  return isValid;
}

/* ---------- Run analysis ---------- */

function runAnalysis() {
  const sender = senderInput.value;
  const subject = subjectInput.value;
  const body = bodyInput.value;

  if (!validateInputs(sender, subject, body)) {
    resetResults();
    return;
  }

  const input = {
    senderEmail: sender.trim(),
    subject: subject.trim(),
    body: body.trim()
  };

  const result = analyzeEmail(input);

  lastAnalysis = { input: input, result: result };
  renderResult(input, result);
}

function analyzeEmail(input) {
  const text = (input.subject + " " + input.body).toLowerCase();

  const suspiciousKeywords = [
    "verify your account", "urgent", "click here", "suspended",
    "password", "confirm your identity", "act now", "limited time",
    "bank details", "wire transfer", "unusual activity", "reset your password"
  ];

  const matchedKeywords = suspiciousKeywords.filter(function (kw) {
    return text.indexOf(kw) !== -1;
  });

  const urlMatches = input.body.match(/https?:\/\/[^\s)]+/g) || [];
  const knownSafeDomains = ["company.com", "yourbank.com"];
  const suspiciousUrls = urlMatches.filter(function (url) {
    return !knownSafeDomains.some(function (domain) {
      return url.indexOf(domain) !== -1;
    });
  });

  const senderLooksOff = /\d{3,}|-support|-secure|verify-/.test(input.senderEmail.toLowerCase());

  let riskScore = 8;
  riskScore += matchedKeywords.length * 12;
  riskScore += suspiciousUrls.length * 15;
  riskScore += senderLooksOff ? 20 : 0;
  riskScore = Math.min(riskScore, 97);

  const isPhishing = riskScore >= 50;
  const confidence = isPhishing
    ? Math.min(90 + matchedKeywords.length * 2, 99)
    : Math.max(80 - suspiciousUrls.length * 5, 60);

  const reasons = [];
  if (matchedKeywords.length > 0) {
    reasons.push("Urgent or credential-related language detected");
  }
  if (suspiciousUrls.length > 0) {
    reasons.push("Suspicious URL detected");
  }
  if (senderLooksOff) {
    reasons.push("Sender address pattern is inconsistent with a legitimate domain");
  }
  if (reasons.length === 0) {
    reasons.push("No strong phishing indicators found in the provided content");
  }

  const keywordResults = suspiciousKeywords
    .filter(function (kw) {
      return matchedKeywords.indexOf(kw) !== -1;
    })
    .map(function (kw) {
      return { term: kw, flagged: true };
    });

  return {
    verdict: isPhishing ? "phishing" : "legitimate",
    riskScore: riskScore,
    confidence: confidence,
    reasons: reasons,
    urls: {
      detected: urlMatches.length,
      suspicious: suspiciousUrls.length
    },
    keywords: keywordResults
  };
}

/* ---------- Render ---------- */

function resetResults() {
  resultEmpty.classList.remove("is-hidden");
  resultContent.classList.remove("is-visible");
  verdictRow.classList.remove("phishing", "legitimate");
}

function renderResult(input, result) {
  resultEmpty.classList.add("is-hidden");
  resultContent.classList.add("is-visible");

  verdictRow.classList.remove("phishing", "legitimate");
  verdictRow.classList.add(result.verdict);
  verdictValue.textContent = result.verdict === "phishing" ? "PHISHING" : "LEGITIMATE";

  riskScoreEl.textContent = result.riskScore + "%";
  confidenceScoreEl.textContent = result.confidence + "%";

  reasonList.innerHTML = "";
  result.reasons.forEach(function (reason) {
    const li = document.createElement("li");
    li.textContent = reason;
    reasonList.appendChild(li);
  });

  urlsDetectedEl.textContent = result.urls.detected;
  urlsSuspiciousEl.textContent = result.urls.suspicious;

  keywordList.innerHTML = "";
  if (result.keywords.length === 0) {
    const span = document.createElement("span");
    span.className = "keyword-chip";
    span.textContent = "No suspicious keywords found";
    keywordList.appendChild(span);
  } else {
    result.keywords.forEach(function (kw) {
      const span = document.createElement("span");
      span.className = "keyword-chip flagged";
      span.textContent = kw.term;
      keywordList.appendChild(span);
    });
  }
}

/* ---------- PDF report ---------- */

function generateReport(analysis) {
  const { jsPDF } = window.jspdf;
  const doc = new jsPDF({ unit: "pt", format: "a4" });

  const marginX = 48;
  let y = 56;
  const lineHeight = 16;
  const pageWidth = doc.internal.pageSize.getWidth();
  const contentWidth = pageWidth - marginX * 2;

  function addLine(text, size, style) {
    doc.setFontSize(size || 11);
    doc.setFont("helvetica", style || "normal");
    const wrapped = doc.splitTextToSize(text, contentWidth);
    wrapped.forEach(function (line) {
      if (y > 780) {
        doc.addPage();
        y = 56;
      }
      doc.text(line, marginX, y);
      y += lineHeight;
    });
  }

  function addSpacer(amount) {
    y += amount || 8;
  }

  // Logo placeholder box (swap this block out once a real logo file exists)
  doc.setDrawColor(150);
  doc.rect(marginX, y - 24, 32, 32);
  doc.setFontSize(7);
  doc.setTextColor(150);
  doc.text("LOGO", marginX + 6, y - 6);
  doc.setTextColor(0);

  doc.setFontSize(16);
  doc.setFont("helvetica", "bold");
  doc.text("PhishGuard AI", marginX + 44, y);
  addSpacer(28);

  addLine("Email Threat Analysis Report", 13, "bold");
  addSpacer(4);

  const now = new Date();
  addLine("Generated: " + now.toLocaleString(), 10);
  addSpacer(10);

  addLine("Email Details", 12, "bold");
  addLine("Sender: " + analysis.input.senderEmail);
  addLine("Subject: " + analysis.input.subject);
  addSpacer(4);
  addLine("Body:", 11, "bold");
  addLine(analysis.input.body || "(empty)");
  addSpacer(10);

  addLine("Verdict and Scoring", 12, "bold");
  addLine("Verdict: " + (analysis.result.verdict === "phishing" ? "PHISHING" : "LEGITIMATE"));
  addLine("Risk Score: " + analysis.result.riskScore + "%");
  addLine("Confidence: " + analysis.result.confidence + "%");
  addSpacer(10);

  addLine("Detection Reasons", 12, "bold");
  analysis.result.reasons.forEach(function (reason) {
    addLine("- " + reason);
  });
  addSpacer(10);

  addLine("URL Analysis", 12, "bold");
  addLine("URLs detected: " + analysis.result.urls.detected);
  addLine("Suspicious URLs: " + analysis.result.urls.suspicious);
  addSpacer(10);

  addLine("Keyword Analysis", 12, "bold");
  if (analysis.result.keywords.length === 0) {
    addLine("No suspicious keywords found.");
  } else {
    addLine(analysis.result.keywords.map(function (k) { return k.term; }).join(", "));
  }
  addSpacer(16);

  addLine("Disclaimer", 12, "bold");
  addLine(
    "This result is an automated assessment and should not be treated as " +
    "definitive proof that an email is malicious or legitimate.",
    10
  );

  doc.save("phishguard-ai-report.pdf");
}
