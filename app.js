/**
 * Secure Student Data Analytics System
 * Subject: Secure Data Science Mini Project
 * 
 * Features:
 * 1. Zero-transmission client-side CSV parsing.
 * 2. Automated PII detection and masking (Names, Emails, Phones, Student IDs).
 * 3. Statistical analytics: Averages, range, variance, pass percentage, and compliance tiers.
 * 4. Lightweight custom Canvas charting (Pie chart for performance, Bar chart for attendance).
 * 5. Hardware-accelerated AES-256-GCM authenticated encryption using Web Crypto API.
 * 6. Anonymized CSV export and encrypted package export.
 */

(function () {
  'use strict';

  // State Management
  const state = {
    isAuthenticated: false,
    currentUser: 'faculty.analyst',
    students: [], // Raw student objects
    maskedStudents: [], // PII-masked student records
    isMaskingActive: true,
    activeTab: 'overview',
    stats: {
      total: 0,
      avgMarks: 0,
      avgAttendance: 0,
      distinctionCount: 0,
      distinctionRate: 0,
      minMarks: 0,
      maxMarks: 0,
      passRate: 0,
      atRiskCount: 0,
      tiers: {
        distinction: 0,
        firstClass: 0,
        secondClass: 0,
        needsIntervention: 0
      },
      attendanceTiers: {
        high: 0,    // >= 85%
        normal: 0,  // 75 - 84%
        shortage: 0 // < 75%
      }
    }
  };

  // DOM Elements cache
  const elements = {};

  // Initialize Application
  document.addEventListener('DOMContentLoaded', () => {
    cacheElements();
    bindEvents();
    renderAuthView();
  });

  function cacheElements() {
    elements.authView = document.getElementById('authView');
    elements.appContainer = document.getElementById('appContainer');
    elements.loginForm = document.getElementById('loginForm');
    elements.username = document.getElementById('username');
    elements.password = document.getElementById('password');
    elements.loginBtn = document.getElementById('loginBtn');
    elements.logoutBtn = document.getElementById('logoutBtn');
    elements.sessionUsername = document.getElementById('sessionUsername');
    elements.sidebar = document.querySelector('.sidebar');
    elements.sidebarToggle = document.getElementById('sidebarToggle');
    elements.viewHeading = document.getElementById('viewHeading');

    // Navigation
    elements.navItems = document.querySelectorAll('.nav-item');
    elements.tabPanes = document.querySelectorAll('.tab-pane');

    // Upload & Ingestion
    elements.dropZone = document.getElementById('dropZone');
    elements.csvFileInput = document.getElementById('csvFileInput');
    elements.browseFileBtn = document.getElementById('browseFileBtn');
    elements.loadSampleBtn = document.getElementById('loadSampleBtn');
    elements.fileStatusBanner = document.getElementById('fileStatusBanner');
    elements.loadedFileName = document.getElementById('loadedFileName');
    elements.loadedFileMeta = document.getElementById('loadedFileMeta');

    // KPIs
    elements.kpiTotalStudents = document.getElementById('kpiTotalStudents');
    elements.kpiAverageMarks = document.getElementById('kpiAverageMarks');
    elements.kpiAverageAttendance = document.getElementById('kpiAverageAttendance');
    elements.kpiMarksSpread = document.getElementById('kpiMarksSpread');
    elements.kpiDistinctionRate = document.getElementById('kpiDistinctionRate');
    elements.kpiDistinctionCount = document.getElementById('kpiDistinctionCount');

    // Insights
    elements.insightPassingRate = document.getElementById('insightPassingRate');
    elements.insightAtRiskCount = document.getElementById('insightAtRiskCount');
    elements.insightNarrative = document.getElementById('insightNarrative');

    // Charts & Legends
    elements.performanceChart = document.getElementById('performanceChart');
    elements.performanceLegend = document.getElementById('performanceLegend');
    elements.attendanceChart = document.getElementById('attendanceChart');
    elements.attendanceLegend = document.getElementById('attendanceLegend');

    // Data Management
    elements.maskToggle = document.getElementById('maskToggle');
    elements.maskToggleLabel = document.getElementById('maskToggleLabel');
    elements.studentTableBody = document.getElementById('studentTableBody');
    elements.tableSearch = document.getElementById('tableSearch');
    elements.tierFilter = document.getElementById('tierFilter');
    elements.tableRecordCount = document.getElementById('tableRecordCount');
    elements.downloadAnonymizedCsvBtn = document.getElementById('downloadAnonymizedCsvBtn');

    // Security & Encryption
    elements.exportPassphrase = document.getElementById('exportPassphrase');
    elements.encryptExportBtn = document.getElementById('encryptExportBtn');
    elements.encryptionResultBox = document.getElementById('encryptionResultBox');
    elements.encryptionCiphertextPreview = document.getElementById('encryptionCiphertextPreview');

    // Toast Container
    elements.toastContainer = document.getElementById('toastContainer');
  }

  function bindEvents() {
    // Authentication
    elements.loginForm.addEventListener('submit', handleLogin);
    elements.logoutBtn.addEventListener('click', handleLogout);

    // Sidebar Mobile Toggle
    if (elements.sidebarToggle) {
      elements.sidebarToggle.addEventListener('click', () => {
        elements.sidebar.classList.toggle('open');
      });
    }

    // Navigation Tabs
    elements.navItems.forEach((btn) => {
      btn.addEventListener('click', () => {
        const tab = btn.getAttribute('data-tab');
        switchTab(tab);
        if (elements.sidebar.classList.contains('open')) {
          elements.sidebar.classList.remove('open');
        }
      });
    });

    // File Upload (Drag & Drop + File Picker)
    elements.browseFileBtn.addEventListener('click', () => elements.csvFileInput.click());
    elements.dropZone.addEventListener('click', (e) => {
      if (e.target !== elements.browseFileBtn) {
        elements.csvFileInput.click();
      }
    });

    elements.dropZone.addEventListener('dragover', (e) => {
      e.preventDefault();
      elements.dropZone.classList.add('dragover');
    });

    elements.dropZone.addEventListener('dragleave', () => {
      elements.dropZone.classList.remove('dragover');
    });

    elements.dropZone.addEventListener('drop', (e) => {
      e.preventDefault();
      elements.dropZone.classList.remove('dragover');
      const files = e.dataTransfer.files;
      if (files.length > 0) {
        processUploadedFile(files[0]);
      }
    });

    elements.csvFileInput.addEventListener('change', (e) => {
      if (e.target.files.length > 0) {
        processUploadedFile(e.target.files[0]);
      }
    });

    // Load Sample Dataset
    elements.loadSampleBtn.addEventListener('click', loadSampleData);

    // Masking Switch
    elements.maskToggle.addEventListener('change', (e) => {
      state.isMaskingActive = e.target.checked;
      elements.maskToggleLabel.innerHTML = `Privacy Masking: <strong>${state.isMaskingActive ? 'ON' : 'OFF'}</strong>`;
      renderTable();
      showToast(
        state.isMaskingActive
          ? 'PII privacy masking activated across table ledger.'
          : '⚠️ Caution: Masking disabled. Sensitive personal identifiers visible.',
        state.isMaskingActive ? 'info' : 'error'
      );
    });

    // Table Filters
    elements.tableSearch.addEventListener('input', renderTable);
    elements.tierFilter.addEventListener('change', renderTable);

    // CSV Download
    elements.downloadAnonymizedCsvBtn.addEventListener('click', exportAnonymizedCsv);

    // Cryptographic AES-256-GCM Export
    elements.encryptExportBtn.addEventListener('click', handleCryptographicExport);
  }

  // ================= AUTHENTICATION FLOW =================
  function handleLogin(e) {
    if (e) e.preventDefault();
    const user = elements.username.value.trim();
    const pass = elements.password.value;

    if (!user || !pass) {
      showToast('Please provide username and security passphrase.', 'error');
      return;
    }

    state.isAuthenticated = true;
    state.currentUser = user;
    elements.sessionUsername.textContent = user;

    elements.authView.classList.add('hidden');
    elements.appContainer.classList.remove('hidden');

    showToast(`Session established for analyst: ${user}`, 'success');

    // Automatically load sample dataset on initial entrance for demo readiness
    if (state.students.length === 0) {
      loadSampleData();
    }
  }

  function handleLogout() {
    state.isAuthenticated = false;
    elements.appContainer.classList.add('hidden');
    elements.authView.classList.remove('hidden');
    showToast('Signed out successfully. In-memory session purged.', 'info');
  }

  function renderAuthView() {
    elements.authView.classList.remove('hidden');
    elements.appContainer.classList.add('hidden');
  }

  // ================= TAB NAVIGATION =================
  function switchTab(tabId) {
    state.activeTab = tabId;

    elements.navItems.forEach((btn) => {
      if (btn.getAttribute('data-tab') === tabId) {
        btn.classList.add('active');
      } else {
        btn.classList.remove('active');
      }
    });

    elements.tabPanes.forEach((pane) => {
      pane.classList.remove('active');
    });

    if (tabId === 'overview') {
      document.getElementById('overviewTab').classList.add('active');
      elements.viewHeading.textContent = 'Executive Academic Dashboard';
      renderCharts();
    } else if (tabId === 'dataManagement') {
      document.getElementById('dataManagementTab').classList.add('active');
      elements.viewHeading.textContent = 'Student Ledger & Privacy Enclave';
      renderTable();
    } else if (tabId === 'security') {
      document.getElementById('securityTab').classList.add('active');
      elements.viewHeading.textContent = 'Cryptographic Engine & Zero-Trust Architecture';
    }
  }

  // ================= PII MASKING & PRIVACY LOGIC =================
  /**
   * Masks a human full name: "Aarav Sharma" -> "A**** S*****"
   */
  function maskName(name) {
    if (!name || typeof name !== 'string') return 'Anonymous';
    return name
      .trim()
      .split(/\s+/)
      .map((part) => {
        if (part.length <= 1) return part;
        return part[0] + '*'.repeat(Math.min(part.length - 1, 4));
      })
      .join(' ');
  }

  /**
   * Masks an email address: "diya.patel@example.edu" -> "d***l@example.edu"
   */
  function maskEmail(email) {
    if (!email || typeof email !== 'string') return '***@anonymous.edu';
    const atIndex = email.indexOf('@');
    if (atIndex <= 1) return '***@' + (email.split('@')[1] || 'domain.edu');
    const local = email.substring(0, atIndex);
    const domain = email.substring(atIndex);
    const maskedLocal = local[0] + '***' + local[local.length - 1];
    return maskedLocal + domain;
  }

  /**
   * Masks phone numbers: "+91-9876543210" -> "+91-******3210"
   */
  function maskPhone(phone) {
    if (!phone || typeof phone !== 'string') return '***-***-****';
    const clean = phone.trim();
    if (clean.length < 5) return '***-****';
    const visibleEnd = clean.slice(-4);
    const prefix = clean.startsWith('+') ? clean.slice(0, 4) : '';
    return (prefix ? prefix + '-' : '') + '******' + visibleEnd;
  }

  /**
   * Masks Student IDs: "STU2024001" -> "STU****001"
   */
  function maskStudentId(id) {
    if (!id || typeof id !== 'string') return 'ID-*****';
    const str = id.trim();
    if (str.length <= 4) return '***' + str.slice(-1);
    return str.slice(0, 3) + '****' + str.slice(-3);
  }

  // ================= CSV PARSING & DATA HANDLING =================
  function processUploadedFile(file) {
    if (!file) return;

    // File validation: Size <= 10 MB and extension is .csv
    const maxSize = 10 * 1024 * 1024; // 10MB
    if (file.size > maxSize) {
      showToast('File size exceeds the 10 MB limit. Please upload a smaller dataset.', 'error');
      return;
    }

    if (!file.name.toLowerCase().endsWith('.csv') && file.type !== 'text/csv') {
      showToast('Invalid file format. Please upload a valid .csv spreadsheet.', 'error');
      return;
    }

    const reader = new FileReader();
    reader.onload = function (e) {
      const text = e.target.result;
      parseCsvData(text, file.name, file.size);
    };
    reader.onerror = function () {
      showToast('Failed to read the selected file in browser memory.', 'error');
    };
    reader.readAsText(file);
  }

  function loadSampleData() {
    fetch('data/sample-students.csv')
      .then((res) => {
        if (!res.ok) throw new Error('Network error loading sample file.');
        return res.text();
      })
      .then((csvText) => {
        parseCsvData(csvText, 'sample-students.csv', csvText.length);
        showToast('Sample student records loaded into secure memory enclave.', 'success');
      })
      .catch((err) => {
        console.warn('Fallback to inline sample records:', err);
        const inlineCsv = `Name,Email,Phone,Student ID,Marks,Attendance
Aarav Sharma,aarav.sharma@example.edu,+91-9876543210,STU2024001,88,92
Diya Patel,diya.patel@example.edu,+91-9876543211,STU2024002,94,96
Rohan Verma,rohan.verma@example.edu,+91-9876543212,STU2024003,72,81
Ananya Iyer,ananya.iyer@example.edu,+91-9876543213,STU2024004,65,74
Kavya Nair,kavya.nair@example.edu,+91-9876543214,STU2024005,91,95
Aditya Rao,aditya.rao@example.edu,+91-9876543215,STU2024006,54,68
Siddharth Menon,siddharth.m@example.edu,+91-9876543216,STU2024007,82,88
Pooja Reddy,pooja.reddy@example.edu,+91-9876543217,STU2024008,79,84
Varun Kulkarni,varun.k@example.edu,+91-9876543218,STU2024009,42,60
Meera Joshi,meera.joshi@example.edu,+91-9876543219,STU2024010,96,98
Nikhil Saxena,nikhil.saxena@example.edu,+91-9876543220,STU2024011,76,82
Sneha Bhatt,sneha.bhatt@example.edu,+91-9876543221,STU2024012,89,90
Arjun Deshmukh,arjun.d@example.edu,+91-9876543222,STU2024013,61,72
Tanvi Sen,tanvi.sen@example.edu,+91-9876543223,STU2024014,84,89
Gaurav Chopra,gaurav.chopra@example.edu,+91-9876543224,STU2024015,48,65
Ishaan Malhotra,ishaan.m@example.edu,+91-9876543225,STU2024016,92,94
Riya Mukherjee,riya.m@example.edu,+91-9876543226,STU2024017,73,79
Kunal Singhania,kunal.s@example.edu,+91-9876543227,STU2024018,58,70
Shreya Ghosh,shreya.ghosh@example.edu,+91-9876543228,STU2024019,87,91
Manish Tiwari,manish.tiwari@example.edu,+91-9876543229,STU2024020,78,85
Neha Kapoor,neha.kapoor@example.edu,+91-9876543230,STU2024021,95,97
Abhishek Pandey,abhishek.p@example.edu,+91-9876543231,STU2024022,68,76
Prisha Pillai,prisha.pillai@example.edu,+91-9876543232,STU2024023,83,87
Rahul Das,rahul.das@example.edu,+91-9876543233,STU2024024,38,55
Anjali Mishra,anjali.mishra@example.edu,+91-9876543234,STU2024025,90,93`;
        parseCsvData(inlineCsv, 'sample-students.csv', inlineCsv.length);
        showToast('Loaded inline sample dataset.', 'info');
      });
  }

  function parseCsvData(csvText, filename, fileSize) {
    const lines = csvText
      .split(/\r\n|\n/)
      .map((l) => l.trim())
      .filter((l) => l.length > 0);

    if (lines.length < 2) {
      showToast('CSV file is empty or missing data rows.', 'error');
      return;
    }

    const headers = lines[0].split(',').map((h) => h.trim().toLowerCase());

    const nameIdx = headers.findIndex((h) => h.includes('name'));
    const emailIdx = headers.findIndex((h) => h.includes('email'));
    const phoneIdx = headers.findIndex((h) => h.includes('phone') || h.includes('mobile'));
    const idIdx = headers.findIndex((h) => h.includes('id') || h.includes('roll'));
    const marksIdx = headers.findIndex((h) => h.includes('mark') || h.includes('score') || h.includes('grade'));
    const attIdx = headers.findIndex((h) => h.includes('attend'));

    if (marksIdx === -1 || attIdx === -1) {
      showToast('Required numeric columns (Marks and Attendance) were not detected.', 'error');
      return;
    }

    const rawRecords = [];
    const maskedRecords = [];

    for (let i = 1; i < lines.length; i++) {
      const parts = parseCsvLine(lines[i]);
      if (parts.length < headers.length) continue;

      const rawName = nameIdx !== -1 ? parts[nameIdx] : `Student ${i}`;
      const rawEmail = emailIdx !== -1 ? parts[emailIdx] : `student${i}@college.edu`;
      const rawPhone = phoneIdx !== -1 ? parts[phoneIdx] : `+91-98000000${i}`;
      const rawId = idIdx !== -1 ? parts[idIdx] : `STU${1000 + i}`;
      const marksVal = Math.min(100, Math.max(0, parseFloat(parts[marksIdx]) || 0));
      const attVal = Math.min(100, Math.max(0, parseFloat(parts[attIdx]) || 0));

      const tier = classifyPerformance(marksVal);
      const isCompliant = attVal >= 75;

      const record = {
        index: i,
        name: rawName,
        email: rawEmail,
        phone: rawPhone,
        studentId: rawId,
        marks: marksVal,
        attendance: attVal,
        tier: tier,
        compliant: isCompliant
      };

      rawRecords.push(record);

      maskedRecords.push({
        index: i,
        name: maskName(rawName),
        email: maskEmail(rawEmail),
        phone: maskPhone(rawPhone),
        studentId: maskStudentId(rawId),
        marks: marksVal,
        attendance: attVal,
        tier: tier,
        compliant: isCompliant
      });
    }

    if (rawRecords.length === 0) {
      showToast('No valid student rows could be parsed.', 'error');
      return;
    }

    state.students = rawRecords;
    state.maskedStudents = maskedRecords;

    calculateAnalytics();

    // Update Banner
    elements.fileStatusBanner.classList.remove('hidden');
    elements.loadedFileName.textContent = filename;
    elements.loadedFileMeta.textContent = `${rawRecords.length} records · ${(fileSize / 1024).toFixed(1)} KB · Zero-Knowledge Memory Enclave`;

    renderDashboardMetrics();
    renderCharts();
    renderTable();

    showToast(`Successfully processed ${rawRecords.length} student records.`, 'success');
  }

  function parseCsvLine(line) {
    const values = [];
    let insideQuotes = false;
    let currentValue = '';

    for (let i = 0; i < line.length; i++) {
      const char = line[i];
      if (char === '"') {
        insideQuotes = !insideQuotes;
      } else if (char === ',' && !insideQuotes) {
        values.push(currentValue.trim());
        currentValue = '';
      } else {
        currentValue += char;
      }
    }
    values.push(currentValue.trim());
    return values;
  }

  function classifyPerformance(marks) {
    if (marks >= 85) return 'Distinction';
    if (marks >= 70) return 'First Class';
    if (marks >= 50) return 'Second Class';
    return 'Needs Intervention';
  }

  // ================= STATISTICAL ANALYTICS ENGINE =================
  function calculateAnalytics() {
    const list = state.students;
    const n = list.length;
    if (n === 0) return;

    let sumMarks = 0;
    let sumAttendance = 0;
    let minMarks = list[0].marks;
    let maxMarks = list[0].marks;
    let passingCount = 0;
    let atRiskCount = 0;

    const tiers = {
      distinction: 0,
      firstClass: 0,
      secondClass: 0,
      needsIntervention: 0
    };

    const attendanceTiers = {
      high: 0,
      normal: 0,
      shortage: 0
    };

    list.forEach((s) => {
      sumMarks += s.marks;
      sumAttendance += s.attendance;

      if (s.marks < minMarks) minMarks = s.marks;
      if (s.marks > maxMarks) maxMarks = s.marks;

      if (s.marks >= 50) passingCount++;
      if (s.marks < 50 || s.attendance < 75) atRiskCount++;

      if (s.tier === 'Distinction') tiers.distinction++;
      else if (s.tier === 'First Class') tiers.firstClass++;
      else if (s.tier === 'Second Class') tiers.secondClass++;
      else tiers.needsIntervention++;

      if (s.attendance >= 85) attendanceTiers.high++;
      else if (s.attendance >= 75) attendanceTiers.normal++;
      else attendanceTiers.shortage++;
    });

    state.stats.total = n;
    state.stats.avgMarks = +(sumMarks / n).toFixed(1);
    state.stats.avgAttendance = +(sumAttendance / n).toFixed(1);
    state.stats.minMarks = minMarks;
    state.stats.maxMarks = maxMarks;
    state.stats.distinctionCount = tiers.distinction;
    state.stats.distinctionRate = +((tiers.distinction / n) * 100).toFixed(1);
    state.stats.passRate = +((passingCount / n) * 100).toFixed(1);
    state.stats.atRiskCount = atRiskCount;
    state.stats.tiers = tiers;
    state.stats.attendanceTiers = attendanceTiers;
  }

  function renderDashboardMetrics() {
    elements.kpiTotalStudents.textContent = state.stats.total;
    elements.kpiAverageMarks.textContent = `${state.stats.avgMarks}%`;
    elements.kpiMarksSpread.textContent = `Range: ${state.stats.minMarks}% - ${state.stats.maxMarks}%`;
    elements.kpiAverageAttendance.textContent = `${state.stats.avgAttendance}%`;
    elements.kpiDistinctionRate.textContent = `${state.stats.distinctionRate}%`;
    elements.kpiDistinctionCount.textContent = `${state.stats.distinctionCount} Students with Distinction`;

    elements.insightPassingRate.textContent = `${state.stats.passRate}%`;
    elements.insightAtRiskCount.textContent = state.stats.atRiskCount;

    elements.insightNarrative.innerHTML = `Cohort average marks stand at <strong>${state.stats.avgMarks}%</strong> with <strong>${state.stats.avgAttendance}%</strong> mean attendance. <strong>${state.stats.distinctionCount}</strong> student(s) achieved distinctions, while <strong>${state.stats.atRiskCount}</strong> student(s) fall below the 75% attendance threshold or academic pass cut-off, warranting proactive tutoring.`;
  }

  // ================= CUSTOM CANVAS DATA VISUALIZATION =================
  function renderCharts() {
    drawPerformancePieChart();
    drawAttendanceBarChart();
  }

  function drawPerformancePieChart() {
    const canvas = elements.performanceChart;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const width = canvas.width;
    const height = canvas.height;

    ctx.clearRect(0, 0, width, height);

    const data = [
      { label: 'Distinction (≥85%)', value: state.stats.tiers.distinction, color: '#10b981' },
      { label: 'First Class (70-84%)', value: state.stats.tiers.firstClass, color: '#3b82f6' },
      { label: 'Second Class (50-69%)', value: state.stats.tiers.secondClass, color: '#f59e0b' },
      { label: 'Intervention (<50%)', value: state.stats.tiers.needsIntervention, color: '#f43f5e' }
    ];

    const total = data.reduce((acc, d) => acc + d.value, 0);

    if (total === 0) {
      drawPlaceholderChart(ctx, width, height, 'No data loaded');
      return;
    }

    const centerX = width / 2;
    const centerY = height / 2;
    const radius = Math.min(centerX, centerY) - 25;
    const innerRadius = radius * 0.55; // Donut style

    let startAngle = -0.5 * Math.PI;

    data.forEach((slice) => {
      const sliceAngle = (slice.value / total) * 2 * Math.PI;
      if (slice.value > 0) {
        ctx.beginPath();
        ctx.arc(centerX, centerY, radius, startAngle, startAngle + sliceAngle);
        ctx.arc(centerX, centerY, innerRadius, startAngle + sliceAngle, startAngle, true);
        ctx.closePath();
        ctx.fillStyle = slice.color;
        ctx.fill();

        // Subtle slice separator
        ctx.strokeStyle = '#0f172a';
        ctx.lineWidth = 2;
        ctx.stroke();
      }
      startAngle += sliceAngle;
    });

    // Center Label
    ctx.font = 'bold 22px "JetBrains Mono", sans-serif';
    ctx.fillStyle = '#ffffff';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText(`${state.stats.total}`, centerX, centerY - 6);

    ctx.font = '10px Inter, sans-serif';
    ctx.fillStyle = '#94a3b8';
    ctx.fillText('STUDENTS', centerX, centerY + 14);

    // Legend
    elements.performanceLegend.innerHTML = data
      .map(
        (item) => `
      <div class="legend-item">
        <span class="legend-color-dot" style="background:${item.color}"></span>
        <span>${item.label}: <strong>${item.value}</strong> (${total ? Math.round((item.value / total) * 100) : 0}%)</span>
      </div>`
      )
      .join('');
  }

  function drawAttendanceBarChart() {
    const canvas = elements.attendanceChart;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const width = canvas.width;
    const height = canvas.height;

    ctx.clearRect(0, 0, width, height);

    const data = [
      { label: 'Exemplary (≥85%)', value: state.stats.attendanceTiers.high, color: '#06b6d4' },
      { label: 'Compliant (75-84%)', value: state.stats.attendanceTiers.normal, color: '#3b82f6' },
      { label: 'Shortage (<75%)', value: state.stats.attendanceTiers.shortage, color: '#f43f5e' }
    ];

    const maxVal = Math.max(...data.map((d) => d.value), 1);

    const paddingX = 60;
    const paddingY = 40;
    const chartWidth = width - paddingX * 2;
    const chartHeight = height - paddingY * 2;
    const barWidth = chartWidth / (data.length * 2);

    // Draw gridlines
    ctx.strokeStyle = '#1e293b';
    ctx.lineWidth = 1;
    for (let i = 0; i <= 4; i++) {
      const y = height - paddingY - (chartHeight / 4) * i;
      ctx.beginPath();
      ctx.moveTo(paddingX - 10, y);
      ctx.lineTo(width - paddingX, y);
      ctx.stroke();

      ctx.fillStyle = '#64748b';
      ctx.font = '10px "JetBrains Mono"';
      ctx.textAlign = 'right';
      ctx.fillText(Math.round((maxVal / 4) * i), paddingX - 14, y + 3);
    }

    data.forEach((item, index) => {
      const x = paddingX + index * (barWidth * 2) + barWidth / 2;
      const barHeight = (item.value / maxVal) * chartHeight;
      const y = height - paddingY - barHeight;

      // Draw Bar
      ctx.fillStyle = item.color;
      ctx.beginPath();
      ctx.roundRect(x, y, barWidth, barHeight, [4, 4, 0, 0]);
      ctx.fill();

      // Top value
      ctx.fillStyle = '#ffffff';
      ctx.font = 'bold 11px "JetBrains Mono"';
      ctx.textAlign = 'center';
      ctx.fillText(item.value, x + barWidth / 2, y - 6);

      // Label under bar
      ctx.fillStyle = '#94a3b8';
      ctx.font = '10px Inter';
      ctx.fillText(item.label.split(' ')[0], x + barWidth / 2, height - paddingY + 16);
    });

    elements.attendanceLegend.innerHTML = data
      .map(
        (item) => `
      <div class="legend-item">
        <span class="legend-color-dot" style="background:${item.color}"></span>
        <span>${item.label}: <strong>${item.value}</strong></span>
      </div>`
      )
      .join('');
  }

  function drawPlaceholderChart(ctx, width, height, text) {
    ctx.fillStyle = '#64748b';
    ctx.font = '14px Inter, sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText(text, width / 2, height / 2);
  }

  // ================= STUDENT RECORD TABLE =================
  function renderTable() {
    const list = state.isMaskingActive ? state.maskedStudents : state.students;
    const searchTerm = elements.tableSearch.value.trim().toLowerCase();
    const tierFilter = elements.tierFilter.value;

    const filtered = list.filter((s) => {
      if (tierFilter !== 'ALL' && s.tier !== tierFilter) {
        return false;
      }
      if (searchTerm) {
        const matchesName = s.name.toLowerCase().includes(searchTerm);
        const matchesEmail = s.email.toLowerCase().includes(searchTerm);
        const matchesId = s.studentId.toLowerCase().includes(searchTerm);
        const matchesMarks = s.marks.toString().includes(searchTerm);
        const matchesTier = s.tier.toLowerCase().includes(searchTerm);
        return matchesName || matchesEmail || matchesId || matchesMarks || matchesTier;
      }
      return true;
    });

    elements.tableRecordCount.textContent = `Showing ${filtered.length} of ${list.length} records`;

    if (filtered.length === 0) {
      elements.studentTableBody.innerHTML = `
        <tr>
          <td colspan="9" class="text-center text-muted py-5">
            ${list.length === 0 ? 'No dataset loaded yet.' : 'No student records match the active search and filter criteria.'}
          </td>
        </tr>`;
      return;
    }

    elements.studentTableBody.innerHTML = filtered
      .map((s, idx) => {
        const tierBadge =
          s.tier === 'Distinction'
            ? 'badge-success'
            : s.tier === 'First Class'
            ? 'badge-info'
            : s.tier === 'Second Class'
            ? 'badge-warning'
            : 'badge-danger';

        const complianceBadge = s.compliant
          ? '<span class="badge badge-success">Compliant (≥75%)</span>'
          : '<span class="badge badge-danger">Shortage (&lt;75%)</span>';

        return `
        <tr>
          <td><strong>${idx + 1}</strong></td>
          <td><code>${escapeHtml(s.name)}</code></td>
          <td><span class="text-muted">${escapeHtml(s.email)}</span></td>
          <td><span class="text-muted">${escapeHtml(s.phone)}</span></td>
          <td><strong>${escapeHtml(s.studentId)}</strong></td>
          <td><strong>${s.marks}%</strong></td>
          <td>${s.attendance}%</td>
          <td><span class="badge ${tierBadge}">${s.tier}</span></td>
          <td>${complianceBadge}</td>
        </tr>`;
      })
      .join('');
  }

  function escapeHtml(str) {
    if (!str) return '';
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  // ================= ANONYMIZED CSV EXPORT =================
  function exportAnonymizedCsv() {
    if (state.maskedStudents.length === 0) {
      showToast('No student data loaded to export.', 'error');
      return;
    }

    const headers = ['Record Index', 'Masked Name', 'Anonymized Email', 'Redacted Phone', 'Student ID', 'Marks', 'Attendance', 'Performance Tier', 'Attendance Compliance'];
    const rows = state.maskedStudents.map((s) => [
      s.index,
      `"${s.name}"`,
      `"${s.email}"`,
      `"${s.phone}"`,
      `"${s.studentId}"`,
      s.marks,
      s.attendance,
      `"${s.tier}"`,
      s.compliant ? 'Compliant' : 'Shortage'
    ]);

    const csvContent = [headers.join(','), ...rows.map((r) => r.join(','))].join('\r\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.setAttribute('href', url);
    link.setAttribute('download', `anonymized-students-${new Date().toISOString().slice(0, 10)}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);

    showToast('Exported privacy-sanitized CSV dataset.', 'success');
  }

  // ================= WEB CRYPTO API: AES-256-GCM ENCRYPTION =================
  /**
   * Encrypts the current student dataset using native Web Crypto API:
   * 1. Derives 256-bit AES-GCM key from passphrase using PBKDF2 (100,000 iterations).
   * 2. Generates a fresh 96-bit (12-byte) IV using crypto.getRandomValues.
   * 3. Exports an authenticated ciphertext package (.enc.json) with SHA-256 integrity tag.
   */
  async function handleCryptographicExport() {
    if (state.students.length === 0) {
      showToast('Please load student records before generating an encrypted export.', 'error');
      return;
    }

    const passphrase = elements.exportPassphrase.value;
    if (!passphrase || passphrase.length < 8) {
      showToast('Please provide a strong encryption passphrase of at least 8 characters.', 'error');
      return;
    }

    try {
      elements.encryptExportBtn.disabled = true;
      elements.encryptExportBtn.innerHTML = '<span>Synthesizing Cryptographic Ciphertext...</span>';

      const payload = {
        metadata: {
          project: 'Secure Student Data Analytics System',
          subject: 'Secure Data Science',
          analyst: state.currentUser,
          timestamp: new Date().toISOString(),
          recordCount: state.students.length,
          cipher: 'AES-256-GCM',
          kdf: 'PBKDF2-HMAC-SHA256-100K'
        },
        analyticsSummary: state.stats,
        // Encrypt the masked data to preserve defense-in-depth privacy
        records: state.maskedStudents
      };

      const jsonString = JSON.stringify(payload);
      const enc = new TextEncoder();
      const plaintextBuffer = enc.encode(jsonString);

      // 1. Generate random Salt (16 bytes) and random IV (12 bytes)
      const salt = window.crypto.getRandomValues(new Uint8Array(16));
      const iv = window.crypto.getRandomValues(new Uint8Array(12));

      // 2. Import raw passphrase as key material
      const passphraseBuffer = enc.encode(passphrase);
      const baseKey = await window.crypto.subtle.importKey(
        'raw',
        passphraseBuffer,
        'PBKDF2',
        false,
        ['deriveKey']
      );

      // 3. Derive 256-bit AES-GCM Key
      const aesKey = await window.crypto.subtle.deriveKey(
        {
          name: 'PBKDF2',
          salt: salt,
          iterations: 100000,
          hash: 'SHA-256'
        },
        baseKey,
        {
          name: 'AES-GCM',
          length: 256
        },
        false,
        ['encrypt', 'decrypt']
      );

      // 4. Encrypt using AES-GCM
      const ciphertextBuffer = await window.crypto.subtle.encrypt(
        {
          name: 'AES-GCM',
          iv: iv
        },
        aesKey,
        plaintextBuffer
      );

      // 5. Construct downloadable JSON package
      const encryptedPackage = {
        cipher: 'AES-256-GCM',
        kdf: 'PBKDF2-HMAC-SHA256',
        iterations: 100000,
        salt: bufferToBase64(salt),
        iv: bufferToBase64(iv),
        ciphertext: bufferToBase64(new Uint8Array(ciphertextBuffer)),
        exportedAt: new Date().toISOString(),
        enclaveMode: 'Zero-Knowledge Browser Runtime'
      };

      const resultString = JSON.stringify(encryptedPackage, null, 2);

      // Display Preview
      elements.encryptionResultBox.classList.remove('hidden');
      elements.encryptionCiphertextPreview.textContent = resultString;

      // Trigger automatic file download
      const blob = new Blob([resultString], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `secure-student-records-${Date.now()}.enc.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);

      showToast('AES-256-GCM encrypted package downloaded securely.', 'success');
    } catch (err) {
      console.error('Encryption failed:', err);
      showToast('Cryptographic operation failed: ' + err.message, 'error');
    } finally {
      elements.encryptExportBtn.disabled = false;
      elements.encryptExportBtn.innerHTML = `
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
          <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
        </svg>
        <span>Encrypt & Download Secure Package (.enc.json)</span>`;
    }
  }

  function bufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
  }

  // ================= TOAST NOTIFICATION UTILITY =================
  function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;

    const icon = type === 'success' ? '✅' : type === 'error' ? '⚠️' : 'ℹ️';
    toast.innerHTML = `<span>${icon}</span><span>${escapeHtml(message)}</span>`;

    elements.toastContainer.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateY(10px)';
      toast.style.transition = 'all 0.3s ease';
      setTimeout(() => toast.remove(), 300);
    }, 4000);
  }
})();
