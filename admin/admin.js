(() => {
  "use strict";

  const API_BASE = "";

  const $ = (selector, root = document) =>
    root.querySelector(selector);

  const $$ = (selector, root = document) =>
    [...root.querySelectorAll(selector)];

  async function api(url, options = {}) {
    const config = {
      credentials: "include",
      headers: {
        "Content-Type": "application/json",
        ...(options.headers || {})
      },
      ...options
    };

    if (
      config.body &&
      typeof config.body !== "string"
    ) {
      config.body = JSON.stringify(config.body);
    }

    const response = await fetch(
      `${API_BASE}${url}`,
      config
    );

    let data = {};

    try {
      data = await response.json();
    } catch {
      data = {};
    }

    if (!response.ok || data.success === false) {
      throw new Error(
        data.message ||
        `Request failed (${response.status})`
      );
    }

    return data;
  }

  function escapeHtml(value) {
    return String(value ?? "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#039;");
  }

  function formatMoney(paise) {
    const amount = Number(paise || 0) / 100;

    return `₹${amount.toLocaleString("en-IN", {
      minimumFractionDigits: 2,
      maximumFractionDigits: 2
    })}`;
  }

  function formatDate(value) {
    if (!value) return "-";

    const date = new Date(value);

    if (Number.isNaN(date.getTime())) {
      return "-";
    }

    return date.toLocaleString("en-IN", {
      dateStyle: "medium",
      timeStyle: "short"
    });
  }

  function showToast(message, type = "info") {
    let box = $("#nove-toast-container");

    if (!box) {
      box = document.createElement("div");
      box.id = "nove-toast-container";

      Object.assign(box.style, {
        position: "fixed",
        right: "20px",
        bottom: "20px",
        zIndex: "99999",
        display: "flex",
        flexDirection: "column",
        gap: "10px",
        maxWidth: "360px"
      });

      document.body.appendChild(box);
    }

    const toast = document.createElement("div");

    toast.textContent = message;

    Object.assign(toast.style, {
      padding: "14px 18px",
      borderRadius: "12px",
      background:
        type === "error"
          ? "#3b0d12"
          : type === "success"
          ? "#0d3b25"
          : "#171717",
      color: "#fff",
      border:
        type === "error"
          ? "1px solid #ff3b4d"
          : type === "success"
          ? "1px solid #22c55e"
          : "1px solid #333",
      boxShadow: "0 12px 30px rgba(0,0,0,.35)",
      fontSize: "14px",
      lineHeight: "1.4"
    });

    box.appendChild(toast);

    setTimeout(() => {
      toast.remove();
    }, 3500);
  }

  async function adminLogin(event) {
    if (event) {
      event.preventDefault();
    }

    const username =
      $("#adminUsername")?.value?.trim() ||
      $("#username")?.value?.trim() ||
      "";

    const password =
      $("#adminPassword")?.value ||
      $("#password")?.value ||
      "";

    if (!username || !password) {
      showToast(
        "Username and password required.",
        "error"
      );
      return false;
    }

    const button =
      $("#adminLoginButton") ||
      $("#loginButton") ||
      document.querySelector(
        'button[type="submit"]'
      );

    const oldText = button?.textContent;

    try {
      if (button) {
        button.disabled = true;
        button.textContent = "Signing in...";
      }

      await api("/api/admin/login", {
        method: "POST",
        body: {
          username,
          password
        }
      });

      showToast(
        "Admin login successful.",
        "success"
      );

      setTimeout(() => {
        window.location.href =
          "/admin-dashboard.html";
      }, 500);

    } catch (error) {
      showToast(
        error.message ||
        "Admin login failed.",
        "error"
      );

      if (button) {
        button.disabled = false;
        button.textContent =
          oldText || "Login";
      }

      return false;
    }
  }

  async function checkAdmin() {
    try {
      const result =
        await api("/api/admin/me");

      return Boolean(
        result.success !== false
      );
    } catch {
      return false;
    }
  }

  async function adminLogout() {
    try {
      await api("/api/admin/logout", {
        method: "POST"
      });
    } catch {}

    window.location.href =
      "/admin.html";
  }

  async function loadDashboardSummary() {
    try {
      const result =
        await api("/api/admin/summary");

      const data =
        result.data ||
        result.summary ||
        result;

      const values = {
        totalUsers:
          data.totalUsers ??
          data.users ??
          0,

        totalBalance:
          data.totalBalance ??
          data.balance ??
          0,

        totalDeposits:
          data.totalDeposits ??
          data.deposits ??
          0,

        pendingWithdrawals:
          data.pendingWithdrawals ??
          data.pending_withdrawals ??
          0
      };

      setText(
        [
          "#totalUsers",
          "#statTotalUsers",
          "[data-stat='users']"
        ],
        values.totalUsers
      );

      setText(
        [
          "#totalBalance",
          "#statTotalBalance",
          "[data-stat='balance']"
        ],
        formatMoney(values.totalBalance)
      );

      setText(
        [
          "#totalDeposits",
          "#statTotalDeposits",
          "[data-stat='deposits']"
        ],
        formatMoney(values.totalDeposits)
      );

      setText(
        [
          "#pendingWithdrawals",
          "#statPendingWithdrawals",
          "[data-stat='pending-withdrawals']"
        ],
        values.pendingWithdrawals
      );

      return result;

    } catch (error) {
      console.error(
        "Summary error:",
        error
      );
    }
  }

  function setText(selectors, value) {
    const list =
      Array.isArray(selectors)
        ? selectors
        : [selectors];

    for (const selector of list) {
      const elements =
        $$(selector);

      for (const element of elements) {
        element.textContent =
          String(value);
      }
    }
  }

  async function loadAdminUsers() {
    try {
      const result =
        await api("/api/admin/users");

      const users =
        result.users ||
        result.data ||
        [];

      renderUsers(users);

      return users;

    } catch (error) {
      console.error(
        "Users error:",
        error
      );

      showToast(
        error.message ||
        "Unable to load users.",
        "error"
      );

      return [];
    }
  }

  function renderUsers(users) {
    const table =
      $("#usersTableBody") ||
      $("#adminUsersTableBody") ||
      document.querySelector(
        "[data-users-table]"
      );

    if (!table) return;

    if (!users.length) {
      table.innerHTML = `
        <tr>
          <td colspan="10" style="text-align:center;padding:30px;">
            No users found.
          </td>
        </tr>
      `;
      return;
    }

    table.innerHTML =
      users.map(user => {
        const id =
          user._id ||
          user.id ||
          "";

        const banned =
          Boolean(user.banned);

        return `
          <tr>
            <td>
              ${escapeHtml(
                user.name || "-"
              )}
            </td>

            <td>
              ${escapeHtml(
                user.phone || "-"
              )}
            </td>

            <td>
              ${escapeHtml(
                user.referral_code || "-"
              )}
            </td>

            <td>
              ${formatMoney(
                user.balance ??
                user.wallet_balance ??
                0
              )}
            </td>

            <td>
              <span class="badge ${
                banned
                  ? "badge-danger"
                  : "badge-success"
              }">
                ${
                  banned
                    ? "Banned"
                    : "Active"
                }
              </span>
            </td>

            <td>
              ${formatDate(
                user.created_at ||
                user.createdAt
              )}
            </td>

            <td>
              <div class="admin-actions">
                ${
                  banned
                    ? `
                      <button
                        type="button"
                        onclick="NOVE_ADMIN.unbanUser('${id}')"
                      >
                        Unban
                      </button>
                    `
                    : `
                      <button
                        type="button"
                        onclick="NOVE_ADMIN.banUser('${id}')"
                      >
                        Ban
                      </button>
                    `
                }

                <button
                  type="button"
                  onclick="NOVE_ADMIN.loginAsUser('${id}')"
                >
                  Login
                </button>

                <button
                  type="button"
                  onclick="NOVE_ADMIN.adjustUserBalance('${id}')"
                >
                  Balance
                </button>
              </div>
            </td>
          </tr>
        `;
      }).join("");
  }

  async function banUser(id) {
    if (!id) return;

    if (!confirm(
      "Are you sure you want to ban this user?"
    )) {
      return;
    }

    try {
      await api(
        `/api/admin/users/${encodeURIComponent(id)}/ban`,
        {
          method: "POST"
        }
      );

      showToast(
        "User banned successfully.",
        "success"
      );

      await loadAdminUsers();

    } catch (error) {
      showToast(
        error.message ||
        "Unable to ban user.",
        "error"
      );
    }
  }

  async function unbanUser(id) {
    if (!id) return;

    try {
      await api(
        `/api/admin/users/${encodeURIComponent(id)}/unban`,
        {
          method: "POST"
        }
      );

      showToast(
        "User unbanned successfully.",
        "success"
      );

      await loadAdminUsers();

    } catch (error) {
      showToast(
        error.message ||
        "Unable to unban user.",
        "error"
      );
    }
  }

  async function loginAsUser(id) {
    if (!id) return;

    try {
      const result =
        await api(
          `/api/admin/users/${encodeURIComponent(id)}/login-as`,
          {
            method: "POST"
          }
        );

      if (
        result.redirect ||
        result.url
      ) {
        window.location.href =
          result.redirect ||
          result.url;
        return;
      }

      showToast(
        result.message ||
        "Login session created.",
        "success"
      );

    } catch (error) {
      showToast(
        error.message ||
        "Unable to login as user.",
        "error"
      );
    }
  }

  async function adjustUserBalance(id) {
    if (!id) return;

    const amount =
      prompt(
        "Enter balance adjustment in ₹.\nUse positive value to add and negative value to deduct."
      );

    if (
      amount === null ||
      amount.trim() === ""
    ) {
      return;
    }

    const value =
      Number(amount);

    if (
      !Number.isFinite(value) ||
      value === 0
    ) {
      showToast(
        "Enter a valid non-zero amount.",
        "error"
      );
      return;
    }

    const reason =
      prompt(
        "Reason for balance adjustment:",
        "Admin adjustment"
      ) || "Admin adjustment";

    try {
      await api(
        `/api/admin/users/${encodeURIComponent(id)}/balance`,
        {
          method: "POST",
          body: {
            amount: Math.round(value * 100),
            reason
          }
        }
      );

      showToast(
        "Balance updated successfully.",
        "success"
      );

      await loadAdminUsers();
      await loadDashboardSummary();

    } catch (error) {
      showToast(
        error.message ||
        "Unable to update balance.",
        "error"
      );
    }
  }

  async function loadAdminWithdrawals() {
    try {
      const result =
        await api("/api/admin/withdrawals");

      const withdrawals =
        result.withdrawals ||
        result.data ||
        [];

      renderWithdrawals(
        withdrawals
      );

      return withdrawals;

    } catch (error) {
      console.error(
        "Withdrawals error:",
        error
      );

      showToast(
        error.message ||
        "Unable to load withdrawals.",
        "error"
      );

      return [];
    }
  }

  function renderWithdrawals(
    withdrawals
  ) {
    const table =
      $("#withdrawalsTableBody") ||
      $("#adminWithdrawalsTableBody") ||
      document.querySelector(
        "[data-withdrawals-table]"
      );

    if (!table) return;

    if (!withdrawals.length) {
      table.innerHTML = `
        <tr>
          <td colspan="10" style="text-align:center;padding:30px;">
            No withdrawal requests found.
          </td>
        </tr>
      `;
      return;
    }

    table.innerHTML =
      withdrawals.map(item => {
        const id =
          item._id ||
          item.id ||
          "";

        const status =
          String(
            item.status || "pending"
          ).toLowerCase();

        return `
          <tr>
            <td>
              ${escapeHtml(
                item.user?.name ||
                item.user_name ||
                item.name ||
                "-"
              )}
            </td>

            <td>
              ${escapeHtml(
                item.user?.phone ||
                item.phone ||
                "-"
              )}
            </td>

            <td>
              ${formatMoney(
                item.amount || 0
              )}
            </td>

            <td>
              ${escapeHtml(
                item.method || "-"
              )}
            </td>

            <td>
              ${escapeHtml(
                item.upi_id ||
                item.upi ||
                item.bank_account ||
                "-"
              )}
            </td>

            <td>
              <span class="badge">
                ${escapeHtml(status)}
              </span>
            </td>

            <td>
              ${formatDate(
                item.created_at ||
                item.createdAt
              )}
            </td>

            <td>
              <div class="admin-actions">
                ${
                  status === "pending"
                    ? `
                      <button
                        type="button"
                        onclick="NOVE_ADMIN.processWithdrawal('${id}')"
                      >
                        Process
                      </button>
                    `
                    : ""
                }

                ${
                  status === "processing"
                    ? `
                      <button
                        type="button"
                        onclick="NOVE_ADMIN.completeWithdrawal('${id}')"
                      >
                        Complete
                      </button>

                      <button
                        type="button"
                        onclick="NOVE_ADMIN.rejectWithdrawal('${id}')"
                      >
                        Reject
                      </button>
                    `
                    : ""
                }

                ${
                  status === "rejected"
                    ? `
                      <button
                        type="button"
                        onclick="NOVE_ADMIN.refundWithdrawal('${id}')"
                      >
                        Refund
                      </button>
                    `
                    : ""
                }
              </div>
            </td>
          </tr>
        `;
      }).join("");
  }

  async function processWithdrawal(id) {
    if (!id) return;

    try {
      await api(
        `/api/admin/withdrawals/${encodeURIComponent(id)}/process`,
        {
          method: "POST"
        }
      );

      showToast(
        "Withdrawal moved to processing.",
        "success"
      );

      await loadAdminWithdrawals();

    } catch (error) {
      showToast(
        error.message ||
        "Unable to process withdrawal.",
        "error"
      );
    }
  }

  async function completeWithdrawal(id) {
    if (!id) return;

    if (!confirm(
      "Mark this withdrawal as completed?"
    )) {
      return;
    }

    try {
      await api(
        `/api/admin/withdrawals/${encodeURIComponent(id)}/complete`,
        {
          method: "POST"
        }
      );

      showToast(
        "Withdrawal completed.",
        "success"
      );

      await loadAdminWithdrawals();
      await loadDashboardSummary();

    } catch (error) {
      showToast(
        error.message ||
        "Unable to complete withdrawal.",
        "error"
      );
    }
  }

  async function rejectWithdrawal(id) {
    if (!id) return;

    const reason =
      prompt(
        "Reason for rejecting withdrawal:",
        "Rejected by admin"
      );

    if (reason === null) {
      return;
    }

    try {
      await api(
        `/api/admin/withdrawals/${encodeURIComponent(id)}/reject`,
        {
          method: "POST",
          body: {
            reason:
              reason ||
              "Rejected by admin"
          }
        }
      );

      showToast(
        "Withdrawal rejected.",
        "success"
      );

      await loadAdminWithdrawals();
      await loadDashboardSummary();

    } catch (error) {
      showToast(
        error.message ||
        "Unable to reject withdrawal.",
        "error"
      );
    }
  }

  async function refundWithdrawal(id) {
    if (!id) return;

    if (!confirm(
      "Refund this withdrawal to the user's wallet?"
    )) {
      return;
    }

    try {
      await api(
        `/api/admin/withdrawals/${encodeURIComponent(id)}/refund`,
        {
          method: "POST"
        }
      );

      showToast(
        "Withdrawal refunded.",
        "success"
      );

      await loadAdminWithdrawals();
      await loadAdminUsers();
      await loadDashboardSummary();

    } catch (error) {
      showToast(
        error.message ||
        "Unable to refund withdrawal.",
        "error"
      );
    }
  }

  function setupSearch() {
    const inputs =
      $$(
        "[data-table-search], #userSearch, #searchUsers, #withdrawalSearch"
      );

    inputs.forEach(input => {
      input.addEventListener(
        "input",
        () => {
          const term =
            input.value
              .trim()
              .toLowerCase();

          const table =
            input.closest(
              ".panel, .table-panel, section, main"
            ) ||
            document;

          const rows =
            $$(
              "tbody tr",
              table
            );

          rows.forEach(row => {
            const text =
              row.textContent
                .toLowerCase();

            row.style.display =
              !term ||
              text.includes(term)
                ? ""
                : "none";
          });
        }
      );
    });
  }

  function setupMobileSidebar() {
    const toggle =
      $("#sidebarToggle") ||
      $("#menuToggle") ||
      document.querySelector(
        "[data-sidebar-toggle]"
      );

    const sidebar =
      $("#adminSidebar") ||
      $(".sidebar") ||
      $(".admin-sidebar");

    if (!toggle || !sidebar) {
      return;
    }

    toggle.addEventListener(
      "click",
      () => {
        sidebar.classList.toggle(
          "open"
        );
      }
    );
  }

  async function loadAdminPanel() {
    const ok =
      await checkAdmin();

    if (!ok) {
      if (
        location.pathname !==
        "/admin.html"
      ) {
        window.location.href =
          "/admin.html";
      }

      return;
    }

    await Promise.allSettled([
      loadDashboardSummary(),
      loadAdminUsers(),
      loadAdminWithdrawals()
    ]);

    setupSearch();
    setupMobileSidebar();
  }

  document.addEventListener(
    "DOMContentLoaded",
    () => {
      const loginForm =
        $("#adminLoginForm") ||
        $("#loginForm") ||
        document.querySelector(
          "form[data-admin-login]"
        );

      if (loginForm) {
        loginForm.addEventListener(
          "submit",
          adminLogin
        );
      }

      const logoutButtons =
        $$(
          "#adminLogout, #logoutAdmin, [data-admin-logout]"
        );

      logoutButtons.forEach(button => {
        button.addEventListener(
          "click",
          adminLogout
        );
      });

      if (
        location.pathname ===
          "/admin-dashboard.html" ||
        location.pathname.includes(
          "admin-dashboard"
        )
      ) {
        loadAdminPanel();
      }
    }
  );

  window.NOVE_ADMIN = {
    api,
    adminLogin,
    adminLogout,
    checkAdmin,
    loadAdminPanel,
    loadDashboardSummary,
    loadAdminUsers,
    loadAdminWithdrawals,
    renderUsers,
    renderWithdrawals,
    banUser,
    unbanUser,
    loginAsUser,
    adjustUserBalance,
    processWithdrawal,
    completeWithdrawal,
    rejectWithdrawal,
    refundWithdrawal,
    formatMoney,
    formatDate,
    showToast
  };
})();
