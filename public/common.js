/* Tiện ích dùng chung cho mọi trang */

const SUBJECTS = [
    ['Tiếng Việt', 'Tiếng Việt'], ['Toán', 'Toán'], ['TNXH', 'TNXH'],
    ['HDTN', 'HDTN'], ['Đạo đức', 'Đạo đức'], ['Tiếng Anh', 'Tiếng Anh'],
    ['Tin học', 'Tin học'], ['GDTC', 'GDTC'], ['Âm nhạc', 'Âm nhạc'], ['Mỹ thuật', 'Mỹ thuật']
];

const CATEGORY_LABELS = { 
    bai_giang: 'Bài giảng điện tử', bai_tap: 'Bài tập', ke_hoach_giang_day: 'Kế hoạch bài dạy',
    ke_hoach_day_hoc: 'Kế hoạch dạy học', de_kiem_tra: 'Đề kiểm tra', tich_hop: 'Tích hợp môn học / HDGD', 
    ke_hoach_chuyen_mon: 'Kế hoạch chuyên môn', ke_hoach_gd_khoi_2: 'Kế hoạch giáo dục khối 2', 
    van_ban_chuyen_mon: 'Văn bản chuyên môn', thu_vien_hinh_anh: 'Thư viện hình ảnh', ai: 'Trí tuệ nhân tạo (AI)' 
};

// ĐẠI TU UI/UX: Hàm tạo trạng thái trống (Empty State) sinh động
function emptyStateHtml(icon, title, desc) {
    return `<div class="col-12 empty-state">
        <div class="empty-state-icon">${icon}</div>
        <h3 class="h5 fw-bold text-body">${escapeHtml(title)}</h3>
        <p class="text-secondary">${escapeHtml(desc)}</p>
    </div>`;
}

// ĐẠI TU UI/UX: Hàm lấy Icon tương ứng với định dạng file
function getFileIcon(type, isUrl) {
    if (isUrl) return '<i class="fa fa-link text-secondary"></i>';
    const t = String(type).toLowerCase();
    if (['pdf'].includes(t)) return '<i class="fa fa-file-pdf text-danger"></i>';
    if (['doc', 'docx'].includes(t)) return '<i class="fa fa-file-word text-primary"></i>';
    if (['xls', 'xlsx', 'csv'].includes(t)) return '<i class="fa fa-file-excel text-success"></i>';
    if (['ppt', 'pptx'].includes(t)) return '<i class="fa fa-file-powerpoint text-warning"></i>';
    if (['mp4', 'mov', 'webm'].includes(t)) return '<i class="fa fa-file-video text-info"></i>';
    if (['jpg', 'jpeg', 'png', 'webp'].includes(t)) return '<i class="fa fa-file-image text-success"></i>';
    return '<i class="fa fa-file text-secondary"></i>';
}

function escapeHtml(value) { return String(value ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }
function safeUrl(url) { try { const u = new URL(url, location.href); return u.protocol === 'https:' || u.protocol === 'http:' ? u.href : ''; } catch { return ''; } }
function optionsHtml(pairs) { return pairs.map(([value, label]) => `<option value="${escapeHtml(value)}">${escapeHtml(label)}</option>`).join(''); }
function debounce(fn, ms = 300) { let t; return (...args) => { clearTimeout(t); t = setTimeout(() => fn(...args), ms); }; }

function notify(message, type = 'danger', ms = 5000) {
    let host = document.getElementById('toastHost');
    if (!host) { host = document.createElement('div'); host.id = 'toastHost'; host.setAttribute('aria-live', 'polite'); document.body.appendChild(host); }
    const el = document.createElement('div'); el.className = `alert alert-${type} shadow-sm mb-0 py-2 px-3`; el.setAttribute('role', 'alert'); el.textContent = message;
    host.appendChild(el); setTimeout(() => el.remove(), ms);
}

function createOverlayDiv() {
    const existing = document.getElementById('customPopupOverlay');
    if (existing) existing.remove();
    const overlay = document.createElement('div'); overlay.id = 'customPopupOverlay';
    overlay.style.cssText = 'position:fixed;top:0;left:0;width:100vw;height:100vh;background:rgba(0,0,0,0.65);z-index:99999;display:flex;align-items:center;justify-content:center;backdrop-filter:blur(4px);';
    return overlay;
}

function showPopup(title, message, type = 'info', actionHtml = '') {
    const overlay = createOverlayDiv();
    let icon = 'ℹ️'; if (type === 'danger') icon = '⚠️'; if (type === 'success') icon = '✅'; if (type === 'warning') icon = '🔔';
    overlay.innerHTML = `<div class="bg-body p-4 rounded-4 shadow-lg text-center mx-3 border" style="max-width: 420px; width: 100%; animation: fadeUp 0.3s ease;">
        <div class="mb-3" style="font-size: 3.5rem;">${icon}</div><h3 class="h5 fw-bold mb-2 text-body">${escapeHtml(title)}</h3><p class="text-secondary mb-4 small">${escapeHtml(message)}</p>
        ${actionHtml || `<button class="btn btn-secondary w-100 py-2 fw-bold" onclick="document.getElementById('customPopupOverlay').remove(); document.body.style.overflow='auto';">Đã hiểu</button>`}</div>`;
    document.body.appendChild(overlay); document.body.style.overflow = 'hidden';
}

function showConfirm(title, message, onConfirm, confirmText = 'Xác nhận', type = 'danger') {
    const overlay = createOverlayDiv();
    let icon = '❓'; if (type === 'danger') icon = '⚠️'; if (type === 'warning') icon = '🔔';
    let btnClass = type === 'danger' ? 'btn-danger' : (type === 'warning' ? 'btn-warning' : 'btn-primary');
    overlay.innerHTML = `<div class="bg-body p-4 rounded-4 shadow-lg text-center mx-3 border" style="max-width: 420px; width: 100%; animation: fadeUp 0.3s ease;">
        <div class="mb-3" style="font-size: 3.5rem;">${icon}</div><h3 class="h5 fw-bold mb-2 text-body">${escapeHtml(title)}</h3><p class="text-secondary mb-4 small">${escapeHtml(message)}</p>
        <div class="d-flex gap-2"><button class="btn btn-light flex-grow-1 py-2 fw-bold border" id="btnCancelPopup">Hủy bỏ</button><button class="btn ${btnClass} flex-grow-1 py-2 fw-bold" id="btnConfirmPopup">${escapeHtml(confirmText)}</button></div></div>`;
    document.body.appendChild(overlay); document.body.style.overflow = 'hidden';
    document.getElementById('btnCancelPopup').addEventListener('click', () => { overlay.remove(); document.body.style.overflow = 'auto'; });
    document.getElementById('btnConfirmPopup').addEventListener('click', () => { overlay.remove(); document.body.style.overflow = 'auto'; onConfirm(); });
}

function showPrompt(title, message, placeholder, onConfirm) {
    const overlay = createOverlayDiv();
    overlay.innerHTML = `<div class="bg-body p-4 rounded-4 shadow-lg text-center mx-3 border" style="max-width: 420px; width: 100%; animation: fadeUp 0.3s ease;">
        <div class="mb-2" style="font-size: 2.5rem;">📝</div><h3 class="h5 fw-bold mb-2 text-body">${escapeHtml(title)}</h3><p class="text-secondary mb-3 small">${escapeHtml(message)}</p>
        <input type="text" id="promptInput" class="form-control mb-4 text-center bg-body-tertiary" placeholder="${escapeHtml(placeholder)}" autocomplete="off">
        <div class="d-flex gap-2"><button class="btn btn-light flex-grow-1 py-2 fw-bold border" id="btnCancelPopup">Hủy</button><button class="btn btn-primary flex-grow-1 py-2 fw-bold" id="btnConfirmPopup">Xác nhận</button></div></div>`;
    document.body.appendChild(overlay); document.body.style.overflow = 'hidden';
    const input = document.getElementById('promptInput'); input.focus();
    input.addEventListener('keydown', (e) => { if (e.key === 'Enter') document.getElementById('btnConfirmPopup').click(); });
    document.getElementById('btnCancelPopup').addEventListener('click', () => { overlay.remove(); document.body.style.overflow = 'auto'; });
    document.getElementById('btnConfirmPopup').addEventListener('click', () => { const val = input.value; overlay.remove(); document.body.style.overflow = 'auto'; onConfirm(val); });
}

function forceLogout(message) {
    localStorage.removeItem('user'); if (heartbeatTimer) clearInterval(heartbeatTimer);
    showPopup('Kết nối bị ngắt', message || 'Tài khoản bị khóa, xóa hoặc phiên hết hạn.', 'danger', '<a href="login.html" class="btn btn-brand w-100 py-2 fw-bold">Quay lại Đăng nhập</a>');
}

function setBusy(btn, busy, busyText) { if (!btn) return; if (busy) { btn.dataset.label = btn.innerHTML; btn.textContent = busyText || 'Đang xử lý...'; } else if (btn.dataset.label) { btn.innerHTML = btn.dataset.label; } btn.disabled = busy; }

class ApiError extends Error { constructor(message, status) { super(message); this.status = status; } }
function goLogin() { localStorage.removeItem('user'); location.replace('login.html'); }

async function api(url, { method = 'GET', json, form, redirectOn401 = true } = {}) {
    const opts = { method, credentials: 'same-origin', headers: {} };
    if (json !== undefined) { opts.headers['Content-Type'] = 'application/json'; opts.body = JSON.stringify(json); } else if (form) { opts.body = form; }
    let res; try { res = await fetch(url, opts); } catch { throw new ApiError('Không thể kết nối máy chủ.', 0); }
    let data = null; try { data = await res.json(); } catch { }
    if (res.status === 401 && redirectOn401) {
        const wasLoggedIn = !!localStorage.getItem('user');
        if (wasLoggedIn) forceLogout((data && data.error) || 'Phiên đăng nhập đã hết hạn.'); else goLogin();
        throw new ApiError((data && data.error) || 'Phiên hết hạn.', 401);
    }
    if (!res.ok) throw new ApiError((data && data.error) || 'Có lỗi xảy ra.', res.status);
    return data;
}

let heartbeatTimer = null, lastPing = 0;
function startHeartbeat() {
    if (heartbeatTimer) return; lastPing = Date.now();
    const ping = async () => {
        if (document.hidden || Date.now() - lastPing < 20000) return; lastPing = Date.now();
        try {
            const data = await api('/api/me');
            if (data && data.user) {
                const oldUser = JSON.parse(localStorage.getItem('user') || '{}');
                if (oldUser.can_manage_docs !== data.user.can_manage_docs) {
                    localStorage.setItem('user', JSON.stringify(data.user)); window.dispatchEvent(new CustomEvent('userUpdated', { detail: data.user }));
                }
            }
        } catch (e) {}
    };
    heartbeatTimer = setInterval(ping, 60000); document.addEventListener('visibilitychange', ping);
}

async function requireUser() {
    try { const { user } = await api('/api/me'); localStorage.setItem('user', JSON.stringify(user)); startHeartbeat(); return user; } 
    catch (e) { if (e.status !== 401) notify(e.message); return null; }
}