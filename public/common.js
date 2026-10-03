/* Tiện ích dùng chung cho mọi trang */

const SUBJECTS = [
    ['Tiếng Việt', 'Tiếng Việt'], ['Toán', 'Toán học'], ['Tiếng Anh', 'Tiếng Anh'],
    ['Tự nhiên & Xã hội', 'Tự nhiên & Xã hội'], ['Khoa học', 'Khoa học'], ['Lịch sử & Địa lý', 'Lịch sử & Địa lý']
];
const CATEGORY_LABELS = { bai_giang: 'Bài giảng', giao_an: 'Giáo án', de_thi: 'Đề thi', tu_lieu: 'Tư liệu', dao_tao: 'Đào tạo' };

// Chống XSS: dùng cho mọi dữ liệu người dùng đưa vào innerHTML
function escapeHtml(value) {
    return String(value ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

// Chỉ cho phép địa chỉ http(s); trả về chuỗi rỗng nếu không hợp lệ
function safeUrl(url) {
    try {
        const u = new URL(url, location.href);
        return u.protocol === 'https:' || u.protocol === 'http:' ? u.href : '';
    } catch { return ''; }
}

function optionsHtml(pairs) {
    return pairs.map(([value, label]) => `<option value="${escapeHtml(value)}">${escapeHtml(label)}</option>`).join('');
}

function debounce(fn, ms = 300) {
    let t;
    return (...args) => { clearTimeout(t); t = setTimeout(() => fn(...args), ms); };
}

// Thông báo nổi thay cho alert()
function notify(message, type = 'danger', ms = 5000) {
    let host = document.getElementById('toastHost');
    if (!host) {
        host = document.createElement('div');
        host.id = 'toastHost';
        host.setAttribute('aria-live', 'polite');
        document.body.appendChild(host);
    }
    const el = document.createElement('div');
    el.className = `alert alert-${type} shadow-sm mb-0 py-2 px-3`;
    el.setAttribute('role', 'alert');
    el.textContent = message;
    host.appendChild(el);
    setTimeout(() => el.remove(), ms);
}

// Khóa / mở nút bấm khi đang gửi yêu cầu
function setBusy(btn, busy, busyText) {
    if (!btn) return;
    if (busy) { btn.dataset.label = btn.innerHTML; btn.textContent = busyText || 'Đang xử lý...'; }
    else if (btn.dataset.label) { btn.innerHTML = btn.dataset.label; }
    btn.disabled = busy;
}

class ApiError extends Error {
    constructor(message, status) { super(message); this.status = status; }
}

function goLogin() {
    localStorage.removeItem('user');
    location.replace('login.html');
}

// Gọi API: tự gửi cookie, kiểm tra res.ok, 401 thì về trang đăng nhập
async function api(url, { method = 'GET', json, form, redirectOn401 = true } = {}) {
    const opts = { method, credentials: 'same-origin', headers: {} };
    if (json !== undefined) { opts.headers['Content-Type'] = 'application/json'; opts.body = JSON.stringify(json); }
    else if (form) { opts.body = form; }

    let res;
    try { res = await fetch(url, opts); }
    catch { throw new ApiError('Không thể kết nối máy chủ. Hãy kiểm tra mạng và thử lại.', 0); }

    let data = null;
    try { data = await res.json(); } catch { /* phản hồi không phải JSON */ }

    if (res.status === 401 && redirectOn401) {
        goLogin();
        throw new ApiError((data && data.error) || 'Phiên đăng nhập đã hết hạn.', 401);
    }
    if (!res.ok) throw new ApiError((data && data.error) || 'Có lỗi xảy ra, vui lòng thử lại.', res.status);
    return data;
}

// Xác nhận phiên đăng nhập với server và đồng bộ thông tin người dùng; trả về null nếu chưa đăng nhập
async function requireUser() {
    try {
        const { user } = await api('/api/me');
        localStorage.setItem('user', JSON.stringify(user));
        return user;
    } catch (e) {
        if (e.status !== 401) notify(e.message);
        return null;
    }
}
