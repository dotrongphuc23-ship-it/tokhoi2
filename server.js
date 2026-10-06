require('dotenv').config();
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const { Pool } = require('pg');
const { createClient } = require('@supabase/supabase-js');
const crypto = require('crypto');
const path = require('path');

// ================= 0. CẤU HÌNH CHUNG =================
const IS_PROD = process.env.NODE_ENV === 'production';
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET.length < 32) {
    console.error('❌ Thiếu JWT_SECRET (tối thiểu 32 ký tự) trong file .env. Server không khởi động.');
    process.exit(1);
}

const ADMIN_ROLES = ['master_admin', 'admin'];
const STAFF_ROLES = ['teacher', ...ADMIN_ROLES];

const CATEGORIES = ['bai_giang', 'bai_tap', 'ke_hoach_giang_day', 'ke_hoach_day_hoc', 'de_kiem_tra', 'tich_hop', 'ke_hoach_chuyen_mon', 'ke_hoach_gd_khoi_2', 'van_ban_chuyen_mon', 'thu_vien_hinh_anh', 'ai'];
const CATEGORIES_WITH_GRADE_SUBJECT = ['bai_giang', 'bai_tap', 'ke_hoach_giang_day', 'de_kiem_tra', 'tich_hop']; 
const STUDENT_CATEGORIES = ['bai_giang', 'bai_tap', 'thu_vien_hinh_anh', 'ai']; 
const GRADES = ['1', '2', '3', '4', '5'];
const SUBJECTS = ['Tiếng Việt', 'Toán', 'TNXH', 'HDTN', 'Đạo đức', 'Tiếng Anh', 'Tin học', 'GDTC', 'Âm nhạc', 'Mỹ thuật'];
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const app = express();
if (IS_PROD) app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '500kb' }));
app.use(express.urlencoded({ extended: true, limit: '500kb' }));
app.use(cookieParser());
app.use(express.static('public'));

const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const httpError = (message, status = 400) => Object.assign(new Error(message), { isHttp: true, status });
const cleanStr = (v) => (typeof v === 'string' ? v.trim() : '');
const normEmail = (v) => cleanStr(v).toLowerCase();
const toInt = (v) => { const n = Number(v); return Number.isInteger(n) && n > 0 && n <= 2147483647 ? n : null; };
const sha = (s) => crypto.createHash('sha256').update(String(s)).digest('hex');
const isStaff = (user) => STAFF_ROLES.includes(user.role);
const isAdmin = (user) => ADMIN_ROLES.includes(user.role);
const canAccessCategory = (user, category) => isStaff(user) || STUDENT_CATEGORIES.includes(category);
const COOKIE_OPTS = { httpOnly: true, secure: IS_PROD, sameSite: 'strict' };
const DUMMY_HASH = bcrypt.hashSync('khong-phai-mat-khau-that', 10);

const PRESENCE_THROTTLE_MS = 30 * 1000;
const ONLINE_WINDOW_MS = 150 * 1000;
const isOnline = (lastSeen) => !!lastSeen && Date.now() - Number(lastSeen) < ONLINE_WINDOW_MS;
const withPresence = ({ last_seen, ...r }) => ({
    ...r,
    online: isOnline(last_seen),
    seen_ago: last_seen ? Math.max(0, Math.round((Date.now() - Number(last_seen)) / 1000)) : null
});

function validatePassword(pw) {
    if (typeof pw !== 'string' || pw.length < 6) return 'Mật khẩu phải có ít nhất 6 ký tự.';
    if (pw.length > 72) return 'Mật khẩu tối đa 72 ký tự.';
    return null;
}

const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT || 5432,
    ssl: { rejectUnauthorized: false },
    max: 10
});
pool.on('error', (err) => console.error('Lỗi kết nối DB nhàn rỗi:', err.message));

const initDB = async () => {
    await pool.query(`
        CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, full_name VARCHAR(100), email VARCHAR(100) UNIQUE, password_hash VARCHAR(255), role VARCHAR(50), status VARCHAR(50), reset_otp_hash VARCHAR(255), reset_otp_expires BIGINT, reset_attempts INT DEFAULT 0, reset_sent_at BIGINT, dob VARCHAR(20), phone VARCHAR(20), workplace VARCHAR(255), position VARCHAR(100), created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS settings (id SERIAL PRIMARY KEY, portal VARCHAR(50) UNIQUE, school_name VARCHAR(255), slogan VARCHAR(255), contact VARCHAR(255), banner_url TEXT);
        CREATE TABLE IF NOT EXISTS lectures (id SERIAL PRIMARY KEY, title VARCHAR(255), description TEXT, grade VARCHAR(50), subject VARCHAR(100), category_type VARCHAR(50), file_name VARCHAR(255), file_url TEXT, file_type VARCHAR(20), author_name VARCHAR(100), views_count INT DEFAULT 0, avg_rating FLOAT DEFAULT 5.0, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS timetable (class_id VARCHAR(50) PRIMARY KEY, schedule JSONB);
        CREATE TABLE IF NOT EXISTS reviews (id SERIAL PRIMARY KEY, lecture_id INT REFERENCES lectures(id) ON DELETE CASCADE, author_name VARCHAR(100), stars INT, comment TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS classes (class_id VARCHAR(20) PRIMARY KEY, class_name VARCHAR(100) NOT NULL, teacher_name VARCHAR(100) DEFAULT '');

        ALTER TABLE users DROP COLUMN IF EXISTS reset_token_hash;
        ALTER TABLE users DROP COLUMN IF EXISTS reset_token_expires;
        ALTER TABLE lectures ADD COLUMN IF NOT EXISTS author_id INT REFERENCES users(id) ON DELETE SET NULL;
        ALTER TABLE lectures ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMP DEFAULT NULL;
        ALTER TABLE lectures ADD COLUMN IF NOT EXISTS week_start INT DEFAULT NULL;
        ALTER TABLE lectures ADD COLUMN IF NOT EXISTS week_end INT DEFAULT NULL;
        ALTER TABLE reviews ADD COLUMN IF NOT EXISTS user_id INT REFERENCES users(id) ON DELETE SET NULL;
        CREATE UNIQUE INDEX IF NOT EXISTS reviews_lecture_user_uq ON reviews (lecture_id, user_id);
        ALTER TABLE users ADD COLUMN IF NOT EXISTS last_seen BIGINT;
        ALTER TABLE users ADD COLUMN IF NOT EXISTS is_locked BOOLEAN NOT NULL DEFAULT FALSE;
        ALTER TABLE users ADD COLUMN IF NOT EXISTS can_manage_docs BOOLEAN NOT NULL DEFAULT FALSE;
        
        ALTER TABLE users ADD COLUMN IF NOT EXISTS class_name VARCHAR(50);
        ALTER TABLE users ADD COLUMN IF NOT EXISTS parent_name VARCHAR(100);
        ALTER TABLE users ADD COLUMN IF NOT EXISTS homeroom_teacher VARCHAR(100);

        ALTER TABLE settings ADD COLUMN IF NOT EXISTS banner_pos INT NOT NULL DEFAULT 50;
        ALTER TABLE settings ADD COLUMN IF NOT EXISTS banner_pos_x INT NOT NULL DEFAULT 50;
        ALTER TABLE settings ADD COLUMN IF NOT EXISTS banner_zoom INT NOT NULL DEFAULT 100;
        ALTER TABLE settings ADD COLUMN IF NOT EXISTS banner_fit VARCHAR(20) NOT NULL DEFAULT 'cover';
        ALTER TABLE settings ADD COLUMN IF NOT EXISTS logo_url TEXT;

        CREATE TABLE IF NOT EXISTS notifications (id SERIAL PRIMARY KEY, user_id INT REFERENCES users(id) ON DELETE CASCADE, type VARCHAR(50), content TEXT, target_url VARCHAR(255), is_read BOOLEAN DEFAULT FALSE, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS bookmarks (id SERIAL PRIMARY KEY, user_id INT REFERENCES users(id) ON DELETE CASCADE, lecture_id INT REFERENCES lectures(id) ON DELETE CASCADE, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
        CREATE UNIQUE INDEX IF NOT EXISTS bookmarks_user_lecture_uq ON bookmarks (user_id, lecture_id);
    `);

    await pool.query(`
        UPDATE lectures l SET author_id = u.id FROM users u
        WHERE l.author_id IS NULL AND l.author_name = u.full_name AND u.role IN ('teacher','master_admin','admin')
          AND (SELECT COUNT(*) FROM users x WHERE x.full_name = u.full_name) = 1
    `);

    const adminEmail = normEmail(process.env.ADMIN_EMAIL);
    const adminPass = process.env.ADMIN_PASSWORD;
    if (adminEmail && adminPass) {
        if (adminPass.length < 8) throw new Error('ADMIN_PASSWORD phải có ít nhất 8 ký tự.');
        const hash = await bcrypt.hash(adminPass, 10);
        const exist = await pool.query('SELECT id FROM users WHERE email = $1', [adminEmail]);
        if (exist.rows.length) {
            await pool.query("UPDATE users SET password_hash = $1, role = 'master_admin', status = 'approved', can_manage_docs = true WHERE id = $2", [hash, exist.rows[0].id]);
        } else {
            await pool.query("INSERT INTO users (full_name, email, password_hash, role, status, can_manage_docs) VALUES ('Quản trị viên', $1, $2, 'master_admin', 'approved', true)", [adminEmail, hash]);
        }
    }
};

setInterval(async () => {
    try {
        const { rows } = await pool.query("SELECT id, file_url, file_type FROM lectures WHERE deleted_at < CURRENT_TIMESTAMP - INTERVAL '30 days'");
        if (rows.length > 0) {
            const ids = rows.map(r => r.id);
            await pool.query('DELETE FROM lectures WHERE id = ANY($1)', [ids]);
            for (const r of rows) {
                if (r.file_type !== 'url') await destroyCloudFile(r.file_url);
            }
            console.log(`Đã dọn dẹp ${ids.length} tài liệu hết hạn trong thùng rác.`);
        }
    } catch (e) { console.error('Lỗi dọn rác tự động:', e); }
}, 24 * 60 * 60 * 1000); 

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);
const BANNER_EXTS = ['.jpg', '.jpeg', '.png', '.webp'];

const memoryStorage = multer.memoryStorage();
const bannerUpload = multer({
    storage: memoryStorage,
    limits: { fileSize: 5 * 1024 * 1024 }, 
    fileFilter: (req, file, cb) => {
        const ext = path.extname(file.originalname).toLowerCase();
        BANNER_EXTS.includes(ext) ? cb(null, true) : cb(httpError('Ảnh banner chỉ nhận .jpg, .png, .webp (tối đa 5MB).'));
    }
});

async function destroyCloudFile(fileUrl) {
    if (!fileUrl) return;
    try {
        const urlObj = new URL(fileUrl);
        const pathParts = urlObj.pathname.split('/thuvien/');
        if (pathParts.length > 1) {
            const filePath = decodeURIComponent(pathParts[1]);
            await supabase.storage.from('thuvien').remove([filePath]);
        }
    } catch (e) { /* Ignore */ }
}

async function uploadToSupabase(fileBuffer, originalName, folderName, mimeType) {
    const ext = path.extname(originalName).toLowerCase();
    const cleanName = path.basename(originalName, ext).normalize('NFD').replace(/[\u0300-\u036f]/g, '').replace(/đ/g, 'd').replace(/Đ/g, 'D').replace(/[^a-zA-Z0-9]/g, '_').slice(0, 60) || 'file';
    const fileName = `${folderName}/${cleanName}_${Date.now()}_${Math.floor(Math.random()*1000)}${ext}`;
    const { data, error } = await supabase.storage.from('thuvien').upload(fileName, fileBuffer, { contentType: mimeType || 'application/octet-stream', upsert: false });
    if (error) throw new Error('Supabase từ chối file: ' + error.message);
    const { data: publicUrlData } = supabase.storage.from('thuvien').getPublicUrl(fileName);
    return publicUrlData.publicUrl;
}

const makeLimiter = (minutes, max, message, extra = {}) => rateLimit({ windowMs: minutes * 60 * 1000, max, standardHeaders: true, legacyHeaders: false, message: { error: message }, ...extra });
const loginLimiter = makeLimiter(15, 10, 'Bạn đăng nhập sai quá nhiều lần. Hãy thử lại sau 15 phút.', { skipSuccessfulRequests: true });
const registerLimiter = makeLimiter(60, 10, 'Bạn đã thử quá nhiều lần. Hãy đợi một chút.');

const verifyToken = wrap(async (req, res, next) => {
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ error: 'Chưa đăng nhập.' });
    let payload;
    try { payload = jwt.verify(token, JWT_SECRET); } catch { return res.status(401).json({ error: 'Phiên đăng nhập đã hết hạn.' }); }
    
    const { rows } = await pool.query('SELECT id, full_name, email, role, status, is_locked, last_seen, can_manage_docs FROM users WHERE id = $1', [payload.id]);
    const u = rows[0];
    
    if (!u) return res.status(401).json({ error: 'Tài khoản của bạn đã bị xóa khỏi hệ thống. Vui lòng liên hệ nhà trường để được hỗ trợ.' });
    if (u.is_locked) return res.status(401).json({ error: 'Tài khoản của bạn đã bị khóa bởi Quản trị viên.' });
    if (u.role === 'teacher' && u.status !== 'approved') return res.status(401).json({ error: 'Tài khoản của bạn đang chờ duyệt hoặc đã bị từ chối.' });
    
    const now = Date.now();
    if (!u.last_seen || now - Number(u.last_seen) > PRESENCE_THROTTLE_MS) { pool.query('UPDATE users SET last_seen = $1 WHERE id = $2', [now, u.id]).catch(() => {}); }
    
    req.user = { id: u.id, name: u.full_name, email: u.email, role: u.role, can_manage_docs: u.can_manage_docs };
    next();
});

const requireRole = (...roles) => (req, res, next) => roles.includes(req.user.role) ? next() : res.status(403).json({ error: 'Bạn không có quyền thực hiện thao tác này.' });
const requireAdmin = requireRole(...ADMIN_ROLES);
const requireStaff = requireRole(...STAFF_ROLES);

app.post('/api/auth/login', loginLimiter, wrap(async (req, res) => {
    const email = normEmail(req.body.email);
    const password = req.body.password;
    if (!email || typeof password !== 'string' || !password) return res.status(400).json({ error: 'Vui lòng nhập email và mật khẩu.' });
    
    const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = rows[0];
    const ok = await bcrypt.compare(password, user ? user.password_hash : DUMMY_HASH);
    
    if (!user || !ok) return res.status(401).json({ error: 'Sai email hoặc mật khẩu.' });
    if (user.role === 'teacher' && user.status !== 'approved') return res.status(403).json({ error: 'Tài khoản đang chờ Ban giám hiệu duyệt.' });
    if (user.is_locked) return res.status(403).json({ error: 'Tài khoản đã bị khóa. Vui lòng liên hệ nhà trường.' });

    const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '7d' });
    res.cookie('token', token, { ...COOKIE_OPTS, maxAge: 7 * 24 * 60 * 60 * 1000 });
    res.json({ user: { id: user.id, name: user.full_name, email: user.email, role: user.role, can_manage_docs: user.can_manage_docs } });
}));

app.post('/api/auth/logout', wrap(async (req, res) => {
    try { const payload = jwt.verify(req.cookies.token, JWT_SECRET); await pool.query('UPDATE users SET last_seen = $1 WHERE id = $2', [Date.now() - ONLINE_WINDOW_MS, payload.id]); } catch { }
    res.clearCookie('token', COOKIE_OPTS); res.json({ message: 'Đã đăng xuất.' });
}));

app.get('/api/me', verifyToken, wrap(async (req, res) => {
    const { rows } = await pool.query('SELECT id, full_name, email, role, status, dob, phone, workplace, position, class_name, parent_name, homeroom_teacher, can_manage_docs FROM users WHERE id = $1', [req.user.id]);
    res.json({ user: rows[0] });
}));

app.post('/api/auth/register', registerLimiter, wrap(async (req, res) => {
    const { full_name, email: rawEmail, password, role, dob, phone, workplace, position, class_name, parent_name, homeroom_teacher } = req.body;
    const email = normEmail(rawEmail); if (!EMAIL_RE.test(email)) return res.status(400).json({ error: 'Email không hợp lệ.' });

    const fullName = cleanStr(full_name); if (fullName.length < 2 || fullName.length > 100) return res.status(400).json({ error: 'Họ tên phải từ 2 đến 100 ký tự.' });
    const pwErr = validatePassword(password); if (pwErr) return res.status(400).json({ error: pwErr });
    const isTeacher = role === 'teacher'; 
    const isStudent = role === 'student';
    const hash = await bcrypt.hash(password, 10);
    
    const cleanPhoneStr = cleanStr(phone);
    if (cleanPhoneStr) {
        const phoneCheck = await pool.query('SELECT id FROM users WHERE phone = $1', [cleanPhoneStr]);
        if (phoneCheck.rows.length > 0) return res.status(409).json({ error: 'Số điện thoại này đã được sử dụng.' });
    }

    try {
        await pool.query(
            `INSERT INTO users (full_name, email, password_hash, role, status, dob, phone, workplace, position, class_name, parent_name, homeroom_teacher, can_manage_docs) 
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, false)`,
            [
                fullName, email, hash, 
                isTeacher ? 'teacher' : 'student', 
                isTeacher ? 'pending' : 'approved', 
                cleanStr(dob) || null, 
                cleanPhoneStr || null, 
                isTeacher ? cleanStr(workplace) : null, 
                isTeacher ? cleanStr(position) : null,
                isStudent ? cleanStr(class_name) : null,
                isStudent ? cleanStr(parent_name) : null,
                isStudent ? cleanStr(homeroom_teacher) : null
            ]
        );
    } catch (err) { if (err.code === '23505') return res.status(409).json({ error: 'Email này đã được đăng ký.' }); throw err; }
    res.json({ message: isTeacher ? 'Đăng ký thành công! Hồ sơ đang chờ Ban giám hiệu duyệt.' : 'Đăng ký thành công! Bạn có thể đăng nhập ngay.' });
}));


/* ================= API HỒ SƠ & THÔNG BÁO & BOOKMARK ================= */
app.put('/api/me', verifyToken, wrap(async (req, res) => {
    const { full_name, dob, phone, workplace, position, class_name, parent_name, homeroom_teacher, password } = req.body;
    const fullName = cleanStr(full_name);
    if (fullName.length < 2) return res.status(400).json({ error: 'Họ tên quá ngắn.' });

    const cleanPhone = cleanStr(phone);
    if (cleanPhone) {
        const phoneCheck = await pool.query('SELECT id FROM users WHERE phone = $1 AND id != $2', [cleanPhone, req.user.id]);
        if (phoneCheck.rows.length > 0) return res.status(409).json({ error: 'Số điện thoại này đã được tài khoản khác sử dụng.' });
    }

    let pwQuery = '', vals = [
        fullName, cleanStr(dob), cleanPhone, 
        cleanStr(workplace), cleanStr(position), 
        cleanStr(class_name), cleanStr(parent_name), cleanStr(homeroom_teacher),
        req.user.id
    ];
    
    if (password) {
        const pwErr = validatePassword(password);
        if (pwErr) return res.status(400).json({ error: pwErr });
        pwQuery = ', password_hash = $10';
        vals.push(await bcrypt.hash(password, 10));
    }

    await pool.query(`UPDATE users SET full_name = $1, dob = $2, phone = $3, workplace = $4, position = $5, class_name = $6, parent_name = $7, homeroom_teacher = $8 ${pwQuery} WHERE id = $9`, vals);
    
    // Gửi thông báo cho Admin nếu là giáo viên sửa hồ sơ
    if (req.user.role === 'teacher') {
        const msg = `Giáo viên ${fullName} vừa cập nhật thông tin hồ sơ cá nhân.`;
        await pool.query(`INSERT INTO notifications (user_id, type, content, target_url) SELECT id, 'system', $1, '#' FROM users WHERE role = 'master_admin'`, [msg]);
    }

    res.json({ message: 'Cập nhật hồ sơ thành công!' });
}));

app.get('/api/notifications', verifyToken, wrap(async (req, res) => {
    const { rows } = await pool.query('SELECT * FROM notifications WHERE user_id = $1 ORDER BY created_at DESC LIMIT 30', [req.user.id]);
    const unread = await pool.query('SELECT COUNT(*) FROM notifications WHERE user_id = $1 AND is_read = FALSE', [req.user.id]);
    res.json({ items: rows, unread: Number(unread.rows[0].count) });
}));

app.post('/api/notifications/read', verifyToken, wrap(async (req, res) => {
    await pool.query('UPDATE notifications SET is_read = TRUE WHERE user_id = $1', [req.user.id]);
    res.json({ message: 'Đã đánh dấu đọc.' });
}));

app.post('/api/lectures/:id/bookmark', verifyToken, wrap(async (req, res) => {
    const id = toInt(req.params.id);
    const { rows } = await pool.query('SELECT id FROM bookmarks WHERE user_id = $1 AND lecture_id = $2', [req.user.id, id]);
    if (rows.length > 0) {
        await pool.query('DELETE FROM bookmarks WHERE user_id = $1 AND lecture_id = $2', [req.user.id, id]);
        res.json({ is_bookmarked: false });
    } else {
        await pool.query('INSERT INTO bookmarks (user_id, lecture_id) VALUES ($1, $2)', [req.user.id, id]);
        res.json({ is_bookmarked: true });
    }
}));

app.post('/api/lectures/:id/report', verifyToken, wrap(async (req, res) => {
    const id = toInt(req.params.id);
    const lec = await pool.query('SELECT title, author_id FROM lectures WHERE id = $1', [id]);
    if (!lec.rows[0]) return res.status(404).json({ error: 'Không tìm thấy tài liệu.' });

    const msg = `Tài liệu "${lec.rows[0].title}" vừa bị báo cáo lỗi truy cập bởi ${req.user.name}.`;
    const targetUrl = `/view.html?id=${id}`;
    
    if (lec.rows[0].author_id) await pool.query('INSERT INTO notifications (user_id, type, content, target_url) VALUES ($1, $2, $3, $4)', [lec.rows[0].author_id, 'report', msg, targetUrl]);
    await pool.query(`INSERT INTO notifications (user_id, type, content, target_url) SELECT id, 'report', $1, $2 FROM users WHERE role = 'master_admin'`, [msg, targetUrl]);

    res.json({ message: 'Đã gửi báo cáo lỗi thành công! Cảm ơn bạn.' });
}));
/* ======================================================================== */

app.get('/api/settings', wrap(async (req, res) => {
    const { rows } = await pool.query("SELECT * FROM settings WHERE portal = 'tieu_hoc'");
    const r = rows[0];
    res.json(r ? { schoolName: r.school_name, slogan: r.slogan, contact: r.contact, bannerUrl: r.banner_url, bannerPosX: r.banner_pos_x ?? 50, bannerPosY: r.banner_pos ?? 50, bannerZoom: r.banner_zoom ?? 100, bannerFit: r.banner_fit || 'cover', logoUrl: r.logo_url || '' } : {});
}));

app.post('/api/settings', verifyToken, requireAdmin, bannerUpload.single('banner'), wrap(async (req, res) => {
    const schoolName = cleanStr(req.body.schoolName), slogan = cleanStr(req.body.slogan), contact = cleanStr(req.body.contact), logoUrl = cleanStr(req.body.logoUrl);
    if (!schoolName || !slogan || !contact) return res.status(400).json({ error: 'Tên trường, slogan và liên hệ là bắt buộc.' });
    
    const clampInt = (v, lo, hi, def) => { const n = Number(v); return Number.isFinite(n) ? Math.min(hi, Math.max(lo, Math.round(n))) : def; };
    const posX = clampInt(req.body.bannerPosX, 0, 100, 50), posY = clampInt(req.body.bannerPosY, 0, 100, 50), zoom = clampInt(req.body.bannerZoom, 100, 300, 100);
    const bannerFit = ['cover', 'contain'].includes(req.body.bannerFit) ? req.body.bannerFit : 'cover';
    const hasView = req.body.bannerZoom !== undefined;

    if (req.file) {
        const publicUrl = await uploadToSupabase(req.file.buffer, req.file.originalname, 'banner', req.file.mimetype);
        const old = await pool.query("SELECT banner_url FROM settings WHERE portal = 'tieu_hoc'");
        await pool.query("UPDATE settings SET school_name = $1, slogan = $2, contact = $3, banner_url = $4, banner_pos_x = $5, banner_pos = $6, banner_zoom = $7, banner_fit = $8, logo_url = $9 WHERE portal = 'tieu_hoc'", [schoolName, slogan, contact, publicUrl, posX, posY, zoom, bannerFit, logoUrl]);
        if (old.rows[0] && old.rows[0].banner_url) await destroyCloudFile(old.rows[0].banner_url);
    } else if (hasView) {
        await pool.query("UPDATE settings SET school_name = $1, slogan = $2, contact = $3, banner_pos_x = $4, banner_pos = $5, banner_zoom = $6, banner_fit = $7, logo_url = $8 WHERE portal = 'tieu_hoc'", [schoolName, slogan, contact, posX, posY, zoom, bannerFit, logoUrl]);
    } else {
        await pool.query("UPDATE settings SET school_name = $1, slogan = $2, contact = $3, banner_fit = $4, logo_url = $5 WHERE portal = 'tieu_hoc'", [schoolName, slogan, contact, bannerFit, logoUrl]);
    }
    res.json({ message: 'Cập nhật thành công!' });
}));

app.get('/api/admin/pending-teachers', verifyToken, requireAdmin, wrap(async (req, res) => {
    const { rows } = await pool.query("SELECT id, full_name, email, dob, phone, workplace, position FROM users WHERE role = 'teacher' AND status = 'pending' ORDER BY created_at");
    res.json(rows);
}));

app.get('/api/admin/teachers', verifyToken, requireAdmin, wrap(async (req, res) => {
    const { rows } = await pool.query("SELECT id, full_name, email, dob, phone, workplace, position, last_seen, can_manage_docs FROM users WHERE role = 'teacher' AND status = 'approved' ORDER BY full_name");
    res.json(rows.map(withPresence));
}));

app.post('/api/admin/manage-teacher', verifyToken, requireAdmin, wrap(async (req, res) => {
    const id = toInt(req.body.teacher_id), action = req.body.action;
    if (!id || !['approve', 'reject'].includes(action)) return res.status(400).json({ error: 'Yêu cầu không hợp lệ.' });
    const result = action === 'approve' ? await pool.query("UPDATE users SET status = 'approved' WHERE id = $1 AND role = 'teacher' AND status = 'pending'", [id]) : await pool.query("DELETE FROM users WHERE id = $1 AND role = 'teacher' AND status = 'pending'", [id]);
    if (!result.rowCount) return res.status(404).json({ error: 'Không tìm thấy hồ sơ giáo viên đang chờ duyệt.' });
    res.json({ message: action === 'approve' ? 'Đã duyệt giáo viên!' : 'Đã từ chối hồ sơ!' });
}));

app.post('/api/admin/teachers/:id/permission', verifyToken, requireAdmin, wrap(async (req, res) => {
    const id = toInt(req.params.id), canManage = Boolean(req.body.can_manage_docs);
    const result = await pool.query("UPDATE users SET can_manage_docs = $1 WHERE id = $2 AND role = 'teacher'", [canManage, id]);
    if (!result.rowCount) return res.status(404).json({ error: 'Không tìm thấy giáo viên.' });

    const msg = canManage ? 'Quản trị viên vừa cấp cho bạn quyền Sửa/Xóa tài liệu.' : 'Quyền Sửa/Xóa tài liệu của bạn đã bị thu hồi.';
    await pool.query('INSERT INTO notifications (user_id, type, content) VALUES ($1, $2, $3)', [id, 'permission', msg]);

    res.json({ message: canManage ? 'Đã cấp quyền sửa/xóa cho giáo viên!' : 'Đã tước quyền sửa/xóa.' });
}));

app.post('/api/admin/delete-teacher', verifyToken, requireAdmin, wrap(async (req, res) => {
    const id = toInt(req.body.teacher_id); if (!id) return res.status(400).json({ error: 'Yêu cầu không hợp lệ.' });
    const result = await pool.query("DELETE FROM users WHERE id = $1 AND role = 'teacher'", [id]);
    if (!result.rowCount) return res.status(404).json({ error: 'Không tìm thấy giáo viên.' }); res.json({ message: 'Đã xóa giáo viên!' });
}));

app.post('/api/admin/users/:id/reset-password', verifyToken, requireAdmin, wrap(async (req, res) => {
    const id = toInt(req.params.id); if (!id) return res.status(400).json({ error: 'Yêu cầu không hợp lệ.' });
    const pwErr = validatePassword(req.body.new_password); if (pwErr) return res.status(400).json({ error: pwErr });
    try {
        const hash = await bcrypt.hash(req.body.new_password, 10);
        const result = await pool.query("UPDATE users SET password_hash = $1 WHERE id = $2 AND role IN ('teacher', 'student')", [hash, id]);
        if (!result.rowCount) return res.status(404).json({ error: 'Không tìm thấy tài khoản hợp lệ.' });
        res.json({ message: 'Đã đặt lại mật khẩu. Hãy báo mật khẩu mới cho người dùng.' });
    } catch(err) {
        return res.status(500).json({ error: 'Đã xảy ra sự cố phía máy chủ.' });
    }
}));

app.get('/api/admin/students', verifyToken, requireAdmin, wrap(async (req, res) => {
    const search = cleanStr(req.query.search).slice(0, 100); const vals = []; let where = "role = 'student'";
    if (search) { vals.push('%' + search.replace(/[\\%_]/g, '\\$&') + '%'); where += ' AND (full_name ILIKE $1 OR email ILIKE $1 OR class_name ILIKE $1)'; }
    const cols = 'id, full_name, email, class_name, parent_name, is_locked, last_seen, created_at';
    
    if (req.query.all === '1') { const { rows } = await pool.query(`SELECT ${cols} FROM users WHERE ${where} ORDER BY full_name, id LIMIT 5000`, vals); return res.json({ items: rows.map(withPresence) }); }

    const limit = Math.min(toInt(req.query.limit) || 15, 50), page = toInt(req.query.page) || 1;
    const total = Number((await pool.query(`SELECT COUNT(*) FROM users WHERE ${where}`, vals)).rows[0].count);
    const { rows } = await pool.query(`SELECT ${cols} FROM users WHERE ${where} ORDER BY full_name, id LIMIT ${limit} OFFSET ${(page - 1) * limit}`, vals);
    const online = Number((await pool.query("SELECT COUNT(*) FROM users WHERE role = 'student' AND last_seen > $1", [Date.now() - ONLINE_WINDOW_MS])).rows[0].count);
    res.json({ items: rows.map(withPresence), total, page, pages: Math.max(1, Math.ceil(total / limit)), online });
}));

app.post('/api/admin/students/:id/lock', verifyToken, requireAdmin, wrap(async (req, res) => {
    const id = toInt(req.params.id), locked = req.body.locked; if (!id || typeof locked !== 'boolean') return res.status(400).json({ error: 'Yêu cầu không hợp lệ.' });
    const result = await pool.query("UPDATE users SET is_locked = $1 WHERE id = $2 AND role = 'student'", [locked, id]);
    if (!result.rowCount) return res.status(404).json({ error: 'Không tìm thấy học sinh.' }); res.json({ message: locked ? 'Đã khóa tài khoản học sinh.' : 'Đã mở khóa tài khoản.' });
}));

app.delete('/api/admin/students/:id', verifyToken, requireAdmin, wrap(async (req, res) => {
    const id = toInt(req.params.id); if (!id) return res.status(400).json({ error: 'Yêu cầu không hợp lệ.' });
    const result = await pool.query("DELETE FROM users WHERE id = $1 AND role = 'student'", [id]);
    if (!result.rowCount) return res.status(404).json({ error: 'Không tìm thấy học sinh.' }); res.json({ message: 'Đã xóa tài khoản học sinh.' });
}));

app.get('/api/albums', verifyToken, wrap(async (req, res) => {
    const { rows } = await pool.query("SELECT DISTINCT subject FROM lectures WHERE category_type = 'thu_vien_hinh_anh' AND subject IS NOT NULL AND subject != '' AND deleted_at IS NULL ORDER BY subject"); res.json(rows.map(r => r.subject));
}));

function parseLectureFields(b) {
    const title = cleanStr(b.title), description = cleanStr(b.description), category = cleanStr(b.category_type) || 'bai_giang'; 
    let grade = cleanStr(String(b.grade ?? '')), subject = cleanStr(b.subject ?? '');
    let week_start = toInt(b.week_start) || null;
    let week_end = toInt(b.week_end) || null;

    if (!title || title.length > 255) return { error: 'Tên tài liệu phải từ 1 đến 255 ký tự.' };
    if (description.length > 2000) return { error: 'Mô tả tối đa 2000 ký tự.' };
    if (!CATEGORIES.includes(category)) return { error: 'Loại tài liệu không hợp lệ.' };
    
    if (week_start && week_end && week_start > week_end) return { error: 'Tuần kết thúc phải lớn hơn hoặc bằng tuần bắt đầu.' };

    if (CATEGORIES_WITH_GRADE_SUBJECT.includes(category)) { 
        if (grade && !GRADES.includes(grade)) return { error: 'Khối lớp không hợp lệ.' }; 
        if (subject && !SUBJECTS.includes(subject)) return { error: 'Môn học không hợp lệ.' }; 
    } else if (category === 'thu_vien_hinh_anh') { 
        grade = ''; 
        if (!subject) return { error: 'Vui lòng điền tên Album ảnh.' }; 
        if (subject.length > 100) return { error: 'Tên Album tối đa 100 ký tự.' }; 
    } else { 
        grade = ''; subject = ''; 
    } 
    return { value: { title, description, grade, subject, category, week_start, week_end } };
}

const canManageLecture = (user, lecture) => isAdmin(user) || (user.role === 'teacher' && user.can_manage_docs && lecture.author_id === user.id);

app.post('/api/lectures/get-upload-url', verifyToken, requireStaff, wrap(async (req, res) => {
    const { files } = req.body; if (!files || !files.length) return res.status(400).json({ error: 'Không có file.' }); if (files.length > 20) return res.status(400).json({ error: 'Tối đa 20 file.' });
    const uploadUrls = [];
    for (const f of files) {
        const ext = path.extname(f.name).toLowerCase(), cleanName = path.basename(f.name, ext).normalize('NFD').replace(/[\u0300-\u036f]/g, '').replace(/đ/g, 'd').replace(/Đ/g, 'D').replace(/[^a-zA-Z0-9]/g, '_').slice(0, 60) || 'file';
        const fileName = `tailieu/${cleanName}_${Date.now()}_${Math.floor(Math.random()*1000)}${ext}`;
        const { data, error } = await supabase.storage.from('thuvien').createSignedUploadUrl(fileName); if (error) throw new Error('Không thể tạo link upload đám mây: ' + error.message);
        const { data: publicUrlData } = supabase.storage.from('thuvien').getPublicUrl(fileName);
        uploadUrls.push({ originalName: f.name, signedUrl: data.signedUrl, publicUrl: publicUrlData.publicUrl, fileType: ext.substring(1) });
    }
    res.json({ urls: uploadUrls });
}));

app.post('/api/lectures', verifyToken, requireStaff, wrap(async (req, res) => {
    const { link_url, uploadedFiles } = req.body; const parsed = parseLectureFields(req.body); if (parsed.error) return res.status(400).json({ error: parsed.error }); const f = parsed.value;
    if (uploadedFiles && uploadedFiles.length > 0) {
        const promises = uploadedFiles.map(async (file, index) => { 
            const displayTitle = uploadedFiles.length > 1 ? `${f.title} (${index + 1})` : f.title; 
            return pool.query(
                'INSERT INTO lectures (title, description, grade, subject, category_type, file_name, file_url, file_type, author_name, author_id, week_start, week_end) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)', 
                [displayTitle, f.description, f.grade, f.subject, f.category, file.originalName.slice(0, 255), file.publicUrl, file.fileType, req.user.name, req.user.id, f.week_start, f.week_end]
            ); 
        });
        await Promise.all(promises);
    } else if (link_url) {
        if (!/^https?:\/\//i.test(link_url)) return res.status(400).json({ error: 'Đường dẫn (URL) phải bắt đầu bằng http:// hoặc https://' }); const originalName = link_url.length > 200 ? link_url.substring(0, 200) + '...' : link_url;
        await pool.query(
            'INSERT INTO lectures (title, description, grade, subject, category_type, file_name, file_url, file_type, author_name, author_id, week_start, week_end) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)', 
            [f.title, f.description, f.grade, f.subject, f.category, originalName.slice(0, 255), link_url, 'url', req.user.name, req.user.id, f.week_start, f.week_end]
        );
    } else { return res.status(400).json({ error: 'Chưa đính kèm file hoặc URL.' }); }
    res.json({ message: 'Đăng tài liệu thành công!' });
}));

app.get('/api/lectures', verifyToken, wrap(async (req, res) => {
    const where = [], vals = []; const add = (sql, v) => { vals.push(v); where.push(sql.split('?').join('$' + vals.length)); };
    const category = cleanStr(req.query.category_type);
    
    if (category && !CATEGORIES.includes(category)) return res.status(400).json({ error: 'Loại tài liệu không hợp lệ.' });
    if (!isStaff(req.user)) { if (category && !STUDENT_CATEGORIES.includes(category)) return res.status(403).json({ error: 'Bạn không có quyền xem mục này.' }); add('category_type = ANY(?)', STUDENT_CATEGORIES); }
    if (category) add('category_type = ?', category); 
    
    const grade = cleanStr(String(req.query.grade ?? '')); if (grade) add('grade = ?', grade);
    const subject = cleanStr(req.query.subject); if (subject) add('subject = ?', subject.slice(0, 100));
    const search = cleanStr(req.query.search).slice(0, 100); if (search) add('(title ILIKE ? OR description ILIKE ?)', '%' + search.replace(/[\\%_]/g, '\\$&') + '%');
    
    const week = toInt(req.query.week);
    if (week) {
        add('COALESCE(week_start, week_end) <= ? AND COALESCE(week_end, week_start) >= ?', week); 
        vals.push(week); 
        where[where.length - 1] = `COALESCE(week_start, week_end) <= $${vals.length - 1} AND COALESCE(week_end, week_start) >= $${vals.length}`;
    }

    if (req.query.bookmarked === '1') {
        add('EXISTS (SELECT 1 FROM bookmarks b WHERE b.lecture_id = lectures.id AND b.user_id = ?)', req.user.id);
    }

    where.push('deleted_at IS NULL');
    const limit = Math.min(toInt(req.query.limit) || 12, 50), page = toInt(req.query.page) || 1; const whereSql = where.length ? 'WHERE ' + where.join(' AND ') : '';
    const total = Number((await pool.query(`SELECT COUNT(*) FROM lectures ${whereSql}`, vals)).rows[0].count);
    
    const { rows } = await pool.query(`SELECT id, title, description, grade, subject, category_type, file_type, file_url, author_name, author_id, views_count, avg_rating, created_at, week_start, week_end, EXISTS(SELECT 1 FROM bookmarks b2 WHERE b2.lecture_id = lectures.id AND b2.user_id = $${vals.length + 1}) AS is_bookmarked FROM lectures ${whereSql} ORDER BY created_at DESC, id DESC LIMIT ${limit} OFFSET ${(page - 1) * limit}`, [...vals, req.user.id]);
    res.json({ items: rows, total, page, pages: Math.max(1, Math.ceil(total / limit)) });
}));

app.get('/api/lectures/:id', verifyToken, wrap(async (req, res) => {
    const id = toInt(req.params.id); if (!id) return res.status(404).json({ error: 'Không tìm thấy tài liệu.' });
    const countView = req.query.count_view !== '0'; const params = [id]; let extra = ' AND deleted_at IS NULL';
    if (!isStaff(req.user)) { params.push(STUDENT_CATEGORIES); extra += ' AND category_type = ANY($2)'; }
    const sql = countView ? `UPDATE lectures SET views_count = views_count + 1 WHERE id = $1${extra} RETURNING *` : `SELECT * FROM lectures WHERE id = $1${extra}`;
    const { rows } = await pool.query(sql, params); if (!rows[0]) return res.status(404).json({ error: 'Không tìm thấy tài liệu (hoặc đã bị đưa vào thùng rác).' });
    const revs = await pool.query(`SELECT r.id, r.author_name AS author, r.stars, r.comment, to_char(r.created_at, 'DD/MM/YYYY') AS created_at, (r.user_id = $2) AS mine FROM reviews r WHERE r.lecture_id = $1 ORDER BY r.created_at DESC, r.id DESC`, [id, req.user.id]);
    const lecture = rows[0]; lecture.ratings = revs.rows.map(({ mine, ...r }) => r); lecture.already_reviewed = revs.rows.some((r) => r.mine); lecture.can_manage = canManageLecture(req.user, lecture); res.json(lecture);
}));

app.post('/api/lectures/:id/reviews', verifyToken, wrap(async (req, res) => {
    const id = toInt(req.params.id), stars = Number(req.body.stars), comment = cleanStr(req.body.comment);
    if (!id) return res.status(404).json({ error: 'Không tìm thấy tài liệu.' }); if (!Number.isInteger(stars) || stars < 1 || stars > 5) return res.status(400).json({ error: 'Số sao phải từ 1 đến 5.' }); if (!comment || comment.length > 1000) return res.status(400).json({ error: 'Nhận xét phải từ 1 đến 1000 ký tự.' });
    const lec = await pool.query('SELECT category_type, author_id FROM lectures WHERE id = $1', [id]); if (!lec.rows[0] || !canAccessCategory(req.user, lec.rows[0].category_type)) return res.status(404).json({ error: 'Không tìm thấy tài liệu.' });
    try { await pool.query('INSERT INTO reviews (lecture_id, user_id, author_name, stars, comment) VALUES ($1, $2, $3, $4, $5)', [id, req.user.id, req.user.name, stars, comment]); } catch (err) { if (err.code === '23505') return res.status(409).json({ error: 'Bạn đã đánh giá tài liệu này rồi.' }); throw err; }
    await pool.query('UPDATE lectures SET avg_rating = (SELECT ROUND(AVG(stars)::numeric, 1) FROM reviews WHERE lecture_id = $1) WHERE id = $1', [id]); 

    if (lec.rows[0].author_id && lec.rows[0].author_id !== req.user.id) {
        const revMsg = `${req.user.name} vừa để lại đánh giá ${stars} sao cho tài liệu của bạn.`;
        await pool.query('INSERT INTO notifications (user_id, type, content, target_url) VALUES ($1, $2, $3, $4)', [lec.rows[0].author_id, 'review', revMsg, `/view.html?id=${id}`]);
    }

    res.json({ message: 'Đã gửi đánh giá!' });
}));

app.put('/api/lectures/:id', verifyToken, requireStaff, wrap(async (req, res) => {
    const id = toInt(req.params.id); if (!id) return res.status(404).json({ error: 'Không tìm thấy tài liệu.' });
    const { rows } = await pool.query('SELECT id, author_id FROM lectures WHERE id = $1 AND deleted_at IS NULL', [id]); if (!rows[0]) return res.status(404).json({ error: 'Không tìm thấy tài liệu.' });
    if (!canManageLecture(req.user, rows[0])) return res.status(403).json({ error: 'Bạn không có quyền sửa tài liệu này (Cần được cấp quyền sửa/xóa).' });
    
    const parsed = parseLectureFields(req.body); if (parsed.error) return res.status(400).json({ error: parsed.error }); const f = parsed.value;
    
    await pool.query(
        'UPDATE lectures SET title=$1, description=$2, grade=$3, subject=$4, category_type=$5, week_start=$6, week_end=$7 WHERE id=$8', 
        [f.title, f.description, f.grade, f.subject, f.category, f.week_start, f.week_end, id]
    ); res.json({ message: 'Đã cập nhật tài liệu!' });
}));

app.delete('/api/lectures/:id', verifyToken, requireStaff, wrap(async (req, res) => {
    const id = toInt(req.params.id); if (!id) return res.status(404).json({ error: 'Không tìm thấy tài liệu.' });
    const { rows } = await pool.query('SELECT id, author_id FROM lectures WHERE id = $1 AND deleted_at IS NULL', [id]); if (!rows[0]) return res.status(404).json({ error: 'Không tìm thấy tài liệu.' });
    if (!canManageLecture(req.user, rows[0])) return res.status(403).json({ error: 'Bạn không có quyền xóa tài liệu này (Cần được cấp quyền sửa/xóa).' });
    await pool.query('UPDATE lectures SET deleted_at = CURRENT_TIMESTAMP WHERE id = $1', [id]); res.json({ message: 'Đã chuyển tài liệu vào thùng rác!' });
}));

app.post('/api/lectures/multi-delete', verifyToken, requireStaff, wrap(async (req, res) => {
    const ids = req.body.ids; if (!Array.isArray(ids) || !ids.length) return res.status(400).json({ error: 'Chưa chọn tài liệu.' });
    let query = '', vals = [];
    if (isAdmin(req.user)) { query = 'UPDATE lectures SET deleted_at = CURRENT_TIMESTAMP WHERE id = ANY($1) AND deleted_at IS NULL'; vals = [ids]; } 
    else { if (!req.user.can_manage_docs) return res.status(403).json({ error: 'Bạn chưa được cấp quyền xóa.' }); query = 'UPDATE lectures SET deleted_at = CURRENT_TIMESTAMP WHERE id = ANY($1) AND author_id = $2 AND deleted_at IS NULL'; vals = [ids, req.user.id]; }
    await pool.query(query, vals); res.json({ message: 'Đã chuyển các tài liệu đã chọn vào thùng rác!' });
}));

app.get('/api/trash', verifyToken, requireStaff, wrap(async (req, res) => {
    let query = `SELECT id, title, category_type, GREATEST(0, 30 - EXTRACT(DAY FROM CURRENT_TIMESTAMP - deleted_at))::int AS days_left FROM lectures WHERE deleted_at IS NOT NULL`, vals = [];
    if (!isAdmin(req.user)) { query += ' AND author_id = $1'; vals.push(req.user.id); } query += ' ORDER BY deleted_at DESC';
    const { rows } = await pool.query(query, vals); res.json(rows);
}));

app.post('/api/trash/restore', verifyToken, requireStaff, wrap(async (req, res) => {
    const ids = req.body.ids; if (!Array.isArray(ids) || !ids.length) return res.status(400).json({ error: 'Chưa chọn tài liệu.' });
    let query = isAdmin(req.user) ? 'UPDATE lectures SET deleted_at = NULL WHERE id = ANY($1)' : 'UPDATE lectures SET deleted_at = NULL WHERE id = ANY($1) AND author_id = $2';
    let vals = isAdmin(req.user) ? [ids] : [ids, req.user.id]; await pool.query(query, vals); res.json({ message: 'Đã khôi phục tài liệu thành công!' });
}));

app.post('/api/trash/permanent', verifyToken, requireStaff, wrap(async (req, res) => {
    const ids = req.body.ids; if (!Array.isArray(ids) || !ids.length) return res.status(400).json({ error: 'Chưa chọn tài liệu.' });
    let query = isAdmin(req.user) ? 'SELECT id, file_url, file_type FROM lectures WHERE id = ANY($1) AND deleted_at IS NOT NULL' : 'SELECT id, file_url, file_type FROM lectures WHERE id = ANY($1) AND author_id = $2 AND deleted_at IS NOT NULL';
    let vals = isAdmin(req.user) ? [ids] : [ids, req.user.id];
    const { rows } = await pool.query(query, vals); const validIds = rows.map(r => r.id);
    if (validIds.length) { await pool.query('DELETE FROM lectures WHERE id = ANY($1)', [validIds]); for (const r of rows) { if (r.file_type !== 'url') await destroyCloudFile(r.file_url); } }
    res.json({ message: 'Đã xóa vĩnh viễn các tài liệu được chọn!' });
}));

const CLASS_ID_RE = /^[A-Za-z0-9]{1,10}$/;
const DEFAULT_SCHEDULE = [['Tiết 1', '07:30'], ['Tiết 2', '08:15'], ['Tiết 3', '09:20'], ['Tiết 4', '10:05'], ['Tiết 5', '10:50']].map(([period, time]) => ({ period, time, t2: '', t3: '', t4: '', t5: '', t6: '' }));

app.get('/api/classes', verifyToken, wrap(async (req, res) => { const { rows } = await pool.query('SELECT class_id, class_name, teacher_name FROM classes ORDER BY class_id'); res.json(rows); }));
app.post('/api/classes', verifyToken, requireAdmin, wrap(async (req, res) => {
    const classId = cleanStr(req.body.class_id).toUpperCase(), teacher = cleanStr(req.body.teacher_name), name = cleanStr(req.body.class_name) || `Lớp ${classId}`;
    if (!CLASS_ID_RE.test(classId)) return res.status(400).json({ error: 'Mã lớp chỉ gồm chữ và số, tối đa 10 ký tự.' }); if (name.length > 100 || teacher.length > 100) return res.status(400).json({ error: 'Tên lớp và tên giáo viên tối đa 100 ký tự.' });
    await pool.query('INSERT INTO classes (class_id, class_name, teacher_name) VALUES ($1, $2, $3) ON CONFLICT (class_id) DO UPDATE SET class_name = EXCLUDED.class_name, teacher_name = EXCLUDED.teacher_name', [classId, name, teacher]); res.json({ message: 'Đã lưu lớp học!' });
}));
app.delete('/api/classes/:classId', verifyToken, requireAdmin, wrap(async (req, res) => {
    const classId = cleanStr(req.params.classId).toUpperCase(); if (!CLASS_ID_RE.test(classId)) return res.status(400).json({ error: 'Mã lớp không hợp lệ.' });
    await pool.query('DELETE FROM timetable WHERE class_id = $1', [classId]); const result = await pool.query('DELETE FROM classes WHERE class_id = $1', [classId]);
    if (!result.rowCount) return res.status(404).json({ error: 'Không tìm thấy lớp.' }); res.json({ message: 'Đã xóa lớp học!' });
}));

app.get('/api/timetable/:classId', verifyToken, wrap(async (req, res) => {
    const classId = cleanStr(req.params.classId).toUpperCase(); if (!CLASS_ID_RE.test(classId)) return res.status(400).json({ error: 'Mã lớp không hợp lệ.' });
    const cls = await pool.query('SELECT 1 FROM classes WHERE class_id = $1', [classId]); if (!cls.rows.length) return res.status(404).json({ error: 'Không tìm thấy lớp.' });
    const { rows } = await pool.query('SELECT schedule FROM timetable WHERE class_id = $1', [classId]); res.json(rows[0] ? rows[0].schedule : DEFAULT_SCHEDULE);
}));
app.post('/api/timetable/:classId', verifyToken, requireAdmin, wrap(async (req, res) => {
    const classId = cleanStr(req.params.classId).toUpperCase(); if (!CLASS_ID_RE.test(classId)) return res.status(400).json({ error: 'Mã lớp không hợp lệ.' });
    const cls = await pool.query('SELECT 1 FROM classes WHERE class_id = $1', [classId]); if (!cls.rows.length) return res.status(404).json({ error: 'Không tìm thấy lớp.' });
    const input = req.body.schedule; if (!Array.isArray(input) || input.length < 1 || input.length > 15) return res.status(400).json({ error: 'Thời khóa biểu phải có từ 1 đến 15 tiết.' });
    const fields = ['period', 'time', 't2', 't3', 't4', 't5', 't6'], schedule = [];
    for (const row of input) { if (!row || typeof row !== 'object') return res.status(400).json({ error: 'Dữ liệu thời khóa biểu không hợp lệ.' }); const clean = {}; for (const f of fields) { const v = cleanStr(row[f]); if (v.length > 60) return res.status(400).json({ error: 'Mỗi ô tối đa 60 ký tự.' }); clean[f] = v; } schedule.push(clean); }
    await pool.query('INSERT INTO timetable (class_id, schedule) VALUES ($1, $2) ON CONFLICT (class_id) DO UPDATE SET schedule = EXCLUDED.schedule', [classId, JSON.stringify(schedule)]); res.json({ message: 'Lưu lịch thành công!' });
}));

app.delete('/api/lectures/:id/reviews/:reviewId', verifyToken, requireAdmin, wrap(async (req, res) => {
    const lectureId = toInt(req.params.id);
    const reviewId = toInt(req.params.reviewId);
    if (!lectureId || !reviewId) return res.status(400).json({ error: 'Đường dẫn không hợp lệ.' });
    
    const result = await pool.query('DELETE FROM reviews WHERE id = $1 AND lecture_id = $2', [reviewId, lectureId]);
    if (!result.rowCount) return res.status(404).json({ error: 'Không tìm thấy đánh giá (hoặc đã bị xóa trước đó).' });
    
    await pool.query(
        'UPDATE lectures SET avg_rating = COALESCE((SELECT ROUND(AVG(stars)::numeric, 1) FROM reviews WHERE lecture_id = $1), 5.0) WHERE id = $1', 
        [lectureId]
    );
    res.json({ message: 'Đã xóa đánh giá thành công!' });
}));

app.use('/api', (req, res) => res.status(404).json({ error: 'Không tìm thấy đường dẫn.' }));
app.use((err, req, res, next) => {
    if (res.headersSent) return next(err);
    if (err instanceof multer.MulterError) return res.status(400).json({ error: err.code === 'LIMIT_FILE_SIZE' ? 'File vượt quá dung lượng cho phép.' : 'Lỗi khi tải file lên.' });
    if (err.isHttp) return res.status(err.status).json({ error: err.message });
    if (err.type === 'entity.parse.failed' || err.type === 'entity.too.large') return res.status(400).json({ error: 'Dữ liệu gửi lên không hợp lệ.' });
    console.error('Lỗi máy chủ:', err); res.status(500).json({ error: 'Lỗi máy chủ. Vui lòng thử lại sau.' });
});

process.on('unhandledRejection', (e) => console.error('Unhandled rejection:', e));
initDB().then(() => { app.listen(PORT, async () => {
    console.log(`>>> Máy chủ chạy tại: http://localhost:${PORT}`);
    if (!IS_PROD) { try { const ngrok = require('@ngrok/ngrok'); const listener = await ngrok.forward({ addr: PORT, authtoken: process.env.NGROK_AUTHTOKEN }); console.log(`>>> 🌐 Ngrok Tunnel (Public URL): ${listener.url()}`); } catch (err) { console.error('⚠ Không thể khởi động ngrok:', err.message); } }
}); }).catch((err) => { console.error('❌ Không khởi động được:', err.message); process.exit(1); });