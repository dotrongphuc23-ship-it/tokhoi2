const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');

const OTP_TTL = 10 * 60 * 1000;
const LINK_TTL = 15 * 60 * 1000;
const RESEND_COOLDOWN = 60 * 1000;
const MAX_ATTEMPTS = 5;

const sha = (s) => crypto.createHash('sha256').update(String(s)).digest('hex');
const safeEqual = (a, b) => {
    const x = Buffer.from(a), y = Buffer.from(b);
    return x.length === y.length && crypto.timingSafeEqual(x, y);
};

module.exports = function (app, { readData, writeData, USERS_FILE }) {
    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: { user: process.env.GMAIL_USER, pass: process.env.GMAIL_APP_PASS }
    });

    const findByEmail = (users, email) => users.find(u => u.email.toLowerCase() === String(email || '').toLowerCase().trim());
    const clearReset = (u) => { delete u.reset_otp_hash; delete u.reset_otp_expires; delete u.reset_attempts; delete u.reset_token_hash; delete u.reset_token_expires; };

    app.post('/api/auth/forgot-password', async (req, res) => {
        const email = String(req.body.email || '').trim();
        if (!email) return res.status(400).json({ error: 'Vui lòng nhập địa chỉ Gmail.' });
        const genericOk = { message: 'Nếu email tồn tại trong hệ thống, mã xác nhận đã được gửi.' };
        const users = readData(USERS_FILE);
        const user = findByEmail(users, email);
        if (!user) return res.json(genericOk);

        if (user.reset_sent_at && Date.now() - user.reset_sent_at < RESEND_COOLDOWN) return res.status(429).json({ error: `Vui lòng đợi 60 giây rồi gửi lại.` });

        const otp = String(crypto.randomInt(100000, 1000000));
        const token = crypto.randomBytes(32).toString('hex');
        const now = Date.now();

        user.reset_otp_hash = sha(otp); user.reset_otp_expires = now + OTP_TTL;
        user.reset_attempts = 0; user.reset_token_hash = sha(token);
        user.reset_token_expires = now + LINK_TTL; user.reset_sent_at = now;
        writeData(USERS_FILE, users);

        try {
            await transporter.sendMail({
                from: `"Cổng Thông Tin Học Tập" <${process.env.GMAIL_USER}>`,
                to: user.email,
                subject: 'Mã xác nhận khôi phục mật khẩu',
                html: `<h3>Khôi phục mật khẩu</h3><p>Mã OTP (10 phút): <b style="font-size:24px;letter-spacing:5px;">${otp}</b></p><p>Hoặc <a href="${process.env.PUBLIC_URL}/reset-password.html?token=${token}">nhấn vào đây</a> (15 phút).</p>`
            });
        } catch (err) { return res.status(500).json({ error: 'Lỗi máy chủ Gmail.' }); }
        res.json(genericOk);
    });

    app.post('/api/auth/verify-otp-reset', async (req, res) => {
        const { email, otp, new_password } = req.body;
        if (!new_password || String(new_password).length < 6) return res.status(400).json({ error: 'Mật khẩu > 6 ký tự.' });
        const users = readData(USERS_FILE); const user = findByEmail(users, email);
        if (!user || !user.reset_otp_hash || Date.now() > user.reset_otp_expires) return res.status(400).json({ error: 'OTP không hợp lệ hoặc hết hạn.' });
        if ((user.reset_attempts || 0) >= MAX_ATTEMPTS) return res.status(429).json({ error: 'Thử sai quá nhiều lần.' });
        if (!safeEqual(sha(String(otp || '').trim()), user.reset_otp_hash)) {
            user.reset_attempts = (user.reset_attempts || 0) + 1; writeData(USERS_FILE, users);
            return res.status(400).json({ error: `Mã OTP sai.` });
        }
        user.password_hash = await bcrypt.hash(new_password, 10); clearReset(user); writeData(USERS_FILE, users);
        res.json({ message: 'Đổi mật khẩu thành công!' });
    });

    app.post('/api/auth/reset-password', async (req, res) => {
        const { token, new_password } = req.body;
        if (!token || String(new_password).length < 6) return res.status(400).json({ error: 'Dữ liệu không hợp lệ.' });
        const users = readData(USERS_FILE); const user = users.find(u => u.reset_token_hash && safeEqual(u.reset_token_hash, sha(token)));
        if (!user || Date.now() > user.reset_token_expires) return res.status(400).json({ error: 'Link hết hạn.' });
        user.password_hash = await bcrypt.hash(new_password, 10); clearReset(user); writeData(USERS_FILE, users);
        res.json({ message: 'Đổi mật khẩu thành công!' });
    });
};