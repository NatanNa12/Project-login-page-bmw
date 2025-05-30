require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const cookieParser = require('cookie-parser');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors({
  origin: `http://localhost:${PORT}`,
  credentials: true
}));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(cookieParser());

// Konfigurasi Database
const dbConfig = {
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
};

async function getConnection() {
    return await mysql.createConnection(dbConfig);
}

// --- FUNGSI PENGIRIMAN EMAIL ---
async function sendEmail(to, subject, htmlContent) {
    if (process.env.EMAIL_HOST && process.env.EMAIL_USER && process.env.EMAIL_PASS) {
        let transporter = nodemailer.createTransport({
            host: process.env.EMAIL_HOST,
            port: parseInt(process.env.EMAIL_PORT, 10),
            secure: process.env.EMAIL_SECURE === 'true',
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASS,
            },
            tls: {
                ciphers: 'SSLv3',
            }
        });
        let mailOptions = { from: process.env.EMAIL_FROM, to, subject, html: htmlContent };
        try {
            console.log(`Mencoba mengirim email ke: ${to} via ${process.env.EMAIL_HOST}:${process.env.EMAIL_PORT}`);
            let info = await transporter.sendMail(mailOptions);
            console.log('Email berhasil dikirim: %s', info.messageId);
            return info;
        } catch (error) {
            console.error('Error saat mengirim email (detail dari fungsi sendEmail):', error);
            throw new Error(`Gagal mengirim email ke ${to}. Kode Error: ${error.code}, Pesan Asli Server: ${error.response || error.message}`);
        }
    } else {
        console.log("--- SIMULASI PENGIRIMAN EMAIL (Variabel SMTP .env tidak diset atau tidak lengkap) ---");
        console.log("Kepada:", to);
        console.log("Subjek:", subject);
        if (htmlContent.includes("<strong>")) {
            const otpMatch = htmlContent.match(/<strong>(\d{6})<\/strong>/);
            if (otpMatch && otpMatch[1]) console.log("OTP (dari simulasi):", otpMatch[1]);
            else console.log("Isi (HTML sebagian):", htmlContent.substring(0, 300) + "...");
        } else if (htmlContent.includes("href=")) {
             const linkMatch = htmlContent.match(/href="(.*?)"/);
             if (linkMatch && linkMatch[1]) console.log("Link (dari simulasi):", linkMatch[1]);
             else console.log("Isi (HTML sebagian):", htmlContent.substring(0, 300) + "...");
        } else console.log("Isi (HTML sebagian):", htmlContent.substring(0, 300) + "...");
        console.log("--- AKHIR SIMULASI ---");
        return { messageId: "simulated_console_log_due_to_missing_env_vars" };
    }
}

// --- MIDDLEWARE UNTUK OTENTIKASI TOKEN JWT ---
function authenticateToken(req, res, next) {
    // Utamakan mengambil token dari cookie
    let token = req.cookies.authTokenBMW;
    
    // Jika tidak ada di cookie, coba dari header Authorization
    if (!token) {
        const authHeader = req.headers['authorization'];
        token = authHeader && authHeader.split(' ')[1];
    }

    console.log("Middleware authenticateToken: Menerima permintaan untuk:", req.originalUrl);
    console.log("Token yang diterima:", token ? "Ada" : "Tidak Ada");
    
    if (token == null) {
        console.log("Token tidak ditemukan (cookie atau header) untuk path:", req.originalUrl);
        if (req.originalUrl.startsWith('/api/')) {
            return res.status(401).json({ message: 'Akses ditolak. Token tidak disediakan.' });
        }
        return res.redirect('/login');
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            console.error("Token tidak valid atau kedaluwarsa untuk path", req.originalUrl, ":", err.message);
            if (req.cookies && req.cookies.authTokenBMW) {
                res.clearCookie('authTokenBMW');
            }
            if (req.originalUrl.startsWith('/api/')) {
                return res.status(403).json({ message: 'Akses ditolak. Token tidak valid.' });
            }
            return res.redirect('/login');
        }
        console.log("Token valid untuk user:", user.username, "mengakses path:", req.originalUrl);
        req.user = user;
        next();
    });
}

// --- RUTE PENYAJIAN HALAMAN HTML ---
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/register', (req, res) => res.sendFile(path.join(__dirname, 'public', 'register.html')));
app.get('/forgot-password', (req, res) => res.sendFile(path.join(__dirname, 'public', 'forgot-password.html')));
app.get('/reset-password.html', (req, res) => res.sendFile(path.join(__dirname, 'public', 'reset-password.html')));
app.get('/verify-email.html', (req, res) => res.sendFile(path.join(__dirname, 'public', 'verify-email.html')));

// RUTE DASHBOARD (DILINDUNGI OLEH authenticateToken)
app.get('/dashboard', authenticateToken, (req, res) => {
    console.log("Menyajikan halaman dashboard untuk pengguna terotentikasi:", req.user.username);
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});


// --- API ENDPOINTS ---

// REGISTRASI PENGGUNA BARU
app.post('/api/register', async (req, res) => {
    const { email, username, password } = req.body;
    if (!email || !username || !password) return res.status(400).json({ message: 'Email, Username, dan password diperlukan' });
    const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailPattern.test(email)) return res.status(400).json({ message: 'Format email tidak valid.' });
    if (password.length < 6) return res.status(400).json({ message: 'Password minimal harus 6 karakter.' });
    let connection;
    try {
        connection = await getConnection();
        const [existingUsers] = await connection.execute('SELECT * FROM users WHERE email = ? OR username = ?', [email, username]);
        if (existingUsers.length > 0) {
            if (existingUsers.find(u => u.email === email)) return res.status(409).json({ message: 'Email sudah digunakan.' });
            if (existingUsers.find(u => u.username === username)) return res.status(409).json({ message: 'Username sudah digunakan.' });
        }
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const saltOtp = await bcrypt.genSalt(10);
        const otpHash = await bcrypt.hash(otp, saltOtp);
        const otpExpiresAt = new Date(Date.now() + 15 * 60000);
        const saltPassword = await bcrypt.genSalt(10);
        const password_hash = await bcrypt.hash(password, saltPassword);
        await connection.execute(
            'INSERT INTO users (email, username, password_hash, is_verified, verification_token_hash, verification_token_expires_at) VALUES (?, ?, ?, ?, ?, ?)',
            [email, username, password_hash, false, otpHash, otpExpiresAt]
        );
        const emailSubject = 'Kode Verifikasi Akun BMW Anda';
        const emailHtmlContent = `<h1>Selamat Datang di BMW!</h1><p>Gunakan kode OTP berikut untuk memverifikasi email Anda: <strong>${otp}</strong></p><p>Kode ini akan kedaluwarsa dalam 15 menit.</p>`;
        try {
            await sendEmail(email, emailSubject, emailHtmlContent);
            res.status(201).json({ message: 'Registrasi berhasil! Kode verifikasi telah dikirim ke email Anda.' });
        } catch (emailError) {
            console.error("Gagal mengirim email verifikasi, tapi pengguna terdaftar:", emailError);
            res.status(201).json({ message: 'Registrasi berhasil, namun gagal mengirim email verifikasi. OTP (dev): ' + otp, otp_debug: otp });
        }
    } catch (error) {
        console.error('Error registrasi database:', error);
        res.status(500).json({ message: 'Terjadi kesalahan pada server saat registrasi' });
    } finally {
        if (connection) await connection.end();
    }
});

// VERIFIKASI EMAIL DENGAN OTP
app.post('/api/verify-email', async (req, res) => {
    const { identifier, otp } = req.body;
    if (!identifier || !otp) return res.status(400).json({ message: 'Email dan OTP diperlukan.' });
    if (!/^\d{6}$/.test(otp)) return res.status(400).json({ message: 'Format OTP tidak valid.' });
    let connection;
    try {
        connection = await getConnection();
        const [users] = await connection.execute('SELECT * FROM users WHERE email = ?', [identifier]);
        if (users.length === 0) return res.status(404).json({ message: 'Pengguna tidak ditemukan.' });
        const user = users[0];
        if (user.is_verified) return res.status(400).json({ message: 'Akun sudah diverifikasi.' });
        if (!user.verification_token_hash || !user.verification_token_expires_at) return res.status(400).json({ message: 'Tidak ada permintaan verifikasi aktif.' });
        if (new Date() > new Date(user.verification_token_expires_at)) {
            await connection.execute('UPDATE users SET verification_token_hash = NULL, verification_token_expires_at = NULL WHERE id = ?', [user.id]);
            return res.status(400).json({ message: 'Kode OTP kedaluwarsa.' });
        }
        const isOtpMatch = await bcrypt.compare(otp, user.verification_token_hash);
        if (!isOtpMatch) return res.status(400).json({ message: 'Kode OTP salah.' });
        await connection.execute('UPDATE users SET is_verified = TRUE, verification_token_hash = NULL, verification_token_expires_at = NULL WHERE id = ?', [user.id]);
        res.status(200).json({ message: 'Email berhasil diverifikasi! Silakan login.' });
    } catch (error) {
        console.error('Error verifikasi email:', error);
        res.status(500).json({ message: 'Kesalahan server.' });
    } finally {
        if (connection) await connection.end();
    }
});

// LOGIN PENGGUNA
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ message: 'Username dan password diperlukan' });
    let connection;
    try {
        connection = await getConnection();
        const [rows] = await connection.execute('SELECT * FROM users WHERE username = ?', [username]);
        if (rows.length === 0) {
            if (connection) await connection.end();
            return res.status(401).json({ message: 'Username atau password salah.' });
        }
        const user = rows[0];
        if (!user.is_verified) {
            if (connection) await connection.end();
            return res.status(403).json({ message: 'Akun Anda belum diverifikasi.', action: 'verify', identifier: user.email });
        }
        const isMatch = await bcrypt.compare(password, user.password_hash);
        if (!isMatch) {
            if (connection) await connection.end();
            return res.status(401).json({ message: 'Username atau password salah.' });
        }
        const payload = { userId: user.id, username: user.username, email: user.email };
        const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({
            message: 'Login berhasil!',
            token: token,
            user: {
                username: user.username,
                email: user.email
            }
        });
    } catch (error) {
        console.error('Error login:', error);
        res.status(500).json({ message: 'Terjadi kesalahan pada server saat login' });
    } finally {
        if (connection) await connection.end();
    }
});

// LUPA PASSWORD - MINTA RESET (Input Username, Kirim ke Email Terkait)
app.post('/api/forgot-password', async (req, res) => {
    const { username } = req.body;
    if (!username) return res.status(400).json({ message: 'Username diperlukan' });
    let connection;
    try {
        connection = await getConnection();
        const [users] = await connection.execute('SELECT id, username, email, is_verified FROM users WHERE username = ?', [username]);
        if (users.length === 0) {
            return res.status(200).json({ message: 'Jika username terdaftar dan email terverifikasi, instruksi akan dikirim.' });
        }
        const user = users[0];
        if (!user.is_verified || !user.email) {
            return res.status(200).json({ message: 'Jika username terdaftar dan email terverifikasi, instruksi akan dikirim.' });
        }
        const resetToken = crypto.randomBytes(32).toString('hex');
        const salt = await bcrypt.genSalt(10);
        const tokenHash = await bcrypt.hash(resetToken, salt);
        const expiresAt = new Date(Date.now() + 3600000);
        await connection.execute('DELETE FROM password_reset_tokens WHERE user_id = ?', [user.id]);
        await connection.execute('INSERT INTO password_reset_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)', [user.id, tokenHash, expiresAt]);
        const resetLink = `http://localhost:${PORT}/reset-password.html?token=${resetToken}&uid=${user.id}`;
        const emailSubject = 'Link Reset Password Akun BMW Anda';
        const emailHtmlContent = `<h1>Reset Password BMW</h1><p>Klik link ini: <a href="${resetLink}">${resetLink}</a></p>`;
        try {
            await sendEmail(user.email, emailSubject, emailHtmlContent);
            res.status(200).json({ message: 'Jika username terdaftar dan email terverifikasi, instruksi akan dikirim.' });
        } catch (emailError) {
            console.error("Gagal mengirim email reset password:", emailError);
            res.status(500).json({ message: 'Gagal mengirim email. Link (dev): ' + resetLink, reset_link_debug: resetLink});
        }
    } catch (error) {
        console.error('Error di /api/forgot-password:', error);
        res.status(500).json({ message: 'Kesalahan server' });
    } finally {
        if (connection) await connection.end();
    }
});

// LUPA PASSWORD - RESET DENGAN TOKEN
app.post('/api/reset-password', async (req, res) => {
    const { token, userId, newPassword } = req.body;
    if (!token || !userId || !newPassword) return res.status(400).json({ message: 'Data tidak lengkap.' });
    if (newPassword.length < 6) return res.status(400).json({ message: 'Password baru minimal 6 karakter.' });
    let connection;
    try {
        connection = await getConnection();
        const [tokenRows] = await connection.execute('SELECT id, token_hash FROM password_reset_tokens WHERE user_id = ? AND expires_at > NOW()', [userId]);
        if (tokenRows.length === 0) return res.status(400).json({ message: 'Token tidak valid/kedaluwarsa.' });
        let validTokenEntry = null;
        for (const row of tokenRows) {
            if (await bcrypt.compare(token, row.token_hash)) {
                validTokenEntry = row;
                break;
            }
        }
        if (!validTokenEntry) return res.status(400).json({ message: 'Token tidak valid/kedaluwarsa (match failed).' });
        const salt = await bcrypt.genSalt(10);
        const newPasswordHash = await bcrypt.hash(newPassword, salt);
        await connection.execute('UPDATE users SET password_hash = ? WHERE id = ?', [newPasswordHash, userId]);
        await connection.execute('DELETE FROM password_reset_tokens WHERE user_id = ?', [userId]);
        res.status(200).json({ message: 'Password berhasil direset. Silakan login.' });
    } catch (error) {
        console.error('Error di /api/reset-password:', error);
        res.status(500).json({ message: 'Kesalahan server' });
    } finally {
        if (connection) await connection.end();
    }
});

// Endpoint untuk mengambil data dashboard (dilindungi token)
app.get('/api/dashboard-data', authenticateToken, async (req, res) => {
    console.log("User data dari token untuk /api/dashboard-data:", req.user);
    try {
        const dashboardData = {
            username: req.user.username,
            email: req.user.email,
            totalSales: 175000000,
            monthlyTarget: 250000000,
            totalPoints: 1500,
            teamMembers: 10,
            recentActivities: [
                { date: '2025-05-30', description: 'Penjualan BMW iX', status: '+20 Poin' },
                { date: '2025-05-29', description: 'Follow up Prospek A', status: 'Dalam Proses' }
            ],
            salesChartData: {
                labels: ['Jan', 'Feb', 'Mar', 'Apr', 'Mei', 'Jun'],
                sales: [65, 59, 80, 81, 56, 55],
                targets: [70, 70, 90, 90, 60, 60]
            }
        };
        res.json(dashboardData);
    } catch (error) {
        console.error("Error mengambil data dashboard:", error);
        res.status(500).json({ message: "Gagal mengambil data dashboard." });
    }
});

// Jalankan server
app.listen(PORT, () => {
    console.log(`Server berjalan di http://localhost:${PORT}`);
    console.log(`Login: http://localhost:${PORT}/`);
    console.log(`Register: http://localhost:${PORT}/register`);
    console.log(`Verify Email (contoh): http://localhost:${PORT}/verify-email.html?identifier=test@example.com`);
    console.log(`Forgot Password: http://localhost:${PORT}/forgot-password`);
    console.log(`Dashboard: http://localhost:${PORT}/dashboard`);
});