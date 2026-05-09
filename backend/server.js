import express from 'express';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { randomBytes, randomUUID } from 'crypto';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DATA_DIR = path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'store.json');

const PORT = Number(process.env.PORT) || 9000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-doi-ngay-trong-production';
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'admin@localhost.local';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123456';

if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
}

const defaultStore = () => ({
    admin: {
        email: ADMIN_EMAIL,
        password_hash: bcrypt.hashSync(ADMIN_PASSWORD, 10),
        access_key: randomBytes(24).toString('hex'),
        name: 'Quản trị viên',
        tz: 'Asia/Ho_Chi_Minh',
        tenor_key: '',
        is_filter: false,
        is_confetti_animation: true,
        can_reply: true,
        can_edit: true,
        can_delete: true,
    },
    comments: [],
    likes: [],
});

const loadStore = () => {
    if (!fs.existsSync(DB_FILE)) {
        const created = defaultStore();
        fs.writeFileSync(DB_FILE, JSON.stringify(created, null, 2), 'utf8');
        console.log('\n=== UNDANGAN API — khởi tạo lần đầu ===');
        console.log('Email:', created.admin.email);
        console.log('Mật khẩu:', ADMIN_PASSWORD);
        console.log('Access key (dán vào data-key):', created.admin.access_key);
        console.log('=======================================\n');
        return created;
    }

    const raw = fs.readFileSync(DB_FILE, 'utf8');
    const parsed = JSON.parse(raw);
    parsed.comments = parsed.comments || [];
    parsed.likes = parsed.likes || [];
    return parsed;
};

let store = loadStore();

const saveStore = () => {
    fs.writeFileSync(DB_FILE, JSON.stringify(store, null, 2), 'utf8');
};

const formatDate = (d = new Date()) => {
    const pad = (n) => String(n).padStart(2, '0');
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
};

const ok = (res, data, status = 200) => res.status(status).json({ data, error: null });
const fail = (res, message, status = 400, id = null) => {
    const body = { data: null, error: [message] };
    if (id) {
        body.id = id;
    }
    return res.status(status).json(body);
};

const getTokenFromReq = (req) => {
    const h = req.headers.authorization;
    if (h?.startsWith('Bearer ')) {
        return h.slice(7);
    }
    return req.headers['x-access-key'] || null;
};

const authMiddleware = (req, res, next) => {
    const raw = getTokenFromReq(req);
    if (!raw) {
        return fail(res, 'Thiếu token hoặc access key.', 401);
    }

    if (raw === store.admin.access_key) {
        req.auth = { type: 'guest' };
        return next();
    }

    try {
        const payload = jwt.verify(raw, JWT_SECRET);
        if (payload.sub === 'admin') {
            req.auth = { type: 'jwt' };
            return next();
        }
    } catch {
        return fail(res, 'Token không hợp lệ.', 401);
    }

    return fail(res, 'Token không hợp lệ.', 401);
};

const requireJwt = (req, res, next) => {
    if (req.auth?.type !== 'jwt') {
        return fail(res, 'Cần đăng nhập quản trị.', 403);
    }
    next();
};

const resolveTenorGifUrl = async (gifId, tenorKey) => {
    if (!tenorKey || !gifId) {
        return null;
    }
    const url = `https://tenor.googleapis.com/v2/posts?ids=${encodeURIComponent(gifId)}&key=${encodeURIComponent(tenorKey)}`;
    const r = await fetch(url);
    if (!r.ok) {
        return null;
    }
    const j = await r.json();
    const media = j.results?.[0]?.media_formats;
    return media?.tinygif?.url || media?.gif?.url || null;
};

const countLike = (commentUuid) => store.likes.filter((i) => i.comment_uuid === commentUuid).length;

const toApiComment = (row, children = []) => ({
    uuid: row.uuid,
    own: row.own_secret,
    name: row.name,
    presence: Boolean(row.presence),
    comment: row.comment,
    created_at: row.created_at,
    is_admin: Boolean(row.is_admin),
    is_parent: !row.parent_uuid,
    gif_url: row.gif_url,
    ip: row.ip,
    user_agent: row.user_agent,
    comments: children,
    like_count: countLike(row.uuid),
});

const buildTree = (parentUuid) => {
    const children = store.comments
        .filter((c) => c.parent_uuid === parentUuid)
        .sort((a, b) => a.created_at.localeCompare(b.created_at));

    return children.map((c) => toApiComment(c, buildTree(c.uuid)));
};

const app = express();
app.use(cors({ origin: process.env.CORS_ORIGIN || true, credentials: true }));
app.use(express.json({ limit: '1mb' }));

app.get('/health', (_req, res) => res.json({ ok: true }));

app.get('/api/v2/config', authMiddleware, (_req, res) => {
    const a = store.admin;
    ok(res, {
        tz: a.tz,
        is_confetti_animation: a.is_confetti_animation,
        can_reply: a.can_reply,
        can_edit: a.can_edit,
        can_delete: a.can_delete,
        tenor_key: a.tenor_key || '',
    });
});

app.get('/api/v2/comment', authMiddleware, (req, res) => {
    const per = Math.min(100, Math.max(1, parseInt(req.query.per, 10) || 10));
    const nextOff = Math.max(0, parseInt(req.query.next, 10) || 0);
    const roots = store.comments
        .filter((c) => c.parent_uuid === null)
        .sort((a, b) => b.created_at.localeCompare(a.created_at));

    const page = roots.slice(nextOff, nextOff + per).map((r) => toApiComment(r, buildTree(r.uuid)));
    ok(res, { count: roots.length, lists: page });
});

app.post('/api/comment', authMiddleware, async (req, res) => {
    const { id: parentId, name, presence, comment, gif_id: gifId } = req.body || {};
    if (!name || String(name).trim().length === 0) {
        return fail(res, 'Tên không được để trống.');
    }

    if (!gifId && (!comment || String(comment).trim().length === 0)) {
        return fail(res, 'Nội dung bình luận không được để trống.');
    }

    if (parentId && !store.comments.find((c) => c.uuid === parentId)) {
        return fail(res, 'Bình luận cha không tồn tại.', 404);
    }

    let gifUrl = null;
    if (gifId) {
        gifUrl = await resolveTenorGifUrl(String(gifId), store.admin.tenor_key);
        if (!gifUrl) {
            return fail(res, 'Không lấy được ảnh GIF. Kiểm tra Tenor key.');
        }
    }

    const row = {
        uuid: randomUUID(),
        parent_uuid: parentId || null,
        own_secret: randomBytes(16).toString('hex'),
        name: String(name).trim(),
        presence: presence ? 1 : 0,
        comment: gifId ? null : String(comment).trim(),
        gif_url: gifUrl,
        ip: req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || '',
        user_agent: req.headers['user-agent'] || '',
        is_admin: req.auth.type === 'jwt',
        created_at: formatDate(),
    };

    store.comments.push(row);
    saveStore();
    return ok(res, toApiComment(row, []), 201);
});

app.put('/api/comment/:own', authMiddleware, async (req, res) => {
    const row = store.comments.find((c) => c.own_secret === req.params.own);
    if (!row) {
        return fail(res, 'Không tìm thấy bình luận.', 404);
    }

    const { presence, comment, gif_id: gifId } = req.body || {};

    if (presence !== null && presence !== undefined) {
        row.presence = presence ? 1 : 0;
    }

    if (gifId) {
        const gifUrl = await resolveTenorGifUrl(String(gifId), store.admin.tenor_key);
        if (!gifUrl) {
            return fail(res, 'Không lấy được ảnh GIF.');
        }
        row.gif_url = gifUrl;
        row.comment = null;
    } else if (comment !== null && comment !== undefined) {
        row.comment = String(comment);
    }

    const hasText = row.comment !== null && row.comment !== undefined && String(row.comment).trim().length > 0;
    if (!row.gif_url && !hasText) {
        return fail(res, 'Nội dung không được để trống.');
    }

    saveStore();
    return ok(res, { status: true });
});

app.delete('/api/comment/:own', authMiddleware, (req, res) => {
    const target = store.comments.find((c) => c.own_secret === req.params.own);
    if (!target) {
        return fail(res, 'Không tìm thấy bình luận.', 404);
    }

    const removeIds = new Set();
    const walk = (id) => {
        removeIds.add(id);
        store.comments.filter((c) => c.parent_uuid === id).forEach((c) => walk(c.uuid));
    };
    walk(target.uuid);

    store.comments = store.comments.filter((c) => !removeIds.has(c.uuid));
    store.likes = store.likes.filter((l) => !removeIds.has(l.comment_uuid));
    saveStore();
    return ok(res, { status: true });
});

app.post('/api/comment/:commentUuid', authMiddleware, (req, res) => {
    const c = store.comments.find((i) => i.uuid === req.params.commentUuid);
    if (!c) {
        return fail(res, 'Bình luận không tồn tại.', 404);
    }

    const row = { uuid: randomUUID(), comment_uuid: c.uuid, created_at: formatDate() };
    store.likes.push(row);
    saveStore();
    return ok(res, { uuid: row.uuid }, 201);
});

app.patch('/api/comment/:likeUuid', authMiddleware, (req, res) => {
    const before = store.likes.length;
    store.likes = store.likes.filter((l) => l.uuid !== req.params.likeUuid);
    if (store.likes.length === before) {
        return fail(res, 'Không tìm thấy lượt thích.', 404);
    }
    saveStore();
    return ok(res, { status: true });
});

app.post('/api/session', (req, res) => {
    const { email, password } = req.body || {};
    if (!email || !password) {
        return fail(res, 'Email hoặc mật khẩu trống.');
    }

    if (email !== store.admin.email || !bcrypt.compareSync(String(password), store.admin.password_hash)) {
        return fail(res, 'Đăng nhập thất bại.', 401);
    }

    const token = jwt.sign({ sub: 'admin' }, JWT_SECRET, { expiresIn: '30d' });
    return ok(res, { token });
});

app.get('/api/user', authMiddleware, requireJwt, (_req, res) => {
    const a = store.admin;
    ok(res, {
        name: a.name,
        email: a.email,
        access_key: a.access_key,
        tz: a.tz,
        tenor_key: a.tenor_key || '',
        is_filter: a.is_filter,
        is_confetti_animation: a.is_confetti_animation,
        can_reply: a.can_reply,
        can_edit: a.can_edit,
        can_delete: a.can_delete,
    });
});

app.patch('/api/user', authMiddleware, requireJwt, (req, res) => {
    const b = req.body || {};

    if (b.old_password !== undefined && b.new_password !== undefined) {
        if (!bcrypt.compareSync(String(b.old_password), store.admin.password_hash)) {
            return fail(res, 'Mật khẩu cũ không đúng.');
        }
        if (String(b.new_password).length < 8) {
            return fail(res, 'Mật khẩu mới phải từ 8 ký tự.');
        }
        store.admin.password_hash = bcrypt.hashSync(String(b.new_password), 10);
        saveStore();
        return ok(res, { status: true });
    }

    if (b.name !== undefined) {
        store.admin.name = String(b.name);
    } else if (b.tz !== undefined) {
        store.admin.tz = String(b.tz);
    } else if (b.tenor_key !== undefined) {
        store.admin.tenor_key = b.tenor_key ? String(b.tenor_key) : '';
    } else if (b.filter !== undefined) {
        store.admin.is_filter = Boolean(b.filter);
    } else if (b.confetti_animation !== undefined) {
        store.admin.is_confetti_animation = Boolean(b.confetti_animation);
    } else if (b.can_reply !== undefined) {
        store.admin.can_reply = Boolean(b.can_reply);
    } else if (b.can_edit !== undefined) {
        store.admin.can_edit = Boolean(b.can_edit);
    } else if (b.can_delete !== undefined) {
        store.admin.can_delete = Boolean(b.can_delete);
    } else {
        return fail(res, 'Không có trường cập nhật hợp lệ.');
    }

    saveStore();
    return ok(res, { status: true });
});

app.put('/api/key', authMiddleware, requireJwt, (_req, res) => {
    store.admin.access_key = randomBytes(24).toString('hex');
    saveStore();
    return ok(res, { status: true });
});

app.get('/api/stats', authMiddleware, requireJwt, (_req, res) => {
    const roots = store.comments.filter((c) => c.parent_uuid === null && !c.is_admin);
    ok(res, {
        comments: store.comments.length,
        likes: store.likes.length,
        present: roots.filter((c) => Boolean(c.presence)).length,
        absent: roots.filter((c) => !Boolean(c.presence)).length,
    });
});

app.get('/api/download', authMiddleware, requireJwt, (_req, res) => {
    const rows = store.comments
        .filter((c) => !c.is_admin)
        .sort((a, b) => b.created_at.localeCompare(a.created_at));
    const esc = (s) => `"${String(s ?? '').replace(/"/g, '""')}"`;
    const header = 'Tên,Nội dung,Tham dự,Ngày,IP\n';
    const body = rows
        .map((r) => [esc(r.name), esc(r.comment), r.presence ? 'Có' : 'Không', esc(r.created_at), esc(r.ip)].join(','))
        .join('\n');
    const csv = '\ufeff' + header + body;
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="binh-luan.csv"');
    res.send(csv);
});

app.use((err, _req, res, _next) => {
    console.error(err);
    fail(res, 'Lỗi máy chủ.', 500, 'srv');
});

app.listen(PORT, () => {
    console.log(`Undangan API chạy tại http://localhost:${PORT}`);
    console.log('Access key hiện tại:', store.admin.access_key);
});
