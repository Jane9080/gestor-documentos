const express = require('express');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.SECRET_KEY || 'documentos_secret_key_2024';

// ============================================
// CONFIGURAÇÃO SUPABASE
// ============================================
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_ANON_KEY;

if (!supabaseUrl || !supabaseKey) {
    console.error('❌ Erro: SUPABASE_URL e SUPABASE_KEY são obrigatórios!');
    process.exit(1);
}

const supabase = createClient(supabaseUrl, supabaseKey);

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// ============================================
// FUNÇÕES AUXILIARES
// ============================================
function fixEncoding(str) {
    if (!str) return str;
    try {
        return decodeURIComponent(escape(str));
    } catch (e) {
        return str;
    }
}

function detectFileType(filename) {
    const ext = filename.split('.').pop().toLowerCase();
    if (ext === 'pdf') return 'pdf';
    if (['doc', 'docx'].includes(ext)) return 'word';
    if (['ppt', 'pptx'].includes(ext)) return 'powerpoint';
    if (['c', 'cpp', 'h', 'hpp', 'py', 'js', 'ts', 'java', 'php', 'rb', 'go', 'rs', 'html', 'css', 'json', 'xml', 'sql', 'sh', 'bat'].includes(ext)) return 'code';
    if (['jpg', 'jpeg', 'png', 'gif', 'svg', 'webp', 'bmp', 'ico'].includes(ext)) return 'image';
    if (['mp3', 'wav', 'ogg', 'flac', 'm4a', 'aac'].includes(ext)) return 'audio';
    if (['mp4', 'avi', 'mkv', 'mov', 'webm', 'wmv', 'flv'].includes(ext)) return 'video';
    if (['xls', 'xlsx', 'ods', 'csv'].includes(ext)) return 'spreadsheet';
    if (['zip', 'rar', '7z', 'tar', 'gz', 'bz2'].includes(ext)) return 'compressed';
    if (['epub', 'mobi', 'azw', 'azw3'].includes(ext)) return 'ebook';
    if (['psd', 'ai', 'eps', 'cdr', 'dwg', 'dxf', 'skp'].includes(ext)) return 'design';
    if (['txt', 'md', 'rtf', 'odt'].includes(ext)) return 'text';
    return 'outro';
}

const authenticate = async (req, res, next) => {
    let token = req.headers.authorization?.split(' ')[1];
    if (!token && req.query.token) token = req.query.token;
    if (!token) return res.status(401).json({ erro: 'Token não fornecido' });
    try {
        const decoded = jwt.verify(token, SECRET_KEY);
        req.userId = decoded.userId;
        req.userEmail = decoded.email;
        next();
    } catch (error) {
        return res.status(401).json({ erro: 'Token inválido' });
    }
};

// ============================================
// ROTA DE TESTE
// ============================================
app.get('/api/test', (req, res) => {
    res.json({ status: 'ok', message: 'Servidor funcionando!' });
});

// ============================================
// ROTAS DE AUTENTICAÇÃO
// ============================================
app.post('/api/register', async (req, res) => {
    const { email, password } = req.body;
    console.log('📝 Tentando registrar:', email);

    if (!email || !password) {
        return res.status(400).json({ erro: 'Email e password são obrigatórios' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        
        const { data, error } = await supabase
            .from('usuarios')
            .insert([{ email, password: hashedPassword }])
            .select()
            .single();

        if (error) {
            console.error('❌ Erro Supabase:', error);
            return res.status(400).json({ erro: error.message });
        }
        
        console.log('✅ Usuário criado:', data.id);
        const token = jwt.sign({ userId: data.id, email }, SECRET_KEY, { expiresIn: '7d' });
        res.json({ sucesso: true, token, userId: data.id, email });
    } catch (error) {
        console.error('❌ Erro geral:', error);
        res.status(500).json({ erro: error.message });
    }
});

app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    console.log('🔐 Tentando login:', email);

    try {
        const { data: user, error } = await supabase
            .from('usuarios')
            .select('*')
            .eq('email', email)
            .single();

        if (error || !user) {
            console.log('❌ Usuário não encontrado');
            return res.status(401).json({ erro: 'Credenciais inválidas' });
        }

        const valid = await bcrypt.compare(password, user.password);
        if (!valid) {
            console.log('❌ Senha inválida');
            return res.status(401).json({ erro: 'Credenciais inválidas' });
        }

        console.log('✅ Login sucesso:', user.id);
        const token = jwt.sign({ userId: user.id, email: user.email }, SECRET_KEY, { expiresIn: '7d' });
        res.json({ sucesso: true, token, userId: user.id, email: user.email });
    } catch (error) {
        console.error('❌ Erro login:', error);
        res.status(500).json({ erro: 'Erro ao fazer login' });
    }
});

// ============================================
// ROTAS DE DOCUMENTOS (resumidas para economizar espaço)
// ============================================

app.post('/api/upload', authenticate, async (req, res) => {
    const multer = require('multer');
    const allowedExtensions = ['.pdf', '.doc', '.docx', '.ppt', '.pptx', '.txt', '.md', '.c', '.cpp', '.py', '.js', '.jpg', '.png', '.gif', '.mp3', '.mp4', '.zip'];
    
    const upload = multer({ 
        storage: multer.memoryStorage(),
        limits: { fileSize: 100 * 1024 * 1024 },
        fileFilter: (req, file, cb) => {
            const ext = path.extname(file.originalname).toLowerCase();
            cb(null, allowedExtensions.includes(ext));
        }
    }).single('documento');

    upload(req, res, async (err) => {
        if (err) return res.status(400).json({ erro: err.message });
        if (!req.file) return res.status(400).json({ erro: 'Nenhum ficheiro enviado' });

        const file = req.file;
        let originalName = fixEncoding(file.originalname);
        let tags = req.body.tags ? JSON.parse(req.body.tags) : [];
        const fileType = detectFileType(originalName);
        const ext = path.extname(originalName).toLowerCase();
        const uniqueFileName = `${Date.now()}-${crypto.randomBytes(8).toString('hex')}${ext}`;
        const filePath = `user_${req.userId}/${uniqueFileName}`;

        try {
            const { error: uploadError } = await supabase.storage.from('documentos').upload(filePath, file.buffer);
            if (uploadError) throw uploadError;

            const { data: urlData } = supabase.storage.from('documentos').getPublicUrl(filePath);
            const { data: docData, error: dbError } = await supabase.from('documentos').insert([{
                user_id: req.userId, filename: uniqueFileName, original_name: originalName,
                file_url: urlData.publicUrl, file_type: fileType, file_size: file.size, tags: JSON.stringify(tags)
            }]).select().single();

            if (dbError) throw dbError;
            res.json({ sucesso: true, documento: docData });
        } catch (error) {
            console.error('Erro upload:', error);
            res.status(500).json({ erro: 'Erro ao fazer upload' });
        }
    });
});

app.get('/api/documents', authenticate, async (req, res) => {
    try {
        const { data, error } = await supabase.from('documentos').select('*').eq('user_id', req.userId).order('uploaded_at', { ascending: false });
        if (error) throw error;
        const documentos = data.map(doc => ({ ...doc, tags: doc.tags ? JSON.parse(doc.tags) : [] }));
        res.json({ documentos });
    } catch (error) {
        res.status(500).json({ erro: 'Erro ao listar documentos' });
    }
});

app.get('/api/download/:id', authenticate, async (req, res) => {
    try {
        const { data: doc } = await supabase.from('documentos').select('file_url, original_name').eq('id', req.params.id).eq('user_id', req.userId).single();
        if (!doc) return res.status(404).json({ erro: 'Documento não encontrado' });
        res.redirect(doc.file_url);
    } catch (error) {
        res.status(500).json({ erro: 'Erro ao fazer download' });
    }
});

app.get('/api/view/:id', authenticate, async (req, res) => {
    try {
        const { data: doc } = await supabase.from('documentos').select('file_url').eq('id', req.params.id).eq('user_id', req.userId).single();
        if (!doc) return res.status(404).json({ erro: 'Documento não encontrado' });
        res.redirect(doc.file_url);
    } catch (error) {
        res.status(500).json({ erro: 'Erro ao visualizar' });
    }
});

app.delete('/api/documents/:id', authenticate, async (req, res) => {
    try {
        const { data: doc } = await supabase.from('documentos').select('filename').eq('id', req.params.id).eq('user_id', req.userId).single();
        if (!doc) return res.status(404).json({ erro: 'Documento não encontrado' });
        await supabase.storage.from('documentos').remove([`user_${req.userId}/${doc.filename}`]);
        await supabase.from('documentos').delete().eq('id', req.params.id);
        res.json({ sucesso: true });
    } catch (error) {
        res.status(500).json({ erro: 'Erro ao apagar' });
    }
});

app.delete('/api/documents/delete-all', authenticate, async (req, res) => {
    try {
        const { data: docs } = await supabase.from('documentos').select('filename').eq('user_id', req.userId);
        if (docs.length === 0) return res.json({ sucesso: true, count: 0 });
        await supabase.storage.from('documentos').remove(docs.map(doc => `user_${req.userId}/${doc.filename}`));
        await supabase.from('documentos').delete().eq('user_id', req.userId);
        res.json({ sucesso: true, count: docs.length });
    } catch (error) {
        res.status(500).json({ erro: 'Erro ao apagar todos' });
    }
});

app.put('/api/documents/:id/rename', authenticate, async (req, res) => {
    try {
        await supabase.from('documentos').update({ original_name: req.body.newName }).eq('id', req.params.id).eq('user_id', req.userId);
        res.json({ sucesso: true });
    } catch (error) {
        res.status(500).json({ erro: 'Erro ao renomear' });
    }
});

app.put('/api/documents/:id/tags', authenticate, async (req, res) => {
    try {
        await supabase.from('documentos').update({ tags: JSON.stringify(req.body.tags || []) }).eq('id', req.params.id).eq('user_id', req.userId);
        res.json({ sucesso: true });
    } catch (error) {
        res.status(500).json({ erro: 'Erro ao atualizar tags' });
    }
});

app.put('/api/documents/:id/favorite', authenticate, async (req, res) => {
    try {
        await supabase.from('documentos').update({ favorite: req.body.favorite ? 1 : 0 }).eq('id', req.params.id).eq('user_id', req.userId);
        res.json({ sucesso: true });
    } catch (error) {
        res.status(500).json({ erro: 'Erro ao atualizar favorito' });
    }
});

app.post('/api/documents/:id/share', authenticate, async (req, res) => {
    try {
        const token = crypto.randomBytes(32).toString('hex');
        const expires_at = new Date();
        expires_at.setDate(expires_at.getDate() + (req.body.expires_days || 7));
        await supabase.from('share_links').insert([{ document_id: req.params.id, token, expires_at: expires_at.toISOString() }]);
        const shareUrl = `${req.protocol}://${req.get('host')}/share/${token}`;
        res.json({ sucesso: true, url: shareUrl, token, expires_at });
    } catch (error) {
        res.status(500).json({ erro: 'Erro ao gerar link' });
    }
});

app.get('/share/:token', async (req, res) => {
    try {
        const { data } = await supabase.from('share_links').select('expires_at, documentos(file_url)').eq('token', req.params.token).single();
        if (!data || new Date(data.expires_at) < new Date()) return res.status(404).send('Link inválido ou expirado');
        res.redirect(data.documentos.file_url);
    } catch (error) {
        res.status(500).send('Erro ao aceder ao documento');
    }
});

app.put('/api/user/change-password', authenticate, async (req, res) => {
    const { currentPassword, newPassword } = req.body;
    try {
        const { data: user } = await supabase.from('usuarios').select('password').eq('id', req.userId).single();
        if (!(await bcrypt.compare(currentPassword, user.password))) return res.status(401).json({ erro: 'Password atual incorreta' });
        await supabase.from('usuarios').update({ password: await bcrypt.hash(newPassword, 10) }).eq('id', req.userId);
        res.json({ sucesso: true });
    } catch (error) {
        res.status(500).json({ erro: 'Erro ao alterar password' });
    }
});

app.delete('/api/user/delete', authenticate, async (req, res) => {
    try {
        const { data: docs } = await supabase.from('documentos').select('filename').eq('user_id', req.userId);
        if (docs.length) await supabase.storage.from('documentos').remove(docs.map(doc => `user_${req.userId}/${doc.filename}`));
        await supabase.from('documentos').delete().eq('user_id', req.userId);
        await supabase.from('usuarios').delete().eq('id', req.userId);
        res.json({ sucesso: true });
    } catch (error) {
        res.status(500).json({ erro: 'Erro ao apagar conta' });
    }
});

// ============================================
// INICIAR SERVIDOR
// ============================================
app.listen(PORT, () => {
    console.log(`📁 Sistema de Documentos rodando em http://localhost:${PORT}`);
    console.log(`🗄️ Supabase conectado: ${supabaseUrl}`);
});
