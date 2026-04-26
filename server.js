
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

// Função para detectar o tipo do arquivo pela extensão
function detectFileType(filename) {
    const ext = filename.split('.').pop().toLowerCase();
    
    // Documentos
    if (ext === 'pdf') return 'pdf';
    if (['doc', 'docx'].includes(ext)) return 'word';
    if (['ppt', 'pptx'].includes(ext)) return 'powerpoint';
    
    // Código
    if (['c', 'cpp', 'h', 'hpp', 'py', 'js', 'ts', 'java', 'php', 'rb', 'go', 'rs', 'html', 'css', 'json', 'xml', 'sql', 'sh', 'bat'].includes(ext)) return 'code';
    
    // Imagens
    if (['jpg', 'jpeg', 'png', 'gif', 'svg', 'webp', 'bmp', 'ico'].includes(ext)) return 'image';
    
    // Áudio
    if (['mp3', 'wav', 'ogg', 'flac', 'm4a', 'aac'].includes(ext)) return 'audio';
    
    // Vídeo
    if (['mp4', 'avi', 'mkv', 'mov', 'webm', 'wmv', 'flv'].includes(ext)) return 'video';
    
    // Planilhas
    if (['xls', 'xlsx', 'ods', 'csv'].includes(ext)) return 'spreadsheet';
    
    // Compactados
    if (['zip', 'rar', '7z', 'tar', 'gz', 'bz2'].includes(ext)) return 'compressed';
    
    // E-books
    if (['epub', 'mobi', 'azw', 'azw3'].includes(ext)) return 'ebook';
    
    // Design
    if (['psd', 'ai', 'eps', 'cdr', 'dwg', 'dxf', 'skp'].includes(ext)) return 'design';
    
    // Texto
    if (['txt', 'md', 'rtf', 'odt'].includes(ext)) return 'text';
    
    return 'outro';
}

// Middleware de autenticação
const authenticate = async (req, res, next) => {
    let token = req.headers.authorization?.split(' ')[1];
    
    if (!token && req.query.token) {
        token = req.query.token;
    }
    
    if (!token) {
        return res.status(401).json({ erro: 'Token não fornecido' });
    }

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
// ROTAS DE AUTENTICAÇÃO
// ============================================

app.post('/api/register', async (req, res) => {
    const { email, password } = req.body;

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
            if (error.code === '23505') {
                return res.status(400).json({ erro: 'Email já registado' });
            }
            console.error('Erro Supabase:', error);
            return res.status(500).json({ erro: 'Erro ao registar' });
        }
        
        const token = jwt.sign({ userId: data.id, email }, SECRET_KEY, { expiresIn: '7d' });
        res.json({ sucesso: true, token, userId: data.id, email });
    } catch (error) {
        console.error(error);
        res.status(500).json({ erro: 'Erro ao registar' });
    }
});

app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ erro: 'Email e password são obrigatórios' });
    }

    try {
        const { data: user, error } = await supabase
            .from('usuarios')
            .select('*')
            .eq('email', email)
            .single();

        if (error || !user) {
            return res.status(401).json({ erro: 'Credenciais inválidas' });
        }

        const valid = await bcrypt.compare(password, user.password);
        if (!valid) {
            return res.status(401).json({ erro: 'Credenciais inválidas' });
        }

        const token = jwt.sign({ userId: user.id, email: user.email }, SECRET_KEY, { expiresIn: '7d' });
        res.json({ sucesso: true, token, userId: user.id, email: user.email });
    } catch (error) {
        console.error(error);
        res.status(500).json({ erro: 'Erro ao fazer login' });
    }
});

// ============================================
// ROTAS DE DOCUMENTOS
// ============================================

// Upload de documento (usando Supabase Storage)
app.post('/api/upload', authenticate, async (req, res) => {
    const multer = require('multer');
    
    // LISTA COMPLETA DE EXTENSÕES PERMITIDAS
    const allowedExtensions = [
        // Documentos
        '.pdf', '.doc', '.docx', '.ppt', '.pptx', '.txt', '.md', '.rtf', '.odt',
        // Código
        '.c', '.cpp', '.h', '.hpp', '.py', '.js', '.ts', '.java', '.php', '.rb', '.go', '.rs', '.html', '.css', '.json', '.xml', '.sql', '.sh', '.bat',
        // Imagens
        '.jpg', '.jpeg', '.png', '.gif', '.svg', '.webp', '.bmp', '.ico',
        // Áudio
        '.mp3', '.wav', '.ogg', '.flac', '.m4a', '.aac',
        // Vídeo
        '.mp4', '.avi', '.mkv', '.mov', '.webm', '.wmv', '.flv',
        // Planilhas
        '.xls', '.xlsx', '.ods', '.csv',
        // Compactados
        '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2',
        // E-books
        '.epub', '.mobi', '.azw', '.azw3',
        // Design
        '.psd', '.ai', '.eps', '.cdr', '.dwg', '.dxf', '.skp'
    ];
    
    const upload = multer({ 
        storage: multer.memoryStorage(),
        limits: { fileSize: 100 * 1024 * 1024 },
        fileFilter: (req, file, cb) => {
            const ext = path.extname(file.originalname).toLowerCase();
            if (allowedExtensions.includes(ext)) {
                cb(null, true);
            } else {
                cb(new Error(`Tipo de ficheiro não permitido. Extensão ${ext} não suportada.`));
            }
        }
    }).single('documento');

    upload(req, res, async (err) => {
        if (err) {
            return res.status(400).json({ erro: err.message });
        }
        
        if (!req.file) {
            return res.status(400).json({ erro: 'Nenhum ficheiro enviado' });
        }

        const file = req.file;
        let originalName = fixEncoding(file.originalname);
        let tags = [];
        
        if (req.body.tags) {
            try {
                tags = JSON.parse(req.body.tags);
            } catch (e) {
                tags = [];
            }
        }
        
        // Detectar o tipo do arquivo usando a nova função
        const fileType = detectFileType(originalName);
        
        // Gerar nome único para o arquivo no Storage
        const ext = path.extname(originalName).toLowerCase();
        const uniqueFileName = `${Date.now()}-${crypto.randomBytes(8).toString('hex')}${ext}`;
        const filePath = `user_${req.userId}/${uniqueFileName}`;

        try {
            // Upload para Supabase Storage
            const { error: uploadError } = await supabase.storage
                .from('documentos')
                .upload(filePath, file.buffer, {
                    contentType: file.mimetype,
                    cacheControl: '3600'
                });

            if (uploadError) {
                console.error('Erro no upload:', uploadError);
                return res.status(500).json({ erro: 'Erro ao fazer upload do ficheiro' });
            }

            // Obter URL pública
            const { data: urlData } = supabase.storage
                .from('documentos')
                .getPublicUrl(filePath);

            const fileUrl = urlData.publicUrl;

            // Salvar no banco de dados
            const { data: docData, error: dbError } = await supabase
                .from('documentos')
                .insert([{
                    user_id: req.userId,
                    filename: uniqueFileName,
                    original_name: originalName,
                    file_url: fileUrl,
                    file_type: fileType,
                    file_size: file.size,
                    tags: JSON.stringify(tags)
                }])
                .select()
                .single();

            if (dbError) {
                console.error('Erro no banco:', dbError);
                await supabase.storage.from('documentos').remove([filePath]);
                return res.status(500).json({ erro: 'Erro ao guardar documento' });
            }

            res.json({ 
                sucesso: true, 
                documento: {
                    id: docData.id,
                    filename: uniqueFileName,
                    original_name: originalName,
                    file_type: fileType,
                    file_size: file.size,
                    tags: tags,
                    uploaded_at: new Date().toISOString()
                }
            });
        } catch (error) {
            console.error('Erro geral:', error);
            res.status(500).json({ erro: 'Erro ao processar upload' });
        }
    });
});

// Listar documentos
app.get('/api/documents', authenticate, async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('documentos')
            .select('*')
            .eq('user_id', req.userId)
            .order('uploaded_at', { ascending: false });

        if (error) throw error;

        const documentos = data.map(doc => ({
            ...doc,
            original_name: fixEncoding(doc.original_name),
            tags: doc.tags ? JSON.parse(doc.tags) : [],
            favorite: doc.favorite || 0
        }));
        
        res.json({ documentos });
    } catch (error) {
        console.error('Erro ao listar documentos:', error);
        res.status(500).json({ erro: 'Erro ao listar documentos' });
    }
});

// Download documento
app.get('/api/download/:id', authenticate, async (req, res) => {
    const docId = req.params.id;
    
    try {
        const { data: doc, error } = await supabase
            .from('documentos')
            .select('*')
            .eq('id', docId)
            .eq('user_id', req.userId)
            .single();

        if (error || !doc) {
            return res.status(404).json({ erro: 'Documento não encontrado' });
        }

        res.redirect(doc.file_url);
    } catch (error) {
        console.error(error);
        res.status(500).json({ erro: 'Erro ao fazer download' });
    }
});

// Visualizar documento
app.get('/api/view/:id', authenticate, async (req, res) => {
    const docId = req.params.id;
    
    try {
        const { data: doc, error } = await supabase
            .from('documentos')
            .select('*')
            .eq('id', docId)
            .eq('user_id', req.userId)
            .single();

        if (error || !doc) {
            return res.status(404).json({ erro: 'Documento não encontrado' });
        }

        res.redirect(doc.file_url);
    } catch (error) {
        console.error(error);
        res.status(500).json({ erro: 'Erro ao visualizar documento' });
    }
});

// Apagar todos os documentos
app.delete('/api/documents/delete-all', authenticate, async (req, res) => {
    const userId = req.userId;
    
    try {
        const { data: docs, error: listError } = await supabase
            .from('documentos')
            .select('id, filename')
            .eq('user_id', userId);

        if (listError) throw listError;

        if (docs.length === 0) {
            return res.json({ sucesso: true, mensagem: 'Nenhum documento para apagar', count: 0 });
        }

        const filesToDelete = docs.map(doc => `user_${userId}/${doc.filename}`);
        await supabase.storage.from('documentos').remove(filesToDelete);

        const { error: deleteError } = await supabase
            .from('documentos')
            .delete()
            .eq('user_id', userId);

        if (deleteError) throw deleteError;

        res.json({ sucesso: true, mensagem: `${docs.length} documentos apagados`, count: docs.length });
    } catch (error) {
        console.error(error);
        res.status(500).json({ erro: 'Erro ao apagar documentos' });
    }
});

// Apagar um documento
app.delete('/api/documents/:id', authenticate, async (req, res) => {
    const docId = req.params.id;
    
    try {
        const { data: doc, error: findError } = await supabase
            .from('documentos')
            .select('filename')
            .eq('id', docId)
            .eq('user_id', req.userId)
            .single();

        if (findError || !doc) {
            return res.status(404).json({ erro: 'Documento não encontrado' });
        }

        const filePath = `user_${req.userId}/${doc.filename}`;
        await supabase.storage.from('documentos').remove([filePath]);

        const { error: deleteError } = await supabase
            .from('documentos')
            .delete()
            .eq('id', docId);

        if (deleteError) throw deleteError;

        res.json({ sucesso: true, mensagem: 'Documento apagado' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ erro: 'Erro ao apagar documento' });
    }
});

// Renomear documento
app.put('/api/documents/:id/rename', authenticate, async (req, res) => {
    const docId = req.params.id;
    const { newName } = req.body;
    
    if (!newName) return res.status(400).json({ erro: 'Nome não fornecido' });
    
    try {
        const { error: updateError } = await supabase
            .from('documentos')
            .update({ original_name: newName })
            .eq('id', docId)
            .eq('user_id', req.userId);

        if (updateError) throw updateError;

        res.json({ sucesso: true, mensagem: 'Documento renomeado' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ erro: 'Erro ao renomear' });
    }
});

// Atualizar tags
app.put('/api/documents/:id/tags', authenticate, async (req, res) => {
    const docId = req.params.id;
    const { tags } = req.body;
    
    try {
        const { error } = await supabase
            .from('documentos')
            .update({ tags: JSON.stringify(tags || []) })
            .eq('id', docId)
            .eq('user_id', req.userId);

        if (error) throw error;

        res.json({ sucesso: true, mensagem: 'Tags atualizadas' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ erro: 'Erro ao atualizar tags' });
    }
});

// Marcar/desmarcar favorito
app.put('/api/documents/:id/favorite', authenticate, async (req, res) => {
    const docId = req.params.id;
    const { favorite } = req.body;
    
    try {
        const { error } = await supabase
            .from('documentos')
            .update({ favorite: favorite ? 1 : 0 })
            .eq('id', docId)
            .eq('user_id', req.userId);

        if (error) throw error;

        res.json({ sucesso: true, mensagem: 'Favorito atualizado' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ erro: 'Erro ao atualizar favorito' });
    }
});

// Gerar link de partilha
app.post('/api/documents/:id/share', authenticate, async (req, res) => {
    const docId = req.params.id;
    const { expires_days = 7 } = req.body;
    
    try {
        const { data: doc, error: findError } = await supabase
            .from('documentos')
            .select('id')
            .eq('id', docId)
            .eq('user_id', req.userId)
            .single();

        if (findError || !doc) {
            return res.status(404).json({ erro: 'Documento não encontrado' });
        }
        
        const token = crypto.randomBytes(32).toString('hex');
        const expires_at = new Date();
        expires_at.setDate(expires_at.getDate() + expires_days);
        
        const { error } = await supabase
            .from('share_links')
            .insert([{
                document_id: docId,
                token: token,
                expires_at: expires_at.toISOString()
            }]);

        if (error) throw error;

        const shareUrl = `${req.protocol}://${req.get('host')}/share/${token}`;
        res.json({ sucesso: true, url: shareUrl, token, expires_at });
    } catch (error) {
        console.error(error);
        res.status(500).json({ erro: 'Erro ao gerar link' });
    }
});

// Rota pública para documento partilhado
app.get('/share/:token', async (req, res) => {
    const token = req.params.token;
    
    try {
        const { data, error } = await supabase
            .from('share_links')
            .select(`
                expires_at,
                documentos (
                    id,
                    original_name,
                    file_url
                )
            `)
            .eq('token', token)
            .single();

        if (error || !data || new Date(data.expires_at) < new Date()) {
            return res.status(404).send(`
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Link inválido</title>
                    <style>
                        body { font-family: sans-serif; text-align: center; padding: 50px; background: #f5f5f5; }
                        .container { max-width: 500px; margin: 0 auto; background: white; padding: 40px; border-radius: 12px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                        h1 { color: #dc3545; }
                        p { color: #666; }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <h1>🔗 Link inválido ou expirado</h1>
                        <p>Este link de partilha não é válido ou já expirou.</p>
                        <p>Contacte o proprietário do documento para um novo link.</p>
                    </div>
                </body>
                </html>
            `);
        }

        const doc = data.documentos;
        res.redirect(doc.file_url);
    } catch (error) {
        console.error(error);
        res.status(500).send('Erro ao aceder ao documento');
    }
});

// Listar links partilhados
app.get('/api/documents/:id/shares', authenticate, async (req, res) => {
    const docId = req.params.id;
    
    try {
        const { data, error } = await supabase
            .from('share_links')
            .select('*')
            .eq('document_id', docId)
            .order('created_at', { ascending: false });

        if (error) throw error;

        res.json({ links: data });
    } catch (error) {
        console.error(error);
        res.status(500).json({ erro: 'Erro ao listar links' });
    }
});

// Revogar link de partilha
app.delete('/api/share/:token', authenticate, async (req, res) => {
    const token = req.params.token;
    
    try {
        const { error } = await supabase
            .from('share_links')
            .delete()
            .eq('token', token);

        if (error) throw error;

        res.json({ sucesso: true, mensagem: 'Link revogado' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ erro: 'Erro ao revogar link' });
    }
});

// Alterar password
app.put('/api/user/change-password', authenticate, async (req, res) => {
    const { currentPassword, newPassword } = req.body;
    const userId = req.userId;

    if (!currentPassword || !newPassword) {
        return res.status(400).json({ erro: 'Password atual e nova password são obrigatórias' });
    }

    if (newPassword.length < 6) {
        return res.status(400).json({ erro: 'A nova password deve ter pelo menos 6 caracteres' });
    }

    try {
        const { data: user, error } = await supabase
            .from('usuarios')
            .select('password')
            .eq('id', userId)
            .single();

        if (error || !user) {
            return res.status(404).json({ erro: 'Utilizador não encontrado' });
        }

        const valid = await bcrypt.compare(currentPassword, user.password);
        if (!valid) {
            return res.status(401).json({ erro: 'Password atual incorreta' });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);

        const { error: updateError } = await supabase
            .from('usuarios')
            .update({ password: hashedPassword })
            .eq('id', userId);

        if (updateError) throw updateError;

        res.json({ sucesso: true, mensagem: 'Password alterada com sucesso' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ erro: 'Erro ao alterar password' });
    }
});

// Apagar conta
app.delete('/api/user/delete', authenticate, async (req, res) => {
    const userId = req.userId;
    
    try {
        const { data: docs, error: listError } = await supabase
            .from('documentos')
            .select('filename')
            .eq('user_id', userId);

        if (listError) throw listError;

        if (docs && docs.length > 0) {
            const filesToDelete = docs.map(doc => `user_${userId}/${doc.filename}`);
            await supabase.storage.from('documentos').remove(filesToDelete);
        }

        await supabase.storage.from('documentos').remove([`user_${userId}`]);
        await supabase.from('documentos').delete().eq('user_id', userId);
        
        const { error: deleteError } = await supabase
            .from('usuarios')
            .delete()
            .eq('id', userId);

        if (deleteError) throw deleteError;

        res.json({ sucesso: true, mensagem: 'Conta apagada com sucesso' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ erro: 'Erro ao apagar conta' });
    }
});

// ============================================
// INICIAR SERVIDOR
// ============================================

// Rota de teste (colocar ANTES do app.listen)
app.get('/api/test', (req, res) => {
    res.json({ status: 'ok', message: 'Servidor funcionando!' });
});

app.listen(PORT, () => {
    console.log(`📁 Sistema de Documentos rodando em http://localhost:${PORT}`);
    console.log(`🗄️ Supabase conectado: ${supabaseUrl}`);
});
