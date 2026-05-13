const express = require('express');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const multer = require('multer');
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
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ============================================
// CONFIGURAÇÃO MULTER (Uma única vez)
// ============================================
const ALLOWED_EXTENSIONS = [
    // Documentos
    'pdf', 'doc', 'docx', 'ppt', 'pptx', 'txt', 'md', 'rtf', 'odt',
    // Código
    'c', 'cpp', 'h', 'hpp', 'py', 'js', 'ts', 'java', 'php', 'rb', 'go', 'rs', 'html', 'css', 'json', 'xml', 'sql', 'sh', 'bat',
    // Imagens
    'jpg', 'jpeg', 'png', 'gif', 'svg', 'webp', 'bmp', 'ico',
    // Áudio
    'mp3', 'wav', 'ogg', 'flac', 'm4a', 'aac',
    // Vídeo
    'mp4', 'avi', 'mkv', 'mov', 'webm', 'wmv', 'flv',
    // Planilhas
    'xls', 'xlsx', 'ods', 'csv',
    // Compactados
    'zip', 'rar', '7z', 'tar', 'gz', 'bz2',
    // E-books
    'epub', 'mobi', 'azw', 'azw3',
    // Design
    'psd', 'ai', 'eps', 'cdr', 'dwg', 'dxf', 'skp',
    // Engenharia / Eletrónica
    'circ', 'pcb', 'sch', 'brd', 'gerber', 'gbr','pwb',
    // CAD / Desenho Técnico
    'stp', 'step', 'iges', 'igs',
    // Modelagem 3D
    'stl', '3mf', 'obj', 'blend',
    // KiCad
    'kicad_pcb', 'kicad_sch',
    // Visio / Diagramas
    'odg', 'vsd',
    //matlab
    'm', 'mlx'
];
const MAX_FILE_SIZE = 100 * 1024 * 1024; // 100MB

const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: MAX_FILE_SIZE },
    fileFilter: (req, file, cb) => {
        const ext = path.extname(file.originalname).toLowerCase().substring(1);
        if (ALLOWED_EXTENSIONS.includes(ext)) {
            cb(null, true);
        } else {
            cb(new Error(`Tipo de ficheiro não permitido. Extensão .${ext} não suportada.`));
        }
    }
}).single('documento');

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

// Validação de email
function isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email) && email.length <= 255;
}

// Função para detectar o tipo do arquivo pela extensão
function detectFileType(filename) {
    const ext = filename.split('.').pop().toLowerCase();
    
    if (['pdf'].includes(ext)) return 'pdf';
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
        return res.status(401).json({ erro: 'Token inválido ou expirado' });
    }
};

// ============================================
// ROTAS DE AUTENTICAÇÃO
// ============================================

app.post('/api/register', async (req, res) => {
    const { email, password } = req.body;
    console.log('📝 Tentando registrar:', email);

    if (!email || !password) {
        return res.status(400).json({ erro: 'Email e password são obrigatórios' });
    }

    if (password.length < 6) {
        return res.status(400).json({ erro: 'A password deve ter pelo menos 6 caracteres' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        
        const { data, error } = await supabase
            .from('usuarios')
            .insert([{ email: email.toLowerCase(), password: hashedPassword }])
            .select()
            .single();

        if (error) {
            // ESTA LINHA É IMPORTANTE - MOSTRA O ERRO REAL
            console.error('❌ ERRO DETALHADO DO SUPABASE:', JSON.stringify(error, null, 2));
            return res.status(400).json({ erro: `Erro: ${error.message}` });
        }
        
        console.log('✅ Usuário criado:', data.id);
        const token = jwt.sign({ userId: data.id, email }, SECRET_KEY, { expiresIn: '7d' });
        res.json({ sucesso: true, token, userId: data.id, email });
    } catch (error) {
        console.error('❌ ERRO GERAL:', error);
        res.status(500).json({ erro: `Erro: ${error.message}` });
    }
});
// Login
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ erro: 'Email e password são obrigatórios' });
    }

    try {
        const { data: user, error } = await supabase
            .from('usuarios')
            .select('*')
            .eq('email', email.toLowerCase())
            .single();

        if (error || !user) {
            return res.status(401).json({ erro: 'Credenciais inválidas' });
        }

        const valid = await bcrypt.compare(password, user.password);
        if (!valid) {
            return res.status(401).json({ erro: 'Credenciais inválidas' });
        }

        const token = jwt.sign(
            { userId: user.id, email: user.email }, 
            SECRET_KEY, 
            { expiresIn: '7d' }
        );

        res.json({ 
            sucesso: true, 
            token, 
            userId: user.id, 
            email: user.email 
        });
    } catch (error) {
        console.error('Erro ao fazer login:', error);
        res.status(500).json({ erro: 'Erro ao fazer login' });
    }
});

// ============================================
// ROTAS DE DOCUMENTOS
// ============================================

// Upload de documento (VERSÃO CORRIGIDA)
app.post('/api/upload', authenticate, (req, res) => {
    upload(req, res, async (err) => {
        // PRIMEIRO: verificar erro do multer
        if (err) {
            console.error('Erro multer:', err);
            return res.status(400).json({ erro: err.message });
        }
        
        // SEGUNDO: verificar se existe ficheiro
        if (!req.file) {
            return res.status(400).json({ erro: 'Nenhum ficheiro enviado' });
        }

        // TERCEIRO: agora sim podemos usar o file
        const file = req.file;
        
        // Verificar se uploads estão permitidos
        const { data: uploadsAllowedData } = await supabase
            .from('config')
            .select('value')
            .eq('key', 'uploads_allowed')
            .single();
        
        if (uploadsAllowedData && uploadsAllowedData.value === 'false') {
            return res.status(403).json({ erro: '📤 Uploads temporariamente desativados pelo administrador' });
        }
        
        // Calcular espaço total usado
        const { data: allDocs } = await supabase.from('documentos').select('file_size');
        const totalUsedBytes = allDocs?.reduce((sum, doc) => sum + (doc.file_size || 0), 0) || 0;
        const totalUsedMB = totalUsedBytes / (1024 * 1024);
        
        const { data: configData } = await supabase
            .from('config')
            .select('value')
            .eq('key', 'max_storage_mb')
            .single();
        
        const maxStorageMB = configData ? parseInt(configData.value) : 102400;
        
        // Verificar se o novo arquivo cabe
        if (totalUsedMB + (file.size / (1024 * 1024)) > maxStorageMB) {
            return res.status(403).json({ erro: `❌ Limite de armazenamento excedido! Usado: ${totalUsedMB.toFixed(1)}MB / ${maxStorageMB}MB` });
        }

        let originalName = fixEncoding(file.originalname);
        let tags = [];
        
        if (originalName.length > 255) {
            originalName = originalName.substring(0, 255);
        }
        
        if (req.body.tags) {
            try {
                tags = JSON.parse(req.body.tags);
                if (!Array.isArray(tags)) tags = [];
                if (tags.length > 50) tags = tags.slice(0, 50);
            } catch (e) {
                tags = [];
            }
        }
        
        const fileType = detectFileType(originalName);
        const ext = path.extname(originalName).toLowerCase();
        const uniqueFileName = `${Date.now()}-${crypto.randomBytes(8).toString('hex')}${ext}`;
        const filePath = `user_${req.userId}/${uniqueFileName}`;

        try {
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

            const { data: urlData } = supabase.storage
                .from('documentos')
                .getPublicUrl(filePath);

            const fileUrl = urlData.publicUrl;

            const { data: docData, error: dbError } = await supabase
                .from('documentos')
                .insert([{
                    user_id: req.userId,
                    filename: uniqueFileName,
                    original_name: originalName,
                    file_url: fileUrl,
                    file_type: fileType,
                    file_size: file.size,
                    tags: JSON.stringify(tags),
                    favorite: 0
                }])
                .select()
                .single();

            if (dbError) {
                console.error('Erro no banco:', dbError);
                await supabase.storage.from('documentos').remove([filePath]);
                return res.status(500).json({ erro: 'Erro ao guardar documento' });
            }

            res.status(201).json({ 
                sucesso: true, 
                documento: {
                    id: docData.id,
                    filename: uniqueFileName,
                    original_name: originalName,
                    file_type: fileType,
                    file_size: file.size,
                    tags: tags,
                    favorite: 0,
                    uploaded_at: new Date().toISOString()
                }
            });
        } catch (error) {
            console.error('Erro geral no upload:', error);
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
            .order('created_at', { ascending: false });

        if (error) throw error;

        const documentos = data.map(doc => ({
            id: doc.id,
            original_name: fixEncoding(doc.original_name),
            filename: doc.filename,
            file_type: doc.file_type,
            file_size: doc.file_size,
            tags: doc.tags ? JSON.parse(doc.tags) : [],
            favorite: doc.favorite || 0,
            created_at: doc.created_at,
            file_url: doc.file_url
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

        // Buscar o arquivo do Supabase Storage
        const filePath = `user_${req.userId}/${doc.filename}`;
        const { data: fileData, error: downloadError } = await supabase.storage
            .from('documentos')
            .download(filePath);

        if (downloadError) {
            console.error('Erro no download do storage:', downloadError);
            return res.status(500).json({ erro: 'Erro ao baixar arquivo' });
        }

        // Extrair a extensão do nome original
        const ext = doc.original_name.split('.').pop().toLowerCase();
        let mimeType = 'application/octet-stream';
        
        // Definir o MIME type correto baseado na extensão
        if (ext === 'pdf') mimeType = 'application/pdf';
        else if (['doc', 'docx'].includes(ext)) mimeType = 'application/msword';
        else if (['ppt', 'pptx'].includes(ext)) mimeType = 'application/vnd.ms-powerpoint';
        else if (['xls', 'xlsx'].includes(ext)) mimeType = 'application/vnd.ms-excel';
        else if (['jpg', 'jpeg'].includes(ext)) mimeType = 'image/jpeg';
        else if (ext === 'png') mimeType = 'image/png';
        else if (ext === 'txt') mimeType = 'text/plain';
        
        // Usar formatação RFC 5987 para caracteres especiais
        const filename = doc.original_name;
        res.setHeader('Content-Type', mimeType);
        res.setHeader('Content-Disposition', `attachment; filename*=UTF-8''${encodeURIComponent(filename)}`);
        res.setHeader('Content-Length', fileData.size);
        res.send(Buffer.from(await fileData.arrayBuffer()));
        
    } catch (error) {
        console.error('Erro ao fazer download:', error);
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
        console.error('Erro ao visualizar documento:', error);
        res.status(500).json({ erro: 'Erro ao visualizar documento' });
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
        
        // Deletar do storage
        const { error: storageError } = await supabase.storage
            .from('documentos')
            .remove([filePath]);

        if (storageError) {
            console.error('Erro ao deletar do storage:', storageError);
        }

        // Deletar do banco de dados
        const { error: deleteError } = await supabase
            .from('documentos')
            .delete()
            .eq('id', docId)
            .eq('user_id', req.userId);

        if (deleteError) throw deleteError;

        res.json({ sucesso: true, mensagem: 'Documento apagado com sucesso' });
    } catch (error) {
        console.error('Erro ao apagar documento:', error);
        res.status(500).json({ erro: 'Erro ao apagar documento' });
    }
});

// Apagar todos os documentos do utilizador
app.delete('/api/documents/delete-all', authenticate, async (req, res) => {
    const userId = req.userId;
    
    try {
        // Buscar documentos do usuário
        const { data: docs, error: listError } = await supabase
            .from('documentos')
            .select('id, filename')
            .eq('user_id', userId);

        if (listError) throw listError;

        if (!docs || docs.length === 0) {
            return res.json({ sucesso: true, mensagem: 'Nenhum documento para apagar', count: 0 });
        }

        // Apagar arquivos do Storage
        const filesToDelete = docs.map(doc => `user_${userId}/${doc.filename}`);
        await supabase.storage.from('documentos').remove(filesToDelete);

        // Apagar registros do banco
        const { error: deleteError } = await supabase
            .from('documentos')
            .delete()
            .eq('user_id', userId);

        if (deleteError) throw deleteError;

        res.json({ sucesso: true, mensagem: `${docs.length} documento(s) apagado(s) com sucesso!`, count: docs.length });
    } catch (error) {
        console.error('Erro ao apagar todos os documentos:', error);
        res.status(500).json({ erro: 'Erro ao apagar documentos' });
    }
});

// Renomear documento
app.put('/api/documents/:id/rename', authenticate, async (req, res) => {
    const docId = req.params.id;
    const { newName } = req.body;
    
    if (!newName || typeof newName !== 'string' || newName.trim() === '') {
        return res.status(400).json({ erro: 'Nome válido não fornecido' });
    }
    
    let finalName = newName.trim();
    if (finalName.length > 255) {
        finalName = finalName.substring(0, 255);
    }
    
    try {
        // Verificar se o documento pertence ao utilizador
        const { data: doc, error: findError } = await supabase
            .from('documentos')
            .select('id')
            .eq('id', docId)
            .eq('user_id', req.userId)
            .single();

        if (findError || !doc) {
            return res.status(404).json({ erro: 'Documento não encontrado' });
        }

        const { error: updateError } = await supabase
            .from('documentos')
            .update({ original_name: finalName })
            .eq('id', docId)
            .eq('user_id', req.userId);

        if (updateError) throw updateError;

        res.json({ sucesso: true, mensagem: 'Documento renomeado com sucesso', newName: finalName });
    } catch (error) {
        console.error('Erro ao renomear:', error);
        res.status(500).json({ erro: 'Erro ao renomear documento' });
    }
});

// Atualizar tags
app.put('/api/documents/:id/tags', authenticate, async (req, res) => {
    const docId = req.params.id;
    const { tags } = req.body;
    
    if (!Array.isArray(tags)) {
        return res.status(400).json({ erro: 'Tags deve ser um array' });
    }

    // Limitar a 50 tags
    const finalTags = tags.slice(0, 50);
    
    try {
        // Verificar se o documento pertence ao utilizador
        const { data: doc, error: findError } = await supabase
            .from('documentos')
            .select('id')
            .eq('id', docId)
            .eq('user_id', req.userId)
            .single();

        if (findError || !doc) {
            return res.status(404).json({ erro: 'Documento não encontrado' });
        }

        const { error } = await supabase
            .from('documentos')
            .update({ tags: JSON.stringify(finalTags) })
            .eq('id', docId)
            .eq('user_id', req.userId);

        if (error) throw error;

        res.json({ sucesso: true, mensagem: 'Tags atualizadas com sucesso' });
    } catch (error) {
        console.error('Erro ao atualizar tags:', error);
        res.status(500).json({ erro: 'Erro ao atualizar tags' });
    }
});

// Marcar/desmarcar favorito
app.put('/api/documents/:id/favorite', authenticate, async (req, res) => {
    const docId = req.params.id;
    const { favorite } = req.body;
    
    if (typeof favorite !== 'boolean') {
        return res.status(400).json({ erro: 'Favorite deve ser true ou false' });
    }
    
    try {
        // Verificar se o documento pertence ao utilizador
        const { data: doc, error: findError } = await supabase
            .from('documentos')
            .select('id')
            .eq('id', docId)
            .eq('user_id', req.userId)
            .single();

        if (findError || !doc) {
            return res.status(404).json({ erro: 'Documento não encontrado' });
        }

        const { error } = await supabase
            .from('documentos')
            .update({ favorite: favorite ? 1 : 0 })
            .eq('id', docId)
            .eq('user_id', req.userId);

        if (error) throw error;

        res.json({ sucesso: true, mensagem: 'Favorito atualizado com sucesso' });
    } catch (error) {
        console.error('Erro ao atualizar favorito:', error);
        res.status(500).json({ erro: 'Erro ao atualizar favorito' });
    }
});

// ============================================
// ROTAS DE PARTILHA
// ============================================

// Gerar link de partilha
app.post('/api/documents/:id/share', authenticate, async (req, res) => {
    const docId = req.params.id;
    const { expires_days = 7 } = req.body;

    if (!Number.isInteger(expires_days) || expires_days < 1 || expires_days > 365) {
        return res.status(400).json({ erro: 'Dias de expiração deve estar entre 1 e 365' });
    }
    
    try {
        // Verificar se o documento pertence ao utilizador
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
        res.status(201).json({ 
            sucesso: true, 
            url: shareUrl, 
            token, 
            expires_at 
        });
    } catch (error) {
        console.error('Erro ao gerar link de partilha:', error);
        res.status(500).json({ erro: 'Erro ao gerar link de partilha' });
    }
});

// Listar links de partilha de um documento
app.get('/api/documents/:id/shares', authenticate, async (req, res) => {
    const docId = req.params.id;
    
    try {
        // Verificar se o documento pertence ao utilizador
        const { data: doc, error: findError } = await supabase
            .from('documentos')
            .select('id')
            .eq('id', docId)
            .eq('user_id', req.userId)
            .single();

        if (findError || !doc) {
            return res.status(404).json({ erro: 'Documento não encontrado' });
        }

        const { data, error } = await supabase
            .from('share_links')
            .select('*')
            .eq('document_id', docId)
            .order('created_at', { ascending: false });

        if (error) throw error;

        res.json({ links: data || [] });
    } catch (error) {
        console.error('Erro ao listar links:', error);
        res.status(500).json({ erro: 'Erro ao listar links de partilha' });
    }
});

// Revogar link de partilha
app.delete('/api/share/:token', authenticate, async (req, res) => {
    const token = req.params.token;
    
    try {
        // Verificar se o utilizador é o proprietário do documento
        const { data: shareLink, error: findError } = await supabase
            .from('share_links')
            .select('document_id')
            .eq('token', token)
            .single();

        if (findError || !shareLink) {
            return res.status(404).json({ erro: 'Link de partilha não encontrado' });
        }

        // Verificar se o documento pertence ao utilizador
        const { data: doc, error: docError } = await supabase
            .from('documentos')
            .select('id')
            .eq('id', shareLink.document_id)
            .eq('user_id', req.userId)
            .single();

        if (docError || !doc) {
            return res.status(403).json({ erro: 'Não tem permissão para revogar este link' });
        }

        const { error } = await supabase
            .from('share_links')
            .delete()
            .eq('token', token);

        if (error) throw error;

        res.json({ sucesso: true, mensagem: 'Link revogado com sucesso' });
    } catch (error) {
        console.error('Erro ao revogar link:', error);
        res.status(500).json({ erro: 'Erro ao revogar link de partilha' });
    }
});

// Rota pública para acessar documento partilhado
// Rota pública para acessar documento partilhado
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

        if (error || !data) {
            return res.status(404).send(`
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Link inválido</title>
                    <meta charset="utf-8">
                    <style>
                        body { font-family: Arial; text-align: center; padding: 50px; background: #1e3c72; }
                        .container { max-width: 500px; margin: 0 auto; background: white; padding: 40px; border-radius: 12px; }
                        h1 { color: #dc3545; }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <h1>🔗 Link inválido</h1>
                        <p>Este link de partilha não é válido ou não existe.</p>
                    </div>
                </body>
                </html>
            `);
        }

        if (new Date(data.expires_at) < new Date()) {
            return res.status(410).send(`
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Link expirado</title>
                    <meta charset="utf-8">
                    <style>
                        body { font-family: Arial; text-align: center; padding: 50px; background: #1e3c72; }
                        .container { max-width: 500px; margin: 0 auto; background: white; padding: 40px; border-radius: 12px; }
                        h1 { color: #dc3545; }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <h1>⏰ Link expirado</h1>
                        <p>Este link de partilha expirou em ${new Date(data.expires_at).toLocaleDateString('pt-PT')}.</p>
                    </div>
                </body>
                </html>
            `);
        }

        const doc = data.documentos;
        const fileUrl = doc.file_url;
        const fileName = doc.original_name;
        const fileExt = fileName.split('.').pop().toLowerCase();
        
        // PDF - abre diretamente
        if (fileExt === 'pdf') {
            return res.redirect(fileUrl);
        }
        
        // Outros formatos - mostra com Google Docs e NOME CORRETO
        const googleViewer = `https://docs.google.com/gview?embedded=true&url=${encodeURIComponent(fileUrl)}`;
        
        res.send(`
            <!DOCTYPE html>
            <html>
            <head>
                <title>${fileName}</title>
                <meta charset="utf-8">
                <style>
                    * { margin: 0; padding: 0; box-sizing: border-box; }
                    body {
                        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                        background: #f5f7fa;
                        height: 100vh;
                        display: flex;
                        flex-direction: column;
                    }
                    .header {
                        background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
                        color: white;
                        padding: 15px 20px;
                        display: flex;
                        justify-content: space-between;
                        align-items: center;
                        flex-wrap: wrap;
                        gap: 10px;
                    }
                    .header h2 {
                        font-size: 18px;
                        font-weight: normal;
                        overflow: hidden;
                        text-overflow: ellipsis;
                        white-space: nowrap;
                        max-width: 60%;
                    }
                    .header a {
                        background: rgba(255,255,255,0.2);
                        color: white;
                        text-decoration: none;
                        padding: 8px 16px;
                        border-radius: 20px;
                        font-size: 14px;
                        transition: all 0.3s;
                    }
                    .header a:hover {
                        background: rgba(255,255,255,0.3);
                    }
                    iframe {
                        flex: 1;
                        width: 100%;
                        border: none;
                    }
                    .footer {
                        text-align: center;
                        padding: 10px;
                        background: #f8f9fa;
                        font-size: 12px;
                        color: #666;
                    }
                    @media (max-width: 700px) {
                        .header h2 { font-size: 14px; max-width: 50%; }
                    }
                </style>
            </head>
            <body>
                <div class="header">
                    <h2>📄 ${escapeHtml(fileName)}</h2>
                    <a href="${fileUrl}" download="${encodeURIComponent(fileName)}">⬇️ Baixar documento</a>
                </div>
                <iframe src="${googleViewer}"></iframe>
                <div class="footer">
                    🔗 Documento partilhado via Meus Documentos • Link válido até ${new Date(data.expires_at).toLocaleDateString('pt-PT')}
                </div>
            </body>
            </html>
        `);
    } catch (error) {
        console.error('Erro ao acessar documento partilhado:', error);
        res.status(500).send('Erro ao acessar o documento');
    }
});

// Função auxiliar para o HTML
function escapeHtml(text) {
    if (!text) return '';
    return text.replace(/[&<>]/g, function(m) {
        if (m === '&') return '&amp;';
        if (m === '<') return '&lt;';
        if (m === '>') return '&gt;';
        return m;
    }).replace(/[\uD800-\uDBFF][\uDC00-\uDFFF]/g, function(c) {
        return c;
    });
}
// ============================================
// ROTAS DE CONTA DE UTILIZADOR
// ============================================

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

    if (currentPassword === newPassword) {
        return res.status(400).json({ erro: 'A nova password deve ser diferente da atual' });
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
        console.error('Erro ao alterar password:', error);
        res.status(500).json({ erro: 'Erro ao alterar password' });
    }
});

// Obter informações do utilizador
app.get('/api/user', authenticate, async (req, res) => {
    try {
        const { data: user, error } = await supabase
            .from('usuarios')
            .select('id, email, created_at')
            .eq('id', req.userId)
            .single();

        if (error || !user) {
            return res.status(404).json({ erro: 'Utilizador não encontrado' });
        }

        // Contar documentos
        const { count, error: countError } = await supabase
            .from('documentos')
            .select('*', { count: 'exact', head: true })
            .eq('user_id', req.userId);

        if (countError) throw countError;

        res.json({ 
            sucesso: true,
            user: {
                id: user.id,
                email: user.email,
                created_at: user.created_at,
                total_documents: count || 0
            }
        });
    } catch (error) {
        console.error('Erro ao obter informações do utilizador:', error);
        res.status(500).json({ erro: 'Erro ao obter informações' });
    }
});

// Apagar conta
app.delete('/api/user/delete', authenticate, async (req, res) => {
    const userId = req.userId;
    const { password } = req.body;

    if (!password) {
        return res.status(400).json({ erro: 'Password obrigatória para confirmar exclusão' });
    }
    
    try {
        // Verificar password
        const { data: user, error: userError } = await supabase
            .from('usuarios')
            .select('password')
            .eq('id', userId)
            .single();

        if (userError || !user) {
            return res.status(404).json({ erro: 'Utilizador não encontrado' });
        }

        const valid = await bcrypt.compare(password, user.password);
        if (!valid) {
            return res.status(401).json({ erro: 'Password incorreta' });
        }

        // Listar documentos
        const { data: docs, error: listError } = await supabase
            .from('documentos')
            .select('filename')
            .eq('user_id', userId);

        if (listError) throw listError;

        // Deletar ficheiros do storage
        if (docs && docs.length > 0) {
            const filesToDelete = docs.map(doc => `user_${userId}/${doc.filename}`);
            await supabase.storage.from('documentos').remove(filesToDelete);
        }

        // Deletar links de partilha
        await supabase.from('share_links').delete().in(
            'document_id',
            (docs || []).map(d => d.id)
        );

        // Deletar documentos
        await supabase.from('documentos').delete().eq('user_id', userId);
        
        // Deletar utilizador
        const { error: deleteError } = await supabase
            .from('usuarios')
            .delete()
            .eq('id', userId);

        if (deleteError) throw deleteError;

        res.json({ sucesso: true, mensagem: 'Conta apagada com sucesso' });
    } catch (error) {
        console.error('Erro ao apagar conta:', error);
        res.status(500).json({ erro: 'Erro ao apagar conta' });
    }
});


// ============================================
// ROTAS DE ARMAZENAMENTO (ADMIN)
// ============================================

// Obter estatísticas de armazenamento
app.get('/api/storage/stats', authenticate, async (req, res) => {
    try {
        const adminEmail = 'contasemnome9080956@gmail.com';
        const isAdmin = req.userEmail === adminEmail;
        
        if (!isAdmin) {
            return res.status(403).json({ erro: 'Acesso apenas para administrador' });
        }
        
       const { data: configData, error: configError } = await supabase
    .from('config')
    .select('value')
    .eq('key', 'max_storage_mb')
    .single();

console.log('🔍 ERRO ao buscar config:', configError);
console.log('🔍 DADO encontrado:', configData);

const maxStorageMB = (configData && !configError) ? parseInt(configData.value) : 102400;
        
        const { data: uploadsAllowedData } = await supabase
            .from('config')
            .select('value')
            .eq('key', 'uploads_allowed')
            .single();
        
        const uploadsAllowed = uploadsAllowedData ? uploadsAllowedData.value === 'true' : true;
        
        const { data: allDocuments } = await supabase
            .from('documentos')
            .select('file_size');
        
        const totalUsedBytes = allDocuments?.reduce((sum, doc) => sum + (doc.file_size || 0), 0) || 0;
        const totalUsedMB = Math.round(totalUsedBytes / (1024 * 1024));
        const totalUsedGB = (totalUsedMB / 1024).toFixed(2);
        const maxStorageGB = (maxStorageMB / 1024).toFixed(2);
        
        const percentUsed = Math.min(100, Math.round((totalUsedMB / maxStorageMB) * 100));
        const remainingMB = Math.max(0, maxStorageMB - totalUsedMB);
        const remainingGB = (remainingMB / 1024).toFixed(2);
        
        const documentCount = allDocuments?.length || 0;
        
        res.json({
            sucesso: true,
            stats: {
                totalUsedMB, totalUsedGB, maxStorageMB, maxStorageGB,
                percentUsed, remainingMB, remainingGB, documentCount, uploadsAllowed
            }
        });
    } catch (error) {
        console.error('Erro:', error);
        res.status(500).json({ erro: 'Erro ao obter estatísticas' });
    }
});

// Alterar configurações
app.post('/api/storage/limit', authenticate, async (req, res) => {
    const { maxStorageMB, uploadsAllowed } = req.body;
    const adminEmail = 'contasemnome9080956@gmail.com';
    
    if (req.userEmail !== adminEmail) {
        return res.status(403).json({ erro: 'Acesso apenas para administrador' });
    }
    
    try {
        if (maxStorageMB !== undefined && maxStorageMB > 0) {
            await supabase.from('config').upsert({ key: 'max_storage_mb', value: String(maxStorageMB) });
        }
        if (uploadsAllowed !== undefined) {
            await supabase.from('config').upsert({ key: 'uploads_allowed', value: String(uploadsAllowed) });
        }
        res.json({ sucesso: true });
    } catch (error) {
        res.status(500).json({ erro: 'Erro ao atualizar' });
    }
});

// ============================================
// ROTAS DE TESTE E SAÚDE
// ============================================

// Rota de teste
app.get('/api/test', (req, res) => {
    res.json({ status: 'ok', message: 'Servidor funcionando!' });
});

// Health check
app.get('/api/health', (req, res) => {
    res.json({ status: 'healthy', timestamp: new Date().toISOString() });
});









// ============================================
// TRATAMENTO DE ERROS GLOBAL
// ============================================

// 404
app.use((req, res) => {
    res.status(404).json({ erro: 'Rota não encontrada' });
});

// Erro geral
app.use((err, req, res, next) => {
    console.error('Erro não tratado:', err);
    res.status(500).json({ erro: 'Erro interno do servidor' });
});

// ============================================
// INICIAR SERVIDOR
// ============================================

app.listen(PORT, () => {
    console.log(`📁 Sistema de Documentos rodando em http://localhost:${PORT}`);
    console.log(`🗄️ Supabase conectado: ${supabaseUrl}`);
    console.log(`✅ Servidor pronto para receber requisições`);
});

// Tratamento de sinais de encerramento
process.on('SIGTERM', () => {
    console.log('SIGTERM recebido. Encerrando...');
    process.exit(0);
});

process.on('SIGINT', () => {
    console.log('SIGINT recebido. Encerrando...');
    process.exit(0);
});

module.exports = app;
