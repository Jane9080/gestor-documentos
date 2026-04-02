const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const sqlite3 = require('sqlite3').verbose();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const multer = require('multer');
const crypto = require('crypto');

const app = express();
const PORT = 3000;
const SECRET_KEY = 'documentos_secret_key_2024';

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Criar pasta de uploads se não existir
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir);
}

// Configuração do multer para upload de ficheiros
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const userDir = path.join(uploadsDir, req.userId.toString());
        if (!fs.existsSync(userDir)) {
            fs.mkdirSync(userDir);
        }
        cb(null, userDir);
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        const ext = path.extname(file.originalname);
        cb(null, uniqueSuffix + ext);
    }
});

const upload = multer({ 
    storage: storage,
    limits: { fileSize: 100 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        const allowedTypes = ['.pdf', '.doc', '.docx', '.ppt', '.pptx'];
        const ext = path.extname(file.originalname).toLowerCase();
        if (allowedTypes.includes(ext)) {
            cb(null, true);
        } else {
            cb(new Error('Tipo de ficheiro não permitido. Apenas PDF, Word e PowerPoint.'));
        }
    }
});

// Base de dados SQLite
const db = new sqlite3.Database(path.join(__dirname, 'database.sqlite'));

// Criar tabelas
db.serialize(() => {
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            original_name TEXT NOT NULL,
            file_path TEXT NOT NULL,
            file_type TEXT NOT NULL,
            file_size INTEGER NOT NULL,
            tags TEXT DEFAULT '[]',
            favorite INTEGER DEFAULT 0,
            uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS share_links (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            document_id INTEGER NOT NULL,
            token TEXT UNIQUE NOT NULL,
            expires_at DATETIME NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (document_id) REFERENCES documents(id) ON DELETE CASCADE
        )
    `);
});

// Função para corrigir codificação de nomes de ficheiro
function fixEncoding(str) {
    if (!str) return str;
    try {
        return decodeURIComponent(escape(str));
    } catch (e) {
        return str;
    }
}

// Middleware de autenticação (aceita token do header OU da URL)
const authenticate = (req, res, next) => {
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

// ==================== ROTAS DE AUTENTICAÇÃO ====================

app.post('/api/register', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ erro: 'Email e password são obrigatórios' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        
        db.run('INSERT INTO users (email, password) VALUES (?, ?)', [email, hashedPassword], function(err) {
            if (err) {
                if (err.message.includes('UNIQUE')) {
                    return res.status(400).json({ erro: 'Email já registado' });
                }
                return res.status(500).json({ erro: 'Erro ao registar' });
            }
            
            const token = jwt.sign({ userId: this.lastID, email }, SECRET_KEY, { expiresIn: '7d' });
            res.json({ sucesso: true, token, userId: this.lastID, email });
        });
    } catch (error) {
        res.status(500).json({ erro: 'Erro ao registar' });
    }
});

app.post('/api/login', (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ erro: 'Email e password são obrigatórios' });
    }

    db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
        if (err || !user) {
            return res.status(401).json({ erro: 'Credenciais inválidas' });
        }

        const valid = await bcrypt.compare(password, user.password);
        if (!valid) {
            return res.status(401).json({ erro: 'Credenciais inválidas' });
        }

        const token = jwt.sign({ userId: user.id, email: user.email }, SECRET_KEY, { expiresIn: '7d' });
        res.json({ sucesso: true, token, userId: user.id, email: user.email });
    });
});

// ==================== ROTAS DE DOCUMENTOS ====================

// 1. APAGAR TODOS (DEVE VIR PRIMEIRO)
app.delete('/api/documents/delete-all', authenticate, (req, res) => {
    const userId = req.userId;
    console.log(`🗑️ Apagar todos os documentos do utilizador: ${userId}`);
    
    db.all('SELECT id, file_path FROM documents WHERE user_id = ?', [userId], (err, docs) => {
        if (err) {
            console.error('Erro ao listar:', err);
            return res.status(500).json({ erro: 'Erro ao listar documentos' });
        }
        if (docs.length === 0) {
            return res.json({ sucesso: true, mensagem: 'Nenhum documento para apagar', count: 0 });
        }
        
        docs.forEach(doc => {
            if (doc.file_path && fs.existsSync(doc.file_path)) {
                fs.unlink(doc.file_path, () => {});
            }
        });
        
        db.run('DELETE FROM documents WHERE user_id = ?', [userId], function(deleteErr) {
            if (deleteErr) {
                return res.status(500).json({ erro: 'Erro ao apagar documentos' });
            }
            res.json({ sucesso: true, mensagem: `${this.changes} documentos apagados`, count: this.changes });
        });
    });
});

// 2. Upload de documento
app.post('/api/upload', authenticate, upload.single('documento'), (req, res) => {
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
    
    const ext = path.extname(originalName).toLowerCase();
    let fileType = 'outro';
    if (ext === '.pdf') fileType = 'pdf';
    else if (['.doc', '.docx'].includes(ext)) fileType = 'word';
    else if (['.ppt', '.pptx'].includes(ext)) fileType = 'powerpoint';

    db.run(`
        INSERT INTO documents (user_id, filename, original_name, file_path, file_type, file_size, tags)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    `, [req.userId, file.filename, originalName, file.path, fileType, file.size, JSON.stringify(tags)], function(err) {
        if (err) {
            console.error('Erro ao guardar documento:', err);
            return res.status(500).json({ erro: 'Erro ao guardar documento' });
        }
        res.json({ 
            sucesso: true, 
            documento: {
                id: this.lastID,
                filename: file.filename,
                original_name: originalName,
                file_type: fileType,
                file_size: file.size,
                tags: tags,
                uploaded_at: new Date().toISOString()
            }
        });
    });
});

// 3. Listar documentos
app.get('/api/documents', authenticate, (req, res) => {
    db.all('SELECT * FROM documents WHERE user_id = ? ORDER BY uploaded_at DESC', [req.userId], (err, rows) => {
        if (err) {
            console.error('Erro ao listar documentos:', err);
            return res.status(500).json({ erro: 'Erro ao listar documentos' });
        }
        const documentos = rows.map(doc => ({
            ...doc,
            original_name: fixEncoding(doc.original_name),
            tags: doc.tags ? JSON.parse(doc.tags) : [],
            favorite: doc.favorite || 0
        }));
        res.json({ documentos });
    });
});

// 4. Download documento
app.get('/api/download/:id', authenticate, (req, res) => {
    const docId = req.params.id;
    
    db.get('SELECT * FROM documents WHERE id = ? AND user_id = ?', [docId, req.userId], (err, doc) => {
        if (err || !doc) {
            return res.status(404).json({ erro: 'Documento não encontrado' });
        }
        
        const originalName = fixEncoding(doc.original_name);
        res.download(doc.file_path, originalName);
    });
});

// 5. Visualizar documento
app.get('/api/view/:id', authenticate, (req, res) => {
    const docId = req.params.id;
    
    db.get('SELECT * FROM documents WHERE id = ? AND user_id = ?', [docId, req.userId], (err, doc) => {
        if (err || !doc) {
            return res.status(404).json({ erro: 'Documento não encontrado' });
        }
        
        const filePath = path.resolve(doc.file_path);
        const ext = path.extname(doc.original_name).toLowerCase();
        
        let contentType = 'application/octet-stream';
        if (ext === '.pdf') contentType = 'application/pdf';
        else if (ext === '.doc') contentType = 'application/msword';
        else if (ext === '.docx') contentType = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document';
        else if (ext === '.ppt') contentType = 'application/vnd.ms-powerpoint';
        else if (ext === '.pptx') contentType = 'application/vnd.openxmlformats-officedocument.presentationml.presentation';
        
        res.setHeader('Content-Type', contentType);
        res.setHeader('Content-Disposition', `inline; filename="${encodeURIComponent(doc.original_name)}"`);
        res.setHeader('Cache-Control', 'no-cache');
        
        res.sendFile(filePath);
    });
});

// 6. Apagar um documento (DEVE VIR DEPOIS DO delete-all)
app.delete('/api/documents/:id', authenticate, (req, res) => {
    const docId = req.params.id;
    
    db.get('SELECT * FROM documents WHERE id = ? AND user_id = ?', [docId, req.userId], (err, doc) => {
        if (err || !doc) {
            return res.status(404).json({ erro: 'Documento não encontrado' });
        }
        
        fs.unlink(doc.file_path, (unlinkErr) => {
            if (unlinkErr) console.error('Erro ao apagar ficheiro:', unlinkErr);
        });
        
        db.run('DELETE FROM documents WHERE id = ?', [docId], (deleteErr) => {
            if (deleteErr) {
                return res.status(500).json({ erro: 'Erro ao apagar documento' });
            }
            res.json({ sucesso: true, mensagem: 'Documento apagado' });
        });
    });
});

// 7. Renomear documento
app.put('/api/documents/:id/rename', authenticate, (req, res) => {
    const docId = req.params.id;
    const { newName } = req.body;
    
    if (!newName) return res.status(400).json({ erro: 'Nome não fornecido' });
    
    db.get('SELECT * FROM documents WHERE id = ? AND user_id = ?', [docId, req.userId], (err, doc) => {
        if (err || !doc) return res.status(404).json({ erro: 'Documento não encontrado' });
        
        const ext = path.extname(doc.original_name);
        let newFileName = newName;
        if (!newName.toLowerCase().endsWith(ext.toLowerCase())) {
            newFileName = newName + ext;
        }
        
        db.run('UPDATE documents SET original_name = ? WHERE id = ?', [newFileName, docId], function(updateErr) {
            if (updateErr) return res.status(500).json({ erro: 'Erro ao renomear' });
            res.json({ sucesso: true, mensagem: 'Documento renomeado' });
        });
    });
});

// 8. Atualizar tags
app.put('/api/documents/:id/tags', authenticate, (req, res) => {
    const docId = req.params.id;
    const { tags } = req.body;
    
    db.get('SELECT * FROM documents WHERE id = ? AND user_id = ?', [docId, req.userId], (err, doc) => {
        if (err || !doc) return res.status(404).json({ erro: 'Documento não encontrado' });
        
        db.run('UPDATE documents SET tags = ? WHERE id = ?', [JSON.stringify(tags || []), docId], function(updateErr) {
            if (updateErr) return res.status(500).json({ erro: 'Erro ao atualizar tags' });
            res.json({ sucesso: true, mensagem: 'Tags atualizadas' });
        });
    });
});

// 9. Marcar/desmarcar favorito
app.put('/api/documents/:id/favorite', authenticate, (req, res) => {
    const docId = req.params.id;
    const { favorite } = req.body;
    
    db.run('UPDATE documents SET favorite = ? WHERE id = ? AND user_id = ?',
        [favorite ? 1 : 0, docId, req.userId], function(err) {
            if (err) return res.status(500).json({ erro: 'Erro ao atualizar favorito' });
            res.json({ sucesso: true, mensagem: 'Favorito atualizado' });
        });
});

// ==================== ROTAS DE PARTILHA ====================

// Gerar link de partilha
app.post('/api/documents/:id/share', authenticate, (req, res) => {
    const docId = req.params.id;
    const { expires_days = 7 } = req.body;
    
    db.get('SELECT * FROM documents WHERE id = ? AND user_id = ?', [docId, req.userId], (err, doc) => {
        if (err || !doc) {
            return res.status(404).json({ erro: 'Documento não encontrado' });
        }
        
        const token = crypto.randomBytes(32).toString('hex');
        const expires_at = new Date();
        expires_at.setDate(expires_at.getDate() + expires_days);
        
        db.run('INSERT INTO share_links (document_id, token, expires_at) VALUES (?, ?, ?)',
            [docId, token, expires_at.toISOString()], function(err) {
                if (err) {
                    return res.status(500).json({ erro: 'Erro ao gerar link' });
                }
                const shareUrl = `${req.protocol}://${req.get('host')}/share/${token}`;
                res.json({ sucesso: true, url: shareUrl, token, expires_at });
            });
    });
});

// Rota pública para aceder ao documento partilhado
app.get('/share/:token', (req, res) => {
    const token = req.params.token;
    
    db.get(`
        SELECT d.*, s.expires_at FROM share_links s
        JOIN documents d ON s.document_id = d.id
        WHERE s.token = ? AND s.expires_at > datetime('now')
    `, [token], (err, doc) => {
        if (err || !doc) {
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
        
        const filePath = path.resolve(doc.file_path);
        const ext = path.extname(doc.original_name).toLowerCase();
        
        let contentType = 'application/octet-stream';
        if (ext === '.pdf') contentType = 'application/pdf';
        else if (ext === '.doc') contentType = 'application/msword';
        else if (ext === '.docx') contentType = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document';
        else if (ext === '.ppt') contentType = 'application/vnd.ms-powerpoint';
        else if (ext === '.pptx') contentType = 'application/vnd.openxmlformats-officedocument.presentationml.presentation';
        
        res.setHeader('Content-Type', contentType);
        res.setHeader('Content-Disposition', `inline; filename="${encodeURIComponent(doc.original_name)}"`);
        res.setHeader('Cache-Control', 'no-cache');
        res.sendFile(filePath);
    });
});

// Listar links partilhados de um documento
app.get('/api/documents/:id/shares', authenticate, (req, res) => {
    const docId = req.params.id;
    
    db.all('SELECT * FROM share_links WHERE document_id = ? ORDER BY created_at DESC', [docId], (err, rows) => {
        if (err) return res.status(500).json({ erro: 'Erro ao listar links' });
        res.json({ links: rows });
    });
});

// Revogar link de partilha
app.delete('/api/share/:token', authenticate, (req, res) => {
    const token = req.params.token;
    
    db.run('DELETE FROM share_links WHERE token = ?', [token], function(err) {
        if (err) return res.status(500).json({ erro: 'Erro ao revogar link' });
        res.json({ sucesso: true, mensagem: 'Link revogado' });
    });
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

    db.get('SELECT * FROM users WHERE id = ?', [userId], async (err, user) => {
        if (err || !user) {
            return res.status(404).json({ erro: 'Utilizador não encontrado' });
        }

        // Verificar password atual
        const valid = await bcrypt.compare(currentPassword, user.password);
        if (!valid) {
            return res.status(401).json({ erro: 'Password atual incorreta' });
        }

        // Hash da nova password
        const hashedPassword = await bcrypt.hash(newPassword, 10);

        db.run('UPDATE users SET password = ? WHERE id = ?', [hashedPassword, userId], function(updateErr) {
            if (updateErr) {
                return res.status(500).json({ erro: 'Erro ao alterar password' });
            }
            res.json({ sucesso: true, mensagem: 'Password alterada com sucesso' });
        });
    });
});

// Apagar conta do utilizador
app.delete('/api/user/delete', authenticate, (req, res) => {
    const userId = req.userId;
    
    db.all('SELECT file_path FROM documents WHERE user_id = ?', [userId], (err, docs) => {
        if (err) {
            console.error('Erro ao listar documentos:', err);
            return res.status(500).json({ erro: 'Erro ao listar documentos' });
        }
        
        docs.forEach(doc => {
            if (doc.file_path && fs.existsSync(doc.file_path)) {
                fs.unlink(doc.file_path, () => {});
            }
        });
        
        const userDir = path.join(uploadsDir, userId.toString());
        if (fs.existsSync(userDir)) {
            fs.rm(userDir, { recursive: true, force: true }, (rmErr) => {
                if (rmErr) console.error('Erro ao apagar pasta:', rmErr);
            });
        }
        
        db.run('DELETE FROM documents WHERE user_id = ?', [userId], (docErr) => {
            if (docErr) console.error('Erro ao apagar documentos:', docErr);
            
            db.run('DELETE FROM users WHERE id = ?', [userId], function(userErr) {
                if (userErr) {
                    console.error('Erro ao apagar utilizador:', userErr);
                    return res.status(500).json({ erro: 'Erro ao apagar conta' });
                }
                res.json({ sucesso: true, mensagem: 'Conta apagada com sucesso' });
            });
        });
    });
});

app.listen(PORT, () => {
    console.log(`📁 Sistema de Documentos rodando em http://localhost:${PORT}`);
});
