const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('database.sqlite');

// Verificar se a coluna tags já existe
db.get("PRAGMA table_info(documents)", (err, rows) => {
    if (err) {
        console.error('Erro:', err);
        db.close();
        return;
    }
    
    // Tentar adicionar a coluna
    db.run("ALTER TABLE documents ADD COLUMN tags TEXT DEFAULT '[]'", function(err) {
        if (err) {
            if (err.message.includes('duplicate column name')) {
                console.log('✅ Coluna tags já existe!');
            } else {
                console.error('Erro ao adicionar coluna:', err);
            }
        } else {
            console.log('✅ Coluna tags adicionada com sucesso!');
        }
        db.close();
    });
});