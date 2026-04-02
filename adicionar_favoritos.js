const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('database.sqlite');

// Adicionar coluna favorite
db.run("ALTER TABLE documents ADD COLUMN favorite INTEGER DEFAULT 0", function(err) {
    if (err) {
        if (err.message.includes('duplicate column name')) {
            console.log('✅ Coluna favorite já existe!');
        } else {
            console.error('Erro ao adicionar coluna:', err);
        }
    } else {
        console.log('✅ Coluna favorite adicionada com sucesso!');
    }
    db.close();
});