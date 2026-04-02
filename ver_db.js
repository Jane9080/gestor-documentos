const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('database.sqlite');

db.all('SELECT * FROM documents', [], (err, rows) => {
    if (err) {
        console.error('Erro:', err);
    } else {
        console.log('Documentos encontrados:', rows);
    }
    db.close();
});