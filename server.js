const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
require('dotenv').config();



// Guarda las variables de entorno en constantes
const dbHost = process.env.DB_HOST;
const dbPort = process.env.DB_PORT || 3306; // Proporciona un valor predeterminado
const dbUser = process.env.DB_USER;
const dbPass = process.env.DB_PASS;
const dbName = process.env.DB_NAME;
const port = process.env.PORT || 3000; // Proporciona un valor predeterminado

const app = express();

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public'))); // Servir archivos estáticos

const db = mysql.createConnection({
  host:dbHost ,
  user: dbUser,
  password: dbPass,
  database: dbName,
  port: dbPort // Asegúrate de que este sea el puerto correcto
});



// Conexión a la base de datos
db.connect((err) => {
  if (err) throw err;
  console.log('Conectado a la base de datos MySQL');
});

// Registro de usuario
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  const query = 'INSERT INTO users (username, password) VALUES (?, ?)';
  db.query(query, [username, hashedPassword], (err) => {
    if (err) return res.status(500).send('Error en el registro');
    res.status(201).send('Usuario registrado');
  });
});

// Login de usuario
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const query = 'SELECT * FROM users WHERE username = ?';

  db.query(query, [username], async (err, results) => {
    if (err) return res.status(500).send('Error en la autenticación');
    if (results.length === 0) return res.status(400).send('Usuario no encontrado');
    
    const user = results[0];
    const isPasswordValid = await bcrypt.compare(password, user.password);
    console.log('Contraseña ingresada:', password); // Para verificar la contraseña ingresada

    if (!isPasswordValid) return res.status(401).send('Contraseña incorrecta');
    
    // Generar token
    const token = jwt.sign({ id: user.id }, 'secretkey', { expiresIn: '1h' });
    res.json({ token });
  });
});

// Middleware para verificar JWT
function authenticateToken(req, res, next) {
  const token = req.headers['authorization'];
  if (!token) return res.sendStatus(403);

  jwt.verify(token, 'secretkey', (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// Obtener preguntas de un test específico
app.get('/api/tests/:testId/questions', authenticateToken, (req, res) => {
  const { testId } = req.params;
  const query = `
    SELECT q.id as question_id, q.question_text, q.type, o.id as option_id, o.option_text
    FROM questions q
    JOIN options o ON q.id = o.question_id
    WHERE q.test_id = ?`;

  db.query(query, [testId], (err, results) => {
    if (err) throw err;

    const questions = {};
    results.forEach(row => {
      if (!questions[row.question_id]) {
        questions[row.question_id] = {
          id: row.question_id,
          text: row.question_text,
          type: row.type,
          options: []
        };
      }
      questions[row.question_id].options.push({
        id: row.option_id,
        text: row.option_text
      });
    });

    res.json(Object.values(questions));
  });
});

// Validar respuestas y mostrar feedback
app.post('/api/tests/:testId/submit', authenticateToken, (req, res) => {
  const { answers } = req.body;
  const { testId } = req.params;

  const query = `
    SELECT q.id as question_id, o.id as option_id, o.is_correct, f.feedback_text
    FROM questions q
    JOIN options o ON q.id = o.question_id
    LEFT JOIN feedback f ON q.id = f.question_id
    WHERE q.test_id = ?`;

  db.query(query, [testId], (err, results) => {
    if (err) throw err;

    const feedback = [];
    let score = 0;

    results.forEach(row => {
      const userAnswer = answers.find(a => a.question_id === row.question_id);
      const isCorrect = userAnswer && userAnswer.option_id === row.option_id && row.is_correct;

      feedback.push({
        question_id: row.question_id,
        is_correct: isCorrect,
        feedback_text: isCorrect ? null : row.feedback_text
      });

      if (isCorrect) score++;
    });

    res.json({
      score,
      feedback
    });
  });
});

// Iniciar el servidor
app.listen(port, () => {
  console.log(`Servidor escuchando en http://localhost:${port}`);
});
