const jwt = require('jsonwebtoken');

function authenticateToken(req, res, next) {
    // Obtenha o token do cabeçalho de autorização
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
  
    if (!token) {
      return res.status(401).json({ error: 'Token não fornecido' });
    }
  
    // Verifique o token
    jwt.verify(token, 'secreto', (err, user) => {
      if (err) {
        return res.status(403).json({ error: 'Token inválido' });
      }
      // O token é válido, você pode adicionar o usuário autenticado ao objeto de solicitação
      req.user = user;
      next(); // Chame next() para continuar a execução da rota protegida
    });
  }
  
  module.exports = authenticateToken;