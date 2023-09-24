var createError = require('http-errors');
var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');

var clientsRouter = require('./routes/clients');

var app = express();

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'jade');

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

app.use('/api/v1', clientsRouter);


// rota curinga para página não encontrada
app.use(function(req, res, next) {
  return res.status(404).send({ message: 'A rota '+req.url+' Não foi encontrada. Verifique a lista de rotas disponíveis abaixo', routes: [
    { method: 'GET', path: '/api/v1/clients', description: 'Listar todos os clientes' },
    { method: 'GET', path: '/api/v1/clients/:id', description: 'Buscar um cliente específico' },
    { method: 'POST', path: '/api/v1/clients', description: 'Criar um novo cliente' },
    { method: 'PUT', path: '/api/v1/clients/:id', description: 'Atualizar um cliente' },
    { method: 'DELETE', path: '/api/v1/clients/:id', description: 'Remover um cliente' }
  ]});
});

module.exports = app;
