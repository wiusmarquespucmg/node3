var express = require('express');
var router = express.Router();

const knex = require('knex');
const db = knex(require('../knexfile')['development']);


// Listando todos os clientes
router.get('/clients', function(req, res, next) {
    db.select().from('clients').then((clients) => {
        res.json(clients);
    }).catch((err) => {
        res.status(500).json({ error: err.message });
    });
});


// Buscando por um cliente específico
router.get('/clients/:id', function(req, res, next) {
    db.select().from('clients').where('id', req.params.id).then((clients) => {
        if (clients.length > 0) {
            res.json(clients[0]);
        } else {
            res.status(404).json({ error: `Cliente com id ${req.params.id} não encontrado`});
        }
    }).catch((err) => {
        res.status(500).json({ error: err.message });
    });
});

// Criando um novo cliente
router.post('/clients', function(req, res, next) {
    db.insert(req.body).returning('*').into('clients').then((clients) => {
        res.json(clients[0]);
    }).catch((err) => {
        res.status(500).json({ error: err.message });
    });
});

// Atualizando um cliente
router.put('/clients/:id', function(req, res, next) {
    db('clients').where('id', req.params.id).update(req.body).returning('*').then((clients) => {
        if (clients.length > 0) {
            res.json(clients[0]);
        } else {
            res.status(404).json({ error: `Cliente com id ${req.params.id} não encontrado`});
        }
    }).catch((err) => {
        res.status(500).json({ error: err.message });
    });
});

// Deletando um cliente
router.delete('/clients/:id', function(req, res, next) {
    db.select().from('clients').where('id', req.params.id).then((clients) => {
        if (clients.length <= 0) {
            res.status(404).json({ error: `Cliente com id ${req.params.id} não encontrado`});
        }else{
            db('clients').where('id', req.params.id).del().returning('*').then((clients) => {
                res.status(200).json({ success: `Cliente com id ${req.params.id} deletado com sucesso` });
            }).catch((err) => {
                res.status(500).json({ error: err.message });
            });
        }
    }).catch((err) => {
        res.status(500).json({ error: err.message });
    });
});

module.exports = router;
