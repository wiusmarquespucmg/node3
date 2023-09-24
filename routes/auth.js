const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const knex = require('knex');
const db = knex(require('../knexfile')['development']);
var express = require('express');
var router = express.Router();

router.post('/register', async function(req, res, next) {
    try {
        const { user, email, password } = req.body;

        //log com os dados do body
        console.log(req.body, user, email, password);


        const hashedPassword = await bcrypt.hash(password, 10);

        
        //verificar se o usuário já existe
        const userExists = await db('users').where({ user }).first();
        if (userExists) {
            return res.status(409).json({ error: 'Usuário já cadastrado' });
        }

        // método insert está a falhar pois está mudando a ordem dos campos com SQLLite
        const sql = 'INSERT INTO users (user, email, password) VALUES (?, ?, ?)';
        const params = [user, email, hashedPassword];

        const result = await db.raw(sql, params);

        res.status(201).json({ message: 'Usuário registrado com sucesso' });
    }catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

router.post('/login', async function(req, res, next) {
    try {
        const { user, password } = req.body;

        if(!user || !password) {
            return res.status(400).json({ error: 'Credenciais inválidas' });
        }


        // verificar se o usuário existe
        const userExists = await db('users').where({ user }).first();

        if (!userExists) {
            return res.status(401).json({ error: 'Credenciais inválidas' });
        }

        // verificar se a senha está correta
        const passwordMatch = await bcrypt.compare(password, userExists.password);

        if (!passwordMatch) {
            return res.status(401).json({ error: 'Credenciais inválidas' });
        }

        // Criar o JWT e retornar para o usuário

        const token = jwt.sign({ userId: user.id }, 'secreto', { expiresIn: '1h' });

        res.status(200).json({ token });


    }catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Erro interno do servidor' });
    }

});

module.exports = router;