import express from 'express'
import { PrismaClient } from '@prisma/client'
import cors from 'cors'
import bcrypt from 'bcrypt';
import dotenv from 'dotenv';
import jwt from 'jsonwebtoken'

const prisma = new PrismaClient()
const app = express()
app.use(express.json())
app.use(cors())
dotenv.config();

const authenticateToken = (req, res, next) => {
    const authHeader = req.header('Authorization');
    if (!authHeader) {
        return res.status(401).json({ error: 'Acesso negado' });
    }

    const token = authHeader && authHeader.startsWith('Bearer ') ? authHeader.replace('Bearer ', '') : null;
    if (!token) {
        return res.status(401).json({ error: 'Acesso negado' });
    }

    try {
        const verified = jwt.verify(token, process.env.JWT_SECRET);
        req.user = verified;
        next();
    } catch (error) {
        res.status(400).json({ error: 'Token inválido' });
    }
};
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        console.log('Iniciando processo de login');
        const user = await prisma.user.findUnique({ where: { email } });
        if (!user) {
            console.log('Email não encontrado');
            return res.status(400).json({ error: 'Email ou senha incorretos' });
        }

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            console.log('Senha inválida');
            return res.status(400).json({ error: 'Email ou senha incorretos' });
        }

        const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        console.log('Token gerado:', token);
        res.header('Authorization', token).json({ token });
    } catch (error) {
        console.error('Erro no login:', error);
        res.status(500).json({ error: 'Erro ao fazer login' });
    }
});

app.get('/usuarios', async (req, res) => {
    try {
        const users = await prisma.user.findMany({
            where: {
                AND: [
                    req.query.name ? { name: { contains: req.query.name } } : {},
                    req.query.email ? { email: { contains: req.query.email } } : {}
                ]
            }
        });
        res.status(200).json(users.map(user => {
            delete user.password; // Excluir a senha da resposta
            return user;
        }));
    } catch (error) {
        res.status(500).json({ error: 'Erro ao listar usuários' });
    }
});

app.put('/usuarios/:id', async (req, res) => {
    try {
        const user = await prisma.user.update({
            where: {
                id: parseInt(req.params.id)
            },
            data: {
                email: req.body.email,
                name: req.body.name,
                password: req.body.password
            }
        })
        res.status(202).json(user)
    } catch (error) {
        res.status(500).json({ error: 'Erro ao atualizar usuário' })
    }
})

app.delete('/usuarios/:id', async (req, res) => {
    try {
        await prisma.user.delete({
            where: {
                id: parseInt(req.params.id)
            }
        })
        res.status(203).json({ message: 'Usuário deletado!' })
    } catch (error) {
        res.status(500).json({ error: 'Erro ao deletar usuário' })
    }
})

app.get('/usuarios/me', authenticateToken, async (req, res) => {
    try {
      const user = await prisma.user.findUnique({
        where: { id: req.user.id }
      });
      if (!user) return res.status(404).json({ error: 'Usuário não encontrado' });
      res.status(200).json(user);
    } catch (error) {
      res.status(500).json({ error: 'Erro ao buscar dados do usuário' });
    }
  });

  app.post('/usuarios', async (req, res) => {
    const { name, email, password } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10); // Hash da senha
        const newUser = await prisma.user.create({
            data: {
                name,
                email,
                password: hashedPassword
            }
        });
        res.status(201).json({ id: newUser.id, name: newUser.name, email: newUser.email }); // Retorne o usuário criado (sem senha)
    } catch (error) {
        console.error('Erro ao criar usuário:', error);
        res.status(500).json({ error: 'Erro ao criar usuário' });
    }
});



app.listen(3000, () => {
    console.log('Servidor rodando na porta 3000')
})
