require('dotenv').config();
const express = require("express");
const app = express();
const { prisma } = require("./database/db");
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const saltRounds = 10;
app.use(express.json());

function generateToken(user){
    return jwt.sign({id: user.id, email: user.email}, process.env.JWTSECRET, { 
        expiresIn: '1h',
        jwtid: crypto.randomUUID()
    });
}

function requireAuth(req,res,next){
    const authHeader = req.headers.authorization;

    if(!authHeader || !authHeader.startsWith('Bearer ')){
        return res.status(401).json({error:"Unauthorized access."})
    }

    const token = authHeader.split(" ")[1];

    try{
        const decoded = jwt.verify(token, process.env.JWTSECRET);
        req.user = decoded;
        next();
    }catch(err){
        return res.status(401).json({error:"Invalid or expired token."})
    }
}

app.post("/signup",async (req,res)=>{
    try{
        const { email, password } = req.body;

        if (typeof email !== 'string' || typeof password !== 'string' || !email.trim() || password.length < 6){
            return res.status(400).json({ error: "Invalid input." });
        }

        const normalizedEmail = email.trim().toLowerCase();

        const user = await prisma.user.findUnique({
            where: { email: normalizedEmail },
        });

        if(user){
            return res.status(409).json({error:"Email already exists."})
        }

        const hashedPassword = await bcrypt.hash(password, saltRounds);

        const newUser = await prisma.user.create({
            data:{
                email: normalizedEmail,
                password: hashedPassword
            }, 
            select: {
            id: true,
            email: true,
            createdAt: true
        }
        })

        const token = generateToken(newUser);
        res.status(201).json({message:"Registration successful.",user: newUser, token})
    }catch(err){
        return res.status(500).json({error:"Internal server error."})
    }
})


app.post("/login",async(req,res)=>{
    try{const {email,password} = req.body;

    if(!email || !password || typeof email !== 'string' || typeof password !=='string' || !email.trim()){
        return res.status(400).json({error: "Missing or invalid input."
    })
    }

    const normalizedEmail = email.trim().toLowerCase();

    const existingEmail = await prisma.user.findUnique({
        where: {email : normalizedEmail}
    })

    if(!existingEmail){
        return res.status(401).json({error:" Invalid email or password."})
    }

    const isPasswordValid = await bcrypt.compare(password, existingEmail.password);

    if(!isPasswordValid){
        return res.status(401).json({error:" Invalid email or password."
    })}

    const token = generateToken(existingEmail);

    return res.status(200).json({message:"Login successful.", token})
    }catch(err){
        return res.status(500).json({error:"Internal server error."})
    }
})

app.get("/me",requireAuth,async(req,res)=>{
    try {
        const user = await prisma.user.findUnique({
            where: {
                id: req.user.id
            },
            select: {
                id: true,
                email: true,
                name: true,
                createdAt: true
            }
        });

        if (!user) {
            return res.status(404).json({
                error: "User not found."
            });
        }

        return res.status(200).json({ user });

    } catch (err) {
        return res.status(500).json({
            error: "Internal server error."
        });
    }
})

app.get("/dashboard", requireAuth, async (req, res) => {
    try {
        const user = await prisma.user.findUnique({
            where: {
                id: req.user.id
            },
            select: {
                email: true,
                name: true
            }
        });

        if (!user) {
            return res.status(404).json({
                error: "User not found."
            });
        }

        const displayName = user.name || user.email;

        return res.status(200).json({
            message: `Welcome, ${displayName}!`
        });

    } catch (err) {
        return res.status(500).json({
            error: "Internal server error."
        });
    }
});

app.listen(3000,()=>{
    console.log("Server is running on port 3000")
})